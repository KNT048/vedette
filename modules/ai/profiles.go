package ai

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// ProfileInput is the body of an add, an edit or a test of a profile. APIKey "" means no new key.
type ProfileInput struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	APIStyle provider.APIStyle `json:"api_style"`
	BaseURL  string            `json:"base_url"`
	Model    string            `json:"model"`
	APIKey   string            `json:"api_key"`
	Location Location          `json:"location"`
	DailyCap int               `json:"daily_cap"`
}

// ProfileView is a profile as the API shows it: never the key, only its last four characters (INV-1).
type ProfileView struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	APIStyle  string  `json:"api_style"`
	BaseURL   string  `json:"base_url"`
	Model     string  `json:"model"`
	KeyLast4  *string `json:"key_last4"`
	Location  string  `json:"location"`
	DailyCap  int     `json:"daily_cap"`
	Usable    bool    `json:"usable"`
	UsedToday int     `json:"used_today"`
}

// TestResult is what a connection test reports (PRE-3).
type TestResult struct {
	OK           bool         `json:"ok"`
	LatencyMS    float64      `json:"latency_ms"`
	TokensIn     int          `json:"tokens_in"`
	TokensOut    int          `json:"tokens_out"`
	Capabilities Capabilities `json:"capabilities"`
}

// Capabilities are what the provider accepted when tried.
type Capabilities struct {
	Tools      bool `json:"tools"`
	Structured bool `json:"structured"`
}

func (s *Service) view(p stored) ProfileView {
	v := ProfileView{ID: p.ID, Name: p.Name, Kind: p.Kind, APIStyle: string(p.APIStyle), BaseURL: p.BaseURL, Model: p.Model,
		Location: string(p.Location), DailyCap: p.DailyCap, Usable: p.Usable(), UsedToday: s.meter.ProfileUsed(p.ID)}
	if p.APIKey.IsSet() {
		l := p.APIKey.Last4()
		v.KeyLast4 = &l
	}
	return v
}

// Profiles lists the profiles in the order they were added.
func (s *Service) Profiles() []ProfileView {
	sn := s.snap.Load()
	out := make([]ProfileView, 0, len(sn.profiles))
	for _, p := range sn.profiles {
		out = append(out, s.view(p))
	}
	return out
}

// mapErr turns a rule failure of the library into the API error with its stable code.
func mapErr(err error) error {
	var pe *ProfileError
	if errors.As(err, &pe) {
		return apierr.New(http.StatusBadRequest, pe.Code, pe.Msg)
	}
	var ae *AssignmentError
	if errors.As(err, &ae) {
		return apierr.New(http.StatusBadRequest, ae.Code, ae.Msg)
	}
	return err
}

func profileNotFound() error {
	return apierr.New(http.StatusNotFound, "not_found", "This AI profile no longer exists.")
}

func duplicateName() error {
	return apierr.New(http.StatusBadRequest, "duplicate_name", "Another profile already has this name. Pick a different one.")
}

func (sn *snapshot) nameTaken(name, except string) bool {
	for _, p := range sn.profiles {
		if p.ID != except && nameKey(p.Name) == nameKey(name) {
			return true
		}
	}
	return false
}

// buildProfile makes the library profile of an input. The API style follows the kind (only a custom profile chooses it).
func buildProfile(in ProfileInput, id string, key provider.Secret) Profile {
	p := Profile{ID: id, Name: strings.TrimSpace(in.Name), Kind: in.Kind, APIStyle: in.APIStyle, BaseURL: strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"),
		Model: in.Model, APIKey: key, Location: in.Location, DailyCap: in.DailyCap}
	if st, err := provider.StyleForKind(in.Kind, in.APIStyle); err == nil {
		p.APIStyle = st
	}
	return p
}

func keyOf(in ProfileInput) provider.Secret {
	if in.APIKey == "" {
		return provider.Secret{}
	}
	return provider.NewSecret(in.APIKey)
}

// AddProfile saves a new profile. A job that has no primary profile takes it, where the privacy rule allows, so a first profile
// works at once.
func (s *Service) AddProfile(ctx context.Context, who string, in ProfileInput) (ProfileView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != "" {
		return ProfileView{}, s.errDegraded()
	}
	cur := s.snap.Load()
	p := buildProfile(in, store.NewID("prof"), keyOf(in))
	if err := p.Validate(); err != nil {
		return ProfileView{}, mapErr(err)
	}
	if len(cur.profiles) >= MaxProfiles {
		return ProfileView{}, apierr.New(http.StatusBadRequest, "too_many", fmt.Sprintf("A box holds up to %d AI profiles. Remove one you no longer use.", MaxProfiles))
	}
	if cur.nameTaken(p.Name, "") {
		return ProfileView{}, duplicateName()
	}
	asg := cloneAssign(cur.assign)
	var taken []Job
	for _, j := range Jobs() {
		if slot := asg.Jobs[j]; slot.Primary == "" && asg.Allowed(j, p) {
			slot.Primary = p.ID
			asg.Jobs[j] = slot
			taken = append(taken, j)
		}
	}
	st := stored{Profile: p}
	next := &snapshot{profiles: append(append([]stored(nil), cur.profiles...), st), assign: asg, cfg: cur.cfg}
	if err := next.check(); err != nil {
		return ProfileView{}, mapErr(err)
	}
	now := s.cfg.Clock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var secretID, last4 sql.NullString
		if p.APIKey.IsSet() {
			id, l4, err := s.cfg.Secrets.Seal(ctx, tx, secretPurpose, []byte(in.APIKey), true)
			if err != nil {
				return fmt.Errorf("ai: seal key: %w", err)
			}
			secretID, last4 = sql.NullString{String: id, Valid: true}, sql.NullString{String: l4, Valid: true}
			st.secretID = id
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO ai_profile (id, name, name_key, kind, api_style, base_url, model, secret_id, key_last4, location, daily_cap, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.Name, nameKey(p.Name), p.Kind, string(p.APIStyle), p.BaseURL, p.Model, secretID, last4, string(p.Location), p.DailyCap, store.FormatTS(now), store.FormatTS(now))
		if err != nil {
			return fmt.Errorf("ai: add profile: %w", err)
		}
		for _, j := range taken {
			if _, err := tx.ExecContext(ctx, `UPDATE ai_assignment SET primary_profile_id = ? WHERE job = ?`, p.ID, string(j)); err != nil {
				return fmt.Errorf("ai: assign new profile: %w", err)
			}
		}
		detail := fmt.Sprintf("%s, %s, model=%s, host=%s", p.Kind, p.Location, p.Model, hostOf(p.BaseURL))
		if p.APIKey.IsSet() {
			detail += ", key set"
		}
		return s.auditTx(ctx, tx, who, "ai.profile.add", p.Name, detail)
	})
	if err != nil {
		if store.IsUniqueViolation(err) {
			return ProfileView{}, duplicateName()
		}
		return ProfileView{}, err
	}
	next.profiles[len(next.profiles)-1] = st
	if err := s.apply(ctx, next); err != nil {
		return ProfileView{}, err
	}
	return s.view(st), nil
}

// EditProfile changes a profile. A blank key keeps the old key, unless the provider type changed: a key belongs to one provider.
func (s *Service) EditProfile(ctx context.Context, who, id string, in ProfileInput) (ProfileView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != "" {
		return ProfileView{}, s.errDegraded()
	}
	cur := s.snap.Load()
	old, ok := cur.find(id)
	if !ok {
		return ProfileView{}, profileNotFound()
	}
	secretID, newKey := old.secretID, in.APIKey != ""
	key, kerr := keyFor(old, in, in.BaseURL)
	if kerr != nil {
		return ProfileView{}, kerr
	}
	p := buildProfile(in, id, key)
	if err := p.Validate(); err != nil {
		return ProfileView{}, mapErr(err)
	}
	if cur.nameTaken(p.Name, id) {
		return ProfileView{}, duplicateName()
	}
	// A cloud profile may not hold a job that sends internal data under the rule: say which jobs, do not drop them silently.
	var held []string
	for _, j := range Jobs() {
		if slot := cur.assign.Jobs[j]; (slot.Primary == id || slot.Fallback == id) && !cur.assign.Allowed(j, p) {
			held = append(held, j.Name())
		}
	}
	if len(held) > 0 {
		return ProfileView{}, apierr.New(http.StatusBadRequest, "privacy_rule", fmt.Sprintf("This profile is assigned to %s, which send internal data, and the privacy rule only allows internal profiles. Unassign it there first or switch the rule off.", strings.Join(held, ", ")))
	}
	keepSecret := key.IsSet() && secretID != ""
	st := stored{Profile: p, secretID: secretID}
	if !key.IsSet() {
		st.secretID = ""
	}
	next := &snapshot{profiles: append([]stored(nil), cur.profiles...), assign: cur.assign, cfg: cur.cfg}
	for i := range next.profiles {
		if next.profiles[i].ID == id {
			next.profiles[i] = st
		}
	}
	if err := next.check(); err != nil {
		return ProfileView{}, mapErr(err)
	}
	now := s.cfg.Clock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var sec, last4 sql.NullString
		switch {
		case newKey && secretID != "":
			l4, err := s.cfg.Secrets.Replace(ctx, tx, secretID, secretPurpose, []byte(in.APIKey), true)
			if err != nil {
				return fmt.Errorf("ai: replace key: %w", err)
			}
			sec, last4 = sql.NullString{String: secretID, Valid: true}, sql.NullString{String: l4, Valid: true}
		case newKey:
			sid, l4, err := s.cfg.Secrets.Seal(ctx, tx, secretPurpose, []byte(in.APIKey), true)
			if err != nil {
				return fmt.Errorf("ai: seal key: %w", err)
			}
			sec, last4, st.secretID = sql.NullString{String: sid, Valid: true}, sql.NullString{String: l4, Valid: true}, sid
		case keepSecret:
			sec, last4 = sql.NullString{String: secretID, Valid: true}, sql.NullString{String: key.Last4(), Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_profile SET name = ?, name_key = ?, kind = ?, api_style = ?, base_url = ?, model = ?, secret_id = ?, key_last4 = ?, location = ?, daily_cap = ?, updated_at = ? WHERE id = ?`,
			p.Name, nameKey(p.Name), p.Kind, string(p.APIStyle), p.BaseURL, p.Model, sec, last4, string(p.Location), p.DailyCap, store.FormatTS(now), id); err != nil {
			return fmt.Errorf("ai: edit profile: %w", err)
		}
		if secretID != "" && !sec.Valid { // the key was dropped (provider type changed on an internal profile)
			if err := s.cfg.Secrets.Delete(ctx, tx, secretID); err != nil {
				return fmt.Errorf("ai: delete key: %w", err)
			}
		}
		detail := fmt.Sprintf("%s, %s, model=%s, host=%s", p.Kind, p.Location, p.Model, hostOf(p.BaseURL))
		if newKey {
			detail += ", key changed"
		}
		return s.auditTx(ctx, tx, who, "ai.profile.edit", p.Name, detail)
	})
	if err != nil {
		if store.IsUniqueViolation(err) {
			return ProfileView{}, duplicateName()
		}
		return ProfileView{}, err
	}
	for i := range next.profiles {
		if next.profiles[i].ID == id {
			next.profiles[i] = st
		}
	}
	if err := s.apply(ctx, next); err != nil {
		return ProfileView{}, err
	}
	return s.view(st), nil
}

// DeleteProfile removes a profile and its key. Every job that used it loses it: a job whose primary was removed keeps its
// fallback as the primary (that profile was already allowed for the job), a removed fallback just leaves. It returns those jobs.
func (s *Service) DeleteProfile(ctx context.Context, who, id string) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != "" {
		return nil, s.errDegraded()
	}
	cur := s.snap.Load()
	old, ok := cur.find(id)
	if !ok {
		return nil, profileNotFound()
	}
	asg := cloneAssign(cur.assign)
	var cleared []Job
	for _, j := range Jobs() {
		slot := asg.Jobs[j]
		switch id {
		case slot.Primary:
			asg.Jobs[j] = Slot{Primary: slot.Fallback}
		case slot.Fallback:
			asg.Jobs[j] = Slot{Primary: slot.Primary}
		default:
			continue
		}
		cleared = append(cleared, j)
	}
	next := &snapshot{assign: asg, cfg: cur.cfg}
	for _, p := range cur.profiles {
		if p.ID != id {
			next.profiles = append(next.profiles, p)
		}
	}
	if err := next.check(); err != nil {
		return nil, mapErr(err)
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, j := range cleared {
			slot := asg.Jobs[j]
			if _, err := tx.ExecContext(ctx, `UPDATE ai_assignment SET primary_profile_id = ?, fallback_profile_id = ? WHERE job = ?`, nullable(slot.Primary), nullable(slot.Fallback), string(j)); err != nil {
				return fmt.Errorf("ai: clear assignment: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_profile WHERE id = ?`, id); err != nil {
			return fmt.Errorf("ai: delete profile: %w", err)
		}
		if old.secretID != "" {
			if err := s.cfg.Secrets.Delete(ctx, tx, old.secretID); err != nil {
				return fmt.Errorf("ai: delete key: %w", err)
			}
		}
		return s.auditTx(ctx, tx, who, "ai.profile.remove", old.Name, "")
	})
	if err != nil {
		return nil, err
	}
	if err := s.apply(ctx, next); err != nil {
		return nil, err
	}
	if cleared == nil {
		cleared = []Job{}
	}
	return cleared, nil
}

// probeTimeout bounds one connection test (three tiny requests).
// probeTimeout bounds one connection test (three tiny requests).
const probeTimeout = 60 * time.Second

// auditTimeout bounds the write of the audit row of a test when the request is already gone.
const auditTimeout = 10 * time.Second

// TestProfile tries a saved or draft profile with three tiny requests. A saved profile is tested with its stored key only while the
// provider type and the origin of the address are the saved ones (M1); another address needs the key entered again. Nothing is
// saved. The test is checked against the caps before it runs and counted after (L5), and it is audited with the host it went to
// (never the key), also when the request is cancelled while the key is on its way (M2).
func (s *Service) TestProfile(ctx context.Context, who string, in ProfileInput) (TestResult, error) {
	cur := s.snap.Load()
	id, key := "draft", keyOf(in)
	name := strings.TrimSpace(in.Name)
	profileCap := MaxDailyCap // a draft is limited by the shared cap only; a saved profile also by its own
	exceptID := ""
	if in.ID != "" {
		old, ok := cur.find(in.ID)
		if !ok {
			return TestResult{}, profileNotFound()
		}
		var kerr error
		if key, kerr = keyFor(old, in, in.BaseURL); kerr != nil {
			return TestResult{}, kerr
		}
		id, exceptID, profileCap = old.ID, old.ID, old.DailyCap
		if name == "" {
			name = old.Name
		}
	}
	if name == "" {
		name = "Test"
	}
	if cur.nameTaken(name, exceptID) {
		return TestResult{}, duplicateName()
	}
	in.Name, in.DailyCap = name, profileCap
	p := buildProfile(in, id, key)
	if err := p.Validate(); err != nil {
		return TestResult{}, mapErr(err)
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, down, probeErr := s.router.Probe(pctx, p, s.cfg.Clock)
	if errors.Is(probeErr, ErrCapped) || errors.Is(probeErr, ErrProfileCapped) {
		// nothing was sent: no audit row is needed for a key that did not leave the box
		return TestResult{}, capError(probeErr, s.snap.Load().cfg.DailyCap)
	}
	outcome := "ok"
	if probeErr != nil {
		outcome = "failed"
	}
	// The key may already have left the box, so the audit row is written whatever happened to the request.
	actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer acancel()
	if err := s.cfg.DB.Write(actx, func(tx *sql.Tx) error {
		if down != nil {
			if err := s.auditTx(actx, tx, who, "ai.downgrade", string(down.From)+"->"+string(down.To), clipRunes(down.Reason, 300)); err != nil {
				return err
			}
		}
		return s.auditTx(actx, tx, who, "ai.test", name, fmt.Sprintf("model=%s, host=%s, result=%s", p.Model, hostOf(p.BaseURL), outcome))
	}); err != nil {
		return TestResult{}, err
	}
	if probeErr != nil {
		if ctx.Err() != nil {
			return TestResult{}, ctx.Err()
		}
		return TestResult{}, probeFailure(probeErr, p.BaseURL)
	}
	return TestResult{OK: true, LatencyMS: float64(res.Latency.Milliseconds()), TokensIn: res.TokensIn, TokensOut: res.TokensOut,
		Capabilities: Capabilities{Tools: res.Tools, Structured: res.Structured}}, nil
}

func clipRunes(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// capError is the 429 of a test that the caps stopped.
func capError(err error, sharedCap int) error {
	if errors.Is(err, ErrProfileCapped) {
		return apierr.New(http.StatusTooManyRequests, "daily_cap", "This profile has used its own daily token cap. Raise it in Settings, AI assistant, or wait until tomorrow.")
	}
	return apierr.New(http.StatusTooManyRequests, "daily_cap", fmt.Sprintf("Today's %s token cap is used up and the tier is already the minimum. Raise the cap in Settings, AI assistant, or wait until tomorrow.", number(sharedCap)))
}

// probeFailure maps a provider error to the API error. The text never repeats the provider's message, the URL or the key. A
// provider that could not be reached (dial error, timeout) is `unreachable`; one that answered but cannot be used is `provider_error`.
func probeFailure(err error, baseURL string) error {
	host := "the server"
	if u, perr := provider.ParseBaseURL(baseURL); perr == nil {
		host = u.Host
	}
	var pe *provider.Error
	status := 0
	if errors.As(err, &pe) {
		status = pe.Status
	}
	bad := func(msg string) error { return apierr.New(http.StatusBadGateway, "provider_error", msg) }
	switch {
	case errors.Is(err, provider.ErrAuth) && status == http.StatusForbidden:
		return bad(fmt.Sprintf("%s accepted the connection but refused this key for this request (HTTP 403). Check the permission of the key for this model.", host))
	case errors.Is(err, provider.ErrAuth):
		return apierr.New(http.StatusUnauthorized, "key_rejected", "The provider rejected the key (HTTP 401). Check the key has not expired and belongs to this provider.")
	case errors.Is(err, provider.ErrNoWorkspace):
		return bad("This Anthropic key is not tied to a workspace. Create the API key inside a workspace in the Anthropic console and use that key.")
	case errors.Is(err, provider.ErrRateLimited):
		return bad(fmt.Sprintf("%s is rate-limiting this key; try again later.", host))
	case errors.Is(err, provider.ErrNetwork), errors.Is(err, provider.ErrTimeout):
		return apierr.New(http.StatusBadGateway, "unreachable", fmt.Sprintf("Could not connect to %s. Check the address, the box's network and the firewall.", host))
	}
	return bad(fmt.Sprintf("%s answered, but not in a way Vedette can use. Check the model name and the address.", host))
}
