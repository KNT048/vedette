package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/store"
)

// Slice 4a of WP-25 (S-AI-7): the rules a company adds to every prompt, its own hooks and the switches of the built-in hooks.
// They live in ai_rule, ai_hook and ai_hook_state. The service keeps one immutable generation of them (harness) that a change
// replaces after its transaction commits, so a call in flight sees either the old settings or the new ones, never a mix.

// MaxRules is how many custom rules a box holds. MaxCustomHooks (hooks.go) is the same limit for hooks.
const MaxRules = 30

// RuleInput is the body of `POST /ai/rules` and `PUT /ai/rules/{id}`.
type RuleInput struct {
	Text    string `json:"text"`
	Jobs    []Job  `json:"jobs"`
	Enabled bool   `json:"enabled"`
}

// RuleView is a custom rule as the API shows it. Jobs is never null: empty = every job.
type RuleView struct {
	ID      string `json:"id"`
	Text    string `json:"text"`
	Jobs    []Job  `json:"jobs"`
	Enabled bool   `json:"enabled"`
}

// BuiltinRuleView is a built-in rule: read-only.
type BuiltinRuleView struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// RulesView is `GET /ai/rules`.
type RulesView struct {
	Builtin []BuiltinRuleView `json:"builtin"`
	Custom  []RuleView        `json:"custom"`
}

// HookMatchJSON is the match of a custom hook on the wire.
type HookMatchJSON struct {
	Type    MatchType `json:"type"`
	Pattern string    `json:"pattern"`
}

// HookJSON is a custom hook on the wire, as input (ID ignored) and as output.
type HookJSON struct {
	ID      string        `json:"id,omitempty"`
	Name    string        `json:"name"`
	When    HookWhen      `json:"when"`
	Match   HookMatchJSON `json:"match"`
	Action  HookAction    `json:"action"`
	Message string        `json:"message"`
	Enabled bool          `json:"enabled"`
}

func (h HookJSON) hook() CustomHook {
	return CustomHook{ID: h.ID, Name: h.Name, When: h.When, Match: HookMatch{Type: h.Match.Type, Pattern: h.Match.Pattern}, Action: h.Action, Message: h.Message, Enabled: h.Enabled}
}

func hookJSON(h CustomHook) HookJSON {
	return HookJSON{ID: h.ID, Name: h.Name, When: h.When, Match: HookMatchJSON{Type: h.Match.Type, Pattern: h.Match.Pattern}, Action: h.Action, Message: h.Message, Enabled: h.Enabled}
}

// BuiltinHookView is a built-in hook with its switch.
type BuiltinHookView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Locked      bool   `json:"locked"`
}

// HooksView is `GET /ai/hooks`.
type HooksView struct {
	Builtin []BuiltinHookView `json:"builtin"`
	Custom  []HookJSON        `json:"custom"`
}

// HookHitView is a hook that acted, in a test result.
type HookHitView struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Kind    HookKind   `json:"kind"`
	When    HookWhen   `json:"when"`
	Action  HookAction `json:"action"`
	Message string     `json:"message"`
}

// HookTestInput is the body of `POST /ai/hooks/test`. Hook nil = run every enabled hook of the stage.
type HookTestInput struct {
	Text string    `json:"text"`
	When HookWhen  `json:"when"`
	Hook *HookJSON `json:"hook,omitempty"`
}

// HookTestResult is what the test produced; nothing of it is stored.
type HookTestResult struct {
	Outcome Outcome       `json:"outcome"`
	Output  string        `json:"output"`
	Hits    []HookHitView `json:"hits"`
}

// MaxHookTestRunes bounds the sample text of a hook test.
const MaxHookTestRunes = 1000

// harness is one immutable generation of the rules and hooks. The runner is built from builtin and custom, so the two cannot differ.
type harness struct {
	rules   []Rule
	builtin map[string]bool
	custom  []CustomHook
	runner  *HookRunner
}

func newHarness(rules []Rule, builtin map[string]bool, custom []CustomHook) (*harness, error) {
	runner, err := NewHookRunner(builtin, custom)
	if err != nil {
		return nil, err
	}
	return &harness{rules: rules, builtin: runner.builtin, custom: custom, runner: runner}, nil
}

// with returns a copy that differs in the parts given; nil keeps the part.
func (h *harness) with(rules []Rule, builtin map[string]bool, custom *[]CustomHook) (*harness, error) {
	next := *h
	if rules != nil {
		next.rules = rules
	}
	b := h.builtin
	if builtin != nil {
		b = builtin
	}
	c := h.custom
	if custom != nil {
		c = *custom
	}
	return newHarness(next.rules, b, c)
}

// Hooks is the runner of the hooks in force now: the stored switches and the stored custom hooks. Use it per call; do not keep it.
func (s *Service) Hooks() *HookRunner { return s.harness.Load().runner }

// Rules returns the enabled and disabled custom rules, in creation order. PromptBuilder drops the disabled ones and the ones
// for other jobs.
func (s *Service) Rules() []Rule { return append([]Rule(nil), s.harness.Load().rules...) }

// RedactPII is the switch of the block-pii hook, the same switch `redact_pii` of `/ai/config` shows (INV-12).
func (s *Service) redactPII() bool { return s.harness.Load().builtin[HookBlockPII] }

func (s *Service) loadHarness(ctx context.Context) (*harness, error) {
	q := s.cfg.DB.Reader()
	var rules []Rule
	rs, err := q.QueryContext(ctx, `SELECT id, text, jobs, enabled FROM ai_rule ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	for rs.Next() {
		var r Rule
		var jobs string
		var on int
		if err := rs.Scan(&r.ID, &r.Text, &jobs, &on); err != nil {
			_ = rs.Close()
			return nil, fmt.Errorf("rules: %w", err)
		}
		if err := json.Unmarshal([]byte(jobs), &r.Jobs); err != nil {
			_ = rs.Close()
			return nil, fmt.Errorf("rule %s: jobs: %w", r.ID, err)
		}
		r.Enabled = on == 1
		if err := r.Validate(); err != nil { // a rule the code refuses is a corrupt row: fail loudly, never drop a restriction silently
			_ = rs.Close()
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		rules = append(rules, r)
	}
	if err := rs.Err(); err != nil {
		_ = rs.Close()
		return nil, fmt.Errorf("rules: %w", err)
	}
	_ = rs.Close()

	builtin := map[string]bool{}
	bs, err := q.QueryContext(ctx, `SELECT builtin_id, enabled FROM ai_hook_state`)
	if err != nil {
		return nil, fmt.Errorf("hook switches: %w", err)
	}
	for bs.Next() {
		var id string
		var on int
		if err := bs.Scan(&id, &on); err != nil {
			_ = bs.Close()
			return nil, fmt.Errorf("hook switches: %w", err)
		}
		builtin[id] = on == 1
	}
	if err := bs.Err(); err != nil {
		_ = bs.Close()
		return nil, fmt.Errorf("hook switches: %w", err)
	}
	_ = bs.Close()

	var custom []CustomHook
	hs, err := q.QueryContext(ctx, `SELECT id, name, "when", match_type, pattern, action, message, enabled FROM ai_hook ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("hooks: %w", err)
	}
	for hs.Next() {
		var h CustomHook
		var when, mt, action string
		var on int
		if err := hs.Scan(&h.ID, &h.Name, &when, &mt, &h.Match.Pattern, &action, &h.Message, &on); err != nil {
			_ = hs.Close()
			return nil, fmt.Errorf("hooks: %w", err)
		}
		h.When, h.Match.Type, h.Action, h.Enabled = HookWhen(when), MatchType(mt), HookAction(action), on == 1
		custom = append(custom, h)
	}
	if err := hs.Err(); err != nil {
		_ = hs.Close()
		return nil, fmt.Errorf("hooks: %w", err)
	}
	_ = hs.Close()
	// Every stored hook is compiled again, the disabled ones too: a hook that no longer compiles is found when the service starts,
	// not on the day somebody turns it on.
	for _, h := range custom {
		if err := h.Validate(); err != nil {
			return nil, fmt.Errorf("hook %s: %w", h.ID, err)
		}
	}
	h, err := newHarness(rules, builtin, custom)
	if err != nil {
		return nil, fmt.Errorf("hooks: %w", err)
	}
	return h, nil
}

func tidy(s string) string { return strings.Join(strings.Fields(s), " ") }

func badInput(code, format string, a ...any) error {
	return apierr.New(http.StatusBadRequest, code, fmt.Sprintf(format, a...))
}

func harnessNotFound(what string) error {
	return apierr.New(http.StatusNotFound, "not_found", "This "+what+" no longer exists.")
}

// hookErr turns a hook validation failure into a 400 with its own code.
func hookErr(err error) error {
	var he *HookError
	if errors.As(err, &he) {
		code := he.Code
		switch code {
		case "invalid_pattern", "unsupported_regex", "pattern_too_large", "invalid_match_type":
			code = "invalid_match" // the form puts every failure of the match on the pattern field, with the specific text
		}
		return apierr.New(http.StatusBadRequest, code, he.Msg)
	}
	return err
}

func ruleView(r Rule) RuleView {
	jobs := r.Jobs
	if jobs == nil {
		jobs = []Job{}
	}
	return RuleView{ID: r.ID, Text: r.Text, Jobs: jobs, Enabled: r.Enabled}
}

// checkRule normalises and validates a rule body (INV-7): the text is tidied (one line, single spaces), 3..300 characters; jobs are known, unique.
func checkRule(in RuleInput) (Rule, error) {
	text := tidy(in.Text)
	if n := utf8.RuneCountInString(text); n < 3 || n > 300 || auth.HasInvisible(text) {
		return Rule{}, badInput("invalid_rule", `Write the rule in 3 to 300 characters, for example "Always name devices by hostname and IP address".`)
	}
	jobs := []Job{}
	seen := map[Job]bool{}
	for _, j := range in.Jobs {
		if !j.Valid() {
			return Rule{}, badInput("invalid_jobs", "One of the chosen jobs is not an AI job. Pick from the list.")
		}
		if !seen[j] {
			seen[j] = true
			jobs = append(jobs, j)
		}
	}
	r := Rule{Text: text, Jobs: jobs, Enabled: in.Enabled}
	if err := r.Validate(); err != nil {
		return Rule{}, badInput("invalid_rule", "The rule is not valid.")
	}
	return r, nil
}

// RulesView returns the built-in and the custom rules (`GET /ai/rules`).
func (s *Service) RulesView() RulesView {
	v := RulesView{Builtin: []BuiltinRuleView{}, Custom: []RuleView{}}
	for _, b := range BuiltinRules() {
		v.Builtin = append(v.Builtin, BuiltinRuleView(b))
	}
	for _, r := range s.harness.Load().rules {
		v.Custom = append(v.Custom, ruleView(r))
	}
	return v
}

func (s *Service) harnessGuard() error {
	if s.degraded != "" {
		return s.errDegraded()
	}
	return nil
}

// AddRule saves a custom rule (`POST /ai/rules`, admin). At most MaxRules.
func (s *Service) AddRule(ctx context.Context, who string, in RuleInput) (RuleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return RuleView{}, err
	}
	r, err := checkRule(in)
	if err != nil {
		return RuleView{}, err
	}
	cur := s.harness.Load()
	if len(cur.rules) >= MaxRules {
		return RuleView{}, badInput("too_many", "A box holds up to %d custom rules. Delete one you no longer need.", MaxRules)
	}
	r.ID = store.NewID("ru")
	next, err := cur.with(append(append([]Rule(nil), cur.rules...), r), nil, nil)
	if err != nil {
		return RuleView{}, err
	}
	now := store.FormatTS(s.cfg.Clock())
	jobs, _ := json.Marshal(r.Jobs)
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_rule (id, text, jobs, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, r.ID, r.Text, string(jobs), b2i(r.Enabled), now, now); err != nil {
			return fmt.Errorf("ai: save rule: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.rule.add", r.ID, clipRunes(r.Text, 60))
	})
	if err != nil {
		return RuleView{}, err
	}
	s.harness.Store(next)
	return ruleView(r), nil
}

// EditRule replaces the text, jobs and switch of a rule (`PUT /ai/rules/{id}`, admin).
func (s *Service) EditRule(ctx context.Context, who, id string, in RuleInput) (RuleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return RuleView{}, err
	}
	cur := s.harness.Load()
	at := -1
	for i, r := range cur.rules {
		if r.ID == id {
			at = i
		}
	}
	if at < 0 {
		return RuleView{}, harnessNotFound("rule")
	}
	r, err := checkRule(in)
	if err != nil {
		return RuleView{}, err
	}
	r.ID = id
	rules := append([]Rule(nil), cur.rules...)
	rules[at] = r
	next, err := cur.with(rules, nil, nil)
	if err != nil {
		return RuleView{}, err
	}
	jobs, _ := json.Marshal(r.Jobs)
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE ai_rule SET text = ?, jobs = ?, enabled = ?, updated_at = ? WHERE id = ?`, r.Text, string(jobs), b2i(r.Enabled), store.FormatTS(s.cfg.Clock()), id); err != nil {
			return fmt.Errorf("ai: save rule: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.rule.edit", id, clipRunes(r.Text, 60))
	})
	if err != nil {
		return RuleView{}, err
	}
	s.harness.Store(next)
	return ruleView(r), nil
}

// DeleteRule removes a custom rule (`DELETE /ai/rules/{id}`, admin).
func (s *Service) DeleteRule(ctx context.Context, who, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return err
	}
	cur := s.harness.Load()
	var rules []Rule
	found := false
	for _, r := range cur.rules {
		if r.ID == id {
			found = true
			continue
		}
		rules = append(rules, r)
	}
	if !found {
		return harnessNotFound("rule")
	}
	next, err := cur.with(append([]Rule{}, rules...), nil, nil)
	if err != nil {
		return err
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_rule WHERE id = ?`, id); err != nil {
			return fmt.Errorf("ai: delete rule: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.rule.remove", id, "")
	})
	if err != nil {
		return err
	}
	s.harness.Store(next)
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// HooksView returns the built-in hooks with their switches and the custom hooks (`GET /ai/hooks`).
func (s *Service) HooksView() HooksView {
	h := s.harness.Load()
	v := HooksView{Builtin: []BuiltinHookView{}, Custom: []HookJSON{}}
	for _, b := range h.runner.Builtins() {
		v.Builtin = append(v.Builtin, BuiltinHookView(b))
	}
	for _, c := range h.custom {
		v.Custom = append(v.Custom, hookJSON(c))
	}
	return v
}

// checkHook normalises a hook body (name and message tidied, pattern trimmed) and validates it, which compiles the pattern with RE2.
// ID is the id of the hook being edited, "" for a new one; names are unique in every letter case.
func checkHook(in CustomHook, others []CustomHook) (CustomHook, error) {
	in.Name, in.Message, in.Match.Pattern = tidy(in.Name), tidy(in.Message), strings.TrimSpace(in.Match.Pattern)
	switch {
	case auth.HasInvisible(in.Name):
		return CustomHook{}, badInput("invalid_name", "The name may not contain control or invisible characters.")
	case auth.HasInvisible(in.Message):
		return CustomHook{}, badInput("invalid_message", "The message may not contain control or invisible characters.")
	case auth.HasInvisible(in.Match.Pattern):
		return CustomHook{}, badInput("invalid_match", "The pattern may not contain control or invisible characters. Write such a character as an escape, for example \\x{200b}.")
	}
	if err := in.Validate(); err != nil {
		return CustomHook{}, hookErr(err)
	}
	key := strings.ToLower(in.Name)
	for _, o := range others {
		if o.ID != in.ID && strings.ToLower(o.Name) == key {
			return CustomHook{}, badInput("duplicate_name", "Another hook already has this name. Pick a different one.")
		}
	}
	return in, nil
}

func (s *Service) saveHooks(ctx context.Context, cur *harness, custom []CustomHook, write func(tx *sql.Tx) error) error {
	next, err := cur.with(nil, nil, &custom)
	if err != nil {
		return hookErr(err)
	}
	if err := s.cfg.DB.Write(ctx, write); err != nil {
		return err
	}
	s.harness.Store(next)
	return nil
}

// AddHook saves a custom hook (`POST /ai/hooks`, admin). At most MaxCustomHooks.
func (s *Service) AddHook(ctx context.Context, who string, in HookJSON) (HookJSON, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return HookJSON{}, err
	}
	cur := s.harness.Load()
	h, err := checkHook(in.hook(), cur.custom)
	if err != nil {
		return HookJSON{}, err
	}
	if len(cur.custom) >= MaxCustomHooks {
		return HookJSON{}, badInput("too_many", "A box holds up to %d custom hooks. Delete one you no longer need.", MaxCustomHooks)
	}
	h.ID = store.NewID("hk")
	now := store.FormatTS(s.cfg.Clock())
	err = s.saveHooks(ctx, cur, append(append([]CustomHook(nil), cur.custom...), h), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_hook (id, name, name_key, "when", match_type, pattern, action, message, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.Name, strings.ToLower(h.Name), h.When, h.Match.Type, h.Match.Pattern, h.Action, h.Message, b2i(h.Enabled), now, now); err != nil {
			return fmt.Errorf("ai: save hook: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.hook.add", h.Name, fmt.Sprintf("%s, %s", h.When, h.Action))
	})
	if err != nil {
		return HookJSON{}, err
	}
	return hookJSON(h), nil
}

// EditHook replaces a custom hook (`PUT /ai/hooks/{id}`, admin).
func (s *Service) EditHook(ctx context.Context, who, id string, in HookJSON) (HookJSON, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return HookJSON{}, err
	}
	cur := s.harness.Load()
	at := -1
	for i, c := range cur.custom {
		if c.ID == id {
			at = i
		}
	}
	if at < 0 {
		return HookJSON{}, harnessNotFound("hook")
	}
	body := in.hook()
	body.ID = id
	h, err := checkHook(body, cur.custom)
	if err != nil {
		return HookJSON{}, err
	}
	custom := append([]CustomHook(nil), cur.custom...)
	custom[at] = h
	err = s.saveHooks(ctx, cur, custom, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE ai_hook SET name = ?, name_key = ?, "when" = ?, match_type = ?, pattern = ?, action = ?, message = ?, enabled = ?, updated_at = ? WHERE id = ?`,
			h.Name, strings.ToLower(h.Name), h.When, h.Match.Type, h.Match.Pattern, h.Action, h.Message, b2i(h.Enabled), store.FormatTS(s.cfg.Clock()), id); err != nil {
			return fmt.Errorf("ai: save hook: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.hook.edit", h.Name, fmt.Sprintf("%s, %s", h.When, h.Action))
	})
	if err != nil {
		return HookJSON{}, err
	}
	return hookJSON(h), nil
}

// DeleteHook removes a custom hook (`DELETE /ai/hooks/{id}`, admin).
func (s *Service) DeleteHook(ctx context.Context, who, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return err
	}
	cur := s.harness.Load()
	custom := []CustomHook{}
	var gone *CustomHook
	for _, c := range cur.custom {
		if c.ID == id {
			gone = &c
			continue
		}
		custom = append(custom, c)
	}
	if gone == nil {
		return harnessNotFound("hook")
	}
	return s.saveHooks(ctx, cur, custom, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_hook WHERE id = ?`, id); err != nil {
			return fmt.Errorf("ai: delete hook: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.hook.remove", gone.Name, "")
	})
}

// SetBuiltinHook turns a built-in hook on or off (`PUT /ai/hooks/builtin/{id}`, admin). write-approval is locked: any request for it
// is 400 `locked`, also one that says "on", because the page offers no switch for it. block-pii is the `redact_pii` of `/ai/config`.
func (s *Service) SetBuiltinHook(ctx context.Context, who, id string, enabled bool) (BuiltinHookView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.harnessGuard(); err != nil {
		return BuiltinHookView{}, err
	}
	switch err := ValidateBuiltinToggle(id, enabled); {
	case errors.Is(err, ErrUnknownHook):
		return BuiltinHookView{}, harnessNotFound("hook")
	case err != nil:
		return BuiltinHookView{}, errLocked()
	}
	for _, b := range builtinInfo {
		if b.ID == id && b.Locked {
			return BuiltinHookView{}, errLocked()
		}
	}
	cur := s.harness.Load()
	on := map[string]bool{}
	for k, v := range cur.builtin {
		on[k] = v
	}
	on[id] = enabled
	next, err := cur.with(nil, on, nil)
	if err != nil {
		return BuiltinHookView{}, err
	}
	cfg := s.snap.Load().cfg
	if id == HookBlockPII {
		cfg.RedactPII = enabled
	}
	state := "off"
	if enabled {
		state = "on"
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := saveHookSwitch(ctx, tx, id, enabled); err != nil {
			return err
		}
		if id == HookBlockPII { // redact_pii of /ai/config is this switch: keep the saved setting in step
			if err := upsertSetting(ctx, tx, "config", cfg, s.cfg.Clock(), who); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, who, "ai.hook.builtin", id, state)
	})
	if err != nil {
		return BuiltinHookView{}, err
	}
	s.harness.Store(next)
	if id == HookBlockPII {
		cur := s.snap.Load()
		s.snap.Store(&snapshot{profiles: cur.profiles, assign: cur.assign, cfg: cfg})
	}
	for _, b := range next.runner.Builtins() {
		if b.ID == id {
			return BuiltinHookView(b), nil
		}
	}
	return BuiltinHookView{}, harnessNotFound("hook")
}

// saveHookSwitch writes one switch. An upsert, not an UPDATE: it cannot pass without a row to change.
func saveHookSwitch(ctx context.Context, tx *sql.Tx, id string, enabled bool) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_hook_state (builtin_id, enabled) VALUES (?, ?) ON CONFLICT (builtin_id) DO UPDATE SET enabled = excluded.enabled`, id, b2i(enabled)); err != nil {
		return fmt.Errorf("ai: save hook switch: %w", err)
	}
	return nil
}

func errLocked() error {
	return apierr.New(http.StatusBadRequest, "locked", `"Write tools need approval" is always on. A tool that changes something can only run through an action a person approves.`)
}

// TestHook runs a sample text through the hooks of one stage (`POST /ai/hooks/test`, admin): through the draft alone when one is
// given (run at the stage asked, whatever stage the draft names, and never saved), otherwise through every enabled hook now in force.
// Nothing is stored, logged or sent anywhere.
func (s *Service) TestHook(ctx context.Context, in HookTestInput) (HookTestResult, error) {
	if n := utf8.RuneCountInString(in.Text); n < 1 || n > MaxHookTestRunes {
		return HookTestResult{}, badInput("invalid_text", "Type a sample text of up to %d characters.", MaxHookTestRunes)
	}
	switch in.When {
	case BeforeAI, AfterAI, BeforeTool:
	default:
		return HookTestResult{}, badInput("invalid_when", "Pick the stage to test.")
	}
	// One test at a time: each can use the whole deadline, so a second waits for a turn and is turned away (503 server_busy, as the log search is) when none comes.
	select {
	case s.testSlot <- struct{}{}: // a free place is taken before any waiting, so a short wait cannot turn away the only test
		defer func() { <-s.testSlot }()
	default:
		wait := time.NewTimer(s.hookTimeout())
		defer wait.Stop()
		select {
		case s.testSlot <- struct{}{}:
			defer func() { <-s.testSlot }()
		case <-wait.C:
			return HookTestResult{}, apierr.New(http.StatusServiceUnavailable, "server_busy", "The box is busy testing another hook. Try again in a moment.")
		case <-ctx.Done():
			return HookTestResult{}, ctx.Err()
		}
	}
	runner := s.Hooks()
	if in.Hook != nil {
		d := in.Hook.hook()
		d.ID, d.When, d.Enabled = "draft", in.When, true
		if strings.TrimSpace(d.Name) == "" {
			d.Name = "Draft"
		}
		d, err := checkHook(d, nil)
		if err != nil {
			return HookTestResult{}, err
		}
		// Only the draft: the built-in hooks that match text are left off, and write-approval (locked on) has no text matcher.
		if runner, err = NewHookRunner(map[string]bool{HookBlockPII: false, HookSecurityOnly: false}, []CustomHook{d}); err != nil {
			return HookTestResult{}, hookErr(err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	res, err := runner.Run(ctx, in.When, in.Text)
	if err != nil {
		return HookTestResult{}, badInput("invalid_text", "The text could not be checked in time. Try a shorter text or a simpler pattern.")
	}
	out := HookTestResult{Outcome: res.Outcome, Output: res.Text, Hits: []HookHitView{}}
	for _, h := range res.Hits {
		out.Hits = append(out.Hits, HookHitView{ID: h.ID, Name: h.Name, Kind: h.Kind, When: h.When, Action: h.Action, Message: h.Message})
	}
	return out, nil
}
