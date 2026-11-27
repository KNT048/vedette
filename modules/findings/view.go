package findings

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// View is the read model of a finding: the stored row with what every place shows next to it (the device, the software line, the
// CVE's severity) and, for the finding's own page, the urgency reasons and the history. Lists, the finding page, the device page, Home,
// reports, notices and the AI read it; none of them reads the columns of fnd_finding.
type View struct {
	Finding  Finding
	Device   AssetView // the device as the Devices page names it
	Line     *Line     // the software line; nil when the finding is on no line or the line is gone
	Severity *CVSS     // the CVE's CVSS base score; nil when not scored yet
	// SafeCheck: a safe vulnerability check exists for the CVE (ServiceConfig.SafeCheck) and the device has an address to run it on.
	SafeCheck bool

	// Only on the finding's own read (Service.View):
	Reasons []ViewReason // every layer of 1..4 that applies at or below the stored layer, most urgent first
	Events  []Event      // oldest first
	Same    []View       // the other findings of this CVE on this device (another software line)
}

// ViewReason is one urgency layer that applies, with its source as people name it.
type ViewReason struct {
	Reason
	Name   string // "CISA KEV", "Rapid7"; for layer 1 "Intrusion alert", for layer 4 "CVSS 9.8"
	Detail string // a short fact: the attacker for layer 1; "" when none
	Due    string // layer 2 on CISA's list: the day the list asks for the fix (YYYY-MM-DD); "" otherwise
}

// SourceNames are the names of the signal sources by id (feeds), read for the reasons of a finding.
type SourceNames func(ctx context.Context) (map[string]string, error)

// View reads one finding as every place shows it: its device, line, severity, the reasons of its urgency, its history and the other
// findings of its CVE on the device.
func (s *Service) View(ctx context.Context, id string) (View, error) {
	q := s.cfg.DB.Reader()
	f, err := loadFinding(ctx, q, id)
	if err != nil {
		return View{}, err
	}
	same, err := selectFindings(ctx, q, `asset_id = ? AND cve = ? AND id <> ? ORDER BY id`, f.AssetID, f.CVE, f.ID)
	if err != nil {
		return View{}, err
	}
	vs, err := s.views(ctx, append([]Finding{f}, same...))
	if err != nil {
		return View{}, err
	}
	v := vs[0]
	v.Same = vs[1:]
	evs, err := eventsOf(ctx, q, `finding_id = ?`, f.ID)
	if err != nil {
		return View{}, fmt.Errorf("findings: reading the history: %w", err)
	}
	v.Events = evs[f.ID]
	if v.Reasons, err = s.reasons(ctx, f); err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the reasons of a finding could not be read", "finding", f.ID, "error", err)
		v.Reasons = nil // the status stands on the stored layer; only its reasons line is missing
	}
	return v, nil
}

// views adds the device, the line and the severity to findings, with one read of each source.
func (s *Service) views(ctx context.Context, fs []Finding) ([]View, error) {
	assets, lines, cves := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range fs {
		assets[f.AssetID], cves[f.CVE] = true, true
		if f.SoftwareID != "" {
			lines[f.SoftwareID] = true
		}
	}
	ref, err := s.refs(ctx, keys(assets), keys(lines), keys(cves))
	if err != nil {
		return nil, err
	}
	out := make([]View, len(fs))
	for i, f := range fs {
		out[i] = ref.view(f)
		out[i].SafeCheck = s.cfg.SafeCheck != nil && s.cfg.SafeCheck(f.CVE) && out[i].Device.HasIP()
	}
	return out, nil
}

// refs is what the views of a set of findings name: devices, lines and CVE scores.
type refs struct {
	assets map[string]AssetView
	lines  map[string]Line
	scores map[string]CVSS
}

func (s *Service) refs(ctx context.Context, assets, lines, cves []string) (refs, error) {
	var r refs
	var err error
	if r.assets, err = s.cfg.Inventory.Assets(ctx, assets); err != nil {
		return r, fmt.Errorf("findings: reading devices: %w", err)
	}
	r.lines = map[string]Line{}
	if len(lines) > 0 {
		if r.lines, err = s.cfg.Inventory.Lines(ctx, lines); err != nil {
			return r, fmt.Errorf("findings: reading software lines: %w", err)
		}
	}
	r.scores = map[string]CVSS{}
	if len(cves) > 0 {
		if r.scores, err = s.cfg.Feeds.CVSS(ctx, cves); err != nil {
			return r, fmt.Errorf("findings: reading CVSS scores: %w", err)
		}
	}
	return r, nil
}

func (r refs) view(f Finding) View {
	v := View{Finding: f, Device: r.device(f.AssetID)}
	if l, ok := r.lines[f.SoftwareID]; ok && f.SoftwareID != "" {
		v.Line = &l
	}
	if c, ok := r.scores[f.CVE]; ok {
		v.Severity = &c
	}
	return v
}

// device is the device of id as the lists name it; a device inventory no longer has keeps its id as its only name.
func (r refs) device(id string) AssetView {
	a, ok := r.assets[id]
	if !ok {
		a = AssetView{ID: id, Name: "Unknown device", IP: NoIP, Kind: "unknown", Approved: true}
	}
	return shownAsset(a)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// reasons are the layers 1..4 that apply to f now, read with the urgency pass's own inputs, kept to those at or below the stored layer
// (a more urgent one the pass has not rated yet is not said: the stored layer is the only urgency).
func (s *Service) reasons(ctx context.Context, f Finding) ([]ViewReason, error) {
	m, err := s.reasonsOf(ctx, []Finding{f})
	return m[f.ID], err
}

// reasonsOf are the reasons of each of fs by finding id, with one read of each input: the finding page and every list row say the same
// reasons line from it.
func (s *Service) reasonsOf(ctx context.Context, fs []Finding) (map[string][]ViewReason, error) {
	out := map[string][]ViewReason{}
	if !s.rates() || len(fs) == 0 {
		return out, nil
	}
	now := s.now()
	in, err := s.urgencyInputs(ctx, fs, now)
	if err != nil {
		return nil, err
	}
	var names map[string]string
	if s.cfg.Urgency.Names != nil {
		if names, err = s.cfg.Urgency.Names(ctx); err != nil {
			return nil, err
		}
	}
	cves := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.Urgency < UrgencyUpdate {
			cves = append(cves, f.CVE)
		}
	}
	slices.Sort(cves)
	kev := map[string]KevInfo{}
	if len(cves) > 0 {
		if k, err := s.cfg.Feeds.KevInfo(ctx, slices.Compact(cves)); err == nil {
			kev = k
		}
	}
	for _, f := range fs {
		if f.Urgency >= UrgencyUpdate {
			continue // an update that is only recommended has no reason to tell
		}
		r := in.rate(f, now)
		var due string
		if d := kev[f.CVE].DueDate; d != nil {
			due = *d
		}
		var rs []ViewReason
		for _, x := range r.Reasons {
			if x.Layer < f.Urgency || x.Layer >= UrgencyUpdate {
				continue
			}
			vr := ViewReason{Reason: x}
			switch x.Layer {
			case UrgencyUnderAttack:
				vr.Name, vr.Source = "Intrusion alert", "ids"
			case UrgencyCriticalEdge:
				vr.Source, vr.Name = "cvss", "CVSS"
				if c := in.facts[f.CVE].CVSS; c != nil {
					vr.Name = fmt.Sprintf("CVSS %.1f", c.Score)
				}
			default:
				if vr.Name = names[x.Source]; vr.Name == "" {
					continue // a source the box no longer has: never shown by its id
				}
				if x.Source == "cisa-kev" {
					vr.Due = due
				}
			}
			rs = append(rs, vr)
		}
		out[f.ID] = rs
	}
	return out, nil
}

// listViews are the views of list rows: the device, line and severity, the reasons of their urgency and the history a confirmation is
// read from (who and when), so a row says the same status, reasons line and confirmation line as the finding's own page.
func (s *Service) listViews(ctx context.Context, fs []Finding) ([]View, error) {
	vs, err := s.views(ctx, fs)
	if err != nil {
		return nil, err
	}
	confirmed := []string{}
	for _, f := range fs {
		if f.Confirmed() {
			confirmed = append(confirmed, f.ID)
		}
	}
	if len(confirmed) > 0 {
		ids, _ := json.Marshal(confirmed)
		evs, err := eventsOf(ctx, s.rd(ctx), `f.id IN (SELECT value FROM json_each(?)) AND e.kind IN ('created', 'confirmed')`, string(ids))
		if err != nil {
			return nil, fmt.Errorf("findings: reading the confirmations: %w", err)
		}
		for i := range vs {
			vs[i].Events = evs[vs[i].Finding.ID]
		}
	}
	rs, err := s.reasonsOf(ctx, fs)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the reasons of list rows could not be read", "error", err)
		return vs, nil // the statuses stand on the stored layers; only their reasons lines are missing
	}
	for i := range vs {
		vs[i].Reasons = rs[vs[i].Finding.ID]
	}
	return vs, nil
}

// ---- the API shape of the view (contract.ts, "The findings model") ----

type deviceRefJS struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	IP      *string `json:"ip"`
	Kind    string  `json:"kind"`
	Added   bool    `json:"added"`
	Ignored bool    `json:"ignored"`
}

func deviceRef(a AssetView) deviceRefJS {
	a = shownAsset(a)
	d := deviceRefJS{ID: a.ID, Name: a.Name, Kind: a.Kind, Added: a.Approved, Ignored: a.Ignored}
	if a.HasIP() {
		ip := a.IP
		d.IP = &ip
	}
	return d
}

type softwareRefJS struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Version *string `json:"version"`
}

// softwareRef is the line of v: its name, and the version the match compared (else the line's version now); nil without a line.
func softwareRef(v View) *softwareRefJS {
	if v.Line == nil {
		return nil
	}
	s := &softwareRefJS{ID: v.Line.ID, Name: cmp.Or(v.Line.Display, v.Line.ProductKey)}
	if ver := cmp.Or(v.Finding.MatchedVersion, v.Line.Version); ver != "" {
		s.Version = &ver
	}
	return s
}

type cveSeverityJS struct {
	Band    string  `json:"band"`
	Score   float64 `json:"score"`
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
}

// severityJS is the CVE's score as the API shows it; nil for no score or a score without the version and vector it is read with.
func severityJS(c *CVSS) *cveSeverityJS {
	if c == nil || c.Vector == "" || len(c.Vector) > 200 || c.Score < 0 || c.Score > 10 {
		return nil
	}
	switch c.Version {
	case "4.0", "3.1", "3.0", "2.0":
	default:
		return nil
	}
	return &cveSeverityJS{Band: SeverityBand(*c), Score: c.Score, Version: c.Version, Vector: c.Vector}
}

type fixJS struct {
	Key     string  `json:"key"`
	Kind    string  `json:"kind"`
	Product string  `json:"product"`
	Version *string `json:"version"`
	Ref     *string `json:"ref"`
	Channel string  `json:"channel"` // FixChannel: where the fix is published (public, ubuntu_pro, esu)
	URL     *string `json:"url"`
}

// knownFixKinds are the fix kinds the API names; a stored kind it does not know reads as unknown.
var knownFixKinds = []FixKind{FixUpdate, FixDistroUpdate, FixOSUpdate, FixFeatureUpdate, FixRestart, FixNoneYet, FixUnknown}

// fixOf is a fix as the API shows it: key is the group it is listed under (a finding's own fix key, or a block's combined one).
func fixOf(key string, fx Fix, product string) fixJS {
	k := fx.Kind
	if !slices.Contains(knownFixKinds, k) {
		k = FixUnknown
	}
	out := fixJS{Key: clipBytes(key, 400), Kind: string(k), Product: product, Channel: string(fx.Chan())}
	if fx.Version != "" {
		v := fx.Version
		out.Version = &v
	}
	if fx.Ref != "" {
		r := fx.Ref
		out.Ref = &r
	}
	return out
}

// productName is the product a finding's fix is for, as people name it: the catalogue's name, else the line's, else the product key.
func productName(f Finding, l *Line) string {
	if p, ok := ProductOf(f); ok && p.Display != "" {
		return p.Display
	}
	if l != nil && l.Display != "" {
		return l.Display
	}
	return productPart(f)
}

// productPart is the product key at the head of a finding's fix key (FixKey: '<product key>|<kind>|<version>').
func productPart(f Finding) string {
	tail := "|" + string(f.Fix.Kind) + "|" + f.Fix.Version
	if c := f.Fix.Chan(); c != ChannelPublic {
		tail += "|" + string(c)
	}
	if f.Fix.Kind != "" && strings.HasSuffix(f.FixKey, tail) {
		return strings.TrimSuffix(f.FixKey, tail)
	}
	v, rest, _ := strings.Cut(f.FixKey, "|")
	p, _, _ := strings.Cut(rest, "|")
	return v + "|" + p
}

type cveRowJS struct {
	ID           string         `json:"id"`
	CVE          string         `json:"cve"`
	Status       string         `json:"status"`
	Severity     *cveSeverityJS `json:"severity"`
	Verified     string         `json:"verified"`
	Check        bool           `json:"safe_check"`
	Urgency      urgencyJS      `json:"urgency"`
	Verification verificationJS `json:"verification"`
}

// cveRow is one CVE of a list with the status lines its finding's page shows: the reasons of its urgency and how it is known.
func cveRow(v View) cveRowJS {
	return cveRowJS{ID: v.Finding.ID, CVE: v.Finding.CVE, Status: v.Status(), Severity: severityJS(v.Severity), Verified: string(v.Finding.Verified),
		Check: v.SafeCheck, Urgency: urgencyOf(v), Verification: verificationOf(v.Finding, v.Events)}
}

type reasonJS struct {
	Layer  int     `json:"layer"`
	Source string  `json:"source"`
	Name   string  `json:"name"`
	Date   string  `json:"date"`
	URL    *string `json:"url"`
	Detail *string `json:"detail"`
	Due    *string `json:"due"`
}

var sourceRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

type urgencyJS struct {
	Layer    int        `json:"layer"`
	Since    string     `json:"since"`
	Reasons  []reasonJS `json:"reasons"`
	Internet *string    `json:"internet"`
}

func urgencyOf(v View) urgencyJS {
	f := v.Finding
	u := urgencyJS{Layer: f.Urgency, Since: store.FormatTS(cmp.Or(f.UrgencyAt, f.FirstSeen)), Reasons: []reasonJS{}}
	for _, r := range v.Reasons {
		src := strings.ToLower(strings.ReplaceAll(r.Source, "_", "-"))
		if !sourceRE.MatchString(src) || r.Since.IsZero() {
			continue
		}
		x := reasonJS{Layer: r.Layer, Source: src, Name: r.Name, Date: r.Since.UTC().Format(time.DateOnly)}
		if web(r.URL) {
			u := r.URL
			x.URL = &u
		}
		if r.Detail != "" {
			d := clipBytes(r.Detail, 120)
			x.Detail = &d
		}
		if _, err := time.Parse(time.DateOnly, r.Due); err == nil {
			d := r.Due
			x.Due = &d
		}
		u.Reasons = append(u.Reasons, x)
	}
	return u
}

// web reports whether s is an http(s) address with a host.
func web(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

type verificationJS struct {
	Verified string  `json:"verified"`
	Basis    string  `json:"basis"`
	By       *string `json:"by"`
	Entered  bool    `json:"entered"` // verified person: Vedette confirmed it on the version By entered (Finding.byEntry)
	At       *string `json:"at"`
}

// knownBases are the bases the API names; a stored basis it does not know reads as banner_version (not confirmed by itself).
var knownBases = DetectionBases

func verificationOf(f Finding, evs []Event) verificationJS {
	b := f.Basis
	if !slices.Contains(knownBases, b) {
		b = DetectBannerVersion
	}
	out := verificationJS{Verified: string(f.Verified), Basis: string(b), Entered: f.Verified == VerifiedPerson && f.byEntry}
	if !f.Confirmed() {
		return out
	}
	for i := len(evs) - 1; i >= 0; i-- { // the confirmation that holds: the newest
		if e := evs[i]; e.Kind == EvConfirmed || e.Kind == EvCreated && f.Verified != VerifiedPerson {
			at := store.FormatTS(e.TS)
			out.At = &at
			if f.Verified == VerifiedPerson {
				by := e.Actor
				if e.Actor == SystemUser && e.Detail.By != "" { // the version a person entered confirmed it (entryConfirms)
					by = e.Detail.By
				}
				out.By = &by
			}
			break
		}
	}
	if out.At == nil {
		at := store.FormatTS(f.FirstSeen)
		out.At = &at
	}
	return out
}

type handledJS struct {
	Resolution    string  `json:"resolution"`
	Via           string  `json:"via"`
	By            string  `json:"by"`
	At            string  `json:"at"`
	Note          *string `json:"note"`
	AcceptedUntil *string `json:"accepted_until"`
	FromVersion   *string `json:"from_version"`
	ToVersion     *string `json:"to_version"`
}

func handledOf(f Finding) *handledJS {
	if f.State != StateHandled {
		return nil
	}
	via := f.Via
	if !via.Valid() {
		via = ViaPerson
	}
	h := &handledJS{Resolution: string(f.Resolution), Via: string(via), By: f.ResolvedBy, At: store.FormatTS(f.ResolvedAt),
		Note: optional(f.Note), FromVersion: optional(f.FromVersion), ToVersion: optional(f.ToVersion)}
	if !f.AcceptedUntil.IsZero() {
		d := f.AcceptedUntil.Format(time.DateOnly)
		h.AcceptedUntil = &d
	}
	return h
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type reopenedJS struct {
	Why string `json:"why"`
	At  string `json:"at"`
	// By is, for detected_again, the person whose version entry made the finding detected again (they set the version back); null
	// when a source's reading did.
	By *string `json:"by"`
}

// reopenedOf says why an open finding that was handled before is open again: its newest reopening, when no handling came after it.
func reopenedOf(f Finding, evs []Event) *reopenedJS {
	if f.State != StateOpen {
		return nil
	}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		switch e.Kind {
		case EvHandled:
			return nil
		case EvAcceptanceExpire:
			return &reopenedJS{Why: WhyAcceptanceExpired, At: store.FormatTS(e.TS)}
		case EvReopened:
			switch e.Detail.Why {
			case WhyStillDetected, WhyDetectedAgain, WhyAcceptanceExpired:
				at := e.TS
				if t, err := parseTS(e.Detail.ReadingAt); err == nil && e.Detail.Why == WhyStillDetected {
					at = t
				}
				return &reopenedJS{Why: e.Detail.Why, At: store.FormatTS(at), By: optional(e.Detail.By)}
			}
			return nil // a person reopened it: nothing to explain
		}
	}
	return nil
}

type eventJS struct {
	TS         string  `json:"ts"`
	Actor      string  `json:"actor"`
	Kind       string  `json:"kind"`
	Layer      *int    `json:"layer"`
	Resolution *string `json:"resolution"`
	Via        *string `json:"via"`
	Note       *string `json:"note"`
}

func eventOf(e Event) (eventJS, bool) {
	if !slices.Contains(EventKinds, e.Kind) {
		return eventJS{}, false
	}
	out := eventJS{TS: store.FormatTS(e.TS), Actor: e.Actor, Kind: string(e.Kind), Note: optional(e.Detail.Note)}
	if e.Kind == EvUrgencyChanged && e.Detail.Layer >= 1 && e.Detail.Layer <= UrgencyUpdate {
		l := e.Detail.Layer
		out.Layer = &l
	}
	if e.Kind == EvHandled && e.Detail.Resolution.Valid() {
		r := string(e.Detail.Resolution)
		out.Resolution = &r
		if e.Detail.Via.Valid() {
			v := string(e.Detail.Via)
			out.Via = &v
		}
	}
	return out, true
}

type sameJS struct {
	ID       string         `json:"id"`
	Software *softwareRefJS `json:"software"`
	Status   string         `json:"status"`
}

// ViewJS is contract.ts View.
type ViewJS struct {
	ID           string         `json:"id"`
	CVE          string         `json:"cve"`
	Device       deviceRefJS    `json:"device"`
	Software     *softwareRefJS `json:"software"`
	Status       string         `json:"status"`
	Urgency      urgencyJS      `json:"urgency"`
	Severity     *cveSeverityJS `json:"severity"`
	Verification verificationJS `json:"verification"`
	Handled      *handledJS     `json:"handled"`
	Reopened     *reopenedJS    `json:"reopened"`
	Fix          fixJS          `json:"fix"`
	SameCVE      []sameJS       `json:"same_cve"`
	FirstSeen    string         `json:"first_seen"`
	LastSeen     string         `json:"last_seen"`
	Events       []eventJS      `json:"events"`
}

// JSON is the view as the API sends it.
func (v View) JSON() ViewJS {
	f := v.Finding
	out := ViewJS{ID: f.ID, CVE: f.CVE, Device: deviceRef(v.Device), Software: softwareRef(v), Status: v.Status(), Urgency: urgencyOf(v),
		Severity: severityJS(v.Severity), Verification: verificationOf(f, v.Events), Handled: handledOf(f), Reopened: reopenedOf(f, v.Events),
		Fix: fixOf(f.FixKey, f.Fix, productName(f, v.Line)), SameCVE: []sameJS{}, FirstSeen: store.FormatTS(f.FirstSeen),
		LastSeen: store.FormatTS(f.LastSeen), Events: []eventJS{}}
	for _, o := range v.Same {
		out.SameCVE = append(out.SameCVE, sameJS{ID: o.Finding.ID, Software: softwareRef(o), Status: o.Status()})
	}
	for _, e := range v.Events {
		if x, ok := eventOf(e); ok {
			out.Events = append(out.Events, x)
		}
	}
	return out
}

// ViewFilter selects the findings Views reads: the findings of one device and of one CVE; an empty field selects all.
type ViewFilter struct {
	AssetID, CVE string
	OpenOnly     bool
}

// Views reads findings as every place shows them, newest first, each with its history (the confirming person and day are read from it).
// The urgency reasons and the other findings of the CVE are only on Service.View. The readers that talk about findings (the assistant,
// the MCP tools, response) read this, never the columns of fnd_finding. The findings of a device a person ignored are left out, as on
// every list (Service.View still reads one: its page stays reachable from the Ignored tab; a reader of one finding checks
// View.Device.Ignored).
func (s *Service) Views(ctx context.Context, f ViewFilter) ([]View, error) {
	q := s.cfg.DB.Reader()
	where := `(?1 = '' OR asset_id = ?1) AND (?2 = '' OR cve = ?2)`
	if f.OpenOnly {
		where += ` AND state = 'open'`
	}
	fs, err := queryFindings(ctx, q, where, f.AssetID, f.CVE)
	if err != nil || len(fs) == 0 {
		return nil, err
	}
	evs, err := eventsOf(ctx, q, strings.ReplaceAll(where, "asset_id", "f.asset_id"), f.AssetID, f.CVE)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the history: %w", err)
	}
	vs, err := s.views(ctx, fs)
	if err != nil {
		return nil, err
	}
	vs = slices.DeleteFunc(vs, func(v View) bool { return v.Device.Ignored })
	for i := range vs {
		vs[i].Events = evs[vs[i].Finding.ID]
	}
	return vs, nil
}

// Confirmation is how sure Vedette is that the device is affected, and who or what said so: the one answer every reader gives to
// "who confirmed it" (the view's Verification on the API is the same fact).
type Confirmation struct {
	Verified Verified
	Basis    DetectionBasis
	By       string    // the person, for Verified person; "" otherwise
	At       time.Time // zero when the finding is not confirmed
}

// Confirmation reads the confirmation of the finding from its row and its history.
func (v View) Confirmation() Confirmation {
	j := verificationOf(v.Finding, v.Events)
	c := Confirmation{Verified: v.Finding.Verified, Basis: DetectionBasis(j.Basis)}
	if j.By != nil {
		c.By = *j.By
	}
	if j.At != nil {
		c.At, _ = parseTS(*j.At)
	}
	return c
}

// FixProduct is the product the finding's fix is for, as people name it: the catalogue's name, else the software line's, else the key.
func (v View) FixProduct() string { return productName(v.Finding, v.Line) }
