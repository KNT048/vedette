package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// legacyTermsVersion is the version of the testing terms before the disruptive checks became part of the one acceptance. Its rows
// stay valid: an acceptance of it keeps its own stored text and its own disruptive flag.
const legacyTermsVersion = "2026-11-18b"

// acceptOnce is the one "Accept the testing terms" button: the version the page showed and nothing else.
func acceptOnce(e *env, who Actor, id, version string) (TargetView, error) {
	return e.svc.AcceptTerms(e.ctx(), who, id, version)
}

// warnLog records the WARN lines of the service's logger.
type warnLog struct {
	mu   sync.Mutex
	recs []map[string]string
}

func (l *warnLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *warnLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *warnLog) WithGroup(string) slog.Handler            { return l }
func (l *warnLog) Handle(_ context.Context, r slog.Record) error {
	if r.Level != slog.LevelWarn {
		return nil
	}
	m := map[string]string{"msg": r.Message}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
	l.mu.Lock()
	l.recs = append(l.recs, m)
	l.mu.Unlock()
	return nil
}

// refusals are the logged refusals of a terms acceptance, as "code target".
func (l *warnLog) refusals() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, m := range l.recs {
		if strings.Contains(m["msg"], "testing terms refused") {
			out = append(out, m["code"]+" "+m["target"])
		}
	}
	return out
}

// secretFree says no logged value carries an e-mail address or a token.
func (l *warnLog) secretFree() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.recs {
		for _, v := range m {
			if strings.Contains(v, "@") || strings.Contains(strings.ToLower(v), "token") {
				return false
			}
		}
	}
	return true
}

func logTo(e *env) *warnLog {
	l := &warnLog{}
	e.svc.cfg.Log = slog.New(l)
	return l
}

func setTermsRow(e *env, id, version, text string, disruptive bool) {
	e.t.Helper()
	d := 0
	if disruptive {
		d = 1
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_consent SET version = ?, text = ?, disruptive = ? WHERE target_id = ? AND kind = 'terms'`, version, text, d, id)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

// One acceptance is the deep scan and the disruptive checks: the stored text is the notice the page showed (the disruptive checks are
// one of its paragraphs), the flag is set, the audit row says so, and a person's scan runs them.
func TestTermsOne_OneAcceptIsDeepAndDisruptive(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	notice := e.target(id).TermsNotice
	if !strings.Contains(notice.Text, "\nDisruptive checks: denial of service, password guessing") {
		t.Fatalf("the disruptive checks are not part of the terms text: %q", notice.Text)
	}
	v, err := acceptOnce(e, termsAdmin, id, TermsVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !v.FullScan || v.Terms == nil || !v.Terms.Disruptive || v.Terms.Text != notice.Text || v.Terms.Version != TermsVersion {
		t.Fatalf("accepted = %+v", v.Terms)
	}
	if acc := e.auditDetails("exposure.terms_accept"); len(acc) != 1 || !strings.HasPrefix(acc[0], "accepted (disruptive checks: yes, user u-admin") {
		t.Fatalf("audit = %q", acc)
	}
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", id); err != nil || m != (modeDefault) { // the default settings leave out DoS
		t.Fatalf("a person's scan: %+v %v", m, err)
	}
	if _, err := acceptOnce(e, termsAdmin, id, TermsVersion); err != nil || len(e.auditDetails("exposure.terms_accept")) != 1 {
		t.Fatalf("accepting the same again: %v, %d rows", err, len(e.auditDetails("exposure.terms_accept")))
	}
}

// The box's own IP it does not go out through now is accepted, disruptive checks included, while its proof holds: no ip_not_current.
func TestTermsOne_NotCurrentIPIsAcceptedWhileItsProofHolds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(id) {
		t.Fatal("not paused")
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	v, err := acceptOnce(e, termsAdmin, id, TermsVersion)
	if err != nil || !v.FullScan || v.Terms == nil || !v.Terms.Disruptive {
		t.Fatalf("accept on the other line: %+v, %v", v.Terms, err)
	}
}

// Scheduled scans never run the disruptive checks; a person's Scan now of an accepted target does.
func TestTermsOne_OnlyAPersonsScanRunsTheDisruptiveChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	if _, err := acceptOnce(e, termsAdmin, id, TermsVersion); err != nil {
		t.Fatal(err)
	}
	if m, err := e.svc.ModeNow(e.ctx(), SystemUser, id); err != nil || m != (modeDeepOnly) {
		t.Fatalf("the box's own scan: %+v %v", m, err)
	}
	r := &modeRunner{}
	e.svc.SetRunner(r)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if len(r.modes) != 1 || r.modes[0] != (modeDefault) {
		t.Fatalf("Scan now: %+v", r.modes)
	}
}

// A box whose gateway is in 100.64.0.0/10 cannot accept the terms of its egress IP (the address is the provider's): refused with the
// warning, logged, nothing stored. A typed IP keeps its own warning and can be accepted.
func TestTermsOne_CarrierGradeNATRefusesTheEgressIP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	logs := logTo(e)
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	w := e.target(id).TermsWarning
	if w == nil || !strings.Contains(*w, "carrier-grade NAT") || !strings.Contains(*w, "cannot be accepted") {
		t.Fatalf("warning = %v", str(w))
	}
	_, err := acceptOnce(e, termsAdmin, id, TermsVersion)
	wantAPI(t, err, 409, "shared_address")
	if !strings.Contains(err.Error(), *w) {
		t.Fatalf("the refusal does not carry the warning: %v", err)
	}
	if v := e.target(id); v.FullScan || v.Terms != nil {
		t.Fatalf("a refused acceptance stored the terms: %+v", v.Terms)
	}
	if got := logs.refusals(); len(got) != 1 || got[0] != "shared_address "+id {
		t.Fatalf("logged refusals = %q", got)
	}

	w2 := newIPWorld(t)
	w2.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	w2.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	typed := w2.addIP(ipC)
	w2.files.serve(ipC, "https", typed.Token+"\n")
	if r := w2.verify(typed.ID); !r.Verified {
		t.Fatalf("typed IP not verified: %+v", r)
	}
	if tw := w2.target(typed.ID).TermsWarning; tw == nil || *tw != typedWarning {
		t.Fatalf("typed warning = %v", str(tw))
	}
	if v, err := acceptOnce(w2.env, termsAdmin, typed.ID, TermsVersion); err != nil || !v.FullScan || !v.Terms.Disruptive {
		t.Fatalf("typed IP: %+v, %v", v.Terms, err)
	}
}

// The guards stay: an administrator with two-step sign-in, the version the page showed, a verified target whose proof has not
// expired. Each refusal is a WARN line with the code and the target id, without an e-mail address or a token.
func TestTermsOne_GuardsStayAndEveryRefusalIsLogged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	logs := logTo(e)
	id := e.committedIP(ipA).ID
	_, err := acceptOnce(e, termsAdmin, id, TermsVersion)
	wantAPI(t, err, 403, "twofa_required")
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err = acceptOnce(e, Actor{ID: "u-op", Email: "op@acme.example"}, id, TermsVersion)
	wantAPI(t, err, 403, "forbidden")
	_, err = acceptOnce(e, termsAdmin, id, legacyTermsVersion+"-old")
	wantAPI(t, err, 409, "notice_changed")
	d, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "unverified.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = acceptOnce(e, termsAdmin, d.ID, TermsVersion)
	wantAPI(t, err, 409, "not_verified")
	e.advance(time.Minute)
	e.fullAs(ipB)
	e.advance(91 * 24 * time.Hour)
	_, err = acceptOnce(e, termsAdmin, id, TermsVersion)
	wantAPI(t, err, 409, "expired")
	want := []string{"twofa_required " + id, "forbidden " + id, "notice_changed " + id, "not_verified " + d.ID, "expired " + id}
	if got := logs.refusals(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("logged refusals = %q, want %q", got, want)
	}
	if !logs.secretFree() {
		t.Fatalf("a refusal logged an e-mail address or a token: %+v", logs.recs)
	}
	if v := e.target(id); v.Terms != nil {
		t.Fatalf("a refused acceptance stored the terms: %+v", v.Terms)
	}
}

// An acceptance of the previous version stays valid after the update, with its own stored version, text and flag: disruptive=yes keeps
// the disruptive checks in a person's scan; disruptive=no keeps the deep scan only until the terms are accepted again, which includes
// them. An acceptance of a version before that one still counts as not accepted.
func TestTermsOne_OldAcceptancesStayValid(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	if _, err := acceptOnce(e, termsAdmin, id, TermsVersion); err != nil {
		t.Fatal(err)
	}
	const oldText = "the text accepted before the update"

	setTermsRow(e, id, legacyTermsVersion, oldText+"\nInclude disruptive checks", true)
	v := e.target(id)
	if !v.FullScan || v.Terms.Version != legacyTermsVersion || v.Terms.Text != oldText+"\nInclude disruptive checks" || !v.Terms.Disruptive {
		t.Fatalf("old row with the tick = %+v (full %v)", v.Terms, v.FullScan)
	}
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", id); err != nil || m != (modeDefault) {
		t.Fatalf("old row with the tick, a person's scan: %+v %v", m, err)
	}
	if m, err := e.svc.ModeNow(e.ctx(), SystemUser, id); err != nil || m != (modeDeepOnly) {
		t.Fatalf("old row with the tick, the box's scan: %+v %v", m, err)
	}

	setTermsRow(e, id, legacyTermsVersion, oldText, false)
	v = e.target(id)
	if !v.FullScan || v.Terms.Version != legacyTermsVersion || v.Terms.Text != oldText || v.Terms.Disruptive {
		t.Fatalf("old row without the tick = %+v (full %v)", v.Terms, v.FullScan)
	}
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", id); err != nil || m != (modeDeepOnly) {
		t.Fatalf("old row without the tick, a person's scan: %+v %v", m, err)
	}
	if n, err := e.svc.Node(e.ctx(), id); err != nil || !n.Deep || n.Terms == nil || n.Terms.Disruptive {
		t.Fatalf("node of an old row without the tick: %+v %v", n.Terms, err)
	}
	v, err := acceptOnce(e, termsAdmin, id, TermsVersion)
	if err != nil || !v.Terms.Disruptive || v.Terms.Version != TermsVersion || v.Terms.Text != v.TermsNotice.Text {
		t.Fatalf("accepted again: %+v, %v", v.Terms, err)
	}
	if acc := e.auditDetails("exposure.terms_accept"); !strings.HasPrefix(acc[len(acc)-1], "accepted again (replaces terms "+legacyTermsVersion+", accepted by admin@acme.example") ||
		!strings.Contains(acc[len(acc)-1], "disruptive checks: no)") {
		t.Fatalf("audit = %q", acc)
	}

	setTermsRow(e, id, "2026-11-18", oldText, true)
	if v = e.target(id); v.FullScan || v.Terms == nil {
		t.Fatalf("a version before the previous one counted: %+v", v)
	}
}

// The API takes the version alone; a request of an older page that still sends the tick is read the same way.
func TestTermsOne_APITakesTheVersionAlone(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	id := e.committedIP(ipA).ID
	code, b := e.call("PUT", "/exposure/targets/"+id+"/terms", "admin", `{"version":"`+TermsVersion+`"}`)
	if terms, _ := b["terms"].(map[string]any); code != 200 || terms["disruptive"] != true || b["full_scan"] != true {
		t.Fatalf("accept: %d %v", code, b)
	}
	id2 := e.committedIP(ipB).ID
	code, b = e.call("PUT", "/exposure/tree/"+id2+"/terms", "admin", `{"version":"`+TermsVersion+`","disruptive":true}`)
	if terms, _ := b["terms"].(map[string]any); code != 200 || terms["disruptive"] != true || b["deep"] != true {
		t.Fatalf("accept with the old tick field: %d %v", code, b)
	}
	if n, _ := b["terms_notice"].(map[string]any); n == nil || n["disruptive"] != nil {
		t.Fatalf("the notice still has a separate tick sentence: %v", b["terms_notice"])
	}
}

// The disruptive checks are part of the testing terms, not a separate tick: no text a person reads (the terms of use, the
// third-party notices, the screens' English text) may still say they run only "when ticked".
func TestTermsOne_NoUserTextMentionsADisruptiveTick(t *testing.T) {
	t.Parallel()
	tick := regexp.MustCompile(`(?i)disruptive tick|disruptive checks (are )?(also )?ticked`)
	// Only documents whose change runs the Go suite (scripts/ci/classify.go); PRIVACY.md, docs/LEGAL.md and the cookbook were swept
	// once when the tick went away.
	files := []string{"../../TERMS.md", "../../THIRD_PARTY_NOTICES.md"}
	locales, err := filepath.Glob("../../web/src/locales/en/*.json")
	if err != nil || len(locales) == 0 {
		t.Fatalf("locales: %v %v", locales, err)
	}
	for _, f := range append(files, locales...) {
		b, err := os.ReadFile(f) //nolint:gosec // G304: fixed repo documents and the English locales
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if m := tick.FindString(line); m != "" {
				t.Errorf("%s:%d still says %q: the disruptive checks are part of the accepted testing terms", f, i+1, m)
			}
		}
	}
}

// review M2: the carrier-grade NAT check also runs when a scan of the box's own IP starts. An acceptance stored before the gateway
// moved into 100.64.0.0/10 keeps the deep scan, but a person's scan drops the disruptive checks while the gateway is there; a gateway
// that cannot be read drops them too (fail closed at scan time). A typed IP keeps what its terms allow.
func TestTermsOne_CarrierGradeNATAtScanTimeDropsTheDisruptiveChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	gw := &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	e.svc.cfg.Gateway = gw
	if m, err := e.svc.ModeNow(e.ctx(), "admin@acme.example", id); err != nil || m != (modeDeepOnly) {
		t.Fatalf("mode behind carrier-grade NAT: %+v %v", m, err)
	}
	r := &modeRunner{}
	e.svc.SetRunner(r)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
		t.Fatal(err)
	}
	gw.g, gw.err = GatewayDevice{}, fmt.Errorf("inventory not ready")
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
		t.Fatal(err)
	}
	gw.g, gw.err = GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}, nil
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", id); err != nil {
		t.Fatal(err)
	}
	want := []ScanMode{modeDeepOnly, modeDeepOnly, modeAll}
	if fmt.Sprint(r.modes) != fmt.Sprint(want) {
		t.Fatalf("modes = %+v, want %+v", r.modes, want)
	}
}

// review L1: an older page sends the tick it showed; with the tick off it asked for the deep scan without the disruptive checks, so
// it is not taken as an acceptance of them: 409 notice_changed, nothing stored. Absent or true is the one acceptance.
func TestTermsOne_AnOlderPageWithTheTickOffIsAskedToReload(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	logs := logTo(e.env)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	id := e.committedIP(ipA).ID
	for _, path := range []string{"/exposure/targets/" + id + "/terms", "/exposure/tree/" + id + "/terms"} {
		code, b := e.call("PUT", path, "admin", `{"version":"`+TermsVersion+`","disruptive":false}`)
		if code != 409 || errCode(b) != "notice_changed" {
			t.Fatalf("%s with the tick off: %d %v", path, code, b)
		}
	}
	if v := e.target(id); v.Terms != nil {
		t.Fatalf("stored: %+v", v.Terms)
	}
	if got := logs.refusals(); len(got) != 2 || got[0] != "notice_changed "+id {
		t.Fatalf("logged refusals = %q", got)
	}
	if code, b := e.call("PUT", "/exposure/targets/"+id+"/terms", "admin", `{"version":"`+TermsVersion+`","disruptive":true}`); code != 200 || b["full_scan"] != true {
		t.Fatalf("with the tick on: %d %v", code, b)
	}
}

// review L5: an unverified IP is refused as not verified, even behind carrier-grade NAT.
func TestTermsOne_AnUnverifiedIPIsNotVerifiedBeforeTheNATCheck(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	w.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	d := w.addIP(ipC)
	_, err := acceptOnce(w.env, termsAdmin, d.ID, TermsVersion)
	wantAPI(t, err, 409, "not_verified")
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	e.advance(time.Minute)
	e.fullAs(ipB)
	e.advance(91 * 24 * time.Hour)
	_, err = acceptOnce(e, termsAdmin, id, TermsVersion)
	wantAPI(t, err, 409, "expired")
}

// A domain's disruptive checks go only to an address proven as this box's own (its public IP inside its proof): the box's IP the
// domain points at gets them in a person's scan; an address that is not the box's (hosting, a CDN, a name pointing outside) gets the
// deep scan without them and a line that says so; a scan the box runs by itself never runs them.
func TestTermsOne_DomainDisruptiveChecksOnlyOnTheBoxsProvenIP(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	s := d.scan()
	modes := func() map[string]bool {
		d.seams.mu.Lock()
		defer d.seams.mu.Unlock()
		out := map[string]bool{}
		for _, c := range append(slices.Clone(d.seams.services), d.seams.templates...) {
			out[c.ip] = out[c.ip] || c.st.Mode.Disruptive
			if !c.st.Mode.Full {
				t.Fatalf("not deep: %+v", c)
			}
		}
		return out
	}
	if got := modes(); !got[ipA] || got[ipB] || got[ipC] {
		t.Fatalf("disruptive per address = %v, want only %s", got, ipA)
	}
	if !hasLine(s, ipB+" (api.acme.example, www.acme.example): "+notDeepNotOwn) {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if hasLine(s, ipA+" (acme.example): "+notDeepNotOwn) {
		t.Fatalf("the box's IP got the line: %q", notChecked(s))
	}

	d.seams.mu.Lock()
	d.seams.services, d.seams.templates = nil, nil
	d.seams.mu.Unlock()
	d.advance(ScanEvery)
	if _, err := d.svc.Scan(d.ctx(), SystemUser, d.dom.ID); err != nil {
		t.Fatal(err)
	}
	if got := modes(); got[ipA] || got[ipB] || got[ipC] || len(got) == 0 {
		t.Fatalf("a scan the box ran by itself, disruptive per address = %v", got)
	}
}
