package exposure

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var termsAdmin = Actor{ID: "u-admin", Email: "admin@acme.example", Admin: true}

func (e *env) auditDetails(action string) []string {
	e.t.Helper()
	var out []string
	for _, a := range e.audits() {
		if a.Action == action {
			out = append(out, a.Detail)
		}
	}
	return out
}

// The testing terms are accepted per verified target by an administrator with two-step sign-in, stored with who, when,
// the version, the text and the disruptive flag (always on), and audited with the flag; accepting the same again changes nothing,
// withdrawing is always possible, and a new version asks again.
func TestTerms_StoredAuditedWithdrawnAndAskedAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	v := e.target(id)
	if v.Terms != nil || v.FullScan || v.TermsNotice.Version != TermsVersion || !strings.Contains(v.TermsNotice.Text, "owns "+ipA) || !strings.Contains(v.TermsNotice.Text, "\n"+termsDisruptive+"\n") {
		t.Fatalf("before = %+v", v)
	}
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion)
	wantAPI(t, err, 403, "twofa_required")
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err = e.svc.AcceptTerms(e.ctx(), termsAdmin, id, "2020-01-01")
	wantAPI(t, err, 409, "notice_changed")
	_, err = e.svc.AcceptTerms(e.ctx(), Actor{ID: "u-op", Email: "op@acme.example"}, id, TermsVersion)
	wantAPI(t, err, 403, "forbidden")

	v = e.acceptTerms(id, true)
	if v.Terms == nil || !v.FullScan || v.Terms.By != "admin@acme.example" || !v.Terms.Disruptive || v.Terms.Text != v.TermsNotice.Text || !v.Terms.current() || !v.Commitment.current() {
		t.Fatalf("accepted = %+v", v)
	}
	acc := e.auditDetails("exposure.terms_accept")
	if len(acc) != 1 || !strings.HasPrefix(acc[0], "accepted (disruptive checks: yes, user u-admin, two-step: app, terms "+TermsVersion+"): I confirm") ||
		len(e.auditDetails("exposure.commitment")) != 1 {
		t.Fatalf("audit = %q", acc)
	}
	e.acceptTerms(id, true)
	if len(e.auditDetails("exposure.terms_accept")) != 1 {
		t.Fatal("accepting the same again wrote a row")
	}
	v, err = e.svc.RevokeTerms(e.ctx(), "admin@acme.example", id)
	if err != nil || v.Terms != nil || v.FullScan {
		t.Fatalf("withdrawn = %+v, %v", v, err)
	}
	if r := e.auditDetails("exposure.terms_revoke"); len(r) != 1 || !strings.Contains(r[0], "disruptive checks: yes") {
		t.Fatalf("audit = %q", r)
	}
	// a new version of the terms: the old acceptance no longer counts until accepted again
	e.acceptTerms(id, true)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_consent SET version = '2020-01-01' WHERE target_id = ? AND kind = 'terms'`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if v = e.target(id); v.FullScan || v.Terms == nil {
		t.Fatalf("old version = %+v", v)
	}
	e.acceptTerms(id, true)
	if acc = e.auditDetails("exposure.terms_accept"); !strings.HasPrefix(acc[len(acc)-1], "accepted again (replaces terms 2020-01-01") || !e.target(id).FullScan {
		t.Fatalf("audit = %q", acc)
	}
}

// Only a verified target can be given the terms.
func TestTerms_OnlyAVerifiedTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	d, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "unverified.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.AcceptTerms(e.ctx(), termsAdmin, d.ID, TermsVersion)
	wantAPI(t, err, 409, "not_verified")
}

type modeRunner struct{ modes []ScanMode }

func (r *modeRunner) Scan(_ context.Context, t ScanTarget) (Content, error) {
	r.modes = append(r.modes, t.Mode)
	return Content{}, nil
}

// The scanner seams receive the accepted level in ScanTarget.Mode: the K-4 scope without terms, Full with an older acceptance
// without the disruptive checks, and Full and Disruptive with the current terms.
func TestTerms_ModeReachesTheScanners(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	if _, err := e.commit(id); err != nil {
		t.Fatal(err)
	}
	r := &modeRunner{}
	e.svc.SetRunner(r)
	scan := func() {
		t.Helper()
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	e.acceptTerms(id, false)
	scan()
	e.acceptTerms(id, true)
	scan()
	want := []ScanMode{{}, {Full: true}, {Full: true, Disruptive: true}}
	if len(r.modes) != 3 || r.modes[0] != want[0] || r.modes[1] != want[1] || r.modes[2] != want[2] {
		t.Fatalf("modes = %+v", r.modes)
	}
}

// The terms the mock shows are the backend's: contract.ts holds the same version and texts.
func TestTermsMatchTheContractOfTheGUI(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../web/src/features/exposure/contract.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	str := func(name string) string {
		m := regexp.MustCompile(name + ` = '((?:[^'\\]|\\.)*)'`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("contract.ts has no %s", name)
		}
		return strings.NewReplacer(`\'`, `'`, `\n`, "\n").Replace(m[1])
	}
	if str("TERMS_VERSION") != TermsVersion || str("TERMS_TEMPLATE") != termsTemplate || str("TERMS_TEMPLATE_DOMAIN") != termsTemplateDomain {
		t.Fatal("contract.ts terms differ from the backend (modules/exposure/terms.go)")
	}
	if want := "export const TERMS_KEPT_VERSIONS: readonly [string, ...string[]] = ['" + strings.Join(keptTermsVersions, "', '") + "']"; !strings.Contains(src, want) {
		t.Fatalf("contract.ts lacks %s", want)
	}
	if strings.Contains(src, "TERMS_DISRUPTIVE") {
		t.Fatal("contract.ts still has a separate sentence for the disruptive checks: they are part of the terms text")
	}
}

// Changing the terms without a new version would store words under a version nobody accepted: the text of each version is pinned.
func TestTermsTextIsPinnedToItsVersion(t *testing.T) {
	t.Parallel()
	pinned := map[string]string{
		"2026-11-14":  "e3cafa3e881a321c3ae62f23c5d6fd32ac7e34c7715dbc1138636682854bfd27",
		"2026-11-14b": "220bd0f322cfe435686be56c09855532b3c18d92cfb2efae9d06126a96f58604",
		"2026-11-14c": "82a9d549446ef21096cf7f035f83d30068bbc07c0f317b3fc48b164c508356e3", // The domain's own text, honest list
		"2026-11-14d": "ec2a0df9ebbe6691d6b7b2ec0b4a7440289b25fdb027baab76287274b029e411", // OpenVAS test files, anonymous login, the tick as PRIVACY lists it
		"2026-11-14e": "b105bdea7ef5cca8b936493a9bc1c6528ce62d517a421139f77a0a0d48a6221e", // The web line word for word as TERMS.md says it (ZAP active, not built)
		"2026-11-18":  "ffec2d4a5e941b0ba409f61cca2e35ea16caa8a82a93ecdf927881a041c93929", // The disclaimer names the Vedette authors
		"2026-11-18b": "8267255defc8ea3f3874050caf8333b8ccc2531ce5e19bd285c65fbb315e4491", // The box also scans on the schedule, never disruptive
		// From here the disruptive checks are a paragraph of the templates, not a third text: the hash is of the two templates.
		"2026-11-26": "8a2de13959eb625030e7289c7360e437211a458207df0358deaef0cccf80f556", // One acceptance: the disruptive checks are part of the terms
	}
	sum := sha256.Sum256([]byte(termsTemplate + "\x00" + termsTemplateDomain))
	if got := pinned[TermsVersion]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("the terms for version %s have hash %x: change TermsVersion (and contract.ts) when the text changes, then pin the new hash", TermsVersion, sum)
	}
}

// review r1 M1: withdrawing the terms stops a deep scan of the target that runs now: during the Greenbone step gvmd's task is stopped,
// the run ends stopped with the reason, the earlier results are kept, and the audit row says a scan was stopped.
func TestTerms_WithdrawStopsTheRunningScan(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.svc.gb().poll = time.Millisecond
	id := e.detect(ipA)[0].ID
	if _, err := e.commit(id); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(id, true)
	var once sync.Once
	revoked := make(chan struct{})
	h.gvm.with(func(g *fakeGVM) {
		g.states = []string{"Running"}
		g.onPoll = func() {
			once.Do(func() {
				defer close(revoked)
				if _, err := e.svc.RevokeTerms(context.Background(), "admin@acme.example", id); err != nil {
					t.Error(err)
				}
			})
		}
	})
	e.svc.SetRunner(&fakeRunner{content: gbOpen()}) // OpenVAS runs only with an open port to check
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err == nil {
		t.Fatal("the scan was not stopped")
	}
	<-revoked // the withdrawal writes its stop row after the cancel; the run may end first
	run := e.svc.CurrentScan(e.ctx())
	if run == nil || run.Status != RunStopped || run.StopReason == nil || *run.StopReason != "the testing terms of this target were withdrawn" || !h.gvm.seen("stop_task") ||
		e.writtenScans() != 1 {
		t.Fatalf("run = %+v, cmds %q", run, h.gvm.cmds)
	}
	if r := e.auditDetails("exposure.terms_revoke"); len(r) != 2 || r[1] != stoppedNote+" (the testing terms of this target were withdrawn)" {
		t.Fatalf("audit = %q", r)
	}
}

// Accepting the terms never stops a scan that runs: it only raises the level (an older acceptance without the disruptive checks to the
// current one); withdrawing them is what stops a run above the new level.
func TestTerms_AcceptingStopsNoRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	e.acceptTerms(id, false)
	x := &scanExec{targetID: id, mode: ScanMode{Full: true}, done: make(chan struct{})}
	e.svc.runMu.Lock()
	e.svc.execs = map[string]*scanExec{"run-1": x}
	e.svc.runMu.Unlock()
	e.acceptTerms(id, true)
	if x.cause != nil {
		t.Fatalf("accepting stopped the scan: %+v", x.cause)
	}
}

// review r1 M2: behind carrier-grade NAT the terms step warns that the address is probably shared and refuses the terms, which include
// the disruptive checks. The terms say the address must be the customer's alone.
func TestTerms_CarrierGradeNAT(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	if v := e.target(id); v.TermsWarning != nil || !strings.Contains(v.TermsNotice.Text, "Accept only if "+ipA+" is yours alone") {
		t.Fatalf("view = %+v", v)
	}
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("100.64.0.1")}}
	if v := e.target(id); v.TermsWarning == nil || !strings.Contains(*v.TermsWarning, "carrier-grade NAT (its gateway 100.64.0.1 is in 100.64.0.0/10)") {
		t.Fatalf("view = %+v", v)
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion)
	wantAPI(t, err, 409, "shared_address")
	if v := e.target(id); v.FullScan || v.Terms != nil {
		t.Fatalf("refused terms stored: %+v", v)
	}
}

// The box's own IP it does not go out through now (the latest full check saw another one) keeps its proof for its 90 days and is
// scanned in that time; the testing terms can be accepted in that time too, as for a domain whose last check missed its record.
func TestTerms_NotCurrentIPInsideItsProofCanAccept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(id) {
		t.Fatal("not paused")
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	v, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion)
	if err != nil {
		t.Fatalf("terms refused inside the proof: %v", err)
	}
	if !v.FullScan {
		t.Fatalf("view = %+v", v)
	}
}

// Once the 90 days of the last sighting have passed, the IP is expired and its terms cannot be accepted.
func TestTerms_NotCurrentIPPastItsProofCannotAccept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.advance(time.Minute)
	e.fullAs(ipB)
	e.advance(91 * 24 * time.Hour)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion)
	wantAPI(t, err, 409, "expired")
}

// review r2 M1: a withdrawal committed while the scan's gate runs (the full public-IP check) is seen when the run registers: the run
// starts in the K-4 scope, not at the mode the gate read.
func TestTerms_WithdrawDuringTheGateStartsTheK4Scope(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	e.advance(time.Hour) // the gate runs a full check again
	var once sync.Once
	e.prober.mu.Lock()
	e.prober.onRound = func() {
		once.Do(func() {
			if _, err := e.svc.RevokeTerms(context.Background(), "admin@acme.example", id); err != nil {
				t.Error(err)
			}
		})
	}
	e.prober.mu.Unlock()
	r := &modeRunner{}
	e.svc.SetRunner(r)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if e.prober.count() == 0 || len(r.modes) != 1 || r.modes[0] != (ScanMode{}) {
		t.Fatalf("rounds %d, modes %+v", e.prober.count(), r.modes)
	}
}
