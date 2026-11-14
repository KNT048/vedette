package exposure

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
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

// FULL-1 (D-566): the testing terms are accepted per verified target by an administrator with two-step sign-in, stored with who, when,
// the version, the text and the disruptive flag, and audited with the flag; accepting the same again changes nothing, the tick is a
// new acceptance, withdrawing is always possible, and a new version asks again.
func TestTerms_StoredAuditedWithdrawnAndAskedAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	v := e.target(id)
	if v.Terms != nil || v.FullScan || v.TermsNotice.Version != TermsVersion || !strings.Contains(v.TermsNotice.Text, "owns "+ipA) || v.TermsNotice.Disruptive != termsDisruptive {
		t.Fatalf("before = %+v", v)
	}
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion, false)
	wantAPI(t, err, 403, "twofa_required")
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err = e.svc.AcceptTerms(e.ctx(), termsAdmin, id, "2020-01-01", false)
	wantAPI(t, err, 409, "notice_changed")
	_, err = e.svc.AcceptTerms(e.ctx(), Actor{ID: "u-op", Email: "op@acme.example"}, id, TermsVersion, false)
	wantAPI(t, err, 403, "forbidden")

	v = e.acceptTerms(id, false)
	if v.Terms == nil || !v.FullScan || v.Terms.By != "admin@acme.example" || v.Terms.Disruptive || v.Terms.Text != v.TermsNotice.Text || !v.Terms.current() || !v.Commitment.current() {
		t.Fatalf("accepted = %+v", v)
	}
	acc := e.auditDetails("exposure.terms_accept")
	if len(acc) != 1 || !strings.HasPrefix(acc[0], "accepted (disruptive checks: no, user u-admin, two-step: app, terms "+TermsVersion+"): I confirm") ||
		len(e.auditDetails("exposure.commitment")) != 1 {
		t.Fatalf("audit = %q", acc)
	}
	e.acceptTerms(id, false)
	if len(e.auditDetails("exposure.terms_accept")) != 1 {
		t.Fatal("accepting the same again wrote a row")
	}
	v = e.acceptTerms(id, true)
	if !v.Terms.Disruptive || !strings.HasSuffix(v.Terms.Text, "\n"+termsDisruptive) || e.target(id).Terms.Disruptive != true {
		t.Fatalf("with the tick = %+v", v.Terms)
	}
	if acc = e.auditDetails("exposure.terms_accept"); len(acc) != 2 || !strings.Contains(acc[1], "disruptive checks: yes, user") {
		t.Fatalf("audit = %q", acc)
	}
	v, err = e.svc.RevokeTerms(e.ctx(), "admin@acme.example", id)
	if err != nil || v.Terms != nil || v.FullScan {
		t.Fatalf("withdrawn = %+v, %v", v, err)
	}
	if r := e.auditDetails("exposure.terms_revoke"); len(r) != 1 || !strings.Contains(r[0], "disruptive checks: yes") {
		t.Fatalf("audit = %q", r)
	}
	// a new version of the terms: the old acceptance no longer counts until accepted again
	e.acceptTerms(id, false)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET terms_version = '2020-01-01' WHERE id = ?`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if v = e.target(id); v.FullScan || v.Terms == nil {
		t.Fatalf("old version = %+v", v)
	}
	e.acceptTerms(id, false)
	if acc = e.auditDetails("exposure.terms_accept"); !strings.HasPrefix(acc[len(acc)-1], "accepted again (replaces terms 2020-01-01") || !e.target(id).FullScan {
		t.Fatalf("audit = %q", acc)
	}
}

// FULL-1: only a verified target can be given the terms.
func TestTerms_OnlyAVerifiedTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	d, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "unverified.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.AcceptTerms(e.ctx(), termsAdmin, d.ID, TermsVersion, false)
	wantAPI(t, err, 409, "not_verified")
}

type modeRunner struct{ modes []ScanMode }

func (r *modeRunner) Scan(_ context.Context, t ScanTarget) (Content, error) {
	r.modes = append(r.modes, t.Mode)
	return Content{}, nil
}

// FULL-1: the scanner seams receive the accepted level in ScanTarget.Mode: the K-4 scope without terms, Full with them, and
// Disruptive only with the tick.
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

// FULL-1: the terms the mock shows are the backend's: contract.ts holds the same version, text and tick.
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
	if str("TERMS_VERSION") != TermsVersion || str("TERMS_TEMPLATE") != termsTemplate || str("TERMS_TEMPLATE_DOMAIN") != termsTemplateDomain || str("TERMS_DISRUPTIVE") != termsDisruptive {
		t.Fatal("contract.ts terms differ from the backend (modules/exposure/terms.go)")
	}
}

// Changing the terms without a new version would store words under a version nobody accepted: the text of each version is pinned.
func TestTermsTextIsPinnedToItsVersion(t *testing.T) {
	t.Parallel()
	pinned := map[string]string{
		"2026-11-14":  "e3cafa3e881a321c3ae62f23c5d6fd32ac7e34c7715dbc1138636682854bfd27",
		"2026-11-14b": "220bd0f322cfe435686be56c09855532b3c18d92cfb2efae9d06126a96f58604",
		"2026-11-14c": "82a9d549446ef21096cf7f035f83d30068bbc07c0f317b3fc48b164c508356e3", // D-571 review r1: the domain's own text, honest list
		"2026-11-14d": "ec2a0df9ebbe6691d6b7b2ec0b4a7440289b25fdb027baab76287274b029e411", // D-571 review r2: OpenVAS test files, anonymous login, the tick as PRIVACY lists it
	}
	sum := sha256.Sum256([]byte(termsTemplate + "\x00" + termsTemplateDomain + "\x00" + termsDisruptive))
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
	e.svc.SetRunner(&fakeRunner{content: Content{}})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err == nil {
		t.Fatal("the scan was not stopped")
	}
	<-revoked // the withdrawal writes its stop row after the cancel; the run may end first
	run := e.svc.CurrentScan()
	if run == nil || run.Status != RunStopped || run.SnapshotID == nil || run.StopReason == nil || *run.StopReason != "the testing terms of this target were withdrawn" || !h.gvm.seen("stop_task") {
		t.Fatalf("run = %+v, cmds %q", run, h.gvm.cmds)
	}
	if r := e.auditDetails("exposure.terms_revoke"); len(r) != 2 || r[1] != stoppedNote+" (the testing terms of this target were withdrawn)" {
		t.Fatalf("audit = %q", r)
	}
}

// review r1 M1: taking the disruptive tick out stops a disruptive run; raising the level, or another target's change, does not.
func TestTerms_LoweringStopsOnlyARunAbove(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.detect(ipA)[0].ID
	e.acceptTerms(id, true)
	var cause error
	fake := func(m ScanMode, target string) {
		e.svc.runMu.Lock()
		e.svc.run = &scanRun{view: ScanRun{TargetID: target, Status: RunRunning}, mode: m, cancel: func(c error) { cause = c }}
		e.svc.runMu.Unlock()
		cause = nil
	}
	fake(ScanMode{Full: true, Disruptive: true}, "other")
	e.acceptTerms(id, false)
	if cause != nil {
		t.Fatal("stopped a scan of another target")
	}
	fake(ScanMode{Full: true}, id)
	e.acceptTerms(id, true)
	if cause != nil {
		t.Fatal("raising the level stopped the scan")
	}
	fake(ScanMode{Full: true, Disruptive: true}, id)
	e.acceptTerms(id, false)
	var sb *stoppedBy
	if !errors.As(cause, &sb) || sb.why != "the disruptive checks were taken out of this target's testing terms" {
		t.Fatalf("cause = %v", cause)
	}
	acc := e.auditDetails("exposure.terms_accept")
	stops := 0
	for _, d := range acc {
		if strings.HasPrefix(d, stoppedNote) {
			stops++
		}
	}
	if stops != 1 || !strings.HasPrefix(acc[len(acc)-1], stoppedNote) { // review r2 L1: only the stop that happened is written
		t.Fatalf("audit = %q", acc)
	}
}

// review r1 M2: behind carrier-grade NAT the terms step warns that the address is probably shared and refuses the disruptive tick;
// the deep scan can still be accepted. The terms say the address must be the customer's alone.
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
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion, true)
	wantAPI(t, err, 409, "shared_address")
	if v := e.acceptTerms(id, false); !v.FullScan {
		t.Fatalf("deep scan refused: %+v", v)
	}
}

// review r1 L2: a paused IP (the latest full check did not see it) cannot accept the terms.
func TestTerms_PausedIPCannotAccept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.committedIP(ipA).ID
	e.advance(time.Minute)
	e.fullAs(ipB)
	if !e.isPaused(id) {
		t.Fatal("not paused")
	}
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "app", nil }
	_, err := e.svc.AcceptTerms(e.ctx(), termsAdmin, id, TermsVersion, false)
	wantAPI(t, err, 409, "ip_not_current")
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
