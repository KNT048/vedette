package exposure

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// twoStep returns a TwoStep that answers for the listed user ids only.
func twoStep(ids ...string) TwoStep {
	return func(_ context.Context, id string) (bool, error) { return slices.Contains(ids, id), nil }
}

func (e *env) unconfirmedDomain() TargetView { return e.addVerifiedDomain() }

var (
	adminOn  = Actor{ID: "u-admin", Email: "admin@acme.example", Admin: true}
	adminOff = Actor{ID: "u-admin2", Email: "other@acme.example", Admin: true}
	operator = Actor{ID: "u-op", Email: "it@acme.example"}
)

// D-473: the first Scan now of an administrator with two-step sign-in records who, when, which target, the sentence and its
// version, and writes the audit row; a second scan, by anyone, does not record again.
func TestContract_INV17_FirstScanByAdminWithTwoStepRecordsCommitment(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = twoStep("u-admin")
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	d := e.unconfirmedDomain()
	if d.CommitmentNotice == nil || d.CommitmentNotice.Version != NoticeVersion || !strings.Contains(d.CommitmentNotice.Text, d.Value) {
		t.Fatalf("offered notice = %+v", d.CommitmentNotice)
	}
	if _, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, NoticeVersion); err != nil {
		t.Fatal(err)
	}
	got := e.target(d.ID)
	c := got.Commitment
	if c == nil || c.By != adminOn.Email || c.At != store.FormatTS(t0) || c.Version == nil || *c.Version != NoticeVersion || c.Sentence == nil || *c.Sentence != d.CommitmentNotice.Text {
		t.Fatalf("commitment = %+v", c)
	}
	if got.CommitmentNotice != nil || run.calls != 1 {
		t.Fatalf("notice still offered %+v, runner calls %d", got.CommitmentNotice, run.calls)
	}
	var detail string
	for _, a := range e.audits() {
		if a.Action == "exposure.commitment" {
			detail = a.Detail
		}
	}
	if a := e.auditActions(); !slices.Equal(a[len(a)-2:], []string{"exposure.commitment", "exposure.scan"}) || !strings.Contains(detail, d.CommitmentNotice.Text) || !strings.Contains(detail, NoticeVersion) {
		t.Fatalf("audit = %v, commitment detail %q", a, detail)
	}
	// later scans (the administrator again, another one, an operator) leave the record as it is
	e.advance(ScanEvery + time.Minute)
	for _, who := range []Actor{adminOn, adminOff, operator} {
		if _, err := e.svc.ScanNow(e.ctx(), who, d.ID, NoticeVersion); err != nil {
			t.Fatalf("%s: %v", who.Email, err)
		}
		e.advance(ScanEvery + time.Minute)
	}
	if after := e.target(d.ID).Commitment; !reflect.DeepEqual(after, c) {
		t.Fatalf("commitment rewritten: %+v -> %+v", c, after)
	}
	if n := strings.Count(strings.Join(e.auditActions(), ","), "exposure.commitment"); n != 1 {
		t.Fatalf("%d commitment rows", n)
	}
}

// D-473: an administrator without two-step sign-in is refused and nothing is recorded or scanned.
func TestContract_INV17_AdminWithoutTwoStepIsRefused(t *testing.T) {
	t.Parallel()
	for name, ts := range map[string]TwoStep{"off": twoStep("u-admin"), "no checker": nil} {
		e := newEnv(t)
		e.svc.cfg.TwoStep = ts
		run := &fakeRunner{content: sampleContent()}
		e.svc.SetRunner(run)
		d := e.unconfirmedDomain()
		_, err := e.svc.ScanNow(e.ctx(), adminOff, d.ID, NoticeVersion)
		wantAPI(t, err, 403, "twofa_required")
		if e.target(d.ID).Commitment != nil || run.calls != 0 {
			t.Fatalf("%s: recorded or scanned", name)
		}
		if a := e.auditActions(); a[len(a)-1] != "exposure.scan" || slices.Contains(a, "exposure.commitment") {
			t.Fatalf("%s: audit = %v (the refusal is a not-done scan row)", name, a)
		}
	}
}

// D-473: an operator cannot scan an unconfirmed target; a confirmed one is open to them.
func TestContract_INV17_OperatorNeedsAnAdminsFirstScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = twoStep("u-admin")
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	d := e.unconfirmedDomain()
	_, err := e.svc.ScanNow(e.ctx(), operator, d.ID, NoticeVersion) // a version from an operator records nothing
	wantAPI(t, err, 400, "commitment_required")
	if !strings.Contains(err.Error(), "administrator must run the first scan") || e.target(d.ID).Commitment != nil {
		t.Fatalf("operator: %v", err)
	}
	if _, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, NoticeVersion); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery + time.Minute)
	if _, err := e.svc.ScanNow(e.ctx(), operator, d.ID, ""); err != nil {
		t.Fatalf("operator on a confirmed target: %v", err)
	}
}

// D-473: the request must carry the version of the sentence the page showed; an old or missing one records nothing.
func TestContract_INV17_StaleOrMissingNoticeVersionIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = twoStep("u-admin")
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	d := e.unconfirmedDomain()
	_, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, "2020-01-01")
	wantAPI(t, err, 409, "notice_changed")
	_, err = e.svc.ScanNow(e.ctx(), adminOn, d.ID, "")
	wantAPI(t, err, 400, "commitment_required")
	if e.target(d.ID).Commitment != nil {
		t.Fatal("recorded without the current version")
	}
}

// D-473: the sentence the mock shows is the backend's: contract.ts holds the same version and text.
func TestNoticeMatchesTheContractOfTheGUI(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../web/src/features/exposure/contract.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	ver := regexp.MustCompile(`NOTICE_VERSION = '([^']+)'`).FindStringSubmatch(src)
	tpl := regexp.MustCompile(`NOTICE_TEMPLATE = '([^']+)'`).FindStringSubmatch(src)
	if ver == nil || tpl == nil || ver[1] != NoticeVersion || tpl[1] != noticeTemplate {
		t.Fatalf("contract.ts notice %q %q differs from the backend (%s)", ver, tpl, NoticeVersion)
	}
}
