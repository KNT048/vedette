package exposure

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// twoStep returns a TwoStep that answers for the listed user ids only.
func twoStep(ids ...string) TwoStep {
	return func(_ context.Context, id string) (string, error) {
		if slices.Contains(ids, id) {
			return "app", nil
		}
		return "", nil
	}
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

// Changing the sentence without a new version would store words under a version nobody agreed to: the text of each version is pinned.
func TestNoticeTextIsPinnedToItsVersion(t *testing.T) {
	t.Parallel()
	pinned := map[string]string{"2026-11-13": "37c87da3084419bf2284a452ea46dd08abb86796060c067709049f6c67cf742b"}
	sum := sha256.Sum256([]byte(noticeTemplate))
	if got := pinned[NoticeVersion]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("the notice text for version %s has hash %x: change NoticeVersion (and contract.ts) when the text changes, then pin the new hash", NoticeVersion, sum)
	}
}

// A check of two-step that fails is not a yes: nothing is recorded and nothing is scanned.
func TestContract_INV17_TwoStepLookupErrorFailsClosed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "", errors.New("db down") }
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	d := e.unconfirmedDomain()
	if _, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, NoticeVersion); err == nil || e.target(d.ID).Commitment != nil || run.calls != 0 {
		t.Fatalf("err=%v commitment=%v calls=%d", err, e.target(d.ID).Commitment, run.calls)
	}
}

// Two administrators press the first Scan now together: one commitment, one scan.
func TestContract_INV17_ConcurrentFirstScansRecordOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = twoStep("u-admin", "u-admin2")
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	d := e.unconfirmedDomain()
	var wg sync.WaitGroup
	for _, who := range []Actor{adminOn, {ID: "u-admin2", Email: "other@acme.example", Admin: true}} {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = e.svc.ScanNow(context.Background(), who, d.ID, NoticeVersion) }()
	}
	wg.Wait()
	if n := strings.Count(strings.Join(e.auditActions(), ","), "exposure.commitment"); n != 1 || run.calls != 1 {
		t.Fatalf("%d commitment rows, %d runner calls", n, run.calls)
	}
}

// The first scan of an IP the box no longer goes out through: the administrator did confirm, so the commitment stays (D-473), but nothing is scanned.
func TestContract_INV17_IPNotCurrentRecordsButDoesNotScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = twoStep("u-admin")
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	ip := e.detect(ipA)[0]
	e.prober.set("1.1.1.1")
	e.advance(10 * time.Minute)
	_, err := e.svc.ScanNow(e.ctx(), adminOn, ip.ID, NoticeVersion)
	wantAPI(t, err, 409, "ip_not_current")
	if e.target(ip.ID).Commitment == nil || run.calls != 0 {
		t.Fatalf("commitment=%v calls=%d", e.target(ip.ID).Commitment, run.calls)
	}
}

// The record keeps the user id and how two-step was met; a commitment written before D-473 (no sentence, no id) still loads.
func TestCommitmentRecordKeepsUserAndMethod(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.TwoStep = func(context.Context, string) (string, error) { return "sso", nil }
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	d := e.unconfirmedDomain()
	if _, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, NoticeVersion); err != nil {
		t.Fatal(err)
	}
	if c := e.target(d.ID).Commitment; c == nil || c.UserID != adminOn.ID || c.Method != "sso" {
		t.Fatalf("commitment = %+v", c)
	}
	old, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "old.example")
	if err != nil {
		t.Fatal(err)
	}
	e.dns.put(old.Value, txtRecord(old.Token))
	if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", old.ID); err != nil || !r.Verified {
		t.Fatal(err)
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET commitment_by = 'old@acme.example', commitment_at = ? WHERE id = ?`, store.FormatTS(t0), old.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if c := e.target(old.ID).Commitment; c == nil || c.Version != nil || c.Sentence != nil || c.UserID != "" {
		t.Fatalf("old commitment = %+v", c)
	}
}
