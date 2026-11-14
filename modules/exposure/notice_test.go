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

// oldCommitted is a verified domain whose commitment was recorded under an older sentence (version "2026-11-13", or none).
func (e *env) oldCommitted(version *string) TargetView {
	e.t.Helper()
	d := e.addVerifiedDomain()
	err := e.svc.write(e.ctx(), func(tx *sql.Tx, _ func(string, any)) error {
		if err := setCommitment(e.ctx(), tx, d.ID, "first@acme.example", t0, Notice{Version: "2026-11-13", Text: "old sentence"}, "u-first", "app"); err != nil {
			return err
		}
		if version == nil { // recorded before D-473: no version, no sentence
			_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET commitment_version = NULL, commitment_sentence = NULL, commitment_user_id = NULL, commitment_method = NULL WHERE id = ?`, d.ID)
			return err
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return e.target(d.ID)
}

// D-559: a commitment of an older sentence (or none recorded) is not confirmed for the current one: the gate blocks, the new sentence is
// offered, an operator and a schedule are refused, and the administrator's first Scan now replaces it, with an audit row naming the old version.
func TestContract_INV17_OlderCommitmentIsAskedAgainOnce(t *testing.T) {
	t.Parallel()
	for name, ver := range map[string]*string{"old version": new("2026-11-13"), "no version": nil} {
		e := newEnv(t)
		e.svc.cfg.TwoStep = twoStep("u-admin")
		run := &fakeRunner{content: sampleContent()}
		e.svc.SetRunner(run)
		d := e.oldCommitted(ver)
		if d.Commitment == nil || d.Scannable || str((*string)(d.BlockedReason)) != "no_commitment" || d.CommitmentNotice == nil || d.CommitmentNotice.Version != NoticeVersion {
			t.Fatalf("%s: commitment %+v scannable %v reason %v notice %+v", name, d.Commitment, d.Scannable, d.BlockedReason, d.CommitmentNotice)
		}
		for _, call := range []func() error{
			func() error { _, err := e.svc.Scan(e.ctx(), "schedule@acme.example", d.ID); return err },
			func() error { _, err := e.svc.ScanNow(e.ctx(), operator, d.ID, NoticeVersion); return err },
		} {
			err := call()
			wantAPI(t, err, 400, "commitment_required")
			if !strings.Contains(err.Error(), "confirmation text changed") {
				t.Fatalf("%s: %v", name, err)
			}
		}
		_, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, "2026-11-13") // the page of the old sentence
		wantAPI(t, err, 409, "notice_changed")
		if run.calls != 0 || e.target(d.ID).Commitment.By != "first@acme.example" {
			t.Fatalf("%s: scanned or rewritten before the administrator confirmed", name)
		}
		if _, err := e.svc.ScanNow(e.ctx(), adminOn, d.ID, NoticeVersion); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := e.target(d.ID)
		if c := got.Commitment; c.By != adminOn.Email || c.Version == nil || *c.Version != NoticeVersion || got.CommitmentNotice != nil || !got.Scannable || run.calls != 1 {
			t.Fatalf("%s: after re-confirm %+v notice %+v calls %d", name, c, got.CommitmentNotice, run.calls)
		}
		var detail string
		for _, a := range e.audits() {
			if a.Action == "exposure.commitment" {
				detail = a.Detail
			}
		}
		old := "2026-11-13"
		if ver == nil {
			old = "recorded before versions"
		}
		if !strings.Contains(detail, "re-confirmed under the new sentence (replaces notice "+old+")") || !strings.Contains(detail, NoticeVersion) {
			t.Fatalf("%s: audit detail %q", name, detail)
		}
		// asked once: the same version is never rewritten, and a schedule scans again
		before := got.Commitment
		e.advance(ScanEvery + time.Minute)
		if _, err := e.svc.ScanNow(e.ctx(), adminOff, d.ID, NoticeVersion); err != nil {
			t.Fatal(err)
		}
		e.advance(ScanEvery + time.Minute)
		if _, err := e.svc.Scan(e.ctx(), "schedule@acme.example", d.ID); err != nil {
			t.Fatalf("%s: scheduled scan after the re-confirmation: %v", name, err)
		}
		if after := e.target(d.ID).Commitment; !reflect.DeepEqual(after, before) {
			t.Fatalf("%s: rewritten %+v -> %+v", name, before, after)
		}
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
	pinned := map[string]string{
		"2026-11-13": "37c87da3084419bf2284a452ea46dd08abb86796060c067709049f6c67cf742b",
		"2026-11-14": "3dd8a9bbd19da97de41909fd864ef1536a1a98a1c289ac5eed7e80d5124a330f",
	}
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
