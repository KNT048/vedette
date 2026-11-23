package exposure

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// addIssue stores an open issue of target id, as a scan would have written it.
func (e *env) addIssue(target, key, severity string) string {
	e.t.Helper()
	id := store.NewID("xi")
	at := store.FormatTS(e.clock.Now())
	e.exec(`INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id)
		VALUES (?, ?, 'nuclei', ?, ?, ?, 'open', ?, ?, 'run-1')`, id, target, key, "Issue "+key, severity, at, at)
	return id
}

// exec runs one statement in a write.
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), query, args...); return err }); err != nil {
		e.t.Fatal(err)
	}
}

// issueRow is the stored handling of an issue.
func (e *env) issueRow(id string) (state, resolution, by, note, until string) {
	e.t.Helper()
	err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT state, coalesce(resolution, ''), coalesce(resolved_by, ''), coalesce(note, ''), coalesce(accepted_until, '')
		FROM exp_issue WHERE id = ?`, id).Scan(&state, &resolution, &by, &note, &until)
	if err != nil {
		e.t.Fatal(err)
	}
	return
}

// Each status of the shared vocabulary: what it needs (a note for the three that leave the flaw, a last day for accepted), what it
// stores, the audit row of each issue, issues that are not open skipped, and reopening.
func TestIssues_EachResolutionOfTheSharedVocabulary(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	d := e.addVerifiedDomain()
	day := func(n int) string { return e.clock.Now().UTC().AddDate(0, 0, n).Format(time.DateOnly) }
	handle := func(ids []string, res, note, until string) (int, map[string]any) {
		body := fmt.Sprintf(`{"ids":["%s"],"resolution":%q,"note":%q`, strings.Join(ids, `","`), res, note)
		if until != "" {
			body += fmt.Sprintf(`,"accepted_until":%q`, until)
		}
		return e.call("POST", "/exposure/issues/handle", "operator", body+"}")
	}
	cases := []struct {
		res, note, until string
		code             int
		err              string
	}{
		{"patched", "", "", 200, ""},
		{"mitigated", "", "", 200, ""},
		{"mitigated", "a rule at the proxy", "", 200, ""},
		{"accepted", "needed by a partner", day(30), 200, ""},
		{"accepted", "needed by a partner", day(365), 200, ""},
		{"accepted", "", day(30), 400, "note_required"},
		{"accepted", "ok", day(30), 400, "note_required"},
		{"accepted", "needed by a partner", "", 400, "bad_until"},
		{"accepted", "needed by a partner", day(0), 400, "bad_until"},
		{"accepted", "needed by a partner", day(-1), 400, "bad_until"},
		{"accepted", "needed by a partner", day(366), 400, "bad_until"},
		{"patched", "", day(30), 400, "bad_until"},
		{"not_relevant", "not this product", "", 200, ""},
		{"not_relevant", "", "", 400, "note_required"},
		{"false_positive", "the page is a honeypot", "", 200, ""},
		{"false_positive", "  ", "", 400, "note_required"},
		{"fixed", "", "", 400, "invalid"}, // not in the vocabulary: refused by the contract before the handler
	}
	for i, c := range cases {
		id := e.addIssue(d.ID, fmt.Sprintf("k%d", i), "high")
		code, b := handle([]string{id}, c.res, c.note, c.until)
		if code != c.code || (c.err != "" && errCode(b) != c.err) {
			t.Errorf("%s %q until %q: %d %v, want %d %s", c.res, c.note, c.until, code, b, c.code, c.err)
			continue
		}
		state, res, by, note, until := e.issueRow(id)
		if c.code != 200 {
			if state != IssueOpen || res != "" {
				t.Errorf("%s refused, yet stored %s %s", c.res, state, res)
			}
			continue
		}
		if state != IssueHandled || res != c.res || by != "it@acme.example" || note != strings.TrimSpace(c.note) || until != c.until || b["handled"] != float64(1) {
			t.Errorf("%s stored %s %s by %s note %q until %q (%v)", c.res, state, res, by, note, until, b)
		}
	}
	// issues not open are skipped, repeats count once; one audit row per issue handled
	a, gone := e.addIssue(d.ID, "a", "low"), e.addIssue(d.ID, "gone", "low")
	e.exec(`UPDATE exp_issue SET state = 'gone' WHERE id = ?`, gone)
	before := len(e.audits())
	if code, b := handle([]string{a, a, gone, "xi-none"}, "patched", "", ""); code != 200 || b["handled"] != float64(1) || b["skipped"] != float64(2) {
		t.Fatalf("handled and skipped: %d %v", code, b)
	}
	if rows := e.audits()[before:]; len(rows) != 1 || rows[0].Action != "exposure.issue_handle" || rows[0].Detail != "patched" || !strings.Contains(rows[0].Target, "acme.example") {
		t.Fatalf("audit of handling: %+v", rows)
	}
	if code, b := e.call("POST", "/exposure/issues/handle", "operator", `{"ids":[],"resolution":"patched","note":""}`); code != 400 {
		t.Fatalf("no ids: %d %v", code, b)
	}
	// reopen: handled ones only, back to open with nothing of the decision left
	if code, b := e.call("POST", "/exposure/issues/reopen", "operator", `{"ids":["`+a+`","`+gone+`"]}`); code != 200 || b["reopened"] != float64(1) || b["skipped"] != float64(1) {
		t.Fatalf("reopen: %d %v", code, b)
	}
	if state, res, by, note, until := e.issueRow(a); state != IssueOpen || res != "" || by != "" || note != "" || until != "" {
		t.Fatalf("reopened: %s %s %s %q %q", state, res, by, note, until)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.issue_reopen' AND detail = 'was patched'`); n != 1 {
		t.Fatalf("audit of reopening: %d", n)
	}
	if code, _ := e.call("POST", "/exposure/issues/reopen", "viewer", `{"ids":["`+a+`"]}`); code != 403 {
		t.Fatalf("a viewer reopens: %d", code)
	}
}

// An accepted risk opens again by itself once its last day is over everywhere, and says who accepted it until when.
func TestIssues_AnAcceptedRiskOpensAfterItsLastDay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain()
	id := e.addIssue(d.ID, "k", "critical")
	until := e.clock.Now().UTC().AddDate(0, 0, 2).Format(time.DateOnly)
	if _, err := e.svc.HandleIssues(e.ctx(), "ana@acme.example", []string{id}, ResolvedAccepted, "a partner needs it", until); err != nil {
		t.Fatal(err)
	}
	e.advance(2 * 24 * time.Hour) // the last day itself: still accepted
	if err := e.svc.RunAcceptExpiry(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if state, _, _, _, _ := e.issueRow(id); state != IssueHandled {
		t.Fatalf("on its last day: %s", state)
	}
	e.advance(2 * 24 * time.Hour)
	if err := e.svc.RunAcceptExpiry(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if state, res, _, _, u := e.issueRow(id); state != IssueOpen || res != "" || u != "" {
		t.Fatalf("after its last day: %s %s %s", state, res, u)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.issue_reopen' AND user = 'system' AND detail LIKE '%accepted by ana@acme.example until ` + until + `%'`); n != 1 {
		t.Fatalf("the audit of the expiry: %d", n)
	}
}
