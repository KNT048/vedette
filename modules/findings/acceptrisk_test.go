package findings

import (
	"database/sql"
	"testing"
	"time"
)

// Accepting the risk of a software line answers its open questions "affected" (a question about several CVEs records each of them),
// accepts those findings and the confirmed open ones of the line until the day, in one transaction with one summary audit row, and
// touches nothing of other lines or devices. A bad or missing day or reason is a 400; the findings open again after the day.
func TestAcceptRiskQuestions(t *testing.T) {
	e := modelEnv(t)
	askTwenty(t, e)
	ctx := t.Context()
	// a question about two CVEs on the line, and a confirmed open finding on it
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at)
			VALUES ('q-old', 'a-fw', 's-j8', NULL, 'older_line', '{"cve_list":["CVE-2026-8001","CVE-2026-8002"]}', 2, '2026-01-01T00:00:00.000Z')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET verified = 'device', basis = 'device_version' WHERE id = 'f-f2'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	day := func(d int) string { return dayOf(t0).AddDate(0, 0, d).Format(time.DateOnly) }
	post := func(user, body string) (int, map[string]any) {
		t.Helper()
		return e.call("POST", "/findings/questions/accept-risk", user, body)
	}
	for name, c := range map[string]struct {
		user, body string
		code       int
	}{
		"no day":        {"operator", `{"device":"a-fw","software":"s-j8","note":"no licence"}`, 400},
		"yesterday":     {"operator", `{"device":"a-fw","software":"s-j8","note":"no licence","until":"` + day(-1) + `"}`, 400},
		"too far":       {"operator", `{"device":"a-fw","software":"s-j8","note":"no licence","until":"` + day(400) + `"}`, 400},
		"not a day":     {"operator", `{"device":"a-fw","software":"s-j8","note":"no licence","until":"soon"}`, 400},
		"no reason":     {"operator", `{"device":"a-fw","software":"s-j8","until":"` + day(90) + `"}`, 400},
		"short reason":  {"operator", `{"device":"a-fw","software":"s-j8","note":"x ","until":"` + day(90) + `"}`, 400},
		"viewer":        {"viewer", `{"device":"a-fw","software":"s-j8","note":"no licence","until":"` + day(90) + `"}`, 403},
		"unknown scope": {"operator", `{"device":"a-nope","note":"no licence","until":"` + day(90) + `"}`, 404},
	} {
		if code, b := post(c.user, c.body); code != c.code {
			t.Errorf("%s: %d %v, want %d", name, code, b, c.code)
		}
	}
	if n := len(e.auditActions()); n != 0 {
		t.Fatalf("a refused request wrote %d audit rows", n)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := e.db.Reader().QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	openQ := func(sw string) int {
		return count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'a-fw' AND answer IS NULL AND (?1 = '' OR software_id = ?1)`, sw)
	}
	otherBefore := count(`SELECT count(*) FROM fnd_finding WHERE state = 'open' AND NOT (asset_id = 'a-fw' AND software_id = 's-j8')`)

	code, b := post("operator", `{"device":"a-fw","software":"s-j8","note":"licence ended, rarely used","until":"`+day(90)+`"}`)
	// 6 questions of the line + the 2-CVE one = 7 questions; 6 + 2 new findings and the confirmed f-f2 = 9
	if code != 200 || b["questions"] != 7.0 || b["findings"] != 9.0 {
		t.Fatalf("accept the line: %d %v", code, b)
	}
	if openQ("s-j8") != 0 || openQ("") != 14 {
		t.Errorf("open questions: %d on the line, %d on the device; want 0 and 14", openQ("s-j8"), openQ(""))
	}
	if n := count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-fw' AND software_id = 's-j8' AND state = 'handled' AND resolution = 'accepted'
		AND accepted_until = ? AND note = 'licence ended, rarely used'`, day(90)); n != 9 {
		t.Errorf("%d findings of the line accepted until %s, want 9", n, day(90))
	}
	if n := count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-fw' AND software_id = 's-j8' AND state = 'open'`); n != 0 {
		t.Errorf("%d findings of the line still open", n)
	}
	if n := count(`SELECT count(*) FROM fnd_finding WHERE state = 'open' AND NOT (asset_id = 'a-fw' AND software_id = 's-j8')`); n != otherBefore {
		t.Errorf("open findings elsewhere: %d, was %d", n, otherBefore)
	}
	nAudit := 0
	for _, a := range e.auditActions() {
		if a == "findings.risk_accepted_in_bulk" {
			nAudit++
		}
	}
	if nAudit != 1 {
		t.Errorf("%d summary audit rows, want 1", nAudit)
	}
	if code, b := post("operator", `{"device":"a-fw","software":"s-j8","note":"again","until":"`+day(90)+`"}`); code != 404 {
		t.Errorf("nothing left to accept: %d %v", code, b)
	}

	// the acceptance ends by itself: the findings open again after the day
	e.advance(time.Duration(92) * 24 * time.Hour)
	if n, err := e.svc.expireAcceptances(ctx); err != nil || n != 10 { // the 9 and the nas01 acceptance seeded until January
		t.Fatalf("expiry: %d, %v; want 10 opened again", n, err)
	}
	if n := count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-fw' AND software_id = 's-j8' AND state = 'open'`); n != 9 {
		t.Errorf("%d findings of the line open after the day, want 9", n)
	}

	// one CVE row of another line: only that question, with no other finding of the line
	if code, b := post("operator", `{"device":"a-fw","software":"s-j21","question":"q-s-j21-0","note":"not used","until":"`+day(120)+`"}`); code != 200 || b["questions"] != 1.0 || b["findings"] != 1.0 {
		t.Errorf("accept one question: %d %v", code, b)
	}
	if openQ("s-j21") != 3 {
		t.Errorf("%d questions open on the line after accepting one, want 3", openQ("s-j21"))
	}
	if n := count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-fw' AND software_id = 's-j21' AND state = 'handled' AND resolution = 'accepted'`); n != 1 {
		t.Errorf("%d findings of the line accepted after one question, want 1", n)
	}

	// the whole device: the other two lines' questions
	if code, b := post("operator", `{"device":"a-fw","note":"lab box","until":"`+day(120)+`"}`); code != 200 || b["questions"] != 13.0 {
		t.Errorf("accept the device: %d %v", code, b)
	}
	if openQ("") != 0 {
		t.Errorf("%d questions open on the device", openQ(""))
	}
}
