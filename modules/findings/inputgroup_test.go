package findings

import (
	"database/sql"
	"fmt"
	"testing"
)

// flatInput lists the items the queue holds as the earlier flat list had them: a device's card replaced by its entries, a software
// line by its questions.
func flatInput(items []InputItemJS) []InputItemJS {
	var out []InputItemJS
	for _, it := range items {
		if it.Kind != KindDeviceNeeds {
			out = append(out, it)
			continue
		}
		for _, e := range it.Entries {
			if e.Kind == KindSoftwareGroup {
				out = append(out, e.Questions...)
			} else {
				out = append(out, e)
			}
		}
	}
	return out
}

// askTwenty adds 20 open questions, one per CVE and software line, on three lines of one device (10, 6 and 4).
func askTwenty(t *testing.T, e *httpEnv) {
	t.Helper()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for i, l := range []struct {
			line string
			n    int
		}{{"s-ssh-fw", 10}, {"s-j8", 6}, {"s-j21", 4}} {
			for k := range l.n {
				if _, err := tx.ExecContext(t.Context(), `INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at)
					VALUES (?, 'a-fw', ?, ?, 'no_range_data', '{}', 1, '2026-01-01T00:00:00.000Z')`,
					fmt.Sprintf("q-%s-%d", l.line, k), l.line, fmt.Sprintf("CVE-2026-7%d%03d", i, k)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A device with 3 software lines and 20 questions is one card with 3 software entries, each counting its CVEs once, next to the
// device's urgent findings; the queue's total counts cards.
func TestInput_OneEntryPerSoftwareLine(t *testing.T) {
	e := modelEnv(t)
	askTwenty(t, e)
	in, err := e.svc.Input(t.Context(), "a-fw", "", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if in.Total != 1 || len(in.Items) != 1 || in.Items[0].Kind != KindDeviceNeeds {
		t.Fatalf("queue of a-fw: total %d, %+v; want one device card", in.Total, in.Items)
	}
	got := map[string]int{}
	asked := 0
	for _, en := range in.Items[0].Entries {
		if en.Kind == KindSoftwareGroup {
			got[en.Software.ID] = en.CVEs
			asked += len(en.Questions)
		}
	}
	if want := map[string]int{"s-ssh-fw": 10, "s-j8": 6, "s-j21": 4}; fmt.Sprint(got) != fmt.Sprint(want) || asked != 20 {
		t.Errorf("software entries %v with %d questions, want %v with 20", got, asked, want)
	}
	// a search by a CVE of one line narrows the card to that line's entry and counts what is left
	f, err := e.svc.Input(t.Context(), "", "CVE-2026-71001", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Items) != 1 || len(f.Items[0].Entries) != 1 || f.Items[0].Entries[0].CVEs != 1 {
		t.Errorf("search by one CVE: %+v", f.Items)
	}
}

// Ignore answers Not affected to every open question of a software line, or of the device, in one transaction with one audit row;
// "Vedette cannot check this device" is not ignorable and an empty ignore is refused.
func TestIgnoreQuestions(t *testing.T) {
	e := modelEnv(t)
	askTwenty(t, e)
	before := len(e.auditActions())
	code, b := e.call("POST", "/findings/questions/ignore", "operator", `{"device":"a-fw","software":"s-j8","note":"not installed here"}`)
	if code != 200 || b["answered"] != float64(6) {
		t.Fatalf("ignore a line: %d %v", code, b)
	}
	open := func(sw string) int {
		var n int
		q := `SELECT count(*) FROM fnd_question WHERE asset_id = 'a-fw' AND answer IS NULL`
		if sw != "" {
			q += ` AND software_id = '` + sw + `'`
		}
		if err := e.db.Reader().QueryRowContext(t.Context(), q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if open("s-j8") != 0 || open("") != 14 {
		t.Errorf("after ignoring one line: %d open on it, %d on the device; want 0 and 14", open("s-j8"), open(""))
	}
	acts := e.auditActions()
	if len(acts) != before+1 || acts[len(acts)-1] != "findings.questions_ignored" {
		t.Errorf("audit %v: want one new findings.questions_ignored", acts[before:])
	}
	if code, _ := e.call("POST", "/findings/questions/ignore", "viewer", `{"device":"a-fw","note":"x"}`); code != 403 {
		t.Errorf("a viewer ignored: %d", code)
	}
	if code, b := e.call("POST", "/findings/questions/ignore", "operator", `{"device":"a-fw","note":"a lab box"}`); code != 200 || b["answered"] != float64(14) {
		t.Errorf("ignore the device: %d %v", code, b)
	}
	if code, b := e.call("POST", "/findings/questions/ignore", "operator", `{"device":"a-fw","note":"again"}`); code != 404 || errCode(b) != "not_found" {
		t.Errorf("nothing left to ignore: %d %v", code, b)
	}
	// the answered questions are listed and each can be asked again
	if in, _ := e.svc.Answered(t.Context(), "a-fw", Page{Limit: PageMax}); in.Total != 20 {
		t.Errorf("answered list %d, want 20", in.Total)
	}
}
