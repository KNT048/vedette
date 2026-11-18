package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A report sent before the not relevant counts is read back into WeeklyReport and written out again (HistoryEntry): the counts
// must stay absent, not come back as 0, or the page stops subtracting its not relevant rows (INV-2, INV-16). A report sent with
// them keeps them.
func TestHistoryEntryKeepsTheNotRelevantCountsAsSent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	in := sampleInput()
	in.findings = append(in.findings,
		Finding{ID: "n1", AssetID: "a1", CVE: "CVE-2026-0101", Status: "not_relevant", Severity: "high", FirstSeen: day0(2)},
		Finding{ID: "n2", AssetID: "a3", CVE: "CVE-2026-0102", Status: "not_relevant", Severity: "low", FirstSeen: day0(3)})
	r := buildWeekly(in)
	if r.Counts.NotRelevantNew != 2 {
		t.Fatalf("counts = %+v", r.Counts)
	}
	current, _ := json.Marshal(r)
	var old map[string]any // the same report as an older release stored it
	mustNoErr(t, json.Unmarshal(current, &old))
	delete(old, "approved_only")
	counts := old["counts"].(map[string]any)
	for _, k := range []string{"not_relevant", "not_relevant_new", "not_relevant_resolved"} {
		delete(counts, k)
	}
	legacy, _ := json.Marshal(old)
	for id, raw := range map[string][]byte{"h-old": legacy, "h-new": current} {
		mustNoErr(t, e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(context.Background(), `INSERT INTO rep_history (id, ts, trigger, recipients, status, error, report) VALUES (?, ?, 'manual', '[]', 'sent', NULL, ?)`,
				id, ts(t0), string(raw))
			return err
		}))
	}

	h, err := e.svc.HistoryEntry(e.ctx(), "h-old")
	mustNoErr(t, err)
	out, _ := json.Marshal(h)
	if strings.Contains(string(out), `"not_relevant":`) || strings.Contains(string(out), `"not_relevant_new":`) || strings.Contains(string(out), `"approved_only"`) || h.Report.Counts.NewFindings != r.Counts.NewFindings {
		t.Fatalf("old report read back = %s", out)
	}
	h, err = e.svc.HistoryEntry(e.ctx(), "h-new")
	mustNoErr(t, err)
	if c := h.Report.Counts; c.NotRelevant != 2 || c.NotRelevantNew != 2 || h.Report.ApprovedOnly == nil {
		t.Fatalf("new report read back = %+v", c)
	}
}

// Each list carries the first MaxRows rows of every view a reader can pick, so filtering never leaves a view short: 120 critical
// findings on a device not approved yet do not push the 10 of the approved devices out, nor 150 not relevant ones the relevant.
func TestWeeklyListsKeepEveryViewFull(t *testing.T) {
	t.Parallel()
	in := sampleInput()
	in.findings = nil
	for i := range 120 {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("u%03d", i), AssetID: "a2", CVE: fmt.Sprintf("CVE-2026-1%04d", i), Status: "confirmed", Severity: "critical", FirstSeen: day0(20)})
	}
	for i := range 10 {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("p%03d", i), AssetID: "a3", CVE: fmt.Sprintf("CVE-2026-2%04d", i), Status: "suspected", Severity: "high", FirstSeen: day0(20)})
	}
	for i := range 150 {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("n%03d", i), AssetID: "a1", CVE: fmt.Sprintf("CVE-2026-3%04d", i), Status: "not_relevant", Severity: "critical", FirstSeen: day0(2), ResolvedAt: day0(1)})
	}
	for i := range 5 {
		in.findings = append(in.findings, Finding{ID: fmt.Sprintf("r%03d", i), AssetID: "a1", CVE: fmt.Sprintf("CVE-2026-4%04d", i), Status: "patched", Severity: "low", FirstSeen: day0(2), ResolvedAt: day0(1)})
	}
	r := buildWeekly(in)
	count := func(rows []FindingRow, keep func(FindingRow) bool) int {
		n := 0
		for _, x := range rows {
			if keep(x) {
				n++
			}
		}
		return n
	}
	approved := func(x FindingRow) bool { return x.DeviceApproved }
	relevant := func(x FindingRow) bool { return x.Status != "not_relevant" }
	if n := count(r.Open, approved); n != 10 || len(r.Open) != MaxRows+10 || r.Open[0].Severity != "critical" {
		t.Fatalf("open: %d approved of %d", n, len(r.Open))
	}
	if r.ApprovedOnly.Counts.OpenSuspected != 10 {
		t.Fatalf("approved-only counts = %+v", r.ApprovedOnly.Counts)
	}
	for _, rows := range [][]FindingRow{r.NewFindings, r.Resolved} {
		if n := count(rows, relevant); n != 5 || len(rows) > 4*MaxRows {
			t.Fatalf("%d relevant of %d", n, len(rows))
		}
	}
}

// The approved-only view counts the newly exploited products in use without those only a device not approved yet has: pc-old
// (a2) is the one device with Microsoft Windows. The count of newly exploited vulnerabilities is the list's and stays.
func TestApprovedOnlyKevMatched(t *testing.T) {
	t.Parallel()
	r := buildWeekly(sampleInput())
	if r.Counts.KevMatched != 1 || r.ApprovedOnly.Counts.KevMatched != 0 || r.ApprovedOnly.Counts.KevNew != r.Counts.KevNew {
		t.Fatalf("full %+v, approved only %+v", r.Counts, r.ApprovedOnly.Counts)
	}
	in := sampleInput()
	in.devices[0].KevKeys = []string{"microsoft|windows"} // an approved device has it too: still in use
	if a := buildWeekly(in).ApprovedOnly.Counts; a.KevMatched != 1 {
		t.Fatalf("approved only %+v", a)
	}
}
