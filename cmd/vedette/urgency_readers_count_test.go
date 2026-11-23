package main

import (
	"database/sql"
	"regexp"
	"testing"

	"github.com/knt048/vedette/content/adminpages"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	mcpserver "github.com/knt048/vedette/modules/mcp-server"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/reports"
)

// Readers of a finding must follow its stored urgency layer: a finding of a CVE nobody is known to exploit (layer 5), with a public
// exploit (3) or critical on an edge device (4) is never shown, counted, worded or alerted as exploited. This counts, per reader, the
// findings above layer 2 that the reader still treats as exploited; the total is 0.

// exploitedWords are the words that say attackers use a flaw (a public exploit is "exploit code", not "exploited").
var exploitedWords = regexp.MustCompile(`(?i)exploited|CISA lists|VulnCheck KEV lists|under attack`)

func withLayer(n notify.Notice, info notify.FindingInfo) notify.Notice {
	n.Layer = info.Layer
	return n
}
func reportsExploited(f reports.Finding) bool { return f.Exploited() }
func mcpExploited(f mcpserver.Finding) bool {
	return f.Urgency == findings.CodeExploited || f.Urgency == findings.CodeUnderAttack
}
func aiExploited(f ai.FindingRow) bool {
	return f.Urgency == findings.CodeExploited || f.Urgency == findings.CodeUnderAttack
}

func TestReadersNeverCallAFindingAboveLayerTwoExploited(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	layers := map[string]int{"CVE-2026-6001": findings.UrgencyUpdate, "CVE-2026-6002": findings.UrgencyPublicExploit,
		"CVE-2026-6003": findings.UrgencyCriticalEdge, "CVE-2026-6004": findings.UrgencyExploited}
	for cve := range layers {
		s.kev(cve, "Fortinet", "FortiOS")
	}
	id := s.addFortiGate()
	recs, err := s.d.Findings.List(ctx, id)
	if err != nil || len(recs) != len(layers) {
		t.Fatalf("findings: %d %v", len(recs), err)
	}
	// the urgency pass is not the subject: store the layers by hand, and make each finding proved, so To fix lists every one
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for cve, layer := range layers {
			if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET urgency = ?, verified = 'scan' WHERE asset_id = ? AND cve = ?`, layer, id, cve); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recs, err = s.d.Findings.List(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var above []findings.Record // the findings of layer 3 to 5
	var cves []string
	exploitedCount := 0
	for _, r := range recs {
		cves = append(cves, r.CVE)
		if r.Row.Urgency > findings.UrgencyExploited {
			above = append(above, r)
		} else {
			exploitedCount++
		}
	}
	if len(above) != 3 || exploitedCount != 1 {
		t.Fatalf("stored layers wrong: %d above layer 2, %d exploited", len(above), exploitedCount)
	}
	counts := map[string]int{}

	// notify: the finding's own notice (title and text), and the digest of several findings
	var notices []notify.Notice
	for _, r := range above {
		info, ok, err := notifyFindings{s.d}.Finding(ctx, r.ID)
		if err != nil || !ok {
			t.Fatalf("notify finding: %v %v", ok, err)
		}
		title, what := info.Product+": "+info.Status, info.Meaning+" "+info.Reasons
		if exploitedWords.MatchString(title + " " + what) {
			counts["notify notice"]++
		}
		notices = append(notices, withLayer(notify.Notice{ID: "nt-" + r.ID, Kind: notify.KindVuln, Severity: notify.High, Product: info.Product, FindingIDs: []string{r.ID},
			CVEs: []string{r.CVE}, Devices: []string{"FortiGate"}, Title: title, What: what, Action: info.Action, Link: "https://vedette.example/findings/" + r.ID}, info))
	}
	for _, b := range notify.GroupHeld(notices, notify.Low) {
		m, err := b.Message()
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Notices) > 1 && exploitedWords.MatchString(m.Title+" "+m.What) {
			counts["notify digest"] += len(b.Notices)
		}
	}

	// ids: the status an alert's finding link shows
	linked, err := idsFindings{s.d}.Linked(ctx, map[string][]string{id: cves})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range linked[id] {
		if layers[l.CVE] > findings.UrgencyExploited && (l.Status == findings.CodeExploited || l.Status == findings.CodeUnderAttack) {
			counts["ids alert link"]++
		}
	}

	// response: the kev flag a trigger reads
	dir := responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}
	for _, r := range above {
		fi, ok, err := dir.Finding(ctx, r.ID)
		if err != nil || !ok {
			t.Fatalf("response finding: %v %v", ok, err)
		}
		if fi.KEV {
			counts["response kev flag"]++
		}
	}

	// exposure: the open exploited findings of an appliance the Internet shows
	var qs []exposure.ApplianceQuery
	for _, f := range adminpages.Families() {
		qs = append(qs, exposure.ApplianceQuery{Family: f.ID, KevKeys: f.KevKeys, Device: f.Device, Kinds: f.Kinds})
	}
	got, err := exposureGateway{inv: s.d.Inventory, fnd: s.d.Findings}.ApplianceDevices(ctx, qs)
	if err != nil || len(got["fortigate"].Devices) != 1 {
		t.Fatalf("appliance devices: %+v %v", got["fortigate"], err)
	}
	counts["exposure open exploited"] = max(0, got["fortigate"].Devices[0].OpenExploited-exploitedCount)

	// To fix: the CVEs its risk marker counts as exploited
	tf, err := s.d.Findings.ToFix(ctx, false, "")
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, d := range tf.Devices {
		marked += findings.RiskOf(d).Exploited
	}
	counts["to fix risk marker"] = max(0, marked-exploitedCount)

	// reports, MCP, AI context: what each carries of the finding
	rf, err := reportsFindings{s.d.Findings, s.d}.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rf {
		if layers[f.CVE] > findings.UrgencyExploited && reportsExploited(f) {
			counts["reports"]++
		}
	}
	for _, r := range above {
		c, err := caseSource{findings: s.d.Findings}.One(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if mcpExploited(mcpFinding(c)) {
			counts["mcp"]++
		}
		if aiExploited(aiFindingRow(c, nil)) {
			counts["ai context"]++
		}
	}

	total := 0
	for _, k := range []string{"notify notice", "notify digest", "ids alert link", "response kev flag", "exposure open exploited", "to fix risk marker", "reports", "mcp", "ai context"} {
		t.Logf("%-24s %d", k, counts[k])
		total += counts[k]
	}
	t.Logf("%-24s %d", "total", total)
	if total != 0 {
		t.Fatalf("%d findings above layer 2 are shown, counted, worded or alerted as exploited", total)
	}
}
