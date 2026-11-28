package notify_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// alertEnv is a box with one Telegram channel on the default minimum (medium), the directory and the
// bus wired: the set-up a customer has after the first-run wizard.
func alertEnv(t *testing.T, dir *liveFindings) (*env, func(name string, data any)) {
	t.Helper()
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.telegram(notify.Medium)
	e.svc.Subscribe(e.bus)
	return e, func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, data)); err != nil {
			t.Fatal(err)
		}
	}
}

// finding is a directory entry of a finding on one device with a CVSS band and its reasons line.
func finding(product, cve, device string, sev notify.Severity) notify.FindingInfo {
	return notify.FindingInfo{CVE: cve, Product: product, Severity: sev, Action: "Apply updates per vendor instructions.", Devices: []string{device},
		Reasons: "Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025"}
}

// toldOK is, per notice, how many delivered messages named it.
func toldOK(e *env) map[string]int {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT n.id, (SELECT count(*) FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id
		WHERE sn.notice_id = n.id AND d.ok = 1) FROM notify_notice n`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			e.t.Fatal(err)
		}
		out[id] = n
	}
	return out
}

// sentMessages is every delivered message, oldest first.
func sentMessages(e *env) []channel.Message {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT message FROM notify_send WHERE ok = 1 ORDER BY at, rowid`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []channel.Message
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			e.t.Fatal(err)
		}
		var m channel.Message
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// A pass like the first hour of a new box: a switch whose five matches attackers use (two critical by CVSS, three not), a declared
// server with two exploited matches and a first-run summary of a third, then a hypervisor with four exploited matches (one of them a
// CVSS 2.7 "low"), then the same four on a second device record. Every finding exploited in the wild is told exactly once, at once
// (an exploited flaw is never held for the grouping window nor dropped by the channel's "medium and above"), and the summary is its own
// message with its own words. Before: 4 of the 16 notices waited an hour for the grouping window, 2 were dropped silently as "low", and the
// summary became a nameless line of the server's digest.
func TestEveryExploitedFindingIsToldOnceAndAtOnce(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	created := func(id string) {
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})
	}
	sw := []struct {
		id, cve string
		sev     notify.Severity
	}{{"f-sw1", "CVE-2020-1631", notify.Critical}, {"f-sw2", "CVE-2023-36844", notify.Medium}, {"f-sw3", "CVE-2023-36845", notify.Critical},
		{"f-sw4", "CVE-2023-36847", notify.Medium}, {"f-sw5", "CVE-2025-21590", notify.Medium}}
	for _, f := range sw {
		dir.at(f.id, 2, finding("Example Switch OS", f.cve, "switch-01", f.sev))
		created(f.id)
	}
	e.flush()

	e.clock.Add(90 * time.Second)
	dir.at("f-vc1", 2, finding("Example Manager", "CVE-2026-123890", "manager-01", notify.Critical))
	dir.at("f-vc2", 2, finding("Example Manager", "CVE-2026-59310", "manager-01", notify.High))
	dir.at("f-vc3", 2, finding("Example Manager", "CVE-2026-59309", "manager-01", notify.Critical))
	created("f-vc1")
	created("f-vc2")
	pub(notify.EventFirstRun, findings.FirstRunEvent{Key: "install", At: e.clock.Now().UTC().Format(time.RFC3339Nano), Findings: 1, Devices: 1, Layer: 2,
		FindingIDs: []string{"f-vc3"}, CVEList: []string{"CVE-2026-59309"}})
	e.flush()

	hv := []struct {
		cve string
		sev notify.Severity
	}{{"CVE-2025-22224", notify.High}, {"CVE-2025-22225", notify.High}, {"CVE-2025-22226", notify.Medium}, {"CVE-2026-41709", notify.Low}}
	for k, device := range []string{"hypervisor-01", "192.0.2.67"} {
		e.clock.Add(9 * time.Minute)
		for i, f := range hv {
			id := fmt.Sprintf("f-hv%d-%d", k, i)
			dir.at(id, 2, finding("Example Hypervisor", f.cve, device, f.sev))
			created(id)
		}
		e.flush()
	}

	told := toldOK(e)
	if len(told) != 16 {
		t.Fatalf("%d notices recorded, want 16 (5 + 2 + the summary + 4 + 4): %v", len(told), told)
	}
	for id, n := range told {
		if n != 1 {
			t.Errorf("notice %s was named by %d delivered messages, want exactly 1", id, n)
		}
	}
	if left := e.count(`SELECT count(*) FROM notify_pending`); left != 0 {
		t.Errorf("%d notices still wait in the queue: an exploited finding must not wait for the grouping window", left)
	}
	var summary *channel.Message
	for _, m := range sentMessages(e) {
		if strings.HasPrefix(m.Title, "Patch first:") {
			summary = &m
		}
		for _, it := range m.Items {
			if strings.Contains(it, "CVE-2026-59309") && !strings.HasPrefix(m.Title, "Patch first:") {
				t.Errorf("the first-run summary became a line of another message %q: %q", m.Title, it)
			}
		}
	}
	if summary == nil {
		t.Fatal("the first-run summary was not sent as its own message")
	}
}

// A grouped alert says why for each finding as the finding page does: the status and its sources with their dates (the reasons line).
func TestDigestLinesCarryTheReasonsLine(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	dir.at("f-1", 2, finding("Example Manager", "CVE-2026-123890", "manager-01", notify.Critical))
	dir.at("f-2", 2, finding("Example Hypervisor", "CVE-2025-22224", "hypervisor-01", notify.High))
	for _, id := range []string{"f-1", "f-2"} {
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})
	}
	e.flush()
	msgs := sentMessages(e)
	if len(msgs) != 1 || len(msgs[0].Items) != 2 {
		t.Fatalf("messages = %+v, want one digest of two lines", msgs)
	}
	for _, it := range msgs[0].Items {
		if !strings.HasSuffix(it, " — Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025") {
			t.Errorf("digest line %q does not carry the finding's reasons line", it)
		}
	}
}

// The alert severity of a finding is its CVSS band raised to the floor of its layer: attackers use it (1–2) → critical; another urgent
// layer (3–4) → at least high; a higher band is kept.
func TestAlertSeverityIsTheCVSSBandRaisedToTheLayerFloor(t *testing.T) {
	for _, c := range []struct {
		cvss  notify.Severity
		layer int
		want  notify.Severity
	}{
		{notify.Low, 1, notify.Critical}, {notify.Low, 2, notify.Critical}, {notify.Medium, 2, notify.Critical},
		{notify.Low, 3, notify.High}, {notify.Medium, 4, notify.High}, {notify.Critical, 3, notify.Critical}, {"", 3, notify.High}, {"", 2, notify.Critical},
	} {
		if got := notify.AlertSeverity(c.cvss, c.layer); got != c.want {
			t.Errorf("AlertSeverity(%q, %d) = %q, want %q", c.cvss, c.layer, got, c.want)
		}
	}
}

// History names every vulnerability notice no channel delivered, with why: below the channel's minimum (and which), waiting for its
// grouping window (until when), found while no channel was set up. A delivered one is not listed. Before, History only listed sends and
// said "No new vulnerability was skipped", whatever was skipped.
func TestHistoryNamesEveryNoticeNotSentAndWhy(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	pub := func(id string) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-none", 2, finding("Example NAS", "CVE-2026-1", "nas-01", notify.High))
	pub("f-none") // no channel yet

	e.telegram(notify.Critical)
	e.clock.Add(time.Minute)
	dir.at("f-low", 3, finding("Example NAS", "CVE-2026-2", "nas-01", notify.High))
	pub("f-low") // public exploit: not exploited in the wild, no alert (INV-32)
	dir.at("f-sent", 2, finding("Example NAS", "CVE-2026-3", "nas-01", notify.Medium))
	pub("f-sent") // exploited: critical, sent at once
	e.flush()

	e.rules(notify.Quiet{Enabled: true, From: "10:00", To: "07:00"})
	e.clock.Add(time.Minute)
	dir.at("f-wait", 2, finding("Example NAS", "CVE-2026-4", "nas-01", notify.High))
	pub("f-wait") // exploited, but quiet hours hold every alert until 07:00
	e.flush()

	h, err := e.svc.History(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]notify.UnsentNotice{}
	for _, n := range h.NotSent {
		got[n.ID] = n
	}
	if len(got) != 3 {
		t.Fatalf("not sent = %+v, want the three notices that no channel delivered", h.NotSent)
	}
	want := func(id string, why notify.NotSentReason, text string) {
		t.Helper()
		n, ok := got["nt-"+id+"-created"]
		if !ok || n.NotSent.Reason != why || !strings.Contains(n.NotSent.Text, text) || n.Link != "/findings/"+id || !strings.Contains(n.What, "Example NAS on nas-01") {
			t.Errorf("%s: %+v, want %s with %q", id, n, why, text)
		}
	}
	want("f-none", notify.UnsentNoChannel, "no alert channel was set up when it was found")
	want("f-low", notify.UnsentNotExploited, "only findings exploited in the wild send one")
	want("f-wait", notify.UnsentQuietHours, "Held for quiet hours until 07:00")
	if w := got["nt-f-wait-created"].NotSent; w.Until == "" || w.Channel != "" {
		t.Errorf("a held notice says until when: %+v", w)
	}
}

// An alert says how Vedette knows the device is affected, as every screen does under the status: the single message after its reasons,
// each line of a grouped message after the finding's reasons line.
func TestAlertsCarryTheVerificationLine(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	one := finding("Example Manager", "CVE-2026-123890", "manager-01", notify.Critical)
	one.Verification = "Not confirmed yet: based on a version someone entered"
	dir.at("f-1", 2, one)
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", CVE: "CVE-x", Severity: findings.SeverityHigh})
	e.flush()
	two := finding("Example Hypervisor", "CVE-2025-22224", "hypervisor-01", notify.High)
	two.Verification = "Confirmed by a safe check"
	three := finding("Example Hypervisor", "CVE-2025-22225", "hypervisor-01", notify.High)
	three.Verification, three.Reasons = "Confirmed: the device reports this version", ""
	dir.at("f-2", 2, two)
	dir.at("f-3", 2, three)
	for _, id := range []string{"f-2", "f-3"} {
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})
	}
	e.flush()
	msgs := sentMessages(e)
	if len(msgs) != 2 || len(msgs[1].Items) != 2 {
		t.Fatalf("messages = %+v, want one single alert and one digest of two lines", msgs)
	}
	if !strings.HasSuffix(msgs[0].What, "Why: Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025. Not confirmed yet: based on a version someone entered.") {
		t.Errorf("single alert: %q", msgs[0].What)
	}
	want := []string{"CVE-2025-22224 on hypervisor-01 — Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025 · Confirmed by a safe check",
		"CVE-2025-22225 on hypervisor-01 — Exploited in the wild · Confirmed: the device reports this version"}
	for i, w := range want {
		if msgs[1].Items[i] != w {
			t.Errorf("digest line %d = %q, want %q", i, msgs[1].Items[i], w)
		}
	}
}

// A digest line longer than a channel keeps is cut in its reasons, never in its verification line: the second line of every screen
// stays whole at the end of the line.
func TestDigestLineCutKeepsTheVerificationLine(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	for i, id := range []string{"f-1", "f-2"} {
		f := finding("Example Hypervisor", fmt.Sprintf("CVE-2025-2222%d", i), "hypervisor-cluster-node-001.datacenter-east.corp.example", notify.High)
		f.Reasons = "Exploited in the wild: " + strings.Repeat("Rapid7, Mandiant, Google Threat Intelligence, ", 8) + "CISA KEV (4 Mar); fix by 25 Mar 2025"
		f.Verification = "Not confirmed yet: based on a version someone entered"
		dir.at(id, 2, f)
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})
	}
	e.flush()
	msgs := sentMessages(e)
	if len(msgs) != 1 || len(msgs[0].Items) != 2 {
		t.Fatalf("messages = %+v", msgs)
	}
	for _, it := range msgs[0].Items {
		if !strings.HasSuffix(it, "… · Not confirmed yet: based on a version someone entered") || !strings.Contains(it, "— Exploited in the wild: Rapid7") ||
			len([]rune(it)) > channel.MaxItemRunes {
			t.Errorf("digest line %q (%d runes)", it, len([]rune(it)))
		}
	}
}
