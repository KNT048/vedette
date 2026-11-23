package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Vulnerability notices are live (S-ALERT-1): the finding directory of notify is wired, on the real bus and a
// real SQLite file. No network: the CISA list is stored with SQL, the channel is saved but nothing is delivered.

func (s *stack) telegramOn() {
	s.t.Helper()
	if _, err := newNotify(s.d).SaveChannel(s.t.Context(), "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true,
		Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: "123456789:AAHexampleExampleExample0123456789ab", MinSeverity: notify.Low}); err != nil { // not a real token
		s.t.Fatal(err)
	}
}

func (s *stack) queuedNotices() []notify.Notice {
	s.t.Helper()
	rows, err := s.d.DB.Reader().QueryContext(s.t.Context(), `SELECT notice FROM notify_pending ORDER BY created_at`)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []notify.Notice
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			s.t.Fatal(err)
		}
		var n notify.Notice
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestWiringKEVMatchQueuesOneNoticeWithRealTexts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.telegramOn()
	s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_kev SET required_action = ? WHERE cve = 'CVE-2026-4001'`, "Apply updates per vendor instructions.\n<b>now</b>")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.addFortiGate()
	got := s.queuedNotices()
	if len(got) != 1 {
		t.Fatalf("queued %d notices, want exactly 1", len(got))
	}
	n := got[0]
	if n.Kind != notify.KindVuln || len(n.CVEs) != 1 || n.CVEs[0] != "CVE-2026-4001" {
		t.Fatalf("notice kind or CVE wrong: %+v", n)
	}
	if len(n.Devices) != 1 || n.Devices[0] != "FortiGate (192.168.30.1)" { // the Devices name with its address
		t.Fatalf("devices = %v, want the Devices name", n.Devices)
	}
	t.Logf("notice: %+v", n)
	if n.Product != "FortiGate firewall (FortiOS)" || n.Title != "FortiGate firewall (FortiOS) on FortiGate (192.168.30.1): exploited in the wild (CVE-2026-4001)" {
		t.Fatalf("product/title: %q / %q", n.Product, n.Title)
	}
	if !strings.HasPrefix(n.What, findings.StatusMeaning(findings.UrgencyExploited)+" Why: Exploited in the wild: ") || n.Action != "Apply updates per vendor instructions. <b>now</b>" {
		t.Fatalf("what/action: %q / %q", n.What, n.Action)
	}
	if n.Event != notify.NoticeCreated || n.Layer != findings.UrgencyExploited {
		t.Fatalf("event %q layer %d", n.Event, n.Layer)
	}
	// findings computed medium (no NVD versions, so the version was not compared); an exploited finding alerts as critical
	if n.Severity != notify.AlertSeverity(notify.Medium, n.Layer) || n.Severity != notify.Critical {
		t.Fatalf("severity %q, want critical: the CVSS band (medium) raised to the floor of an exploited finding", n.Severity)
	}
}

func TestWiringFindingDirectoryClipsHostileFeedText(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-4002", "Fortinet", "FortiOS")
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_kev SET required_action = ?, name = ? WHERE cve = 'CVE-2026-4002'`, strings.Repeat("A\r\n", 5000), "x\x00y"+strings.Repeat("N", 5000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.addFortiGate()
	recs, err := s.d.Findings.List(t.Context(), "")
	if err != nil || len(recs) != 1 {
		t.Fatalf("findings: %v %v", recs, err)
	}
	info, ok, err := notifyFindings{s.d}.Finding(t.Context(), recs[0].ID)
	if err != nil || !ok {
		t.Fatalf("Finding: %v %v", ok, err)
	}
	for _, v := range []string{info.Action, info.Meaning, info.Reasons, info.Product} {
		if strings.ContainsAny(v, "\r\n\x00") {
			t.Fatalf("control characters survived: %q", v)
		}
	}
	if n := len([]rune(info.Action)); n > noticeActionMax || n < 100 {
		t.Fatalf("action has %d characters", n)
	}
	if n := len([]rune(info.Meaning + info.Reasons + info.Product)); n > 800 {
		t.Fatalf("the texts have %d characters", n)
	}
}

func TestWiringMissingFindingIsSkipped(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.telegramOn()
	info, ok, err := notifyFindings{s.d}.Finding(t.Context(), "fnd-gone")
	if err != nil || ok || info.CVE != "" {
		t.Fatalf("Finding of a deleted finding: %+v %v %v", info, ok, err)
	}
	if err := s.d.Bus.Publish(context.Background(), events.Event{Name: "findings.finding.created",
		Data: map[string]any{"finding_id": "fnd-gone", "asset_id": "a-gone", "cve": "CVE-2026-4003", "severity": "high", "basis": "product"}}); err != nil {
		t.Fatal(err)
	}
	if n := pendingNotices(s); n != 0 {
		t.Fatalf("a deleted finding queued %d notices", n)
	}
}

func TestPlainTextClipsAndFlattens(t *testing.T) {
	t.Parallel()
	if got := plainText("a\r\n\tb\x00 c", 50); got != "a b c" {
		t.Fatalf("got %q", got)
	}
	if got := plainText("byn\u202egnp.exe\u200b", 50); got != "byngnp.exe" { // a host name from the network
		t.Fatalf("got %q", got)
	}
	if got := plainText(strings.Repeat("é", 30), 10); len([]rune(got)) != 10 {
		t.Fatalf("got %q", got)
	}
}

// The alert for an entry only VulnCheck KEV lists says so, and never says CISA lists it.
func TestWiringNoticeNamesVulnCheckAsTheSource(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.telegramOn()
	s.kev("CVE-2026-4003", "Fortinet", "FortiOS")
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), `UPDATE feeds_kev SET source_id = 'vulncheck-kev', list = 'vulncheck' WHERE cve = 'CVE-2026-4003'`); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_signal SET source = 'vulncheck-kev' WHERE cve = 'CVE-2026-4003' AND source = 'cisa-kev'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.addFortiGate()
	got := s.queuedNotices()
	if len(got) != 1 || !strings.Contains(got[0].What, "Exploited in the wild: VulnCheck KEV (") || strings.Contains(got[0].What, "CISA lists") ||
		strings.Contains(got[0].What, "wild: CISA") {
		t.Fatalf("notices: %+v", got)
	}
}

// An alert about a finding of a device nobody approved says so ("device not added yet"), also for a device with no name; an
// approved device and an ignored one get no mark.
func TestWiringAlertMarksADeviceNotAddedYet(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-4010", "Fortinet", "FortiOS")
	id := s.addFortiGate() // hand-added: approved
	recs, _ := s.d.Findings.List(t.Context(), id)
	if len(recs) != 1 {
		t.Fatalf("findings: %v", recs)
	}
	info, _, err := notifyFindings{s.d}.Finding(t.Context(), recs[0].ID)
	if err != nil || strings.Contains(strings.Join(info.Devices, ","), "not added yet") {
		t.Fatalf("an approved device is marked: %+v %v", info, err)
	}
	// Stop ignoring sends a device back through review: not approved
	ign := func(on bool) {
		t.Helper()
		if err := s.d.Inventory.SetIgnored(t.Context(), "it@acme.example", id, on); err != nil {
			t.Fatal(err)
		}
	}
	ign(true)
	ign(false)
	info, _, err = notifyFindings{s.d}.Finding(t.Context(), recs[0].ID)
	if err != nil || len(info.Devices) != 1 || !strings.HasSuffix(info.Devices[0], " (device not added yet)") || !strings.Contains(info.Note, "not added yet") {
		t.Fatalf("an unapproved device: %+v %v", info, err)
	}
	ign(true)
	if info, _, _ = (notifyFindings{s.d}).Finding(t.Context(), recs[0].ID); strings.Contains(strings.Join(info.Devices, ","), "not added yet") {
		t.Fatalf("an ignored device is marked: %+v", info)
	}
}

// The History page's count of exploited vulnerabilities that matched no device is read from the signals: a source's news of the last days,
// not what came with its first load, and not a CVE a device has a finding for.
func TestWiringUnmatchedExploitedIsReadFromTheSignals(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	now := time.Now().UTC()
	signal := func(cve, source string, qualifies int, stored time.Time) {
		t.Helper()
		s.exec(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES (?1, 'exploited', ?2, ?3, ?3, ?3, ?4)`,
			cve, source, store.FormatTS(stored), qualifies)
	}
	count := func() int {
		t.Helper()
		n, err := notifySignals{s.d}.UnmatchedExploited(t.Context(), now.AddDate(0, 0, -7))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	signal("CVE-2019-0002", "rapid7-blog", 1, now.AddDate(0, -1, 0)) // the source's first load, a month ago: too old for the window
	if n := count(); n != 0 {
		t.Fatalf("an old signal counted: %d", n)
	}
	signal("CVE-2026-7001", "rapid7-blog", 1, now.Add(-time.Hour))
	signal("CVE-2026-7002", "rapid7-blog", 1, now.Add(-2*time.Hour))
	signal("CVE-2026-7003", "rapid7-blog", 0, now.Add(-time.Hour)) // does not qualify
	signal("CVE-2026-7004", "metasploit", 1, now.Add(-time.Hour))  // metasploit's first sighting is this one: its first load
	if n := count(); n != 2 {
		t.Fatalf("unmatched exploited CVEs = %d, want the 2 news of rapid7-blog (not the unqualified row, not another source's first load)", n)
	}
	// a device that has a finding for one of them takes it out of the count
	s.kev("CVE-2026-7001", "Fortinet", "FortiOS")
	s.addFortiGate()
	if s.nf("", "CVE-2026-7001") == 0 {
		t.Fatal("the fixture made no finding for CVE-2026-7001")
	}
	if n := count(); n != 1 {
		t.Fatalf("after a finding matched one of them: %d, want 1", n)
	}
}
