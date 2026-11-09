package main

import (
	"context"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// anyFinding answers for every finding id: the real directory is not wired in cmd yet, and this test is about
// whether an event reaches notify with the D-78 marker, not about what the notice says.
type anyFinding struct{}

func (anyFinding) Finding(context.Context, string) (notify.FindingInfo, bool, error) {
	return notify.FindingInfo{Severity: notify.Critical, Title: "is being exploited", What: "w", Action: "a", Devices: []string{"FortiGate"}}, true, nil
}

// The first CISA pull is silent (D-78) end to end on the real bus and a real SQLite file: the baseline event makes
// inventory re-match every device, findings creates findings, and notify queues nothing for them. A pull after that
// (feeds.vuln.new_kev) is not silenced: its finding is one queued notice.
func TestWiringBaselinePullQueuesNoNotice(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	svc, err := notify.New(notify.Config{DB: s.d.DB, Secrets: s.d.Secrets, Audit: s.d.Audit, Users: notifyUsers{s.d}, Log: s.d.Log, Modules: s.d.Reg, Bus: s.d.Bus, Findings: anyFinding{}, Clock: s.d.Clock})
	if err != nil {
		t.Fatal(err)
	}
	svc.Subscribe(s.d.Bus) // beside the service newHandler built, which has no finding directory and so queues nothing
	if _, err := svc.SaveChannel(t.Context(), "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"},
		Secret: "123456789:AAHexampleExampleExample0123456789ab", MinSeverity: notify.Low}); err != nil { // not a real token
		t.Fatal(err)
	}
	s.addFortiGate()
	s.kev("CVE-2026-3001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-3002", "Fortinet", "FortiOS")
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventSyncBaseline, Data: feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 2}}); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 2 {
		t.Fatalf("the re-match created %d findings, want 2", n)
	}
	if n := pendingNotices(s); n != 0 {
		t.Fatalf("the baseline queued %d notices", n)
	}

	s.kev("CVE-2026-3003", "Fortinet", "FortiOS")
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventNewKEV, Data: feeds.NewKEVEvent{CVE: "CVE-2026-3003", Vendor: "Fortinet", Product: "FortiOS"}}); err != nil {
		t.Fatal(err)
	}
	if n := pendingNotices(s); n != 1 {
		t.Fatalf("a finding of a later pull queued %d notices, want 1", n)
	}
}

func pendingNotices(s *stack) int {
	s.t.Helper()
	var n int
	if err := s.d.DB.Reader().QueryRowContext(s.t.Context(), `SELECT COUNT(*) FROM notify_pending`).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}
