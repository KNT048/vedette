package main

import (
	"database/sql"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// findings' reconcile job (D-144) is wired for the module, and its device list is every device of the real inventory.
func TestFindingsReconcileJobAndDeviceList(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	jobs := findingsJobs(*s.d)
	if len(jobs) != 1 || jobs[0].Module != "findings" || jobs[0].Name != "reconcile" {
		t.Fatalf("jobs = %+v", jobs)
	}
	var want []string
	for i, ip := range []string{"192.168.50.1", "192.168.50.2"} {
		r, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Name: []string{"fw-a", "fw-b"}[i], IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, r.ID)
	}
	got, err := findingsInventory{s.d.Inventory}.AssetIDs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("AssetIDs = %v, missing %s", got, id)
		}
	}
}

// kevAdded stores a CISA entry with the date CISA added it.
func (s *stack) kevAdded(cve, vendor, product string, added time.Time) {
	s.t.Helper()
	now := time.Now().UTC()
	err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(s.t.Context(), `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, date_added, ransomware, source_id, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 0, 'cisa-kev', ?)`, cve, vendor, product, feeds.ProductKey(vendor, product), vendor+" "+product+" flaw", added.Format("2006-01-02"), store.FormatTS(now))
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

// setFindings turns the findings module on or off the way the settings page does.
func (s *stack) setFindings(on bool) {
	s.t.Helper()
	ctx := s.t.Context()
	var change modreg.Change
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if on {
			change, err = s.d.Reg.Enable(ctx, tx, "admin@acme.example", "findings", true)
		} else {
			change, err = s.d.Reg.Disable(ctx, tx, "admin@acme.example", "findings")
		}
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.d.Reg.Publish(change)
}

// The baseline events of the first CISA pull were lost (findings was off, or the re-match was cut by its timeout), so no
// finding exists. The reconcile then creates them all; notify must stay silent for the old entries (D-78: backlog is
// silent) and announce the one CISA added two days ago, once.
func TestWiringReconcileAfterALostBaselineIsSilentForBacklogAndAnnouncesRecentNews(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	svc, err := notify.New(notify.Config{DB: s.d.DB, Secrets: s.d.Secrets, Audit: s.d.Audit, Users: notifyUsers{s.d}, Log: s.d.Log, Modules: s.d.Reg, Bus: s.d.Bus, Findings: anyFinding{}, Clock: s.d.Clock})
	if err != nil {
		t.Fatal(err)
	}
	svc.Subscribe(s.d.Bus)
	if _, err := svc.SaveChannel(t.Context(), "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"},
		Secret: "123456789:AAHexampleExampleExample0123456789ab", MinSeverity: notify.Low}); err != nil { // not a real token
		t.Fatal(err)
	}
	s.setFindings(false) // the events go nowhere
	s.addFortiGate()
	for i := range 5 {
		s.kevAdded(fmt.Sprintf("CVE-2020-%04d", 5000+i), "Fortinet", "FortiOS", time.Now().AddDate(-3, 0, 0))
	}
	s.kevAdded("CVE-2026-7001", "Fortinet", "FortiOS", time.Now().AddDate(0, 0, -2))
	if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventSyncBaseline, Data: feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 6}}); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 0 {
		t.Fatalf("%d findings exist although findings was off", n)
	}
	s.setFindings(true)
	if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := s.nf("", ""); n != 6 {
		t.Fatalf("the reconcile created %d findings, want 6", n)
	}
	if n := pendingNotices(s); n != 1 {
		t.Fatalf("queued %d notices, want exactly 1 (the CVE CISA added two days ago)", n)
	}
	if err := findingsJobs(*s.d)[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := pendingNotices(s); n != 1 {
		t.Fatalf("a second reconcile queued %d notices in total, want still 1", n)
	}
}
