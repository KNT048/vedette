package main

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// D-328 (deferred sweep item 10): a CISA entry whose vendor or product changed reaches the devices of its new product through
// feeds.vuln.updated; an update that moved no key (a has_template flip) announces nothing to a device that already has the finding.
func TestVulnUpdatedRematchesAChangedProduct(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	var announced atomic.Int64
	s.d.Bus.Subscribe(inventory.EventMatchChanged, func(context.Context, events.Event) error { announced.Add(1); return nil })
	fw := s.addFortiGate()
	const cve = "CVE-2026-8101"
	s.kevAdded(cve, "Acme", "Widget", time.Now().AddDate(0, 0, -30)) // first listed under another product: no device runs it
	publish := func() {
		t.Helper()
		if err := s.d.Bus.Publish(t.Context(), events.Event{Name: feeds.EventVulnUpdated, Data: feeds.VulnUpdatedEvent{CVEs: []string{cve}}}); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	if n := s.nf(fw, cve); n != 0 || announced.Load() != 0 {
		t.Fatalf("an entry of another product made %d findings, %d announcements", n, announced.Load())
	}
	// CISA corrects the entry to FortiOS: the FortiGate now matches
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_vuln SET vendor = 'Fortinet', product = 'FortiOS', product_key = ? WHERE cve = ?`, feeds.ProductKey("Fortinet", "FortiOS"), cve)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	publish()
	if n := s.nf(fw, cve); n != 1 {
		t.Fatalf("after the product changed to FortiOS the FortiGate has %d findings for it, want 1", n)
	}
	before := announced.Load()
	publish() // the same entry again (a has_template flip): the device already has the finding
	if got := announced.Load(); got != before {
		t.Fatalf("an update that moved no key announced %d more matches", got-before)
	}
}
