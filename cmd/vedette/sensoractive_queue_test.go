package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The person turns active scanning off while the queue is being drained, between two device scans. The real
// inventory answers ScanPolicy {Allowed: false, Reason: scanning_off}; that is a state of the box, not of the
// device, so the remaining devices stay queued for the next window. A box-wide refusal (scanning_off,
// scope_not_confirmed) keeps the queue; only a device's own refusal drops it.
func TestScanningOffDuringDrainKeepsTheQueue(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	nm := newFakeNmap(t)
	clock := func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) } // Monday 02:00, inside 01:00-05:00
	s.saveScope(t)
	var ids []string
	for i, ip := range []string{"192.168.10.20", "192.168.10.21", "192.168.10.22"} {
		ids = append(ids, s.seen(t, ip, "aa:bb:cc:00:02:2"+string(rune('0'+i)), "server"))
	}
	turnedOff := false
	pub := sensoractive.PublisherFunc(func(ctx context.Context, e sensoractive.Event) error {
		if e.Name == sensoractive.EventScanFinished && !turnedOff { // the first device scan just finished
			turnedOff = true
			_, err := s.d.Inventory.SaveSettings(ctx, "admin@acme.example", inventory.SettingsInput{
				Settings: inventory.Settings{
					LANRanges: []string{"192.168.10.0/24"},
					Active:    inventory.ActiveWindow{Enabled: false, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100, Exclusions: []string{"192.168.10.99"}},
				},
				ScopeConfirmed: true,
			})
			return err
		}
		return nil
	})
	svc, err := sensoractive.New(sensoractive.Config{DB: s.d.DB, Inventory: sensorInventory{s.d.Inventory}, Observe: s.d.Inventory, Software: s.d.Inventory,
		Events: pub, NmapPath: nm.path, Clock: clock, Location: func() *time.Location { return time.Local }})
	if err != nil {
		t.Fatal(err)
	}
	s.d.Bus.Subscribe(inventory.EventSettingsChanged, func(ctx context.Context, _ events.Event) error { return svc.SettingsChanged(ctx) })
	for _, id := range ids {
		if err := svc.Enqueue(t.Context(), id, "discovered"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error { // today's sweep is done: Tick goes to the queue
		_, err := tx.ExecContext(t.Context(), `INSERT INTO sa_job (id, kind, started_at, finished_at, status) VALUES ('saj-review2', 'sweep', ?, ?, 'done')`, store.FormatTS(clock()), store.FormatTS(clock()))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !turnedOff {
		t.Fatal("setup: no device scan finished")
	}
	n, err := svc.QueueLen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("scanning was turned off after the first device scan: %d devices left in the queue, want the 2 not yet scanned kept for the next window (device scans run: %d)", n, len(nm.calls(t)))
	}
}
