package sensoractive

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

type countSink struct{ macs map[string]bool }

func (c *countSink) Record(_ context.Context, obs []observe.Observation) error {
	for _, o := range obs {
		if o.Field == observe.MAC {
			c.macs[o.Value] = true
		}
	}
	return nil
}

func newBudgetService(sink *countSink, now time.Time) *Service {
	return &Service{obs: sink, clock: func() time.Time { return now }, log: slog.New(slog.DiscardHandler), budget: capture.NewFloodBudgetLimits(sweepNewPerMinute, sweepNewPerHour)}
}

func mac(n int) string {
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", n>>24&255, n>>16&255, n>>8&255, n&255)
}

// L8: a sweep over a /16 whose hosts all carry random MACs stops minting devices at the sweep's own budget (1,000 an hour, enough for the
// design scale in one pass); the hosts the inventory already has by MAC are not charged.
func TestRecordSweepStopsAtTheNewDeviceBudget(t *testing.T) {
	t.Parallel()
	sink := &countSink{macs: map[string]bool{}}
	s := newBudgetService(sink, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
	known := map[string]bool{}
	var fresh int
	for b := range 400 { // 400 batches of 160 hosts: 64000 hosts in one scope
		var hosts []host
		var batch []netip.Addr
		for i := range 160 {
			n := b*160 + i
			a := netip.AddrFrom4([4]byte{10, 1, byte(n >> 8 & 255), byte(n & 255)})
			hosts = append(hosts, host{addr: a, mac: mac(n)})
			batch = append(batch, a)
		}
		n, err := s.recordSweep(t.Context(), hosts, batch, known)
		if err != nil {
			t.Fatal(err)
		}
		fresh += n
	}
	if fresh != sweepNewPerHour || len(sink.macs) != sweepNewPerHour {
		t.Fatalf("%d new devices reported, %d recorded; the budget is %d an hour", fresh, len(sink.macs), sweepNewPerHour)
	}
}

// L8 bypass: one IP the inventory already has, answering with 200 different MACs in one result, is charged by MAC (not free because the IP
// is known) and one entry per target counts; DHCP churn (known MACs on new IPs) is free.
func TestRecordSweepChargesByMACNotByIP(t *testing.T) {
	t.Parallel()
	sink := &countSink{macs: map[string]bool{}}
	s := newBudgetService(sink, time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
	s.budget = capture.NewFloodBudgetLimits(60, 60)
	ip := netip.MustParseAddr("10.0.0.5") // the inventory has a device here
	known := map[string]bool{mac(1): true}
	var hosts []host
	for i := range 200 {
		hosts = append(hosts, host{addr: ip, mac: mac(1000 + i)})
	}
	n, err := s.recordSweep(t.Context(), hosts, []netip.Addr{ip}, known)
	if err != nil || n != 1 || len(sink.macs) != 1 { // one entry per target: only the first counts
		t.Fatalf("200 entries for one target: %d new, %d recorded, %v", n, len(sink.macs), err)
	}
	// the same address over several batches (a hostile scan container) with a new MAC each time is charged and capped
	for i := range 200 {
		if _, err := s.recordSweep(t.Context(), []host{{addr: ip, mac: mac(2000 + i)}}, []netip.Addr{ip}, known); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.macs) != 60 {
		t.Fatalf("%d MACs recorded for one known IP, want the budget of 60", len(sink.macs))
	}
	// DHCP churn: devices with known MACs on new addresses are free, however many
	var churn []host
	var batch []netip.Addr
	for i := range 500 {
		known[mac(5000+i)] = true
		a := netip.AddrFrom4([4]byte{10, 3, byte(i >> 8), byte(i)})
		churn, batch = append(churn, host{addr: a, mac: mac(5000 + i)}), append(batch, a)
	}
	if n, err := s.recordSweep(t.Context(), churn, batch, known); err != nil || n != 0 {
		t.Fatalf("known MACs on new IPs: %d new, %v", n, err)
	}
	for i := range 500 {
		if !sink.macs[mac(5000+i)] {
			t.Fatalf("known MAC %d was not recorded", i)
		}
	}
}
