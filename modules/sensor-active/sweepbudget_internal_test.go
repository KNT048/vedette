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

// L8: a sweep over a /16 whose hosts all carry random MACs must stop minting devices at the budget of new devices (60 a minute, 200 an hour),
// the same one the passive sensor uses; devices the inventory already has are not charged.
func TestRecordSweepStopsAtTheNewDeviceBudget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	sink := &countSink{macs: map[string]bool{}}
	s := &Service{obs: sink, clock: func() time.Time { return now }, log: slog.New(slog.DiscardHandler), budget: capture.NewFloodBudget()}
	known := map[netip.Addr]string{}
	var fresh int
	for b := range 400 { // 400 batches of 160 hosts: 64000 hosts in one scope
		var hosts []host
		var batch []netip.Addr
		for i := range 160 {
			n := b*160 + i
			a := netip.AddrFrom4([4]byte{10, 1, byte(n >> 8 & 255), byte(n & 255)})
			hosts = append(hosts, host{addr: a, mac: fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", n>>24, n>>16&255, n>>8&255, n&255)})
			batch = append(batch, a)
		}
		n, err := s.recordSweep(t.Context(), hosts, batch, known)
		if err != nil {
			t.Fatal(err)
		}
		fresh += n
	}
	if fresh > 60 || len(sink.macs) > 60 {
		t.Fatalf("%d new devices reported, %d recorded; the minute budget is 60", fresh, len(sink.macs))
	}
	if fresh == 0 {
		t.Fatal("the budget admitted nothing")
	}
	// a device the inventory knows by address is recorded and not charged
	a := netip.MustParseAddr("10.9.9.9")
	known[a] = "asset-1"
	if _, err := s.recordSweep(t.Context(), []host{{addr: a, mac: "02:aa:bb:cc:dd:ee"}}, []netip.Addr{a}, known); err != nil || !sink.macs["02:aa:bb:cc:dd:ee"] {
		t.Fatalf("a known device was dropped: %v", err)
	}
}
