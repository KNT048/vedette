package main

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// WP-31 close-out (D-296): the inventory asks for the box's MACs on the passive ingest path. A failed ask is remembered for
// hostNetBackoff (a hung host costs one timeout, not one per batch), and Fresh skips the TTL at most every hostMACsFreshEvery.
func TestHostMACsBackoffAndFresh(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	f := &fakeNetState{st: api.NetState{Decoys: []api.NetDecoy{{IP: "192.168.10.240", MAC: "02:00:00:00:02:40"}}}}
	h := &hostMACs{r: f, now: func() time.Time { return now }}
	ctx := t.Context()
	if got, err := h.Get(ctx); err != nil || !slices.Contains(got, "02:00:00:00:02:40") || f.n != 1 {
		t.Fatalf("first ask: %v, %v, %d asks", got, err, f.n)
	}
	// Fresh within hostMACsFreshEvery of the answer: served from it.
	if _, err := h.Fresh(ctx); err != nil || f.n != 1 {
		t.Fatalf("a fresh ask right after the answer reached the host (%d asks)", f.n)
	}
	// A decoy added since: Fresh asks, a second Fresh in the same window does not.
	f.st.Decoys = append(f.st.Decoys, api.NetDecoy{IP: "192.168.10.241", MAC: "02:00:00:00:02:41"})
	now = now.Add(5 * time.Second)
	if got, err := h.Fresh(ctx); err != nil || !slices.Contains(got, "02:00:00:00:02:41") || f.n != 2 {
		t.Fatalf("fresh ask: %v, %v, %d asks", got, err, f.n)
	}
	now = now.Add(time.Second)
	if _, err := h.Fresh(ctx); err != nil || f.n != 2 {
		t.Fatalf("Fresh was not rate limited (%d asks)", f.n)
	}
	// The host hangs: one failed ask, then the last answer for hostNetBackoff without asking.
	f.err = errors.New("timeout")
	now = now.Add(hostNetTTL)
	for range 5 {
		if got, err := h.Fresh(ctx); err != nil || !slices.Contains(got, "02:00:00:00:02:41") {
			t.Fatalf("during the backoff: %v, %v", got, err)
		}
	}
	if f.n != 3 {
		t.Fatalf("%d asks to a failing host, want 3", f.n)
	}
	f.err = nil
	now = now.Add(hostNetBackoff)
	if _, err := h.Get(ctx); err != nil || f.n != 4 {
		t.Fatalf("after the backoff: %v, %d asks", err, f.n)
	}
}
