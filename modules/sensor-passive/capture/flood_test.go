package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

func floodMAC(n int) string {
	return fmt.Sprintf("0a:00:00:00:%02x:%02x", n>>8&0xff, n&0xff)
}

// Decide answers from the book as it is and counts the claims of one call against each other, but records nothing: asking twice
// gives the same answer, and only Commit uses up budget.
func TestFloodBudgetDecidesWithoutRecording(t *testing.T) {
	t.Parallel()
	b := NewFloodBudget()
	now := pktgen.T0
	claims := make([]Claim, 100)
	for i := range claims {
		claims[i] = Claim{MAC: floodMAC(i), Field: observe.Hostname, Value: "h"}
	}
	first := b.Decide(claims, now)
	again := b.Decide(claims, now)
	admitted := 0
	for i := range first {
		if first[i] != again[i] {
			t.Fatalf("claim %d: %+v then %+v: Decide recorded something", i, first[i], again[i])
		}
		if first[i].Admit {
			admitted++
		}
	}
	if admitted != NewMACsPerMinute {
		t.Errorf("%d admitted in one call, want the minute's %d", admitted, NewMACsPerMinute)
	}
	b.Commit(claims, first, now)
	other := []Claim{{MAC: floodMAC(1000), Field: observe.Hostname, Value: "h"}}
	if v := b.Decide(other, now); v[0].Admit {
		t.Error("the minute is spent and a new device was admitted")
	}
	if v := b.Decide(claims[:1], now); !v[0].Admit || !v[0].Pass {
		t.Errorf("a known device was refused: %+v", v[0])
	}
}

// An observation without a MAC counts against the budget by its address.
func TestFloodBudgetCountsAnAddressWithoutAMAC(t *testing.T) {
	t.Parallel()
	b := NewFloodBudget()
	claims := make([]Claim, 100)
	for i := range claims {
		claims[i] = Claim{IP: netip.AddrFrom4([4]byte{10, 0, byte(i), 1}), Field: observe.Hostname, Value: "h"}
	}
	n := 0
	for _, v := range b.Decide(claims, pktgen.T0) {
		if v.Pass {
			n++
		}
	}
	if n != NewMACsPerMinute {
		t.Errorf("%d devices by address in a minute, want %d", n, NewMACsPerMinute)
	}
}

// FuzzFloodBudget: however claims arrive, in however many batches, within one minute at most 60 devices are admitted, a device and
// a field never has more than 4 new values pass, and Decide alone changes nothing.
func FuzzFloodBudget(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add(make([]byte, 400))
	seed := make([]byte, 600)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		b := NewFloodBudget()
		now := pktgen.T0
		fields := []observe.Field{observe.Hostname, observe.MAC, observe.Vendor, observe.Model, observe.OS, observe.Kind}
		type slot struct {
			mac string
			f   observe.Field
		}
		devices := map[string]bool{}
		values := map[slot]map[string]bool{}
		for len(data) >= 4 {
			n := int(data[0])%40 + 1
			data = data[1:]
			var claims []Claim
			for range n {
				if len(data) < 3 {
					break
				}
				mac := floodMAC(int(binary.BigEndian.Uint16([]byte{data[0] % 8, data[1]})))
				claims = append(claims, Claim{MAC: mac, Field: fields[int(data[2])%len(fields)], Value: fmt.Sprintf("v%d", data[2]/6%9)})
				data = data[3:]
			}
			vs := b.Decide(claims, now)
			vs2 := b.Decide(claims, now)
			for i := range vs {
				if vs[i] != vs2[i] {
					t.Fatalf("Decide changed the budget")
				}
			}
			b.Commit(claims, vs, now)
			for i, c := range claims {
				if vs[i].Admit {
					devices[c.MAC] = true
				}
				if vs[i].Pass {
					s := slot{c.MAC, c.Field}
					if values[s] == nil {
						values[s] = map[string]bool{}
					}
					values[s][c.Value] = true
				}
			}
			if len(devices) > NewMACsPerMinute {
				t.Fatalf("%d devices admitted in a minute", len(devices))
			}
			for s, v := range values {
				if len(v) > NewValuesPerHour {
					t.Fatalf("%v passed %d new values in an hour", s, len(v))
				}
			}
		}
	})
}

// M4: one MAC that says many addresses is a flood like one that says many names: 4 new addresses an hour, the rest is over budget;
// a repeat of an address is not new.
func TestFloodBudgetBoundsTheAddressesOfOneMAC(t *testing.T) {
	t.Parallel()
	b := NewFloodBudget()
	now := pktgen.T0
	var claims []Claim
	for i := range 20 {
		claims = append(claims, Claim{MAC: floodMAC(1), IP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), Field: observe.Hostname, Value: "h"})
	}
	pass := func(vs []Verdict) (n int) {
		for _, v := range vs {
			if v.Pass {
				n++
			}
		}
		return n
	}
	vs := b.Decide(claims, now)
	if n := pass(vs); n != NewValuesPerHour {
		t.Fatalf("%d addresses passed for one MAC in a call, want %d", n, NewValuesPerHour)
	}
	b.Commit(claims, vs, now)
	if n := pass(b.Decide(claims, now)); n != NewValuesPerHour {
		t.Errorf("the same 20 again: %d passed, want the same 4 (repeats are not new)", n)
	}
	other := []Claim{{MAC: floodMAC(1), IP: netip.MustParseAddr("10.0.9.9"), Field: observe.Hostname, Value: "h"}}
	if pass(b.Decide(other, now)) != 0 {
		t.Error("a fifth address in the hour passed")
	}
	if pass(b.Decide(other, now.Add(time.Hour+time.Second))) != 1 {
		t.Error("the hour is over and a new address still does not pass")
	}
}

// The capture's own book says the same before anything is sent (M4).
func TestEngineBoundsTheAddressesOfOneMAC(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	for i := range 30 {
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)}), pktgen.MAC{}, pktgen.RouterIP)})
	}
	obs, _ := e.Drain(pktgen.T0, false)
	ips := map[string]bool{}
	for _, o := range obs {
		if o.AssetHint.IP.IsValid() {
			ips[o.AssetHint.IP.String()] = true
		}
	}
	if len(ips) != NewValuesPerHour || e.Counters()["values_dropped"] != 26 {
		t.Errorf("%d addresses for one MAC, counters %v: want %d and 26 dropped", len(ips), e.Counters(), NewValuesPerHour)
	}
}

// L1: the kinds a parser emits, each capped at the highest confidence a parser gives it.
func TestMaxConfidenceKnowsOnlyTheKindsTheParsersEmit(t *testing.T) {
	t.Parallel()
	for kind, want := range map[string]float64{"ap": 0.6, "switch": 0.6, "router": 0.6, "printer": 0.5, "iot": 0.3} {
		if got, ok := MaxConfidence(observe.Kind, kind); !ok || got != want {
			t.Errorf("kind %s: %v %v, want %v", kind, got, ok, want)
		}
	}
	for _, kind := range []string{"toaster", "server", "", "Printer"} {
		if _, ok := MaxConfidence(observe.Kind, kind); ok {
			t.Errorf("kind %q is accepted: no parser emits it", kind)
		}
	}
}

// L6: devices the budget was seeded with are known: they pass although the minute is spent.
func TestFloodBudgetSeedMakesDevicesKnown(t *testing.T) {
	t.Parallel()
	b := NewFloodBudget()
	b.Seed([]string{floodMAC(500), "not a mac"})
	now := pktgen.T0
	claims := make([]Claim, 0, 101)
	for i := range 100 {
		claims = append(claims, Claim{MAC: floodMAC(i), Field: observe.Hostname, Value: "h"})
	}
	b.Commit(claims, b.Decide(claims, now), now)
	if v := b.Decide([]Claim{{MAC: floodMAC(500), Field: observe.Hostname, Value: "x"}}, now); !v[0].Pass {
		t.Error("a device the budget was seeded with was refused")
	}
	if v := b.Decide([]Claim{{MAC: floodMAC(501), Field: observe.Hostname, Value: "x"}}, now); v[0].Pass {
		t.Error("an unknown device passed with the minute spent")
	}
}
