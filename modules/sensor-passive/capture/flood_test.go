package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

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
