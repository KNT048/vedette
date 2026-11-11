package capture

import (
	"net/netip"
	"strings"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// What core applies to everything a sensor sends (D-111 (2), SYS-6): the same book and the same numbers as the capture
// process uses for itself, without the two-frame confirmation (the capture already asked for it). A sensor that has been taken
// over passes its own book, not this one.

// Limits the capture and core share (sensor-protocol.md section 9). Core's tests compare its behaviour with these.
const (
	NewMACsPerMinute = maxNewMACsPerMinute
	NewMACsPerHour   = maxNewMACsPerHour
	NewValuesPerHour = maxNewValuesPerHour
	MaxValueBytes    = maxValue
)

// Printable reports whether s is text a person can read (INV-3): valid UTF-8, no control character, no invisible format
// character, no line or paragraph separator. Core uses the capture's own rule for what a sensor may send.
func Printable(s string) bool { return printable(s) }

// kindCap is the kinds a parser of this package emits and the highest confidence any of them gives to each (INV-5): LLDP says
// ap, switch and router at 0.6, mDNS says printer at 0.5 and iot at 0.3, SSDP says router at 0.5. Nothing else is a passive kind.
var kindCap = map[string]float64{"ap": ConfLLDPKind, "switch": ConfLLDPKind, "router": ConfLLDPKind, "printer": ConfMDNSKind, "iot": ConfMDNSIotKind}

// MaxConfidence is the highest confidence a passive observation of field with value may have (INV-5, "Thang tin cậy" of the
// CONTRACT): the highest of the Conf constants any parser of this package gives to that field (for a kind, to that kind). Core
// clamps what a sensor says to it; ok is false for a value a passive sensor cannot report at all (a kind no parser emits).
func MaxConfidence(f observe.Field, value string) (limit float64, ok bool) {
	switch f {
	case observe.MAC:
		return ConfMACBinding, true
	case observe.Hostname:
		return ConfLLDPName, true
	case observe.Kind:
		c, ok := kindCap[value]
		return c, ok
	case observe.Model:
		return ConfSSDPModel, true
	case observe.Vendor:
		return ConfOUIVendor, true
	}
	return ConfMDNSIotKind, true // os: no passive source reports it, so the lowest rung
}

// Claim is one observation as the budget sees it: whose it is (a MAC, or an IPv4 address for an observation without one),
// the field and the value.
type Claim struct {
	MAC   string // aa:bb:cc:dd:ee:ff, or ""
	IP    netip.Addr
	Field observe.Field
	Value string
}

// Verdict is the budget's answer to one Claim.
type Verdict struct {
	Admit bool // the device may exist: it is known, or it is new and the minute and the hour have room
	Pass  bool // the claim may go on: Admit and the value fits the values of this device and field in the hour
}

// FloodBudget is core's budget of new devices (60 a minute, 200 an hour) and of new values (4 per device and field per hour).
// It is in memory: a restart of core starts it empty.
type FloodBudget struct{ b *deviceBook }

// NewFloodBudget returns an empty budget.
func NewFloodBudget() *FloodBudget {
	return &FloodBudget{b: newDeviceBook(bookLimits{PerMinute: maxNewMACsPerMinute, PerHour: maxNewMACsPerHour})}
}

// NewFloodBudgetLimits is a budget with its own numbers of new devices a minute and an hour, for a caller that is not the passive
// sensor (the active sweep: a fresh install must find the design scale in one pass, yet a /16 of random MACs must still stop).
func NewFloodBudgetLimits(perMinute, perHour int) *FloodBudget {
	return &FloodBudget{b: newDeviceBook(bookLimits{PerMinute: perMinute, PerHour: perHour})}
}

func claimKey(c Claim) (mac, bool) {
	if m, ok := parseMAC(strings.ToLower(c.MAC)); ok {
		return m, true
	}
	if c.MAC == "" && c.IP.Is4() { // no MAC: the address stands for the device, in a range no real card has (locally administered, multicast bit set)
		a := c.IP.As4()
		return mac{0x03, 0xfe, a[0], a[1], a[2], a[3]}, true
	}
	return mac{}, false
}

// Decide says what the budget allows for claims, counting the claims of one call against each other, and records nothing:
// when core's store then fails, the batch has used no budget and the sensor's second try meets the same budget (sensor-protocol.md 6.2).
// Commit records what Decide allowed.
func (f *FloodBudget) Decide(claims []Claim, now time.Time) []Verdict {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	minuteLeft, hourLeft := b.lim.PerMinute-b.minuteN, b.lim.PerHour-b.hourN
	if b.minute.IsZero() || now.Sub(b.minute) >= time.Minute {
		minuteLeft = b.lim.PerMinute
	}
	if b.hour.IsZero() || now.Sub(b.hour) >= time.Hour {
		hourLeft = b.lim.PerHour
	}
	type slot struct {
		m mac
		f int
	}
	admitted := map[mac]bool{}
	added := map[slot][]uint64{} // new values of this call, by device and field
	out := make([]Verdict, len(claims))
	for i, c := range claims {
		m, ok := claimKey(c)
		if !ok {
			continue
		}
		_, exists := b.index[m]
		switch {
		case exists, admitted[m]:
		case minuteLeft > 0 && hourLeft > 0:
			minuteLeft--
			hourLeft--
			admitted[m] = true
		default:
			continue
		}
		out[i].Admit = true
		fi := fieldIndex(c.Field)
		if fi < 0 {
			out[i].Pass = true
			continue
		}
		// the value must fit the device's values of this field, and a device that says an address must fit its addresses
		fits := func(si int, text string) (ok bool, record func()) {
			h := hashOf(b, text)
			var have []uint64
			if el, ok := b.index[m]; ok {
				if k := el.Value.(*known); k.vals != nil {
					if fb := &k.vals[si]; fb.n > 0 && now.Sub(fb.start) < valueWindow {
						have = fb.h[:fb.n]
					}
				}
			}
			mine := added[slot{m, si}]
			switch {
			case contains(have, h), contains(mine, h):
				return true, func() {}
			case len(have)+len(mine) < maxNewValuesPerHour:
				return true, func() { added[slot{m, si}] = append(added[slot{m, si}], h) }
			}
			return false, nil
		}
		okV, recV := fits(fi, c.Value)
		okIP, recIP := true, func() {}
		if c.MAC != "" && c.IP.IsValid() { // an observation with no MAC is already counted by its address
			okIP, recIP = fits(ipSlot, c.IP.String())
		}
		if okV && okIP {
			recV()
			recIP()
			out[i].Pass = true
		}
	}
	return out
}

// Seed tells the budget about devices that exist already (core's inventory at start): they are known, so they pass and do not
// count as new devices. Only the most recent maxKnown are kept.
func (f *FloodBudget) Seed(macs []string) {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	for _, s := range macs {
		m, ok := parseMAC(strings.ToLower(s))
		if !ok {
			continue
		}
		if _, known := f.b.index[m]; !known {
			f.b.remember(m)
		}
	}
}

func contains(s []uint64, h uint64) bool {
	for _, x := range s {
		if x == h {
			return true
		}
	}
	return false
}

// Commit records the devices and values Decide allowed for the same claims at the same time.
func (f *FloodBudget) Commit(claims []Claim, verdicts []Verdict, now time.Time) {
	for i, c := range claims {
		if i >= len(verdicts) || !verdicts[i].Admit {
			continue
		}
		m, ok := claimKey(c)
		if !ok {
			continue
		}
		f.b.admit(m, now)
		if verdicts[i].Pass {
			f.b.allowValue(m, c.Field, c.Value, now)
			if c.MAC != "" && c.IP.IsValid() {
				f.b.allowIP(m, c.IP.String(), now)
			}
		}
	}
}
