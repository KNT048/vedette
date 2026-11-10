package capture

// Limits on new devices (SYS-6): the source MAC of every frame is chosen by whoever is on the wire, and every new MAC
// the sensor reports becomes an unapproved device, an audit row and an event.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

func strictCfg(book *deviceBook) engineConfig {
	return engineConfig{OwnMACs: own.OwnMACs, OwnIPs: own.OwnIPs, Devices: book}
}

func arpFrom(m pktgen.MAC, ip netip.Addr) []byte {
	return pktgen.ARP(pktgen.Bcast, 1, m, ip, pktgen.MAC{}, pktgen.RouterIP)
}

func macOf(a, b, c byte) pktgen.MAC { return pktgen.MAC{0x00, 0x16, 0x3e, a, b, c} }

func reportedDevices(obs []observe.Observation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		out[o.AssetHint.MAC] = true
	}
	return out
}

// (a) A new MAC is reported only after two frames at least two seconds apart.
func TestNewMACNeedsTwoFramesTwoSecondsApart(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	frame := func(at time.Duration) {
		e.Handle(Packet{At: pktgen.T0.Add(at), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
	}
	frame(0)
	frame(time.Second) // too soon
	frame(-time.Hour)  // a timestamp that goes back is not a second sighting
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != 0 {
		t.Fatalf("reported before the second frame: %+v", obs)
	}
	frame(2 * time.Second)
	obs, _ := e.Drain(pktgen.T0, false)
	if !reportedDevices(obs)[pktgen.PC.String()] {
		t.Fatalf("not reported after the second frame: %+v", obs)
	}
	if e.Counters()["new_macs_unconfirmed"] != 3 {
		t.Errorf("counters %v", e.Counters())
	}
}

// (a) One frame per random MAC, sustained for an hour, creates nothing.
func TestOneFramePerMACFloodCreatesNothing(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	devices := map[string]bool{}
	for minute := range 60 {
		at := pktgen.T0.Add(time.Duration(minute) * time.Minute)
		for i := range 100 {
			e.Handle(Packet{At: at.Add(time.Duration(i) * 100 * time.Millisecond), Data: arpFrom(macOf(byte(minute), byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
		for m := range reportedDevices(first(e.Drain(at.Add(59*time.Second), false))) {
			devices[m] = true
		}
	}
	if len(devices) != 0 {
		t.Errorf("%d devices from MACs that each sent a single frame", len(devices))
	}
}

func first(obs []observe.Observation, _ []MetaItem) []observe.Observation { return obs }

// (b) The set of devices already reported belongs to the Service: a new Engine (settings change, capture reopened after
// an error) neither forgets them nor hands a flood a fresh budget. Known devices keep being reported during the flood.
func TestKnownDevicesAreStillReportedAfterARestartDuringAFlood(t *testing.T) {
	t.Parallel()
	book := newDeviceBook(defaultLimits)
	before, _ := newEngine(strictCfg(book))
	for _, at := range []time.Duration{0, 3 * time.Second} {
		before.Handle(Packet{At: pktgen.T0.Add(at), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
	}
	if obs, _ := before.Drain(pktgen.T0, true); !reportedDevices(obs)[pktgen.PC.String()] {
		t.Fatal("the PC was not reported before the restart")
	}
	e, _ := newEngine(strictCfg(book)) // the same box after a settings change
	pcSeen, flooded := 0, map[string]bool{}
	for minute := range 10 {
		at := pktgen.T0.Add(time.Duration(minute+1) * time.Hour)
		for _, shift := range []time.Duration{0, 3 * time.Second} { // the flood: 200 MACs, two frames each, every hour
			for i := range 200 {
				e.Handle(Packet{At: at.Add(shift), Data: arpFrom(macOf(byte(minute), byte(i>>8), byte(i)), netip.AddrFrom4([4]byte{10, 9, byte(minute), byte(i)}))})
			}
		}
		e.Handle(Packet{At: at.Add(10 * time.Second), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
		obs, _ := e.Drain(at.Add(11*time.Second), false)
		for m := range reportedDevices(obs) {
			if m == pktgen.PC.String() {
				pcSeen++
			} else {
				flooded[m] = true
			}
		}
	}
	if pcSeen != 10 { // once an hour (the repeat filter holds a sighting for 15 minutes), flood or not
		t.Errorf("the PC was reported %d times in 10 flooded hours, want 10", pcSeen)
	}
	if e.Counters()["new_macs_dropped"] == 0 {
		t.Errorf("the flood was not counted: %v", e.Counters())
	}
	if len(flooded) > maxNewMACsPerMinute*10 {
		t.Errorf("%d flood devices got through in 10 hours", len(flooded))
	}
}

// (c) At most maxNewMACsPerHour new devices an hour; after that new MACs are only counted, known ones go on, and the next
// hour the budget is back (a flood starves real new devices for the rest of the hour at most).
func TestHourlyCeilingOfNewDevices(t *testing.T) {
	t.Parallel()
	book := newDeviceBook(bookLimits{PerMinute: 1 << 20, PerHour: maxNewMACsPerHour, ConfirmAfter: confirmAfter})
	e, _ := newEngine(strictCfg(book))
	const n = maxNewMACsPerHour + 100
	for _, shift := range []time.Duration{0, 3 * time.Second} {
		for i := range n {
			e.Handle(Packet{At: pktgen.T0.Add(time.Duration(i)*time.Second/10 + shift), Data: arpFrom(macOf(byte(i>>16), byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
	}
	e.Handle(Packet{At: pktgen.T0.Add(time.Minute), Data: arpFrom(macOf(0, 0, 5), netip.MustParseAddr("10.1.1.1"))}) // device 5 is known
	obs, _ := e.Drain(pktgen.T0, true)
	seen := reportedDevices(obs)
	if len(seen) != maxNewMACsPerHour {
		t.Errorf("%d devices reported, want %d", len(seen), maxNewMACsPerHour)
	}
	if got := e.Counters()["new_macs_dropped"]; got != 100 {
		t.Errorf("new_macs_dropped = %d, want 100", got)
	}
	var again bool
	for _, o := range obs {
		again = again || (o.AssetHint.IP == netip.MustParseAddr("10.1.1.1"))
	}
	if !again {
		t.Error("a known device was refused after the ceiling")
	}
	// an hour later the budget is back
	later := pktgen.T0.Add(time.Hour + time.Minute)
	e.Handle(Packet{At: later, Data: arpFrom(macOf(0xee, 0, 1), netip.IPv4Unspecified())})
	e.Handle(Packet{At: later.Add(3 * time.Second), Data: arpFrom(macOf(0xee, 0, 1), netip.IPv4Unspecified())})
	if obs, _ := e.Drain(later.Add(time.Minute), true); !reportedDevices(obs)[macOf(0xee, 0, 1).String()] {
		t.Error("an hour after the ceiling, a new device was still refused")
	}
}

// The per-minute budget is a burst limit on top of the daily one.
func TestNewDevicesPerMinuteBudget(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	for _, shift := range []time.Duration{0, 3 * time.Second} {
		for i := range 300 {
			e.Handle(Packet{At: pktgen.T0.Add(shift), Data: arpFrom(macOf(1, byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
	}
	if got := len(reportedDevices(first(e.Drain(pktgen.T0, true)))); got != maxNewMACsPerMinute {
		t.Errorf("%d devices in one minute, want %d", got, maxNewMACsPerMinute)
	}
}

func bookMAC(prefix byte, n uint32) mac {
	var m mac
	m[0] = prefix
	binary.BigEndian.PutUint32(m[2:], n)
	return m
}

// (b) A full book forgets the least recently seen device first; it does not clear everything.
func TestBookEvictsTheLeastRecentlySeenFirst(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(bookLimits{PerMinute: 1 << 30, PerHour: 1 << 30})
	for i := range uint32(maxKnown + 3) {
		if b.admit(bookMAC(0, i), pktgen.T0) != admitNew {
			t.Fatalf("device %d was not new", i)
		}
	}
	if b.size() != maxKnown {
		t.Fatalf("the book holds %d devices, want %d", b.size(), maxKnown)
	}
	if b.admit(bookMAC(0, maxKnown+2), pktgen.T0) != admitKnown || b.admit(bookMAC(0, 3), pktgen.T0) != admitKnown {
		t.Error("a recent device was forgotten")
	}
	// device 0 was evicted; seen again it is new again (the two-frame rule and the budgets apply to it as to any new device)
	if b.admit(bookMAC(0, 0), pktgen.T0) != admitNew {
		t.Error("the least recently seen device was not the one forgotten")
	}
	if b.size() != maxKnown {
		t.Errorf("the book holds %d devices after a re-admission", b.size())
	}
}

// A device heard all along is not evicted before stale ones: the order is by last use, not by admission.
func TestActiveDevicesAreNotEvictedBeforeStaleOnes(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(bookLimits{PerMinute: 1 << 30, PerHour: 1 << 30}) // budgets lifted to compress 50 days
	devs := []mac{bookMAC(0x3c, 1), bookMAC(0x3c, 2), bookMAC(0x3c, 3)}
	for _, m := range devs {
		b.admit(m, pktgen.T0)
	}
	for i := range uint32(maxKnown) {
		if i%1000 == 0 { // the real devices keep talking
			for _, m := range devs {
				b.admit(m, pktgen.T0)
			}
		}
		b.admit(bookMAC(0x02, i), pktgen.T0)
	}
	for _, m := range devs {
		if !b.hasKnown(m) {
			t.Errorf("%v was forgotten while stale flood MACs were kept", m)
		}
	}
}

// (a) First sightings are a FIFO ring: a full ring evicts the oldest first sighting and never refuses a new MAC.
func TestFirstSightingsRingEvictsTheOldestAndNeverRefuses(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	for i := range uint32(maxFirstSightings + 100) {
		if got := b.admit(bookMAC(0x02, i), pktgen.T0); got != admitWait {
			t.Fatalf("first sighting %d: %v, want a wait", i, got)
		}
	}
	if b.waiting() != maxFirstSightings {
		t.Errorf("the ring holds %d first sightings, want %d", b.waiting(), maxFirstSightings)
	}
	later := pktgen.T0.Add(3 * time.Second)
	if b.admit(bookMAC(0x02, 0), later) != admitWait { // among the 100 evicted: a first sighting again
		t.Error("an evicted first sighting was confirmed")
	}
	if b.admit(bookMAC(0x02, 101), later) != admitNew { // still in the ring (the line above took the slot of 100)
		t.Error("a first sighting still in the ring was not confirmed")
	}
}

// (a) A first sighting lives two hours: a device that talks in bursts tens of minutes apart is still confirmed, and one
// that comes back after the TTL starts over.
func TestFirstSightingLivesTwoHours(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	m := bookMAC(0x3c, 1)
	b.admit(m, pktgen.T0)
	if b.admit(m, pktgen.T0.Add(firstSightingTTL-time.Minute)) != admitNew {
		t.Error("a second frame inside the TTL did not confirm the device")
	}
	o := bookMAC(0x3c, 2)
	b.admit(o, pktgen.T0)
	if b.admit(o, pktgen.T0.Add(firstSightingTTL+time.Minute)) != admitWait {
		t.Error("a first sighting older than the TTL was still taken for a first frame")
	}
}

// Every frame of the flood costs the same however full the book is: no scan of a map on the hot path. The work is
// counted, not timed: the ring and the LRU have no loop, so a full book and an empty one differ only by constants;
// the generous bound on the timing guards against a scan coming back (the old one cost ~20,000 steps per frame).
func TestFullBookCostsLikeAnEmptyOne(t *testing.T) {
	t.Parallel()
	const probes = 2000
	measure := func(fill uint32) time.Duration {
		b := newDeviceBook(defaultLimits)
		for i := range fill {
			b.admit(bookMAC(0x02, i), pktgen.T0)
		}
		best := time.Duration(1 << 62)
		for round := range 5 {
			start := time.Now()
			for i := range uint32(probes) {
				b.admit(bookMAC(0x06+byte(round), i), pktgen.T0.Add(time.Second))
			}
			best = min(best, time.Since(start)/probes)
		}
		return best
	}
	roomy := measure(maxFirstSightings - 5*probes - 1)
	full := measure(maxFirstSightings)
	t.Logf("admit of a new MAC: %v with room, %v when the ring is full", roomy, full)
	if full > 10*max(roomy, 500*time.Nanosecond) {
		t.Errorf("a new MAC costs %v when the ring is full vs %v with room", full, roomy)
	}
}

func BenchmarkAdmitNewMACOnAFullBook(b *testing.B) {
	book := newDeviceBook(defaultLimits)
	for i := range uint32(maxFirstSightings) {
		book.admit(bookMAC(0x02, i), pktgen.T0)
	}
	b.ResetTimer()
	for i := range b.N {
		book.admit(bookMAC(0x06, uint32(i)), pktgen.T0.Add(time.Second))
	}
}

// A flood of one-frame MACs, refilling the ring every few minutes, does not blind discovery: a real device that sends a
// frame every 30 s is confirmed, because its own frames stay in the ring while fewer than 20,000 other MACs arrive between two.
func TestFirstSightingFloodDoesNotBlockRealNewDevices(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	legit := mac{0x3c, 0x07, 0x54, 0, 0, 0x99}
	n := uint32(0)
	got := map[admission]int{}
	for cycle := range 3 { // 30 minutes
		start := pktgen.T0.Add(time.Duration(cycle) * 10 * time.Minute)
		for range maxFirstSightings - 1000 { // below the bound of CONTRACT: fewer than 20,000 between two frames
			n++
			b.admit(bookMAC(0x02, n), start)
		}
		for s := 1; s < 600; s += 30 {
			got[b.admit(legit, start.Add(time.Duration(s)*time.Second))]++
		}
	}
	if got[admitNew] == 0 {
		t.Errorf("a real device heard every 30 s for 30 min was never admitted (%v)", got)
	}
}

// A device heard in bursts shorter than 2 s, a quarter of an hour apart (SSDP NOTIFY, DHCP rebinding, mDNS announces), is
// discovered.
func TestBurstOnlyDeviceIsDiscovered(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	for burst := range 12 { // 3 hours
		start := pktgen.T0.Add(time.Duration(burst) * 15 * time.Minute)
		for _, d := range []time.Duration{0, 300 * time.Millisecond, 1500 * time.Millisecond} {
			e.Handle(Packet{At: start.Add(d), Data: arpFrom(pktgen.Laptop, pktgen.LaptopIP)})
		}
	}
	if !reportedDevices(first(e.Drain(pktgen.T0, true)))[pktgen.Laptop.String()] {
		t.Errorf("a device heard in 36 frames over 3 hours was never reported; counters %v", e.Counters())
	}
}

// A device that sends one frame per minute is discovered.
func TestOneFramePerMinuteIsDiscovered(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	for i := range 3 {
		e.Handle(Packet{At: pktgen.T0.Add(time.Duration(i) * time.Minute), Data: arpFrom(pktgen.Laptop, pktgen.LaptopIP)})
	}
	if !reportedDevices(first(e.Drain(pktgen.T0, true)))[pktgen.Laptop.String()] {
		t.Error("a device with one frame per minute was not discovered")
	}
}

// A known device passes during a flood, with the budgets spent and the ring full.
func TestKnownDevicePassesDuringFlood(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	pc := bookMAC(0x3c, 7)
	b.admit(pc, pktgen.T0)
	if b.admit(pc, pktgen.T0.Add(3*time.Second)) != admitNew {
		t.Fatal("setup: device not admitted")
	}
	for i := range uint32(maxFirstSightings + 10) {
		b.admit(bookMAC(0x02, i), pktgen.T0.Add(4*time.Second))
	}
	if b.admit(pc, pktgen.T0.Add(5*time.Second)) != admitKnown {
		t.Error("a known device was refused during a flood")
	}
}

// A flood of MACs that send two frames 2 s apart spends the hour's budget, not the day's: a real device that joins an hour
// later is admitted.
func TestTwoFrameFloodDoesNotStarveRealNewDevicesBeyondTheHour(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	n := uint32(0)
	for minute := range 20 {
		at := pktgen.T0.Add(time.Duration(minute) * time.Minute)
		for range maxNewMACsPerMinute {
			n++
			b.admit(bookMAC(0x02, n), at)
			b.admit(bookMAC(0x02, n), at.Add(confirmAfter))
		}
	}
	if b.hourN != maxNewMACsPerHour {
		t.Fatalf("setup: the hour's budget is %d, want it spent (%d)", b.hourN, maxNewMACsPerHour)
	}
	legit := mac{0x3c, 0x07, 0x54, 0, 0, 0x77}
	at := pktgen.T0.Add(time.Hour + 20*time.Minute)
	b.admit(legit, at)
	if got := b.admit(legit, at.Add(5*time.Second)); got != admitNew {
		t.Errorf("a real device joining after the hour was refused (%d)", got)
	}
}

// Per known MAC and field at most maxNewValuesPerHour new values an hour pass; repeats of a value already passed are not
// new; the next hour the budget is back; other fields and other MACs have budgets of their own.
func TestNewValuesPerMACAndFieldAreBounded(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(bookLimits{PerMinute: 1 << 30, PerHour: 1 << 30})
	m, other := bookMAC(0x3c, 1), bookMAC(0x3c, 2)
	b.admit(m, pktgen.T0)
	b.admit(other, pktgen.T0)
	allowed := 0
	for i := range 100 {
		if b.allowValue(m, observe.Hostname, fmt.Sprintf("n%d", i%50), pktgen.T0.Add(time.Duration(i)*time.Second)) {
			allowed++
		}
	}
	if want := 2 * maxNewValuesPerHour; allowed != want { // the first four names, then only their repeats (i = 50..53)
		t.Errorf("%d values passed in an hour, want %d (%d new + their repeats)", allowed, want, maxNewValuesPerHour)
	}
	if !b.allowValue(m, observe.Model, "x", pktgen.T0) || !b.allowValue(other, observe.Hostname, "x", pktgen.T0) {
		t.Error("another field or another MAC was held back by this budget")
	}
	if !b.allowValue(m, observe.Hostname, "fresh", pktgen.T0.Add(time.Hour+time.Second)) {
		t.Error("the budget did not come back after an hour")
	}
}

// One admitted MAC that sends a new DHCP name in every frame passes on at most maxNewValuesPerHour names an hour, counted
// as values_dropped.
func TestOneKnownMACCannotFloodNewNames(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	dhcp := func(at time.Duration, name string) {
		req := pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 3, Hostname: name})
		e.Handle(Packet{At: pktgen.T0.Add(at), Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.PC, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), 68, 67, req)})
	}
	dhcp(0, "pc")
	dhcp(3*time.Second, "pc")
	for i := range 2000 {
		dhcp(4*time.Second+time.Duration(i)*time.Millisecond, fmt.Sprintf("n%05d", i))
	}
	names := 0
	for _, o := range first(e.Drain(pktgen.T0.Add(time.Minute), true)) {
		if o.Field == observe.Hostname {
			names++
		}
	}
	if names > maxNewValuesPerHour {
		t.Errorf("%d names passed in one hour, want at most %d", names, maxNewValuesPerHour)
	}
	if got := e.Counters()["values_dropped"]; got < 1990 {
		t.Errorf("values_dropped = %d", got)
	}
}

// Low: a timestamp earlier than the start of the window does not reset the budget (a crafted recording with times that
// keep going back would lift the cap).
func TestBackwardTimestampsDoNotResetTheBudget(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{OwnMACs: own.OwnMACs, Devices: newDeviceBook(bookLimits{PerMinute: maxNewMACsPerMinute, PerHour: maxNewMACsPerHour})})
	for i := range 600 {
		e.Handle(Packet{At: pktgen.T0.Add(time.Duration(600-i) * time.Millisecond), Data: arpFrom(macOf(1, byte(i>>8), byte(i)), netip.IPv4Unspecified())})
	}
	if got := len(reportedDevices(first(e.Drain(pktgen.T0, true)))); got > maxNewMACsPerMinute {
		t.Errorf("%d new MACs within 0.6 s of capture time", got)
	}
}
