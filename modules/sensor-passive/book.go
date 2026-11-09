package sensorpassive

import (
	"container/list"
	"hash/maphash"
	"sync"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// Limits on new devices and on what one device may say (SYS-6: every source MAC and every field on the wire is
// attacker-controlled, and every new MAC the sensor reports becomes an unapproved device, an audit row and an event).
// Every operation of the book is O(1) under its lock: it runs inside Engine.Handle, on the capture goroutine.
const (
	maxNewMACsPerMinute = 60              // a burst of new devices one minute may add
	maxNewMACsPerHour   = 200             // all that an hour may add; after it new MACs are only counted
	confirmAfter        = 2 * time.Second // a MAC is new only after two frames this far apart: a one-frame random MAC creates nothing
	firstSightingTTL    = 2 * time.Hour   // a first sighting older than this is forgotten
	maxKnown            = 50000           // devices remembered as reported (LRU)
	maxFirstSightings   = 20000           // slots of the ring of first sightings (FIFO)
	maxNewValuesPerHour = 4               // per known MAC and field: new values the sensor passes on in an hour
	valueWindow         = time.Hour       // the window of maxNewValuesPerHour
	maxFields           = 6               // the fields of observe.Field
)

// bookLimits are the thresholds of a deviceBook. The zero value of ConfirmAfter means a MAC is accepted at its
// first frame (the unit tests of the engine use it; Service always uses defaultLimits).
type bookLimits struct {
	PerMinute, PerHour int
	ConfirmAfter       time.Duration
}

var defaultLimits = bookLimits{PerMinute: maxNewMACsPerMinute, PerHour: maxNewMACsPerHour, ConfirmAfter: confirmAfter}

// admission is what the book says about a source MAC.
type admission int

const (
	admitKnown   admission = iota // reported before: goes through
	admitNew                      // reported now for the first time
	admitWait                     // seen once; not yet reported
	admitRefused                  // over the budget: only counted
)

// firstSlot is one slot of the ring of first sightings; used is false for a free or a tombstoned slot.
type firstSlot struct {
	m    mac
	at   time.Time
	used bool
}

// known is the entry of a device the sensor has reported: its place in the LRU list and what it said this hour.
type known struct {
	m    mac
	owed bool                    // the vendor row of this device has not reached the inventory yet
	vals *[maxFields]fieldBudget // allocated with the first value
}

// fieldBudget counts the distinct values of one field of one MAC in the current window. Values are kept as keyed
// hashes (8 bytes each, seed chosen at start-up), not as text: 50,000 devices x 6 fields stay at a few megabytes.
type fieldBudget struct {
	start time.Time
	n     uint8
	h     [maxNewValuesPerHour]uint64
}

// deviceBook is the set of devices the sensor has already reported. It lives on the Service, so a new Engine
// (settings change, capture reopened after an error) does not forget it and does not hand the flood a fresh
// budget; it is in memory, so a process restart starts it empty (the inventory is not asked, see CONTRACT).
//
// First sightings are a fixed-capacity FIFO ring with a map MAC -> slot: a new one overwrites the oldest and is never
// refused. Known devices are an LRU (list + map): a seen device moves to the front, the least recently seen is evicted.
type deviceBook struct {
	mu   sync.Mutex
	lim  bookLimits
	seed maphash.Seed

	ring  []firstSlot
	head  int // the next slot to write; when the ring is full it holds the oldest first sighting
	slots map[mac]int

	lru   *list.List // of *known, most recently seen first
	index map[mac]*list.Element

	minute, hour   time.Time
	minuteN, hourN int
}

func newDeviceBook(lim bookLimits) *deviceBook {
	return &deviceBook{lim: lim, seed: maphash.MakeSeed(), ring: make([]firstSlot, maxFirstSightings), slots: map[mac]int{},
		lru: list.New(), index: map[mac]*list.Element{}}
}

// admit decides what to do with a source MAC seen at now. Known devices always pass (a flood must not blind the
// sensor to the devices that exist); a new one needs a second frame at least ConfirmAfter after its first while that
// is still in the ring, and a place in this minute's budget and this hour's.
func (b *deviceBook) admit(m mac, now time.Time) admission {
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.index[m]; ok {
		b.lru.MoveToFront(el)
		return admitKnown
	}
	if b.lim.ConfirmAfter > 0 {
		slot, seen := b.slots[m]
		if seen && now.Sub(b.ring[slot].at) > firstSightingTTL {
			b.free(slot)
			seen = false
		}
		if !seen {
			b.addFirst(m, now)
			return admitWait
		}
		if now.Sub(b.ring[slot].at) < b.lim.ConfirmAfter { // too soon, or a timestamp that went back
			return admitWait
		}
	}
	// A timestamp that goes back never resets a window: only time moving forward does.
	if b.minute.IsZero() || now.Sub(b.minute) >= time.Minute {
		b.minute, b.minuteN = now, 0
	}
	if b.hour.IsZero() || now.Sub(b.hour) >= time.Hour {
		b.hour, b.hourN = now, 0
	}
	if b.minuteN >= b.lim.PerMinute || b.hourN >= b.lim.PerHour {
		return admitRefused
	}
	b.minuteN++
	b.hourN++
	if slot, ok := b.slots[m]; ok {
		b.free(slot)
	}
	b.remember(m)
	return admitNew
}

// addFirst records a first sighting in the oldest slot of the ring.
func (b *deviceBook) addFirst(m mac, now time.Time) {
	if old := &b.ring[b.head]; old.used {
		delete(b.slots, old.m)
	}
	b.ring[b.head] = firstSlot{m: m, at: now, used: true}
	b.slots[m] = b.head
	b.head = (b.head + 1) % len(b.ring)
}

// free forgets the first sighting in slot, leaving a tombstone the ring reuses when its turn comes.
func (b *deviceBook) free(slot int) {
	delete(b.slots, b.ring[slot].m)
	b.ring[slot] = firstSlot{}
}

// remember adds m as the most recently seen device, forgetting the least recently seen when the book is full.
func (b *deviceBook) remember(m mac) {
	if b.lru.Len() >= maxKnown {
		last := b.lru.Back()
		delete(b.index, last.Value.(*known).m)
		b.lru.Remove(last)
	}
	b.index[m] = b.lru.PushFront(&known{m: m, owed: true})
}

// allowValue says whether the sensor may pass on value of field for the known device m: a value it already passed on in
// this window is a repeat and goes on to the repeat filter; a new one counts against maxNewValuesPerHour. One MAC
// that changes a name in every frame thus writes at most that many rows an hour, whatever the speed of the wire.
func (b *deviceBook) allowValue(m mac, field observe.Field, value string, now time.Time) bool {
	i := fieldIndex(field)
	if i < 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	el, ok := b.index[m]
	if !ok {
		return true
	}
	k := el.Value.(*known)
	if k.vals == nil {
		k.vals = new([maxFields]fieldBudget)
	}
	fb := &k.vals[i]
	if fb.n == 0 || now.Sub(fb.start) >= valueWindow {
		*fb = fieldBudget{start: now}
	}
	h := maphash.String(b.seed, value)
	for _, x := range fb.h[:fb.n] {
		if x == h {
			return true
		}
	}
	if int(fb.n) >= maxNewValuesPerHour {
		return false
	}
	fb.h[fb.n] = h
	fb.n++
	return true
}

func fieldIndex(f observe.Field) int {
	switch f {
	case observe.Hostname:
		return 0
	case observe.MAC:
		return 1
	case observe.Vendor:
		return 2
	case observe.Model:
		return 3
	case observe.OS:
		return 4
	case observe.Kind:
		return 5
	}
	return -1
}

// size is how many devices the book remembers.
func (b *deviceBook) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lru.Len()
}

// waiting is how many first sightings the ring holds.
func (b *deviceBook) waiting() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.slots)
}

// hasKnown reports whether m is a known device, without touching its place in the LRU.
func (b *deviceBook) hasKnown(m mac) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.index[m]
	return ok
}

// vendorOwed reports whether the vendor row of the known device m is still owed to the inventory. A device is owed its
// vendor from its admission until a delivery (or a refusal) of that row, so the debt survives the Engine that queued it.
func (b *deviceBook) vendorOwed(m mac) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	el, ok := b.index[m]
	return ok && el.Value.(*known).owed
}

// vendorDone says the vendor row of m reached the inventory, was refused by it, or does not exist.
func (b *deviceBook) vendorDone(m mac) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.index[m]; ok {
		el.Value.(*known).owed = false
	}
}
