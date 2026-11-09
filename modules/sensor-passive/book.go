package sensorpassive

import (
	"sync"
	"time"
)

// Limits on new devices (SYS-6: every source MAC on the wire is attacker-controlled, and every new MAC the sensor
// reports becomes an unapproved device, an audit row and an event).
const (
	maxNewMACsPerMinute = 60               // a burst of new devices one minute may add
	maxNewMACsPerDay    = 1000             // all that a day may add; after it new MACs are only counted
	confirmAfter        = 2 * time.Second  // a MAC is new only after two frames this far apart: a one-frame random MAC creates nothing
	unconfirmedTTL      = 10 * time.Minute // a first sighting older than this is forgotten
	maxKnown            = 50000            // devices remembered as reported; the oldest is forgotten first
	maxUnconfirmed      = 20000            // MACs seen once, waiting for a second frame
)

// bookLimits are the thresholds of a deviceBook. The zero value of ConfirmAfter means a MAC is accepted at its
// first frame (the unit tests of the engine use it; Service always uses defaultLimits).
type bookLimits struct {
	PerMinute, PerDay int
	ConfirmAfter      time.Duration
}

var defaultLimits = bookLimits{PerMinute: maxNewMACsPerMinute, PerDay: maxNewMACsPerDay, ConfirmAfter: confirmAfter}

// admission is what the book says about a source MAC.
type admission int

const (
	admitKnown   admission = iota // reported before: goes through
	admitNew                      // reported now for the first time
	admitWait                     // seen once; not yet reported
	admitRefused                  // over the budget or the table is full: only counted
)

// deviceBook is the set of devices the sensor has already reported. It lives on the Service, so a new Engine
// (settings change, capture reopened after an error) does not forget it and does not hand the flood a fresh
// budget; it is in memory, so a process restart starts it empty (the inventory is not asked, see CONTRACT).
type deviceBook struct {
	mu  sync.Mutex
	lim bookLimits

	known map[mac]struct{}
	ring  []mac // known, oldest first (a ring of at most maxKnown)
	head  int

	first map[mac]time.Time // first sighting of MACs not yet reported

	minute  time.Time
	minuteN int
	day     time.Time
	dayN    int
}

func newDeviceBook(lim bookLimits) *deviceBook {
	return &deviceBook{lim: lim, known: map[mac]struct{}{}, first: map[mac]time.Time{}}
}

// admit decides what to do with a source MAC seen at now. Known devices always pass (a flood must not blind the
// sensor to the devices that exist); a new one needs a second frame at least ConfirmAfter later, a place in this
// minute's budget and in today's.
func (b *deviceBook) admit(m mac, now time.Time) admission {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.known[m]; ok {
		return admitKnown
	}
	if b.lim.ConfirmAfter > 0 {
		t, seen := b.first[m]
		if seen && now.Sub(t) > unconfirmedTTL {
			seen = false
		}
		if !seen {
			if _, replacing := b.first[m]; !replacing && len(b.first) >= maxUnconfirmed {
				b.dropOldFirst(now)
				if len(b.first) >= maxUnconfirmed {
					return admitRefused
				}
			}
			b.first[m] = now
			return admitWait
		}
		if now.Sub(t) < b.lim.ConfirmAfter { // too soon, or a timestamp that went back
			return admitWait
		}
	}
	// A timestamp that goes back never resets a window: only time moving forward does.
	if b.minute.IsZero() || now.Sub(b.minute) >= time.Minute {
		b.minute, b.minuteN = now, 0
	}
	if b.day.IsZero() || now.Sub(b.day) >= 24*time.Hour {
		b.day, b.dayN = now, 0
	}
	if b.minuteN >= b.lim.PerMinute || b.dayN >= b.lim.PerDay {
		return admitRefused
	}
	b.minuteN++
	b.dayN++
	delete(b.first, m)
	b.remember(m)
	return admitNew
}

func (b *deviceBook) dropOldFirst(now time.Time) {
	for k, t := range b.first {
		if now.Sub(t) > unconfirmedTTL {
			delete(b.first, k)
		}
	}
}

// remember adds m, forgetting the oldest device when the book is full.
func (b *deviceBook) remember(m mac) {
	if len(b.ring) < maxKnown {
		b.ring = append(b.ring, m)
	} else {
		delete(b.known, b.ring[b.head])
		b.ring[b.head] = m
		b.head = (b.head + 1) % maxKnown
	}
	b.known[m] = struct{}{}
}

// size is how many devices the book remembers.
func (b *deviceBook) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.known)
}
