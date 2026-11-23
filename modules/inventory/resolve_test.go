package inventory

import (
	"testing"
)

// The resolver's rules, case by case: a person's entry against an older, the same and a newer reading, read before or after the
// entry; two agents; a package against a banner; two installs of one source; nmap's guess; "not installed"; removal.
func TestResolve_Rules(t *testing.T) {
	t.Parallel()
	const (
		before = "2026-11-01T10:00:00.000Z"
		set    = "2026-11-02T10:00:00.000Z" // when the person set the entry or the mark
		after  = "2026-11-03T10:00:00.000Z"
	)
	entry := func(v, pkg string) Reading {
		return Reading{Source: sourceManual, Display: "OpenSSH", Version: v, PkgVersion: pkg, SetBy: "op@example.com", Confidence: 1, FirstSeen: set, SeenAt: set}
	}
	read := func(src, inst, v, pkg, first string) Reading {
		return Reading{Source: src, Instance: inst, Display: "OpenSSH", Version: v, PkgVersion: pkg, Packaged: pkg != "", Confidence: 0.9, FirstSeen: first, SeenAt: after}
	}
	present := LineState{State: statePresent}
	for _, c := range []struct {
		name     string
		line     LineState
		readings []Reading
		// want
		source, version string
		lapsed          bool
		matched         []string // versions of Matched
		state           string
		unmarked        bool
	}{
		{name: "entry against an older reading read after it", line: present,
			readings: []Reading{entry("10.2p1", ""), read("nmap", "", "9.6p1", "", after)},
			source:   sourceManual, version: "10.2p1", matched: []string{"9.6p1"}, state: statePresent},
		{name: "entry against the same release read after it: the reading adds its package release", line: present,
			readings: []Reading{entry("10.2p1", ""), read("osquery", "", "10.2p1", "1:10.2p1-2ubuntu3.8", after)},
			source:   "osquery", version: "10.2p1", state: statePresent},
		{name: "a less precise reading of the person's release keeps the person's version", line: present,
			readings: []Reading{entry("9.6p1", ""), read("nmap", "tcp/22", "9.6", "", after)},
			source:   sourceManual, version: "9.6p1", state: statePresent},
		{name: "SNMP agreeing with the person leaves the person's value", line: present,
			readings: []Reading{entry("10.2", ""), read("snmp", "", "10.2", "", after)},
			source:   sourceManual, version: "10.2", state: statePresent},
		{name: "the agent's package of the person's release is the line, the banner is not", line: present,
			readings: []Reading{entry("10.2", "10.2_p1-r1"), read("nmap", "tcp/22", "10.2", "", before), read("osquery", "", "10.2p1", "10.2_p1-r1", set)},
			source:   "osquery", version: "10.2p1", state: statePresent},
		{name: "entry against a newer reading read after it: the entry lapses", line: present,
			readings: []Reading{entry("10.2p1", ""), read("nmap", "", "10.3p1", "", after)},
			source:   "nmap", version: "10.3p1", lapsed: true, state: statePresent},
		{name: "entry against a newer banner already there when it was set: the entry holds and the banner does not match", line: present,
			readings: []Reading{entry("9.6p1", ""), read("nmap", "", "10.2p1", "", before)},
			source:   sourceManual, version: "9.6p1", state: statePresent},
		{name: "entry against a newer release an agent reports again after it: the entry lapses (the dialog's promise)", line: present,
			readings: []Reading{entry("9.6p1", ""), read("osquery", "", "10.2p1", "", before)},
			source:   "osquery", version: "10.2p1", lapsed: true, state: statePresent},
		{name: "entry against a newer agent reading not reported since it was set: the entry holds", line: present,
			readings: []Reading{entry("9.6p1", ""), func() Reading { r := read("osquery", "", "10.2p1", "", before); r.SeenAt = before; return r }()},
			source:   sourceManual, version: "9.6p1", state: statePresent},
		{name: "entry against a version that cannot be ordered", line: present,
			readings: []Reading{entry("10.2p1", ""), read("snmp", "", "snapshot-2026", "", after)},
			source:   sourceManual, version: "10.2p1", matched: []string{"snapshot-2026"}, state: statePresent},
		{name: "a package release update of the person's release ends the entry", line: present,
			readings: []Reading{entry("10.2p1", "1:10.2p1-2ubuntu3.5"), read("osquery", "", "10.2p1", "1:10.2p1-2ubuntu3.8", after)},
			source:   "osquery", version: "10.2p1", lapsed: true, state: statePresent},
		{name: "two agents: one class, the newer release, the other still matched", line: present,
			readings: []Reading{read("osquery", "", "1.0", "", before), read("wazuh", "", "1.1", "", before)},
			source:   "wazuh", version: "1.1", matched: []string{"1.0"}, state: statePresent},
		{name: "the package beats the banner; the banner's other release still matches", line: present,
			readings: []Reading{read("nmap", "tcp/22", "9.6p1", "", before), read("osquery", "", "10.2p1", "1:10.2p1-2ubuntu3.8", before)},
			source:   "osquery", version: "10.2p1", matched: []string{"9.6p1"}, state: statePresent},
		{name: "the banner of the same release is no difference", line: present,
			readings: []Reading{read("nmap", "tcp/22", "10.2p1", "", before), read("osquery", "", "10.2p1", "1:10.2p1-2ubuntu3.8", before)},
			source:   "osquery", version: "10.2p1", state: statePresent},
		{name: "SNMP beats a banner", line: present,
			readings: []Reading{read("nmap", "", "7.4.1", "", before), read("snmp", "", "7.2.5", "", before)},
			source:   "snmp", version: "7.2.5", matched: []string{"7.4.1"}, state: statePresent},
		{name: "two installed versions of one source: the newest is the line, the other matches", line: present,
			readings: []Reading{read("osquery", "@6.12.116-1", "6.12.116", "6.12.116-1", before), read("osquery", "@6.12.117", "6.12.117", "", before)},
			source:   "osquery", version: "6.12.117", matched: []string{"6.12.116"}, state: statePresent},
		{name: "a guess only when nothing else reads it", line: present,
			readings: []Reading{read("nmap", instanceOSGuess, "", "", before), read("nmap", "tcp/445", "10.0", "", before)},
			source:   "nmap", version: "10.0", state: statePresent},
		{name: "not installed holds while the readings are the ones the person saw", line: LineState{State: stateNotInstalled, NotInstalledAt: set},
			readings: []Reading{read("nmap", "", "10.2", "", before)},
			source:   "nmap", version: "10.2", state: stateNotInstalled},
		{name: "a reading first seen after the mark is a new install", line: LineState{State: stateNotInstalled, NotInstalledAt: set},
			readings: []Reading{read("nmap", "", "10.3", "", after)},
			source:   "nmap", version: "10.3", state: statePresent, unmarked: true},
		{name: "no reading: removed", line: present, state: stateRemoved},
		{name: "a removed line read again is present", line: LineState{State: stateRemoved},
			readings: []Reading{read("osquery", "", "1.0", "", after)},
			source:   "osquery", version: "1.0", state: statePresent},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			res := Resolve(c.line, c.readings)
			if res.State != c.state || res.Unmarked != c.unmarked || (res.Lapsed != nil) != c.lapsed {
				t.Fatalf("state %q unmarked %v lapsed %v, want %q %v %v", res.State, res.Unmarked, res.Lapsed != nil, c.state, c.unmarked, c.lapsed)
			}
			if c.state == stateRemoved {
				if res.Live {
					t.Fatal("a removed line has no value")
				}
				return
			}
			if res.Effective.Source != c.source || res.Effective.Version != c.version {
				t.Fatalf("effective %s %q, want %s %q", res.Effective.Source, res.Effective.Version, c.source, c.version)
			}
			var got []string
			for _, m := range res.Matched {
				got = append(got, m.Version)
			}
			if len(got) != len(c.matched) || res.Differs != (len(c.matched) > 0) {
				t.Fatalf("matched %v (differs %v), want %v", got, res.Differs, c.matched)
			}
			for i := range got {
				if got[i] != c.matched[i] {
					t.Fatalf("matched %v, want %v", got, c.matched)
				}
			}
		})
	}
}

// The resolver does not depend on the order its readings come in.
func TestResolve_OrderFree(t *testing.T) {
	t.Parallel()
	rs := []Reading{
		{Source: "osquery", Version: "1.0", FirstSeen: "2026-11-01T10:00:00.000Z", SeenAt: "2026-11-03T10:00:00.000Z"},
		{Source: "wazuh", Version: "1.0.1", FirstSeen: "2026-11-01T10:00:00.000Z", SeenAt: "2026-11-02T10:00:00.000Z"},
		{Source: "nmap", Instance: "tcp/80", Version: "0.9", FirstSeen: "2026-11-01T10:00:00.000Z", SeenAt: "2026-11-03T10:00:00.000Z"},
		{Source: sourceManual, Version: "1.0", FirstSeen: "2026-11-02T10:00:00.000Z", SeenAt: "2026-11-02T10:00:00.000Z"},
	}
	want := Resolve(LineState{State: statePresent}, rs)
	for i := range rs {
		turned := append(append([]Reading{}, rs[i:]...), rs[:i]...)
		got := Resolve(LineState{State: statePresent}, turned)
		if got.Effective != want.Effective || len(got.Matched) != len(want.Matched) {
			t.Fatalf("rotation %d: %+v, want %+v", i, got.Effective, want.Effective)
		}
	}
}
