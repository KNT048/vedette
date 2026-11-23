package inventory

import (
	"cmp"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/pkgrel"
)

// The software line resolver: one pure function from what the sources read of one software of one device (its readings) to what
// the device runs (the effective reading). Every write path that changes a reading (a list replaced, a person's entry set or
// cleared, a "not installed" mark) runs it in the same transaction and stores its result on inv_software (settleLine); the
// selfcheck and the tests recompute it and compare.
//
// The rules, in order:
//  1. A person's entry (source manual) is the line until a reading first seen after the entry was set reads a newer release; then
//     the entry lapses: it is deleted and the history says so. A reading that is older, the same release, or one that was already
//     there when the person set the entry never lapses it, nor does a pair of versions that cannot be ordered.
//  2. While the entry holds, an agent that reads the very release the person gave (with more or less detail, core/pkgrel) confirms
//     it: the agent's reading is the line's value, with the package release and the packaged flag the agent read. Any other source
//     that agrees leaves the person's value as it is.
//  3. Without an entry, the strongest source is the line: an agent (osquery, Wazuh, the box's own list) over what the device states
//     (SNMP, the OS it announces) over a scan's banner over traffic; nmap's OS fingerprint guess only when nothing else reads it.
//     Of several readings of the strongest source (two installs), the newest release.
//  4. Every other reading of another release still feeds matching (an older second install, another port), unless the person's
//     entry holds and the reading was already there when the person set it: the person looked at it and said otherwise. Such a
//     reading sets differs.
//  5. A "not installed" mark holds until a reading first seen after the mark (a new install, or the source reading a new release),
//     also across a removal. A line with no reading and no entry is removed; one that gets a reading again is present.

// The instances a source gives that mean something to the resolver.
const (
	instanceOSGuess = "os_guess" // nmap's OS fingerprint: a guess, never matched
	instanceOS      = "os"       // the operating system a network device states (SNMP, LLDP)
)

// The states of a software line.
const (
	statePresent      = "present"
	stateNotInstalled = "not_installed"
	stateRemoved      = "removed"
)

// sourceManual is the source of a person's entry.
const sourceManual = "manual"

// Reading is what one source reads now of one software line (inv_software_reading).
type Reading struct {
	Source, Instance             string
	Display, Version, PkgVersion string
	PkgSource, CPE, SetBy        string
	Packaged                     bool
	Confidence                   float64
	FirstSeen, SeenAt            string // fixed-width UTC times: text order is time order
	// Addr is the address a network scan read it at: "" for the device's main address and for every source that reads the whole
	// machine, else the id of one of the device's other addresses (INV-57). Two interfaces of one device read by one scan are two
	// readings.
	Addr string
}

// entry says whether the reading is a person's entry.
func (r Reading) entry() bool { return r.Source == sourceManual }

// guess says whether the reading is nmap's OS fingerprint guess.
func (r Reading) guess() bool { return r.Instance == instanceOSGuess }

// LineState is what a line holds besides its readings: its state and when a person marked it not installed.
type LineState struct {
	State          string
	NotInstalledAt string
}

// Resolution is the resolver's answer for one line.
type Resolution struct {
	// Effective is the line's value; meaningful only when Live (a line without readings keeps the value it had).
	Effective Reading
	Live      bool
	// Lapsed is the person's entry a newer reading outgrew (the caller deletes it), By that reading; nil when none lapsed.
	Lapsed, LapsedBy *Reading
	// Matched are the other readings that feed matching besides Effective (rule 4); Differs is len(Matched) > 0.
	Matched []Reading
	Differs bool
	// State is the line's state after the readings; Unmarked says a "not installed" mark ended (rule 5).
	State    string
	Unmarked bool
}

// readingRank is the place of a reading in rule 3, highest first.
func readingRank(r Reading) int {
	switch {
	case r.guess():
		return 1
	case r.entry():
		return 7
	}
	switch r.Source {
	case "osquery", "wazuh", "box", "agent":
		return 6
	case "snmp":
		return 5
	case "passive":
		if r.Instance == instanceOS {
			return 5 // the OS a device states over LLDP on its own vendor's card
		}
		return 2
	case "nmap", "scan":
		return 3
	}
	return 0
}

// agentSource says whether a reading source is one of the agents (they rank as one class, observe.ClassOf).
func agentSource(source string) bool {
	switch source {
	case "osquery", "wazuh", "box", "agent":
		return true
	}
	return false
}

// sourceClass is the class a reading source is shown and matched as: "agent" for the agents, the source otherwise.
func sourceClass(source string) string {
	if agentSource(source) {
		return "agent"
	}
	return source
}

// Resolve applies the rules above to the readings of one line.
func Resolve(line LineState, readings []Reading) Resolution {
	rs := slices.Clone(readings)
	// a stable order first, so the result never depends on the order the database returned
	slices.SortFunc(rs, func(a, b Reading) int {
		return cmp.Or(readingRank(b)-readingRank(a), strings.Compare(b.SeenAt, a.SeenAt), strings.Compare(a.Source, b.Source), strings.Compare(a.Instance, b.Instance),
			strings.Compare(a.Addr, b.Addr))
	})
	res := Resolution{State: line.State}
	var entry *Reading
	for i := range rs {
		if rs[i].entry() {
			entry = &rs[i]
			break
		}
	}
	// rule 1: the newest release among the readings first seen after the entry that read a newer release than it
	if entry != nil {
		var by *Reading
		for i := range rs {
			r := &rs[i]
			if r.entry() || r.guess() || r.FirstSeen <= entry.FirstSeen || !newerRelease(r.Version, r.PkgVersion, entry.Version, entry.PkgVersion) {
				continue
			}
			if by == nil || newerRelease(r.Version, r.PkgVersion, by.Version, by.PkgVersion) {
				by = r
			}
		}
		if by != nil {
			e, b := *entry, *by
			res.Lapsed, res.LapsedBy = &e, &b
			rs = slices.DeleteFunc(rs, Reading.entry)
			entry = nil
		}
	}
	// rule 5
	switch {
	case len(rs) == 0:
		res.State = stateRemoved
		return res
	case line.State == stateNotInstalled || line.State == stateRemoved && line.NotInstalledAt != "": // a removed line keeps the mark
		res.State = stateNotInstalled
		for _, r := range rs {
			if !r.entry() && r.FirstSeen > line.NotInstalledAt {
				res.State, res.Unmarked = statePresent, true
				break
			}
		}
	default:
		res.State = statePresent
	}
	res.Live = true
	// rules 2 and 3
	if entry != nil {
		res.Effective = *entry
		for _, r := range rs { // an agent's reading of the person's very release confirms it: it is the line
			if agentSource(r.Source) && r.Version != "" && pkgrel.Same(entry.Version, entry.PkgVersion, r.Version, r.PkgVersion) {
				res.Effective = r
				break
			}
		}
	} else {
		best := rs[0]
		for _, r := range rs[1:] {
			if readingRank(r) == readingRank(best) && newerRelease(r.Version, r.PkgVersion, best.Version, best.PkgVersion) {
				best = r
			}
		}
		res.Effective = best
	}
	// rule 4
	eff := res.Effective
	for _, r := range rs {
		if r.entry() || r.guess() || r.Source == eff.Source && r.Instance == eff.Instance && r.Addr == eff.Addr {
			continue
		}
		if pkgrel.Same(eff.Version, eff.PkgVersion, r.Version, r.PkgVersion) {
			continue
		}
		if entry != nil && r.FirstSeen <= entry.FirstSeen {
			continue // the person saw it when they set their version
		}
		res.Matched = append(res.Matched, r)
	}
	res.Differs = len(res.Matched) > 0
	return res
}
