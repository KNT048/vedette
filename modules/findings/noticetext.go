package findings

import (
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
)

// The words of a status and of its reasons in English: the text the finding page shows (web findingStatus) and every message that
// speaks of a finding (alerts, reports, the AI) says, from this one place. TestStatusTextMatchesTheWeb keeps it equal to the page's.

// StatusName is the name of the open status of an urgency layer ("Public exploit available"); a value outside 1..5 reads as update
// recommended.
func StatusName(layer int) string {
	switch layer {
	case UrgencyUnderAttack:
		return "Under attack here"
	case UrgencyExploited:
		return "Exploited in the wild"
	case UrgencyPublicExploit:
		return "Public exploit available"
	case UrgencyCriticalEdge:
		return "Critical on an edge device"
	}
	return "Update recommended"
}

// StatusMeaning is the sentence that says what an open status asks of a person.
func StatusMeaning(layer int) string {
	switch layer {
	case UrgencyUnderAttack:
		return "Someone on your network sent this exploit, and this device is affected. Isolate or patch it now."
	case UrgencyExploited:
		return "Attackers use this flaw in real attacks. Patch it now."
	case UrgencyPublicExploit:
		return "Working exploit code is public. Patch it this week."
	case UrgencyCriticalEdge:
		return "A critical flaw that needs no login, on a device class attackers target first. Patch it now."
	}
	return "A known flaw affects this version; no sign of exploitation yet. Update when convenient."
}

// ReasonsLine is the urgency reasons of the view as one line, a layer at a time, most urgent first: "Exploited in the wild: CISA KEV
// (19 Nov 2026, fix due 3 Dec 2026), Rapid7 (20 Nov 2026) · Public exploit available: Metasploit (18 Nov 2026)". The reasons are the
// ones the finding page lists (View.Reasons, those at or below the stored layer). "" when there are none. A day of an intrusion alert is
// the box's own time (loc); the others are calendar days of their sources.
func (v View) ReasonsLine(loc *time.Location) string {
	var layers []int
	by := map[int][]ViewReason{}
	for _, r := range v.Reasons {
		if _, ok := by[r.Layer]; !ok {
			layers = append(layers, r.Layer)
		}
		by[r.Layer] = append(by[r.Layer], r)
	}
	slices.Sort(layers)
	var parts []string
	for _, l := range layers {
		var names []string
		listed := false
		for _, r := range by[l] {
			n := r.Name
			if !r.Since.IsZero() {
				day := orgtime.CalendarDay(r.Since)
				if l == UrgencyUnderAttack {
					day = orgtime.Day(r.Since, loc)
				}
				n += " (" + day
				if d, err := time.Parse(time.DateOnly, r.Due); err == nil {
					n += ", fix due " + orgtime.CalendarDay(d)
				}
				n += ")"
			}
			listed = listed || r.Source == "cisa-kev"
			names = append(names, n)
		}
		text := StatusName(l) + ": " + strings.Join(names, ", ")
		if l == UrgencyExploited && !listed {
			text += ", not yet on CISA's list"
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " · ")
}
