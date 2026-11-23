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

// ReasonsLine is the urgency reasons of the view as one line, built the way the finding page builds its line (ReasonsLine.tsx): a layer at a
// time, most urgent first, each with its sources ("name, detail"), the earliest date of the layer, and after it "not yet in CISA KEV" (an
// exploited layer with no CISA entry) and "fix by <day>" (the earliest day a list asks for): "Exploited in the wild: Rapid7, Mandiant
// (19 Nov); not yet in CISA KEV · Public exploit available: GitHub, 244 stars (18 Nov)". The reasons are the ones the page lists
// (View.Reasons: the layers at or below the stored one, those with a date). "" when there are none.
func (v View) ReasonsLine() string {
	var layers []int
	by := map[int][]ViewReason{}
	for _, r := range v.Reasons {
		if r.Since.IsZero() {
			continue // the page lists no reason without a date
		}
		if _, ok := by[r.Layer]; !ok {
			layers = append(layers, r.Layer)
		}
		by[r.Layer] = append(by[r.Layer], r)
	}
	slices.Sort(layers)
	var parts []string
	for _, l := range layers {
		var names []string
		var first time.Time
		var due string
		listed := false
		for _, r := range by[l] {
			n := r.Name
			if d := clipBytes(r.Detail, 120); d != "" {
				n += ", " + d
			}
			names = append(names, n)
			if first.IsZero() || r.Since.Before(first) {
				first = r.Since
			}
			if _, err := time.Parse(time.DateOnly, r.Due); err == nil && (due == "" || r.Due < due) {
				due = r.Due
			}
			listed = listed || r.Source == "cisa-kev"
		}
		text := StatusName(l) + ": " + strings.Join(names, ", ") + " (" + orgtime.CalendarShort(first) + ")"
		if l == UrgencyExploited && !listed {
			text += "; not yet in CISA KEV"
		}
		if d, err := time.Parse(time.DateOnly, due); err == nil {
			text += "; fix by " + orgtime.CalendarDay(d)
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " · ")
}
