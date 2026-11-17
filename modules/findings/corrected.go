package findings

import "strings"

// correctionWhy names the person's corrections behind a match of one software row (inventory INV-40, review r1 M3 and r2 M-B, L-a of
// #950), so a finding Vedette closes or reopens because of them says who changed what instead of reading as Vedette's own proof:
//   - the row's own correction, or the resting correction its reading replaced (Superseded);
//   - the device's corrected OS, only for a row whose match reads the OS (built by an agent or read over SNMP) and for the OS row.
//
// softwareID "" (or a row the match no longer reads) names every correction of the device, resting ones included. "" when none.
func correctionWhy(a Asset, softwareID string) string {
	var parts []string
	lead := "This follows a person's correction: "
	var row *Software
	for i := range a.Software {
		if softwareID != "" && a.Software[i].ID == softwareID {
			row = &a.Software[i]
		}
	}
	switch {
	case row != nil:
		for _, p := range []string{row.Correction, row.Superseded} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		if b := row.builtBy(); a.OSCorrection != "" && (b == "agent" || b == "snmp") {
			parts = append(parts, a.OSCorrection)
		}
	case strings.HasPrefix(softwareID, "os:"):
		if a.OSCorrection != "" {
			parts = append(parts, a.OSCorrection)
		}
	default:
		lead = "This device has a person's correction: "
		for _, s := range a.Software {
			if s.Correction != "" {
				parts = append(parts, s.Correction)
			}
		}
		parts = append(parts, a.StaleCorrections...)
		if a.OSCorrection != "" {
			parts = append(parts, a.OSCorrection)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return lead + strings.Join(parts, "; ") + "."
}

// withCorrection adds why to a history note; when both do not fit, the note is cut, never why (review r2 L-b).
func withCorrection(note, why string) string {
	if why == "" || strings.Contains(note, why) {
		return note
	}
	if room := MaxNote - jsLen(why) - 1; room > 0 && jsLen(note) > room {
		note = clipNoteTo(note, room)
	}
	return clipNote(strings.TrimSpace(note + " " + why))
}

// clipNoteTo cuts s to at most n UTF-16 units, on a character boundary, ending with "…".
func clipNoteTo(s string, n int) string {
	out := []rune{}
	for _, r := range s {
		if jsLen(string(append(out, r))) > n-1 {
			break
		}
		out = append(out, r)
	}
	return string(out) + "…"
}

// usesCorrection is the sentence a finding's evidence carries when its row is a person's correction, or a reading that replaced a
// resting one (review r2 M-B): the version is not Vedette's own reading.
func usesCorrection(a Asset, softwareID string) string {
	for _, s := range a.Software {
		switch {
		case s.ID != softwareID:
		case s.Correction != "":
			return "Vedette uses a person's correction for this version: " + s.Correction + "."
		case s.Superseded != "":
			return "A person's correction no longer applies: " + s.Superseded + "."
		}
	}
	return ""
}
