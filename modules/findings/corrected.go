package findings

import "strings"

// correctionWhy names the person's corrections behind a match of one software row (inventory INV-39, review r1 M3 of #950), so a
// finding Vedette closes or reopens because of them says who changed what instead of reading as Vedette's own proof: the row's own
// correction and the device's corrected OS. softwareID "" (or a row the match no longer reads: a correction replaced it) names
// every correction of the device. "" when the device has none.
func correctionWhy(a Asset, softwareID string) string {
	var parts []string
	found := false
	for _, s := range a.Software {
		if softwareID != "" && s.ID == softwareID {
			found = true
			if s.Correction != "" {
				parts = append(parts, s.Correction)
			}
		}
	}
	lead := "This follows a person's correction: "
	if !found && !strings.HasPrefix(softwareID, "os:") {
		lead = "This device has a person's correction: "
		for _, s := range a.Software {
			if s.Correction != "" {
				parts = append(parts, s.Correction)
			}
		}
	}
	if a.OSCorrection != "" {
		parts = append(parts, a.OSCorrection)
	}
	if len(parts) == 0 {
		return ""
	}
	return lead + strings.Join(parts, "; ") + "."
}

// withCorrection adds why to a history note, within the note's length.
func withCorrection(note, why string) string {
	if why == "" || strings.Contains(note, why) {
		return note
	}
	return clipNote(strings.TrimSpace(note + " " + why))
}
