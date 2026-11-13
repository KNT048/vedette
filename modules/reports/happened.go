package reports

import (
	"fmt"
	"strings"
)

// maxHappened is how many incidents the page names; the counts are of all.
const maxHappened = 3

// buildHappened turns what notify counted in the week into the section (D-490). Titles come from notify, which cleaned them already;
// they are cleaned again here because they began as log lines.
func buildHappened(w IncidentWeek) *Happened {
	h := &Happened{Traps: w.Traps, FailedLogins: w.FailedLogins, AcceptedLogins: w.AcceptedLogins, BadConnections: w.BadConnections, Other: w.Other, Top: []HappenedLine{}}
	for _, i := range w.Top {
		if len(h.Top) == maxHappened {
			break
		}
		h.Top = append(h.Top, HappenedLine{Kind: i.Kind, Title: clip(i.Title, 160), Severity: i.Severity, At: ts(i.LastSeen)})
	}
	var parts []string
	add := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, plural(n, one, many))
		}
	}
	add(h.AcceptedLogins, "login ACCEPTED after failed attempts", "logins ACCEPTED after failed attempts")
	add(h.Traps, "honeypot touch", "honeypot touches")
	add(h.FailedLogins, "failed-login attack", "failed-login attacks")
	add(h.BadConnections, "connection to a known-bad address", "connections to known-bad addresses")
	add(h.Other, "other unusual log item", "other unusual log items")
	if len(parts) == 0 {
		h.Summary = "No incidents this week."
	} else {
		h.Summary = fmt.Sprintf("This week: %s.", strings.Join(parts, ", "))
	}
	return h
}
