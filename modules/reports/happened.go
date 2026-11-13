package reports

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// maxHappened is how many incidents the page names; the counts are of all.
const maxHappened = 3

// happenedRank orders what a person must not miss: a login that got in, then a trap touched, then failed-login attacks, then
// connections to known-bad addresses, then the rest.
var happenedRank = map[string]int{"login_accepted": 0, "trap": 1, "failed_logins": 2, "bad_connection": 3}

// buildHappened counts the incidents last seen in the week (D-490) and names the first few. Titles come from notify, which cleaned
// them already; they are cleaned again here because they began as log lines.
func buildHappened(in []Incident, from, to time.Time) *Happened {
	h := &Happened{Top: []HappenedLine{}}
	var week []Incident
	for _, i := range in {
		if i.LastSeen.After(from) && !i.LastSeen.After(to) {
			week = append(week, i)
		}
	}
	for _, i := range week {
		switch i.Kind {
		case "trap":
			h.Traps++
		case "failed_logins":
			h.FailedLogins++
		case "login_accepted":
			h.AcceptedLogins++
		case "bad_connection":
			h.BadConnections++
		default:
			h.Other++
		}
	}
	rank := func(k string) int {
		if r, ok := happenedRank[k]; ok {
			return r
		}
		return len(happenedRank)
	}
	sort.SliceStable(week, func(a, b int) bool {
		x, y := week[a], week[b]
		if rank(x.Kind) != rank(y.Kind) {
			return rank(x.Kind) < rank(y.Kind)
		}
		if severityRank[x.Severity] != severityRank[y.Severity] {
			return severityRank[x.Severity] < severityRank[y.Severity]
		}
		return x.LastSeen.After(y.LastSeen)
	})
	for _, i := range week {
		if len(h.Top) == maxHappened {
			break
		}
		h.Top = append(h.Top, HappenedLine{Kind: i.Kind, Title: clip(i.Title, 160), Severity: i.Severity, Count: max(i.Count, 1), At: ts(i.LastSeen)})
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
