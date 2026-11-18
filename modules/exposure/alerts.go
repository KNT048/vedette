package exposure

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Alert is what a scheduled scan found new on a target (INV-36), for the alert channels: cmd/vedette sends it through notify's
// system notice path (an incident-kind notice without a link). Severity is critical, high or medium.
type Alert struct {
	ID       string
	Severity string
	Title    string
	Text     string
}

// The severities of an Alert (notify's names).
const (
	AlertCritical = "critical"
	AlertHigh     = "high"
	AlertMedium   = "medium"
)

// maxAlertLines bounds the lines of one alert; the rest are counted.
const maxAlertLines = 20

// change is one thing a scheduled scan found new, with how serious it is (0 medium, 1 high, 2 critical).
type change struct {
	rank int
	line string
}

// changes is what is new in now compared with prev, the newest snapshot before the scan: an open port no earlier scan had, an admin page
// newly exposed, a certificate that now expires within CertWarnDays (and did not at the scan before), an exploited CVE newly matched on
// a service. Both snapshots are read against today's exploited list (withVulns), so a CVE comes only with what the scan saw.
func (s *Service) changes(ctx context.Context, prev, now Snapshot, at time.Time) []change {
	s.withVulns(ctx, &prev)
	s.withVulns(ctx, &now)
	var out []change
	ports := map[string]bool{}
	for _, p := range prev.Ports {
		ports[fmt.Sprintf("%s:%d", p.IP, p.Port)] = true
	}
	for _, p := range now.Ports {
		key := fmt.Sprintf("%s:%d", p.IP, p.Port)
		if ports[key] || p.LastSeen != "" { // a port kept from an earlier scan is not new
			continue
		}
		what := ServiceLabel(p)
		if p.Product != "" {
			what = strings.TrimPrefix(what+", "+p.Product, ", ")
		}
		line := "New open port: " + key
		if what != "" {
			line += " (" + what + ")"
		}
		out = append(out, change{rank: 1, line: line})
	}
	admin := map[string]bool{}
	for _, a := range prev.AdminPanels {
		admin[a.URL] = true
	}
	for _, a := range now.AdminPanels {
		if admin[a.URL] {
			continue
		}
		line := "Newly exposed admin page: " + a.URL
		if a.Product != "" {
			line += " (" + a.Product + ")"
		}
		out = append(out, change{rank: 1, line: line})
	}
	before := map[string]time.Time{}
	prevAt := at
	if t, err := parseTS(prev.StartedAt); err == nil {
		prevAt = t
	}
	for _, c := range prev.Certs {
		if t, err := parseTS(c.ExpiresAt); err == nil {
			before[c.Host] = t
		}
	}
	limit := at.Add(CertWarnDays * 24 * time.Hour)
	for _, c := range now.Certs {
		exp, err := parseTS(c.ExpiresAt)
		if err != nil || exp.After(limit) {
			continue
		}
		if old, ok := before[c.Host]; ok && !old.After(prevAt.Add(CertWarnDays*24*time.Hour)) {
			continue // it was already under the limit at the scan before
		}
		out = append(out, change{rank: 0, line: fmt.Sprintf("Certificate of %s expires within %d days, on %s", c.Host, CertWarnDays, s.dayText(exp))})
	}
	cves := map[string]bool{}
	for _, v := range prev.Vulns {
		cves[fmt.Sprintf("%s:%d:%s", v.IP, v.Port, v.CVE)] = true
	}
	for _, v := range now.Vulns {
		if cves[fmt.Sprintf("%s:%d:%s", v.IP, v.Port, v.CVE)] {
			continue
		}
		line := fmt.Sprintf("Newly matched exploited vulnerability: %s on %s:%d", v.CVE, v.IP, v.Port)
		if v.Name != "" {
			line += " (" + v.Name + ")"
		}
		out = append(out, change{rank: 2, line: line})
	}
	return out
}

// alertOf is the one alert of a scan's changes; ok is false when there are none (no change, no message).
func alertOf(value, snapID string, cs []change) (Alert, bool) {
	if len(cs) == 0 {
		return Alert{}, false
	}
	top := 0
	var lines []string
	for i, c := range cs {
		top = max(top, c.rank)
		if i < maxAlertLines {
			lines = append(lines, "- "+c.line)
		}
	}
	if n := len(cs) - maxAlertLines; n > 0 {
		lines = append(lines, fmt.Sprintf("- and %d more", n))
	}
	sev := []string{AlertMedium, AlertHigh, AlertCritical}[top]
	s := "s"
	if len(cs) == 1 {
		s = ""
	}
	text := fmt.Sprintf("The scheduled scan of %s found %d new thing%s since the scan before:\n%s\nOpen External exposure in Vedette and choose %s to see the scan.",
		value, len(cs), s, strings.Join(lines, "\n"), value)
	return Alert{ID: "exp-" + snapID, Severity: sev, Title: fmt.Sprintf("%s: the scheduled scan found something new", value), Text: text}, true
}

// alertChanges compares a scheduled scan's snapshot with the newest one before it and sends one alert when something is new; nothing
// when there was no earlier snapshot (the first scan is not news), nothing changed, or no Alert is wired. A failure is logged: the scan
// is stored either way.
func (s *Service) alertChanges(ctx context.Context, t Target, prev *Snapshot, now Snapshot) {
	if prev == nil || s.cfg.Alert == nil || now.ID == "" {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	a, ok := alertOf(t.Value, now.ID, s.changes(actx, *prev, now, s.clock()))
	if !ok {
		return
	}
	if err := s.cfg.Alert(actx, a); err != nil {
		s.cfg.Log.WarnContext(actx, "exposure: sending the changes of a scheduled scan failed", "target", t.Value, "error", err)
	}
}
