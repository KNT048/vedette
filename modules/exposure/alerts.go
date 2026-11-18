package exposure

import (
	"context"
	"fmt"
	"net/url"
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

// where names an address of a snapshot for the comparison: the address itself for an IP target; for a domain, the names under it
// that point at the address (a CDN or a load balancer rotates the addresses of a name, which alone is not news), else the address.
type where func(ip string) []string

func whereOf(snap Snapshot, domain bool) where {
	if !domain {
		return func(ip string) []string { return []string{ip} }
	}
	names := map[string][]string{}
	for _, h := range snap.Hosts {
		if h.IP != "" {
			names[h.IP] = append(names[h.IP], h.Name)
		}
		for _, a := range h.IPs {
			if a.IP != "" && a.IP != h.IP {
				names[a.IP] = append(names[a.IP], h.Name)
			}
		}
	}
	return func(ip string) []string {
		if n := names[ip]; len(n) > 0 {
			return n
		}
		return []string{ip}
	}
}

// urlPath is the path of an admin page's URL ("/" when it has none or cannot be read), the part of its key that tells two pages on
// one name and port apart (/wp-admin and /phpmyadmin).
func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// keys are the comparison keys of something on ip with the rest of its key (":443", ":443:CVE-…").
func (w where) keys(ip, rest string) []string {
	var out []string
	for _, n := range w(ip) {
		out = append(out, n+rest)
	}
	return out
}

// seen says whether any of keys is in set.
func seen(set map[string]bool, keys []string) bool {
	for _, k := range keys {
		if set[k] {
			return true
		}
	}
	return false
}

// changes is what is new in now compared with prev, the newest snapshot before the scan: an open port no earlier scan had, an admin page
// newly exposed, a certificate that now expires within CertWarnDays (and did not at the scan before), an exploited CVE newly matched on
// a service. Both snapshots are read against today's exploited list (withVulns), so a CVE comes only with what the scan saw. A domain's
// ports, admin pages and CVEs are compared by the names that point at their address (whereOf), not by the address.
func (s *Service) changes(ctx context.Context, prev, now Snapshot, at time.Time, domain bool) []change {
	s.withVulns(ctx, &prev)
	s.withVulns(ctx, &now)
	wPrev, wNow := whereOf(prev, domain), whereOf(now, domain)
	var out []change
	ports := map[string]bool{}
	for _, p := range prev.Ports {
		for _, k := range wPrev.keys(p.IP, fmt.Sprintf(":%d", p.Port)) {
			ports[k] = true
		}
	}
	for _, p := range now.Ports {
		key := fmt.Sprintf("%s:%d", p.IP, p.Port)
		if seen(ports, wNow.keys(p.IP, fmt.Sprintf(":%d", p.Port))) || p.LastSeen != "" { // a port kept from an earlier scan is not new
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
		for _, k := range wPrev.keys(a.IP, fmt.Sprintf(":%d%s", a.Port, urlPath(a.URL))) {
			admin[k] = true
		}
	}
	for _, a := range now.AdminPanels { // a domain's page: by the names of its address, its port and its path, so another page is new
		if admin[a.URL] || (domain && seen(admin, wNow.keys(a.IP, fmt.Sprintf(":%d%s", a.Port, urlPath(a.URL))))) {
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
		for _, k := range wPrev.keys(v.IP, fmt.Sprintf(":%d:%s", v.Port, v.CVE)) {
			cves[k] = true
		}
	}
	for _, v := range now.Vulns {
		if seen(cves, wNow.keys(v.IP, fmt.Sprintf(":%d:%s", v.Port, v.CVE))) {
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
	a, ok := alertOf(t.Value, now.ID, s.changes(actx, *prev, now, s.clock(), t.Kind == KindDomain))
	if !ok {
		return
	}
	if err := s.cfg.Alert(actx, a); err != nil {
		s.cfg.Log.WarnContext(actx, "exposure: sending the changes of a scheduled scan failed", "target", t.Value, "error", err)
	}
}
