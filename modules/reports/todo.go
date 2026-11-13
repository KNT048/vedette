package reports

import (
	"fmt"
	"sort"
	"strings"
)

// TopRiskCount is how many risks the management page names (W1-24, D-485).
const TopRiskCount = 3

// deviceRisk is the open findings of one product on one device: the unit of an upgrade.
type deviceRisk struct {
	device                string
	open, confirmed       int
	severity              string
	first, firstConfirmed int // index in the ordered list of open findings
	fix                   Fix // the release for the device and product; Kind "" = none known
	closed                int // open findings the release closes
}

// line is the devices of one product that call for the same step, as Rapid7's and Tenable's remediation lists do (one line per
// patch with the vulnerabilities it fixes): one upgrade that closes several findings is one line, and so is the same release on
// several devices.
type line struct {
	class           string // what makes two device risks one line
	devs            []*deviceRisk
	open, confirmed int
}

// product is every open finding of one product, over all devices: what the top three are ranked by (D-485).
type product struct {
	name            string
	open, confirmed int
	severity        string
	first, firstC   int
	devs            []*deviceRisk
}

// topRisks ranks products (as D-485: confirmed by a scan first, then the worst severity, then the most open findings across all
// devices, then the name), takes the TopRiskCount biggest and writes each one action sentence. A product whose devices need
// different steps gets the biggest step in the sentence and says how many more devices need another. open is ordered by severity,
// newest first. kinds is "fix" or "verify" for each risk. fixes says the release for each finding (may be nil).
func topRisks(open []FindingRow, fixes map[string]Fix) (out []TopRisk, kinds []string) {
	byDev := map[string]*deviceRisk{}
	byProd := map[string]*product{}
	var prods []*product
	for i, f := range open {
		p := byProd[f.Product]
		if p == nil {
			p = &product{name: f.Product, severity: f.Severity, first: i, firstC: -1}
			byProd[f.Product] = p
			prods = append(prods, p)
		}
		k := f.AssetID + "\x00" + f.Product
		g := byDev[k]
		if g == nil {
			g = &deviceRisk{device: f.Device, severity: f.Severity, first: i, firstConfirmed: -1}
			byDev[k] = g
			p.devs = append(p.devs, g)
		}
		p.open++
		g.open++
		if f.Status == "confirmed" {
			if p.confirmed == 0 {
				p.firstC = i
			}
			p.confirmed++
			g.confirmed++
		}
		if severityRank[f.Severity] < severityRank[p.severity] {
			p.severity = f.Severity
		}
		if severityRank[f.Severity] < severityRank[g.severity] {
			g.severity = f.Severity
		}
		if fx, ok := fixes[f.ID]; ok && fx.Kind != "" {
			g.fix = fx
			if fx.Closed {
				g.closed++
			}
		}
	}
	sort.SliceStable(prods, func(i, j int) bool {
		a, b := prods[i], prods[j]
		if (a.confirmed > 0) != (b.confirmed > 0) {
			return a.confirmed > 0
		}
		if severityRank[a.severity] != severityRank[b.severity] {
			return severityRank[a.severity] < severityRank[b.severity]
		}
		if a.open != b.open {
			return a.open > b.open
		}
		return a.name < b.name
	})
	out = []TopRisk{}
	for _, p := range prods {
		if len(out) == TopRiskCount {
			break
		}
		lines := p.lines()
		w := open[p.first]
		if p.firstC >= 0 { // the finding named is one a scan confirmed; severity stays the worst of the product
			w = open[p.firstC]
		}
		var names []string
		for _, g := range p.devs {
			names = append(names, g.device)
		}
		lead := lines[0]
		sentence := lead.sentence(p.name)
		if more := len(p.devs) - len(lead.devs); more > 0 {
			if more == 1 {
				sentence += "; 1 more device needs another step"
			} else {
				sentence += fmt.Sprintf("; %d more devices need another step", more)
			}
		}
		out = append(out, TopRisk{Product: p.name, Device: nameList(names), Devices: len(names), Open: p.open, Confirmed: p.confirmed,
			Severity: p.severity, CVE: w.CVE, FindingID: w.ID, Action: sentence})
		kind := "verify"
		if p.confirmed > 0 || strings.HasPrefix(lead.class, "fixed") {
			kind = "fix"
		}
		kinds = append(kinds, kind)
	}
	return out, kinds
}

// lines merges the product's device risks by class, the biggest line first (confirmed, then open findings, then class).
func (p *product) lines() []*line {
	by := map[string]*line{}
	var out []*line
	for _, g := range p.devs {
		c := g.class()
		l := by[c]
		if l == nil {
			l = &line{class: c}
			by[c] = l
			out = append(out, l)
		}
		l.devs = append(l.devs, g)
		l.open += g.open
		l.confirmed += g.confirmed
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.confirmed > 0) != (b.confirmed > 0) {
			return a.confirmed > 0
		}
		if a.open != b.open {
			return a.open > b.open
		}
		return a.class < b.class
	})
	return out
}

// class is what makes two device risks one line: the same release to go to (and the same caveat), or the same fallback.
func (g *deviceRisk) class() string {
	switch g.fix.Kind {
	case "fixed":
		return "fixed " + clip(g.fix.Fixed, 40) + "|" + clip(g.fix.Distro, 40)
	case "line":
		return "line " + clip(g.fix.Line, 40)
	case "distro":
		return "distro " + clip(g.fix.Distro, 40)
	case "up_to":
		return "up_to"
	}
	if g.confirmed > 0 {
		return "advisory"
	}
	return "version"
}

func nameList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return fmt.Sprintf("%s and %d more", names[0], len(names)-1)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// sentence is the step of the line, in the words of the page and the email. A release is named only when NVD's ranges say it
// (findings.FixedInForAll) and it is outside the range of every finding of the product; otherwise the honest fallback: the vendor
// advisory, or the version to check. A distribution caveat is carried: a package of the distribution is fixed by its own updates.
func (l *line) sentence(product string) string {
	first := l.devs[0]
	var names []string
	closed := 0
	for _, g := range l.devs {
		names = append(names, g.device)
		closed += g.closed
	}
	dev := nameList(names)
	fx := first.fix
	switch fx.Kind {
	case "fixed":
		what := plural(closed, "exploited vulnerability", "exploited vulnerabilities")
		if closed < l.open {
			what = fmt.Sprintf("%d of %d exploited vulnerabilities", closed, l.open)
		}
		var s string
		if len(l.devs) == 1 {
			from := ""
			if v := clip(fx.Version, 40); v != "" {
				from = " from " + v
			}
			s = fmt.Sprintf("Upgrade %s on %s%s to %s or later — fixes %s", product, dev, from, clip(fx.Fixed, 40), what)
		} else {
			s = fmt.Sprintf("Upgrade %s to %s or later on %s — fixes %s", product, clip(fx.Fixed, 40), dev, what)
		}
		if d := clip(fx.Distro, 40); d != "" { // inventory does not say whether it came from the distribution's packages
			s += fmt.Sprintf(" (if you installed it from %s's packages, install its security updates instead)", d)
		}
		return s
	case "line":
		return fmt.Sprintf("Install the latest release on your line (%s) of %s on %s — no single release in NVD's ranges clears every finding, so check the vendor advisory (%s)",
			clip(fx.Line, 40), product, dev, plural(l.open, "open finding", "open findings"))
	case "distro":
		who := "your distribution's"
		if d := clip(fx.Distro, 40); d != "" {
			who = d
		}
		return fmt.Sprintf("Install the latest %s security updates for %s on %s — %s", who, product, dev, plural(l.open, "exploited vulnerability is open", "exploited vulnerabilities are open"))
	case "up_to":
		return fmt.Sprintf("Check the vendor advisory for %s on %s: NVD names no fixed release, so use the vendor's temporary fix (%s)", product, dev, plural(l.open, "open finding", "open findings"))
	}
	if l.confirmed > 0 {
		return fmt.Sprintf("Update %s on %s, or apply the vendor's temporary fix: a scan confirmed it (%s)", product, dev, plural(l.open, "open finding", "open findings"))
	}
	return fmt.Sprintf("Check the version of %s on %s to confirm or rule out %s", product, dev, plural(l.open, "suspected finding", "suspected findings"))
}
