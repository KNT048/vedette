package reports

import (
	"fmt"
	"sort"
	"strings"
)

// TopRiskCount is how many risks the management page names (W1-24, D-485).
const TopRiskCount = 3

// deviceRisk is the open findings of one installed software on one device (their CISA product names merged: one phone is one
// group whatever CISA calls its CVEs), or of one product name when no software row is known: the unit of an upgrade.
type deviceRisk struct {
	asset, device, label  string
	noDevice              bool           // a product added by hand with no device: the step does not name it twice (W5-2)
	names                 map[string]int // findings by the CISA product name they carry; the label is the biggest
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
	var devs []*deviceRisk
	for i, f := range open {
		fx := fixes[f.ID]
		k := f.AssetID + "\x00" + fx.Group
		if fx.Group == "" {
			k = f.AssetID + "\x00p:" + f.Product
		}
		g := byDev[k]
		if g == nil {
			g = &deviceRisk{asset: f.AssetID, device: f.Device, noDevice: f.noDevice, names: map[string]int{}, severity: f.Severity, first: i, firstConfirmed: -1}
			byDev[k] = g
			devs = append(devs, g)
		}
		g.names[f.Product]++
		g.open++
		if f.Status == "confirmed" {
			if g.confirmed == 0 {
				g.firstConfirmed = i
			}
			g.confirmed++
		}
		if severityRank[f.Severity] < severityRank[g.severity] {
			g.severity = f.Severity
		}
		if fx.Kind != "" {
			g.fix = fx
			if fx.Closed {
				g.closed++
			}
		}
	}
	// Rank products as D-485: the product of a group is the name most of its findings carry.
	byProd := map[string]*product{}
	var prods []*product
	for _, g := range devs {
		g.label = g.productName()
		p := byProd[g.label]
		if p == nil {
			p = &product{name: g.label, severity: g.severity, first: g.first, firstC: -1}
			byProd[g.label] = p
			prods = append(prods, p)
		}
		p.devs = append(p.devs, g)
		p.open += g.open
		p.confirmed += g.confirmed
		p.first = min(p.first, g.first)
		if g.firstConfirmed >= 0 && (p.firstC < 0 || g.firstConfirmed < p.firstC) {
			p.firstC = g.firstConfirmed
		}
		if severityRank[g.severity] < severityRank[p.severity] {
			p.severity = g.severity
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
		lead := lines[0]
		all := distinctDevices(p.devs)
		sentence := lead.sentence(p.name)
		if more := len(all) - len(distinctDevices(lead.devs)); more > 0 {
			if more == 1 {
				sentence += "; 1 more device needs another step"
			} else {
				sentence += fmt.Sprintf("; %d more devices need another step", more)
			}
		}
		out = append(out, TopRisk{Product: p.name, Device: nameList(all), Devices: len(all), Open: p.open, Confirmed: p.confirmed,
			Severity: p.severity, CVE: w.CVE, FindingID: w.ID, Action: sentence})
		kind := "verify"
		if p.confirmed > 0 || strings.HasPrefix(lead.class, "fixed") || strings.HasPrefix(lead.class, "feature_update") || strings.HasPrefix(lead.class, "esu") {
			kind = "fix"
		}
		kinds = append(kinds, kind)
	}
	return out, kinds
}

// productName is the CISA name most findings of the group carry (the worst-ranked name on a tie, then the alphabetical one).
func (g *deviceRisk) productName() string {
	best := ""
	for n, c := range g.names {
		if best == "" || c > g.names[best] || c == g.names[best] && n < best {
			best = n
		}
	}
	return best
}

// distinctDevices lists the device names once each, in order: two software rows on one device are one device.
func distinctDevices(gs []*deviceRisk) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range gs {
		if !seen[g.asset] {
			seen[g.asset] = true
			out = append(out, g.device)
		}
	}
	return out
}

// where is what the step is about and where: the product and " on " the devices. A product added by hand with no device (D-471) is
// named after the product already, so it is not named again ("Cisco BroadWorks on Cisco BroadWorks (no device)", W5-2): alone it
// is said once after the product; next to real devices it is "the copy added by hand".
func where(product string, gs []*deviceRisk) (what, on string) {
	seen := map[string]bool{}
	var names []string
	byHand := false
	for _, g := range gs {
		if seen[g.asset] {
			continue
		}
		seen[g.asset] = true
		if g.noDevice {
			byHand = true
		} else {
			names = append(names, g.device)
		}
	}
	if len(names) == 0 {
		return product + " (added by hand, no device)", ""
	}
	if byHand {
		names = append(names, "the copy added by hand")
	}
	return product, " on " + nameList(names)
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
		if fa, fb := strings.HasPrefix(a.class, "fixed"), strings.HasPrefix(b.class, "fixed"); fa != fb {
			return fa // on a tie the line that names a release leads
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
	case "none":
		return "none"
	case "distro":
		return "distro " + clip(g.fix.Distro, 40)
	case "up_to":
		return "up_to"
	case "feature_update", "esu": // D-546: a step of its own, never merged with devices that need another build or have no fix data
		return g.fix.Kind + " " + clip(g.fix.Fixed, 40)
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
	closed := 0
	for _, g := range l.devs {
		closed += g.closed
	}
	names := distinctDevices(l.devs)
	product, on := where(product, l.devs)
	fx := first.fix
	switch fx.Kind {
	case "fixed":
		what := plural(closed, "exploited vulnerability", "exploited vulnerabilities")
		if closed < l.open {
			what = fmt.Sprintf("%d of %d exploited vulnerabilities", closed, l.open)
		}
		var s string
		if len(names) == 1 {
			from := ""
			if v := clip(fx.Version, 40); v != "" {
				from = " from " + v
			}
			s = fmt.Sprintf("Upgrade %s%s%s to %s or later — fixes %s", product, on, from, clip(fx.Fixed, 40), what)
		} else {
			s = fmt.Sprintf("Upgrade %s to %s or later%s — fixes %s", product, clip(fx.Fixed, 40), on, what)
		}
		if d := clip(fx.Distro, 40); d != "" { // inventory does not say whether it came from the distribution's packages
			s += fmt.Sprintf(" (if you installed it from %s's packages, install its security updates instead)", d)
		}
		return s
	case "feature_update": // D-546: a Windows release Microsoft no longer updates; only a later release has the fix
		return fmt.Sprintf("Move %s%s to a Windows release Microsoft still services (a feature update): it gets no more monthly updates, and NVD names the fix only for %s — fixes %s",
			product, on, clip(fx.Fixed, 40), plural(closed, "exploited vulnerability", "exploited vulnerabilities"))
	case "esu": // D-546: the fixing build comes only with Extended Security Updates
		return fmt.Sprintf("Install the Extended Security Update %s or later on %s%s, or move it to a Windows release Microsoft still services — fixes %s",
			clip(fx.Fixed, 40), product, on, plural(closed, "exploited vulnerability", "exploited vulnerabilities"))
	case "none":
		return fmt.Sprintf("NVD names no single release that fixes all %s of %s%s: check the vendor advisory", plural(l.open, "exploited vulnerability", "exploited vulnerabilities"), product, on)
	case "distro":
		who := "your distribution's"
		if d := clip(fx.Distro, 40); d != "" {
			who = d
		}
		return fmt.Sprintf("Install the latest %s security updates for %s%s — %s", who, product, on, plural(l.open, "exploited vulnerability is open", "exploited vulnerabilities are open"))
	case "up_to":
		return fmt.Sprintf("Check the vendor advisory for %s%s: NVD names no fixed release, so use the vendor's temporary fix (%s)", product, on, plural(l.open, "open finding", "open findings"))
	}
	if l.confirmed > 0 {
		return fmt.Sprintf("Update %s%s, or apply the vendor's temporary fix: a scan confirmed it (%s)", product, on, plural(l.open, "open finding", "open findings"))
	}
	return fmt.Sprintf("Check the version of %s%s to confirm or rule out %s", product, on, plural(l.open, "suspected finding", "suspected findings"))
}
