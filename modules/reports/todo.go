package reports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// TopRiskCount is how many risks the management page names (W1-24, D-485).
const TopRiskCount = 3

// deviceRisk is the open findings of one product on one device: the unit of an upgrade.
type deviceRisk struct {
	asset, device, product string
	open, confirmed        int
	severity               string
	first, firstConfirmed  int // index in the ordered list of open findings
	fixed, version, distro string
	fixes                  int  // open findings the release in fixed closes
	upTo, distroFix        bool // NVD names no fixed release / the distribution's updates carry it
}

// risk is one line of the page: the device risks that call for the same action, as Rapid7's and Tenable's remediation lists do
// (one line per patch with the vulnerabilities it fixes), so one upgrade that closes several findings is one line.
type risk struct {
	product, action string // action: the class of the action, what makes two device risks one line
	devs            []*deviceRisk
	open, confirmed int
	severity        string
	first, firstC   int
}

// topRisks groups the open findings (ordered by severity, newest first) per device and product, merges the groups that need the
// same action, and returns the TopRiskCount biggest: confirmed by a scan first, then the worst severity, then the most open
// findings, then the name. kinds is "fix" or "verify" for each. fixes says the release that closes each finding (may be nil).
func topRisks(open []FindingRow, fixes map[string]Fix) (out []TopRisk, kinds []string) {
	by := map[string]*deviceRisk{}
	var groups []*deviceRisk
	fixedAt := map[string][]string{} // finding ids with a fixed release, by device risk key
	for i, f := range open {
		k := f.AssetID + "\x00" + f.Product
		g := by[k]
		if g == nil {
			g = &deviceRisk{asset: f.AssetID, device: f.Device, product: f.Product, severity: f.Severity, first: i, firstConfirmed: -1}
			by[k] = g
			groups = append(groups, g)
		}
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
		switch fx := fixes[f.ID]; fx.Kind {
		case "fixed":
			if fx.Fixed == "" {
				break
			}
			if g.fixed == "" || verLess(g.fixed, fx.Fixed) {
				g.fixed = clip(fx.Fixed, 40)
			}
			if g.version == "" {
				g.version = clip(fx.Version, 40)
			}
			fixedAt[k] = append(fixedAt[k], f.ID)
		case "up_to":
			g.upTo = true
		case "distro":
			g.distroFix, g.distro = true, clip(fx.Distro, 40)
		}
		g.fixes = len(fixedAt[k])
	}
	merged := map[string]*risk{}
	var order []*risk
	for _, g := range groups {
		class := g.class()
		k := g.product + "\x00" + class
		r := merged[k]
		if r == nil {
			r = &risk{product: g.product, action: class, severity: g.severity, first: g.first, firstC: -1}
			merged[k] = r
			order = append(order, r)
		}
		r.devs = append(r.devs, g)
		r.open += g.open
		r.confirmed += g.confirmed
		r.first = min(r.first, g.first)
		if g.firstConfirmed >= 0 && (r.firstC < 0 || g.firstConfirmed < r.firstC) {
			r.firstC = g.firstConfirmed
		}
		if severityRank[g.severity] < severityRank[r.severity] {
			r.severity = g.severity
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if (a.confirmed > 0) != (b.confirmed > 0) {
			return a.confirmed > 0
		}
		if severityRank[a.severity] != severityRank[b.severity] {
			return severityRank[a.severity] < severityRank[b.severity]
		}
		if a.open != b.open {
			return a.open > b.open
		}
		if a.product != b.product {
			return a.product < b.product
		}
		return a.action < b.action
	})
	out = []TopRisk{}
	for _, r := range order {
		if len(out) == TopRiskCount {
			break
		}
		w := open[r.first]
		if r.firstC >= 0 { // the finding named is one a scan confirmed; severity stays the worst of the line
			w = open[r.firstC]
		}
		var names []string
		for _, g := range r.devs {
			names = append(names, g.device)
		}
		dev := nameList(names)
		out = append(out, TopRisk{Product: r.product, Device: dev, Devices: len(names), Open: r.open, Confirmed: r.confirmed,
			Severity: r.severity, CVE: w.CVE, FindingID: w.ID, Action: r.sentence(dev)})
		kind := "verify"
		if r.confirmed > 0 || strings.HasPrefix(r.action, "fixed") {
			kind = "fix"
		}
		kinds = append(kinds, kind)
	}
	return out, kinds
}

// class is what makes two device risks one line: the same product, and the same release to upgrade to, or the same fallback.
func (g *deviceRisk) class() string {
	switch {
	case g.fixed != "":
		return "fixed " + g.fixed
	case g.distroFix:
		return "distro " + g.distro
	case g.upTo:
		return "up_to"
	case g.confirmed > 0:
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

// sentence is the action of the line, in the words of the page and the email. The fixed release is named only when NVD's ranges say
// it (findings.FixedInFor); otherwise the honest fallback: the vendor advisory, or the version to add.
func (r *risk) sentence(dev string) string {
	first := r.devs[0]
	switch {
	case first.fixed != "":
		fixes := 0
		for _, g := range r.devs {
			fixes += g.fixes
		}
		what := plural(fixes, "exploited vulnerability", "exploited vulnerabilities")
		if fixes < r.open {
			what = fmt.Sprintf("%d of %d exploited vulnerabilities", fixes, r.open)
		}
		if len(r.devs) == 1 {
			from := ""
			if first.version != "" {
				from = " from " + first.version
			}
			return fmt.Sprintf("Upgrade %s on %s%s to %s or later — fixes %s", r.product, dev, from, first.fixed, what)
		}
		return fmt.Sprintf("Upgrade %s to %s or later on %s — fixes %s", r.product, first.fixed, dev, what)
	case first.distroFix:
		who := "your distribution's"
		if first.distro != "" {
			who = first.distro
		}
		return fmt.Sprintf("Install the latest %s security updates for %s on %s — %s", who, r.product, dev, plural(r.open, "exploited vulnerability is open", "exploited vulnerabilities are open"))
	case r.action == "up_to":
		return fmt.Sprintf("Check the vendor advisory for %s on %s: NVD names no fixed release, so use the vendor's temporary fix (%s)", r.product, dev, plural(r.open, "open finding", "open findings"))
	case r.action == "advisory":
		return fmt.Sprintf("Update %s on %s, or apply the vendor's temporary fix: a scan confirmed it (%s)", r.product, dev, plural(r.open, "open finding", "open findings"))
	}
	return fmt.Sprintf("Check the version of %s on %s to confirm or rule out %s", r.product, dev, plural(r.open, "suspected finding", "suspected findings"))
}

// verLess says a is an older version than b: dotted parts compare as numbers when both are numbers, else as text.
func verLess(a, b string) bool {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	}
	x, y := split(a), split(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		m, e1 := strconv.Atoi(x[i])
		n, e2 := strconv.Atoi(y[i])
		switch {
		case e1 == nil && e2 == nil && m != n:
			return m < n
		case (e1 != nil || e2 != nil) && x[i] != y[i]:
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}
