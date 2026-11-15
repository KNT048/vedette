package findings

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// "Updates to plan" (S-TIER-1, S-TIER-2; D-613, D-615, D-616, D-617): CVEs on no exploited list, published in the last 12 months,
// that a device's own version is proved to be inside, one item per update. Not findings: nothing here is stored, alerts or counts.

// TierVuln is one CVE of the tier data (feeds epss-all and nvd-recent, D-614) as the plan reads it: an NVD record of the last 12
// months with the affected entries of the products the devices run (TierScope), and its EPSS score.
type TierVuln struct {
	CVE              string
	Tier             string // "likely" (EPSS at or above feeds.EPSSLikely) or "recent"
	Published        time.Time
	Severity         string // lower-case CVSS severity NVD gives ("high"), "" when it has not scored the CVE
	Score            *float64
	EPSS, Percentile *float64 // nil when epss-all is not ready or has no score for the CVE
	Affected         []Affected
}

// PlanCVE is one CVE of a plan item (contract PlanCve).
type PlanCVE struct {
	CVE        string   `json:"cve"`
	Tier       string   `json:"tier"`
	Basis      string   `json:"basis"` // agent or version in this version (D-617): scan and distro have no source yet
	Severity   *string  `json:"severity"`
	Score      *float64 `json:"score"`
	Published  string   `json:"published"`
	EPSS       *float64 `json:"epss"`
	Percentile *float64 `json:"percentile"`
}

// PlanItem is one update on one device (contract PlanItem without the device's name, which the handler adds).
type PlanItem struct {
	Group    string    `json:"group"`
	AssetID  string    `json:"-"`
	Software string    `json:"software"`
	Version  string    `json:"version"`
	Fixed    string    `json:"fixed"`
	Kind     string    `json:"kind"` // fixed, windows (distro has no source yet, D-617)
	CVEs     []PlanCVE `json:"cves"`
}

// Basis values of a plan CVE (D-615 (8)).
const (
	planAgent   = "agent"
	planVersion = "version"
)

// tierSource says whether a row's version may confirm a tier CVE (D-613 (2), D-617): the device's agent, a person, the device's own
// SNMP answer, or the network OS the device states (deviceSoftware's OS row). Never a version read from a banner (nmap, the scan, the
// passive sensor) or a row of unknown origin: for CVEs nobody exploits yet a guess is noise, so it is dropped (the brief's worst case).
func tierSource(s Software) bool {
	switch s.Source {
	case "agent", "manual", "snmp":
		return true
	}
	return strings.HasPrefix(s.ID, "os:")
}

// tierInfo is the swInfo of a row the plan compares, false when it compares none: a source tierSource refuses, no readable version, or
// a distribution's package (an agent's deb/rpm row, or a version with a distribution's mark): the distributions backport fixes, so
// NVD's upstream ranges would put a patched package inside, and their own data has no word on tier CVEs in this version (D-617).
func tierInfo(a Asset, s Software) (swInfo, bool) {
	if !tierSource(s) {
		return swInfo{}, false
	}
	in := newSWInfo(s, a.OS)
	in.platformOS = platformOS(s, a)
	if !in.given || !versionKnown(in.ver) || in.packaged || distroMarked(in.ver) || distroMarked(s.Version) {
		return swInfo{}, false
	}
	return in, true
}

// tierKey is the product key of an NVD CPE as the plan indexes it: norm(vendor) "|" norm(product), read without a full parse (an
// escaped colon makes a key that matches nothing, which only drops). "" when the string is not a CPE 2.3 name.
func tierKey(cpe string) string {
	rest, ok := strings.CutPrefix(cpe, cpePrefix)
	if !ok {
		return ""
	}
	_, rest, ok = strings.Cut(rest, ":") // the part
	if !ok {
		return ""
	}
	v, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	p, _, _ := strings.Cut(rest, ":")
	return normed(v) + "|" + normed(p)
}

// normed is norm without a copy for a name that is already only [a-z0-9] (most of NVD's): Keep runs on every distinct CPE of a pass.
func normed(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return norm(s)
		}
	}
	return s
}

// isWindowsKey says whether a key is a Microsoft Windows release (windows_11_23h2): a Windows row is read with every one of them (D-546).
func isWindowsKey(k string) bool { return strings.HasPrefix(k, "microsoft|windows") }

// TierScope is the set of products the devices run, as the tier data is asked for them (Feeds.TierVulns): only the NVD entries of
// these products are read, so a pass holds the CVEs of the devices, not the 100,000 of the year (D-617).
type TierScope struct {
	keys    map[string]bool
	prefix  []identity // aliases that match every product starting with them (cpeAliases)
	windows bool
}

// NewTierScope collects the products of the devices' rows that the plan compares.
func NewTierScope(assets []Asset) *TierScope {
	t := &TierScope{keys: map[string]bool{}}
	for _, a := range assets {
		for _, s := range deviceSoftware(a) {
			in, ok := tierInfo(a, s)
			if !ok {
				continue
			}
			if _, win := winDevice(in); win {
				t.windows = true
			}
			if in.hasCPE {
				v, _ := in.cpe.Vendor.Literal()
				p, _ := in.cpe.Product.Literal()
				t.keys[norm(v)+"|"+norm(p)] = true
			}
			for _, id := range in.ids {
				if id.prefix {
					t.prefix = append(t.prefix, id)
					continue
				}
				t.keys[id.vendor+"|"+id.product] = true
			}
		}
	}
	return t
}

// Empty says no row of the devices can be compared: the tier data need not be read.
func (t *TierScope) Empty() bool { return len(t.keys) == 0 && len(t.prefix) == 0 && !t.windows }

// Keep says whether an NVD entry's CPE names a product of the scope.
func (t *TierScope) Keep(cpe string) bool {
	k := tierKey(cpe)
	if k == "" {
		return false
	}
	if t.keys[k] || t.windows && isWindowsKey(k) {
		return true
	}
	v, p, _ := strings.Cut(k, "|")
	for _, id := range t.prefix {
		if id.matches(v, p) {
			return true
		}
	}
	return false
}

// tierIndex finds the tier CVEs of a product without reading them all for each row.
type tierIndex struct {
	vulns  []Vuln     // as the matcher reads them (Affected, Published; no KEV fields)
	tier   []TierVuln // the same order
	byKey  map[string][]int
	byName map[string]int // CVE -> index
}

func newTierIndex(tv []TierVuln) *tierIndex {
	x := &tierIndex{vulns: make([]Vuln, len(tv)), tier: tv, byKey: map[string][]int{}, byName: make(map[string]int, len(tv))}
	for i, t := range tv {
		x.vulns[i] = Vuln{CVE: t.CVE, Published: t.Published, Affected: t.Affected}
		x.byName[t.CVE] = i
		for _, af := range t.Affected {
			k := tierKey(af.CPE)
			if l := x.byKey[k]; k != "" && (len(l) == 0 || l[len(l)-1] != i) {
				x.byKey[k] = append(l, i)
			}
		}
	}
	return x
}

// candidates are the indexes of the CVEs whose entries name the row's product, in data order, each once.
func (x *tierIndex) candidates(in swInfo, win bool) []int {
	seen := map[int]bool{}
	var out []int
	add := func(l []int) {
		for _, i := range l {
			if !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
	}
	if in.hasCPE {
		v, _ := in.cpe.Vendor.Literal()
		p, _ := in.cpe.Product.Literal()
		add(x.byKey[norm(v)+"|"+norm(p)])
	}
	for _, id := range in.ids {
		if !id.prefix {
			add(x.byKey[id.vendor+"|"+id.product])
		}
	}
	for k, l := range x.byKey { // aliases by prefix and Windows releases: few rows, a walk of the keys
		v, p, _ := strings.Cut(k, "|")
		if win && isWindowsKey(k) || slices.ContainsFunc(in.ids, func(id identity) bool { return id.prefix && id.matches(v, p) }) {
			add(l)
		}
	}
	slices.Sort(out)
	return out
}

// matchTiers is the plan of one device (D-613, D-615, D-617): every tier CVE (not on an exploited list, published since now minus
// AgeLimit) whose NVD range a compared row's version is proved inside, with a range that ends (a fix exists), grouped by the update
// that fixes them (D-545 GroupFix, Ranged only). Windows release rows read NVD's entries by their monthly update (D-546, D-610).
// Platform-limited CVEs count only when the row names a platform they affect (D-547). compared says the device has a row the plan
// compares. Nothing is a guess: an Unknown, a product-only match or a range with no end gives no item.
func matchTiers(a Asset, x *tierIndex, kev map[string]bool, now time.Time) (items []PlanItem, compared bool) {
	cut := now.Add(-AgeLimit)
	for _, s := range deviceSoftware(a) {
		in, ok := tierInfo(a, s)
		if !ok {
			continue
		}
		compared = true
		d, win := winDevice(in)
		if win {
			in.winNamed = winNamed(x.vulns, d.rel.Product) // D-546, review H2: every Windows entry of the pass is in x
		}
		var mine []int
		for _, i := range x.candidates(in, win) {
			v := x.vulns[i]
			if kev[v.CVE] || v.Published.Before(cut) || !ValidCVE(v.CVE) || !platformSettled(in, v.CVE) {
				continue
			}
			if why, out := platformRuledOut(in, v.CVE); out || why != "" {
				continue
			}
			if win {
				w, ok := windowsDecide(in, v, in.winNamed, now)
				if !ok || w.t != Yes || w.within.EndExcl == "" {
					continue
				}
			} else if t, within, _, _ := decide(in, v, false); t != Yes || within.EndExcl == "" && within.EndIncl == "" {
				continue
			}
			mine = append(mine, i)
		}
		items = append(items, tierItems(a, s, in, win, x, mine)...)
	}
	return items, compared
}

// tierItems groups the matched CVEs of one row by the update that fixes them: one item when one release fixes them all, else one
// item per release that fixes some (each CVE once, by its own nearest fix); a CVE no release is named for is left out (no update to
// plan for it).
func tierItems(a Asset, s Software, in swInfo, win bool, x *tierIndex, mine []int) []PlanItem {
	if len(mine) == 0 {
		return nil
	}
	vulns := make([]Vuln, len(mine))
	for j, i := range mine {
		vulns[j] = x.vulns[i]
	}
	group := func(vs []Vuln) *GroupFix {
		if win {
			return windowsGroupFix(in, vs)
		}
		return groupFixOf(in, vs)
	}
	base := a.ID + "/" + s.ID
	item := func(g *GroupFix, suffix string) PlanItem {
		kind := "fixed"
		if win && g.Kind != "feature_update" {
			kind = "windows"
		}
		it := PlanItem{Group: base + suffix, AssetID: a.ID, Software: clean(s.Display), Version: clean(in.ver), Fixed: g.Fixed, Kind: kind}
		basis := planVersion
		if s.Source == "agent" {
			basis = planAgent
		}
		for _, v := range vulns {
			if g.Ranged[v.CVE] {
				it.CVEs = append(it.CVEs, planCVE(x.tier[x.byName[v.CVE]], basis))
			}
		}
		sortPlanCVEs(it.CVEs)
		return it
	}
	if g := group(vulns); g != nil && namesFix(g) {
		if it := item(g, ""); len(it.CVEs) > 0 {
			return []PlanItem{it}
		}
		return nil
	}
	byFix := map[string]*GroupFix{} // no release fixes them all: each CVE by its own nearest fix
	var order []string
	for _, v := range vulns {
		g := group([]Vuln{v})
		if g == nil || !namesFix(g) || !g.Ranged[v.CVE] {
			continue
		}
		key := g.Kind + "/" + g.Fixed
		if o := byFix[key]; o != nil {
			o.Ranged[v.CVE] = true
			continue
		}
		byFix[key] = g
		order = append(order, key)
	}
	var out []PlanItem
	for _, k := range order {
		out = append(out, item(byFix[k], "/"+k))
	}
	return out
}

// namesFix says the group names an update a person can install (D-545 RowFix kinds; distro has no source here).
func namesFix(g *GroupFix) bool {
	switch g.Kind {
	case "fixed", "esu", "feature_update":
		return g.Fixed != ""
	}
	return false
}

func planCVE(t TierVuln, basis string) PlanCVE {
	c := PlanCVE{CVE: t.CVE, Tier: t.Tier, Basis: basis, Score: t.Score, Published: t.Published.UTC().Format(time.DateOnly), EPSS: t.EPSS, Percentile: t.Percentile}
	if t.Severity != "" {
		sev := t.Severity
		c.Severity = &sev
	}
	return c
}

// sortPlanCVEs orders an item's CVEs as the contract says: likely first, then by EPSS, then newest.
func sortPlanCVEs(cs []PlanCVE) {
	ep := func(p *float64) float64 {
		if p == nil {
			return -1
		}
		return *p
	}
	slices.SortStableFunc(cs, func(a, b PlanCVE) int {
		if a.Tier != b.Tier {
			if a.Tier == "likely" {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(ep(b.EPSS), ep(a.EPSS)), strings.Compare(b.Published, a.Published), strings.Compare(a.CVE, b.CVE))
	})
}

// sortPlanItems orders items: the most likely-to-be-exploited CVEs first, then the highest EPSS, then the most CVEs, then the group.
func sortPlanItems(items []PlanItem) {
	likely := func(i PlanItem) int {
		n := 0
		for _, c := range i.CVEs {
			if c.Tier == "likely" {
				n++
			}
		}
		return n
	}
	top := func(i PlanItem) float64 {
		if len(i.CVEs) == 0 || i.CVEs[0].EPSS == nil {
			return -1
		}
		return *i.CVEs[0].EPSS
	}
	slices.SortStableFunc(items, func(a, b PlanItem) int {
		return cmp.Or(cmp.Compare(likely(b), likely(a)), cmp.Compare(top(b), top(a)), cmp.Compare(len(b.CVEs), len(a.CVEs)), strings.Compare(a.Group, b.Group))
	})
}
