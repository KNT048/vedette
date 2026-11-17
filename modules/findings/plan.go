package findings

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/debver"
)

// "Updates to plan" (S-TIER-1, S-TIER-2): CVEs on no exploited list, published in the last 12 months,
// that a device's own version is proved to be inside, one item per update. Not findings: nothing here is stored, alerts or counts.

// TierVuln is one CVE of the tier data (feeds epss-all and nvd-recent) as the plan reads it: an NVD record of the last 12
// months with the affected entries of the products the devices run (TierScope), and its EPSS score.
type TierVuln struct {
	CVE              string
	Tier             string // "likely" (EPSS at or above feeds.EPSSLikely) or "recent"
	Published        time.Time
	Severity         string // lower-case CVSS severity NVD gives ("high"), "" when it has not scored the CVE
	Score            *float64
	EPSS, Percentile *float64 // nil when epss-all is not ready or has no score for the CVE
	Affected         []Affected
	// Distro is, for Feeds.TierDistro, the distributions' fixed rows of the packages asked for; nil otherwise.
	Distro []DistroFix
	// Platforms is, per entry of Affected, the operating systems NVD says it affects only when running on ("microsoft:windows"); nil
	// or empty for none; ["?"] when the record was stored before Vedette kept that (not known: the entry never counts).
	Platforms [][]string
}

// PlanCVE is one CVE of a plan item (contract PlanCve).
type PlanCVE struct {
	CVE        string   `json:"cve"`
	Tier       string   `json:"tier"`
	Basis      string   `json:"basis"` // agent, version or distro: scan has no source yet
	Severity   *string  `json:"severity"`
	Score      *float64 `json:"score"`
	Published  string   `json:"published"`
	EPSS       *float64 `json:"epss"`
	Percentile *float64 `json:"percentile"`
}

// PlanItem is one update on one device (contract PlanItem without the device's name, which the handler adds).
type PlanItem struct {
	Group   string `json:"group"`
	AssetID string `json:"-"`
	// SoftwareID is the device's software row the item is about (for a distribution's package, the first row of that source
	// package), so a page can show the item on the row (DeviceUpdates). Not in the API.
	SoftwareID string    `json:"-"`
	Software   string    `json:"software"`
	Version    string    `json:"version"`
	Fixed      string    `json:"fixed"`
	Kind       string    `json:"kind"` // fixed, windows, esu, distro
	Pro        bool      `json:"pro"`  // distro: the fixed version is in Ubuntu Pro (ESM) only
	CVEs       []PlanCVE `json:"cves"`
	// Reported is, for an agent's row, when the agent last reported it (Software.SeenAt): the day of the list the version comes from,
	// which GET /findings/plan names once no agent reports the device (agent_reported). Zero otherwise. Not in the pass's JSON.
	Reported time.Time `json:"-"`
}

// Basis values of a plan CVE.
const (
	planAgent   = "agent"
	planVersion = "version"
	planDistro  = "distro"
)

// DistroPackage is a source package of one release as the distributions' security data names it, for Feeds.TierDistro.
type DistroPackage struct{ Distro, Release, Package string }

// tierSource says whether a row's version may confirm a tier CVE: the device's agent, a person, the device's own
// SNMP answer, or the network OS the device states (deviceSoftware's OS row). Never a version read from a banner (nmap, the scan, the
// passive sensor) or a row of unknown origin: for CVEs nobody exploits yet a guess is noise, so it is dropped (the brief's worst case).
func tierSource(s Software) bool {
	switch s.Source {
	case "agent", "manual", "snmp":
		return true
	}
	return strings.HasPrefix(s.ID, "os:")
}

// tierInfo is the swInfo of a row the plan compares with NVD's ranges, false when it compares none: a source tierSource refuses, no
// readable version, or a distribution's package (an agent's deb/rpm row, or a version with a distribution's mark): the distributions
// backport fixes, so NVD's upstream ranges would put a patched package inside. An agent's deb row on Ubuntu or Debian is
// compared with the distribution's own data instead (distroTierItems).
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

// isWindowsKey says whether a key is a Microsoft Windows release (windows_11_23h2): a Windows row is read with every one of them.
func isWindowsKey(k string) bool { return strings.HasPrefix(k, "microsoft|windows") }

// TierScope is the set of products the devices run, as the tier data is asked for them (Feeds.TierVulns): only the NVD entries of
// these products are read, so a pass holds the CVEs of the devices, not the 100,000 of the year.
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

// tierIndex finds the tier CVEs of a product without reading them all for each row. Every entry's CPE is parsed once here (review r1
// #7 of #804: windowsDecide, winRows and the grouping read the same Windows entries again for each row and each CVE).
type tierIndex struct {
	vulns  []Vuln     // as the matcher reads them (Affected with their parsed CPE, Published; no KEV fields)
	tier   []TierVuln // the same order
	cond   []bool     // the CVE has an entry with a platform condition (TierVuln.Platforms)
	byKey  map[string][]int
	byName map[string]int  // CVE -> index
	named  map[string]bool // Windows release -> NVD names it in some entry of the pass (winNamed, computed once)
	// The distributions' fixed rows of the tier CVEs for the devices' packages (withDistro): dtier by CVE, its indexes by
	// "distro/release/package", and the releases ("ubuntu/24.04") the feeds hold rows for.
	dtier   []TierVuln
	dby     map[string][]int
	covered map[string]bool
}

// withDistro adds the distributions' fixed rows (Feeds.TierDistro) to the index.
func (x *tierIndex) withDistro(dv []TierVuln, covered map[string]bool) *tierIndex {
	x.dtier, x.dby, x.covered = dv, map[string][]int{}, covered
	for i, t := range dv {
		for _, f := range t.Distro {
			k := f.Distro + "/" + f.Release + "/" + f.Package
			if l := x.dby[k]; len(l) == 0 || l[len(l)-1] != i {
				x.dby[k] = append(l, i)
			}
		}
	}
	return x
}

func newTierIndex(tv []TierVuln) *tierIndex {
	x := &tierIndex{vulns: make([]Vuln, len(tv)), tier: tv, cond: make([]bool, len(tv)), byKey: map[string][]int{}, byName: make(map[string]int, len(tv)), named: map[string]bool{}}
	for i, t := range tv {
		aff := make([]Affected, len(t.Affected))
		for j, af := range t.Affected {
			if c, err := ParseCPE(af.CPE); err == nil {
				af.parsed = &c
			}
			aff[j] = af
			k := tierKey(af.CPE)
			if l := x.byKey[k]; k != "" && (len(l) == 0 || l[len(l)-1] != i) {
				x.byKey[k] = append(l, i)
			}
			x.cond[i] = x.cond[i] || j < len(t.Platforms) && len(t.Platforms[j]) > 0
		}
		x.vulns[i] = Vuln{CVE: t.CVE, Published: t.Published, Affected: aff}
		x.byName[t.CVE] = i
	}
	return x
}

func (x *tierIndex) winNamed(product string) bool {
	n, ok := x.named[product]
	if !ok {
		n = winNamed(x.vulns, product)
		x.named[product] = n
	}
	return n
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

// platformIDs are the platform ids (platformWords) an NVD "running on" operating-system CPE ("microsoft:windows",
// "linux:linux_kernel") stands for; none for a platform Vedette does not recognise (or "?": NVD's condition is not known), which no
// device evidence can then satisfy (review r1 #6 of #804: drop when unsure).
func platformIDs(vendorProduct string) []string {
	v, p, _ := strings.Cut(vendorProduct, ":")
	switch v, p = norm(v), norm(p); {
	case v == "microsoft" && strings.HasPrefix(p, "windows"):
		return []string{"windows"}
	case v == "apple" && (strings.HasPrefix(p, "macos") || strings.HasPrefix(p, "macosx")):
		return []string{"macos"}
	case v == "linux" && p == "linuxkernel":
		return []string{"alpine", "ubuntu", "debian", "rhel", "suse"}
	case v == "canonical" && p == "ubuntulinux":
		return []string{"ubuntu"}
	case v == "debian" && p == "debianlinux":
		return []string{"debian"}
	case v == "redhat" || v == "fedoraproject" || v == "centos" || v == "rockylinux" || v == "almalinux":
		return []string{"rhel"}
	case v == "suse" || v == "opensuse":
		return []string{"suse"}
	case v == "alpinelinux":
		return []string{"alpine"}
	case v == "freebsd" || v == "openbsd" || v == "netbsd":
		return []string{"bsd"}
	case v == "juniper" && strings.HasPrefix(p, "junos"):
		return []string{"junos"}
	}
	return nil
}

// onPlatform keeps the entries of a tier CVE whose platform condition the row's evidence satisfies: an
// entry NVD lists "running on" some operating systems counts only when the device's OS is known (evidenceOf: the agent's OS, the
// device's SNMP statement, the software's own text; a Windows release row is Windows) and is one of them. Entries without a condition
// stay. ok is false when no entry is left.
func onPlatform(v Vuln, t TierVuln, in swInfo, win bool) (Vuln, bool) {
	ids := evidenceOf(in).ids
	if win {
		ids = append(ids, "windows")
	}
	var keep []Affected
	for j, af := range v.Affected {
		if j < len(t.Platforms) && len(t.Platforms[j]) > 0 && !slices.ContainsFunc(t.Platforms[j], func(p string) bool {
			return slices.ContainsFunc(platformIDs(p), func(id string) bool { return slices.Contains(ids, id) })
		}) {
			continue
		}
		keep = append(keep, af)
	}
	v.Affected = keep
	return v, len(keep) > 0
}

// matchTiers is the plan of one device: every tier CVE (not on an exploited list, published since now minus
// AgeLimit) whose NVD range a compared row's version is proved inside, with a range that ends (a fix exists), grouped by the update
// that fixes them (GroupFix, Ranged only). Windows release rows read NVD's entries by their monthly update.
// Platform-limited CVEs count only when the row names a platform they affect (the platform rules, and NVD's own "running on" conditions,
// onPlatform). A CVE two rows of the device match at the same version is listed once, under the agent's row first (review r1 #10 of
// #804). Ubuntu and Debian packages go by the distribution's data (distroTierItems). compared says the device has a row the
// plan compares. Nothing is a guess: an Unknown, a product-only match or a range with no end gives no item.
func matchTiers(a Asset, x *tierIndex, kev map[string]bool, now time.Time) (items []PlanItem, compared bool) {
	cut := now.Add(-AgeLimit)
	sws := slices.Clone(deviceSoftware(a))
	slices.SortStableFunc(sws, func(p, q Software) int {
		return cmp.Compare(boolInt(q.Source == "agent"), boolInt(p.Source == "agent"))
	})
	listed := map[string]bool{}
	for _, s := range sws {
		in, ok := tierInfo(a, s)
		if !ok {
			continue
		}
		compared = true
		d, win := winDevice(in)
		if win {
			in.winNamed = x.winNamed(d.rel.Product) // Every Windows entry of the pass is in x
		}
		var mine []Vuln
		for _, i := range x.candidates(in, win) {
			v := x.vulns[i]
			if listed[v.CVE+"|"+clean(in.ver)] || kev[v.CVE] || v.Published.Before(cut) || !ValidCVE(v.CVE) || !platformSettled(in, v.CVE) {
				continue
			}
			if why, out := platformRuledOut(in, v.CVE); out || why != "" {
				continue
			}
			if x.cond[i] {
				if v, ok = onPlatform(v, x.tier[i], in, win); !ok {
					continue
				}
			}
			if win {
				w, ok := windowsDecide(in, v, in.winNamed, now)
				if !ok || w.t != Yes || w.within.EndExcl == "" {
					continue
				}
			} else if t, within, _, _ := decide(in, v, keyIDs(v)); t != Yes || within.EndExcl == "" && within.EndIncl == "" {
				continue
			}
			mine = append(mine, v)
		}
		its := tierItems(a, s, in, win, x, mine)
		for _, it := range its { // the same install seen twice (the agent's and a typed row) folds; two installs at two versions do not (review r2 #2 of #804)
			for _, c := range it.CVEs {
				listed[c.CVE+"|"+clean(in.ver)] = true
			}
		}
		items = append(items, its...)
	}
	its, dc := distroTierItems(a, x, kev, cut)
	return append(items, its...), compared || dc
}

// distroTierItems is the plan of a device's Ubuntu or Debian packages: an agent's deb row (full version and source package)
// on a device whose OS names the release is compared with the distribution's own first fixed version for that release and source
// package (the feeds keep only fixed rows of tier CVEs; a public fix over one only Ubuntu Pro has). Below it, and
// the installed revision is the distribution's own build (ownBuild: never a PPA or a vendor's .deb), the CVE is listed with basis
// distro. A CVE the distribution's data does not name for that release and package is left out (drop when unsure). One item per
// source package (and per Pro-only fixes), naming the highest fixed version: a distribution's updates within a release are
// cumulative, so that one version fixes every CVE of the item (the one update that fixes them all). A kernel's packages count
// only for the running kernel (distroRows). compared says the device has such a row of a release the feeds stored tier rows for.
func distroTierItems(a Asset, x *tierIndex, kev map[string]bool, cut time.Time) (items []PlanItem, compared bool) {
	if len(x.dtier) == 0 && len(x.covered) == 0 {
		return nil, false
	}
	type key struct {
		pkg string
		pro bool
	}
	var order []key
	got := map[key]*PlanItem{}
	seen := map[key]map[string]bool{}
	d, rel, rows := distroRows(a)
	if len(rows) == 0 || !x.covered[d+"/"+rel] {
		return nil, false
	}
	for _, r := range rows {
		s, in, pkg := r.s, r.in, r.pkg
		compared = true
		if !ownBuild(d, pkg, in.pkgVer, false) {
			continue
		}
		for _, i := range x.dby[d+"/"+rel+"/"+pkg] {
			t := x.dtier[i]
			if kev[t.CVE] || t.Published.Before(cut) || !ValidCVE(t.CVE) {
				continue
			}
			fix := distroFixOf(t.Distro, d, rel, pkg)
			if fix == nil {
				continue
			}
			if c, err := debver.Compare(in.pkgVer, fix.Fixed); err != nil || c >= 0 {
				continue // fixed here, or a version Vedette cannot compare: nothing to plan
			}
			k := key{pkg, fix.Pro}
			it := got[k]
			if it == nil {
				group := a.ID + "/" + s.ID
				if fix.Pro {
					group += "/pro"
				}
				it = &PlanItem{Group: group, AssetID: a.ID, SoftwareID: s.ID, Software: clean(pkg), Version: in.pkgVer, Fixed: fix.Fixed, Kind: "distro", Pro: fix.Pro}
				got[k], seen[k] = it, map[string]bool{}
				order = append(order, k)
			}
			if c, err := debver.Compare(in.pkgVer, it.Version); err == nil && c < 0 { // two installs of one source: the oldest
				it.Version = in.pkgVer
			}
			if c, err := debver.Compare(fix.Fixed, it.Fixed); err == nil && c > 0 {
				it.Fixed = fix.Fixed
			}
			if s.SeenAt.After(it.Reported) {
				it.Reported = s.SeenAt
			}
			if !seen[k][t.CVE] {
				seen[k][t.CVE] = true
				it.CVEs = append(it.CVEs, planCVE(t, planDistro))
			}
		}
	}
	for _, k := range order {
		it := got[k]
		it.Version, it.Fixed = clean(it.Version), clean(it.Fixed)
		sortPlanCVEs(it.CVEs)
		items = append(items, *it)
	}
	return items, compared
}

// distroFixOf is the fixed row of the release and source package among a CVE's rows, a public fix over one only Ubuntu Pro has.
func distroFixOf(rows []DistroFix, distro, release, pkg string) *DistroFix {
	var fix *DistroFix
	for i := range rows {
		f := &rows[i]
		if f.Distro != distro || f.Release != release || f.Package != pkg || f.Status != "fixed" || f.Fixed == "" {
			continue
		}
		if fix == nil || fix.Pro && !f.Pro {
			fix = f
		}
	}
	return fix
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tierItems groups the matched CVEs of one row by the update that fixes them: one item when one release fixes them all, else one
// item per release that fixes some (each CVE once, by its own nearest fix); a CVE no release is named for is left out (no update to
// plan for it).
func tierItems(a Asset, s Software, in swInfo, win bool, x *tierIndex, vulns []Vuln) []PlanItem {
	if len(vulns) == 0 {
		return nil
	}
	group := func(vs []Vuln) *GroupFix {
		if win {
			return windowsGroupFix(in, vs)
		}
		return groupFixOf(in, vs, nil)
	}
	base := a.ID + "/" + s.ID
	item := func(g *GroupFix, suffix string) PlanItem {
		kind := "fixed" // a Windows feature update: move to the release g.Fixed names
		switch {
		case win && g.Kind == "esu": // the release is out of support: the fix comes only with Extended Security Updates (review r1 #5 of #804)
			kind = "esu"
		case win && g.Kind != "feature_update":
			kind = "windows"
		}
		it := PlanItem{Group: base + suffix, AssetID: a.ID, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(in.ver), Fixed: g.Fixed, Kind: kind}
		basis := planVersion
		if s.Source == "agent" {
			basis, it.Reported = planAgent, s.SeenAt
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

// namesFix says the group names an update a person can install (RowFix kinds; a distribution's package is planned by
// distroTierItems).
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

// sortPlanCVEs orders an item's CVEs as the contract says: likely first, by EPSS; then the recent ones by CVSS score (the
// severity a customer reads; their EPSS is under 10 % and close together), then EPSS; then newest. A list of thousands (the
// cumulative update of a Windows release) opens on what matters.
func sortPlanCVEs(cs []PlanCVE) {
	num := func(p *float64) float64 {
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
		if a.Tier == "likely" {
			return cmp.Or(cmp.Compare(num(b.EPSS), num(a.EPSS)), cmp.Compare(num(b.Score), num(a.Score)), strings.Compare(b.Published, a.Published), strings.Compare(a.CVE, b.CVE))
		}
		return cmp.Or(cmp.Compare(num(b.Score), num(a.Score)), cmp.Compare(num(b.EPSS), num(a.EPSS)), strings.Compare(b.Published, a.Published), strings.Compare(a.CVE, b.CVE))
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
	top := func(i PlanItem) float64 { // the highest EPSS (the first CVE is the highest only among likely ones, sortPlanCVEs)
		m := -1.0
		for _, c := range i.CVEs {
			if c.EPSS != nil && *c.EPSS > m {
				m = *c.EPSS
			}
		}
		return m
	}
	slices.SortStableFunc(items, func(a, b PlanItem) int {
		return cmp.Or(cmp.Compare(likely(b), likely(a)), cmp.Compare(top(b), top(a)), cmp.Compare(len(b.CVEs), len(a.CVEs)), strings.Compare(a.Group, b.Group))
	})
}
