package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/winrel"
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
	SoftwareID string `json:"-"`
	Software   string `json:"software"`
	Version    string `json:"version"`
	Fixed      string `json:"fixed"`
	Kind       string `json:"kind"` // fixed, windows, esu, distro
	Pro        bool   `json:"pro"`  // distro: the fixed version is in Ubuntu Pro (ESM) only
	// Distro (distro without Fixed: the fallback, pkgTierItem, or no fix yet): the distribution ("Alpine Linux"); "" for the
	// distribution's.
	Distro string `json:"distro"`
	// DistroData (kind distro): what the distribution's own data says (plandistro.go): DistroDataFixed (Fixed is its fixed release),
	// DistroDataNoFix (no fix from it yet for these CVEs), DistroDataNone (no data from it for the package: NVD's upstream ranges); ""
	// for another kind.
	DistroData string `json:"distro_data"`
	// NVDLag (windows, esu): Fixed is the newest monthly update Microsoft lists for the release, newer than the update that carries
	// every fixed build NVD names (GroupFix.NVDLag): the item fixes at least its CVEs; the newest update's are not analysed by NVD yet.
	NVDLag bool `json:"nvd_lag"`
	// KB (windows, esu): the KB number of Fixed when Microsoft's release information lists that build; "" otherwise.
	KB   string    `json:"kb"`
	CVEs []PlanCVE `json:"cves"`
	// Basis is how the row's version is known (planAgent or planVersion; planDistro for a package): the basis of its CVEs, and of an
	// item with none (awaitsNVD), which GET /findings/plan reads for agent_gone. Not in the API.
	Basis string `json:"-"`
	// Reported is, for an agent's row, when the agent last reported it (Software.SeenAt): the day of the list the version comes from,
	// which GET /findings/plan names once no agent reports the device (agent_reported). Zero otherwise. Not in the pass's JSON.
	Reported time.Time `json:"-"`
	// agentRow: the item rests on a row the device's agent reported (a distribution's package judged by its data): GET /findings/plan
	// names the day of that report once no agent reports the device. Not in the API.
	agentRow bool
}

// Basis values of a plan CVE.
const (
	planAgent   = "agent"
	planVersion = "version"
	planDistro  = "distro"
)

// tierSource is trustedReading for the plan.
func tierSource(s Software) bool { return trustedReading(s) }

// tierInfo is the swInfo of a row the plan compares with NVD's ranges, false when it compares none: a source tierSource refuses, no
// readable version, or a version with a distribution's mark and no package release ("1.18.0-6ubuntu14.6" typed as the version).
// pkg says the row is a distribution's package (pkgBuilt: an agent's deb/rpm/apk row, a package release a person gave): the
// distributions backport fixes, so the update to name is the distribution's, never an upstream release. An Ubuntu or Debian
// package is judged by the distribution's own data (plandistro.go, distroRows); any other package is compared by its
// upstream version and, inside a range, gets one item "install <distribution>'s security updates" (pkgTierItem).
func tierInfo(a Asset, s Software) (in swInfo, pkg, ok bool) {
	if !tierSource(s) {
		return swInfo{}, false, false
	}
	in = newSWInfo(s, a.OS)
	in.platformOS = platformOS(s, a)
	if !in.given || !versionKnown(in.ver) {
		return swInfo{}, false, false
	}
	if in.pkgBuilt() {
		return in, true, true
	}
	if distroMarked(in.ver) || distroMarked(s.Version) {
		return swInfo{}, false, false
	}
	return in, false, true
}

// tierKey is the product key of an NVD CPE as the plan indexes it: productid.NormKey(vendor, product), read without a full parse (an
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
	return productid.NormKey(v, p)
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
func NewTierScope(assets []Asset) *TierScope { return newTierScope(assets, nil) }

// newTierScope is NewTierScope without the rows of skip (device -> software ids): a distribution's package its data alone decides
// (TierSkip), whose NVD entries the plan never reads.
func newTierScope(assets []Asset, skip map[string]map[string]bool) *TierScope {
	t := &TierScope{keys: map[string]bool{}}
	for _, a := range assets {
		for _, s := range deviceSoftware(a) {
			in, _, ok := tierInfo(a, s)
			if !ok || skip[a.ID][s.ID] {
				continue
			}
			if _, win := winDevice(in); win {
				t.windows = true
			}
			if in.hasCPE {
				v, _ := in.cpe.Vendor.Literal()
				p, _ := in.cpe.Product.Literal()
				t.keys[productid.NormKey(v, p)] = true
			}
			for _, id := range in.ids {
				if id.prefix {
					t.prefix = append(t.prefix, id)
					continue
				}
				t.keys[productid.NormKey(id.vendor, id.product)] = true
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
	dpkg    map[string][]int // "distro/package" -> indexes of dtier with a row of that package (any release)
	dname   map[string]int   // CVE -> index of dtier
	covered map[string]bool
	known   map[string]bool // "distro/package" a feed has any row of (withKnown); nil: the packages of dtier's rows
	loading map[string]bool // distributions whose feed is on but not loaded yet
	// kevWin are the exploited-list entries with a Windows release row, and open the CVEs of each device's open findings (withKEV): a
	// Windows row inside one of them with a fix and an open finding has an exploited update To fix names (the same target), so the plan
	// names no newest update for it (newestUpdateItem).
	kevWin []Vuln
	open   map[string]map[string]bool
}

// withKEV adds the exploited-list entries that name a Windows release, and each device's open findings (device -> CVEs), to the index.
func (x *tierIndex) withKEV(kevs []Vuln, open map[string]map[string]bool) *tierIndex {
	for _, v := range kevs {
		if slices.ContainsFunc(v.Affected, func(af Affected) bool { return isWindowsKey(tierKey(af.CPE)) }) {
			x.kevWin = append(x.kevWin, v)
		}
	}
	x.open = open
	return x
}

// exploitedFix says whether the device has an open finding of an exploited-list entry the Windows row is inside through a range with
// an end: To fix lists that update for the device (exploitedUpdates: open findings only, the same target, winLatest). A finding a
// person closed (mitigated, risk accepted) names no update, so the newest one is planned.
func (x *tierIndex) exploitedFix(assetID string, in swInfo, now time.Time) bool {
	return slices.ContainsFunc(x.kevWin, func(v Vuln) bool {
		if !x.open[assetID][v.CVE] {
			return false
		}
		w, ok := windowsDecide(in, v, true, now)
		return ok && w.t == Yes && w.within.EndExcl != ""
	})
}

// withDistro adds the distributions' fixed rows (Feeds.TierDistro) to the index.
func (x *tierIndex) withDistro(dv []TierVuln, covered map[string]bool) *tierIndex {
	x.dtier, x.dpkg, x.dname, x.covered = dv, map[string][]int{}, map[string]int{}, covered
	if x.known == nil {
		x.known = map[string]bool{}
	}
	for i, t := range dv {
		x.dname[t.CVE] = i
		for _, f := range t.Distro {
			k := f.Distro + "/" + f.Package
			x.known[k] = true
			if l := x.dpkg[k]; len(l) == 0 || l[len(l)-1] != i {
				x.dpkg[k] = append(l, i)
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
		add(x.byKey[productid.NormKey(v, p)])
	}
	for _, id := range in.ids {
		if !id.prefix {
			add(x.byKey[productid.NormKey(id.vendor, id.product)])
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
	switch v, p = productid.Norm(v), productid.Norm(p); {
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
// #804). A distribution's package goes by its data (plandistro.go). compared says the device has a row the
// plan compares. Nothing is a guess: an Unknown, a product-only match or a range with no end gives no item.
func matchTiers(a Asset, x *tierIndex, kev map[string]bool, now time.Time) (items []PlanItem, compared bool) {
	cut := now.Add(-AgeLimit)
	sws := slices.Clone(deviceSoftware(a))
	slices.SortStableFunc(sws, func(p, q Software) int {
		return cmp.Compare(boolInt(q.Source == "agent"), boolInt(p.Source == "agent"))
	})
	listed := map[string]bool{}
	winItem := map[string]bool{} // a Windows install (its version) that has an item: one row per install, never a second one
	d, rel, judged, wait := x.distroWords(a)
	nvd := map[string][]Vuln{} // a judged row of a distribution whose data lists fixed releases only: the CVEs NVD puts it inside
	for _, s := range sws {
		in, pkg, ok := tierInfo(a, s)
		if !ok || pkg && wait[s.ID] {
			continue // the distribution's data is loading: no item on a guess
		}
		_, byData := judged[s.ID]
		if pkg && byData && !d.fixedOnly {
			continue // the distribution's data alone decides: distroItems
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
		if pkg && byData { // judged by the distribution's data, with these CVEs as the ones it may have no fix for yet
			nvd[s.ID] = mine
			continue
		}
		if pkg { // a package of a distribution whose data has no word on it: its security updates, never an upstream release
			if it, ok := pkgTierItem(a, s, in, x, mine); ok {
				for _, c := range it.CVEs {
					listed[c.CVE+"|"+clean(in.ver)] = true
				}
				items = append(items, it)
			}
			continue
		}
		its := tierItems(a, s, in, win, x, mine, now)
		for _, it := range its { // the same install seen twice (the agent's and a typed row) folds; two installs at two versions do not (review r2 #2 of #804)
			for _, c := range it.CVEs {
				listed[c.CVE+"|"+clean(in.ver)] = true
			}
		}
		if win && len(its) == 0 && !winItem[clean(in.ver)] && !x.exploitedFix(a.ID, in, now) {
			if it, ok := newestUpdateItem(a, s, in, d, now); ok {
				its = []PlanItem{it}
			}
		}
		if win && len(its) > 0 {
			winItem[clean(in.ver)] = true
		}
		items = append(items, its...)
	}
	return append(items, x.distroItems(a, d, rel, judged, nvd, kev, cut)...), compared || len(judged) > 0
}

// pkgTierItem is the fallback item of a distribution's package its distribution's data has no word on (Red Hat, SUSE and the others the
// feeds supply no data for; an Ubuntu, Debian or Alpine package their data never names, another build such as a PPA, a row without its
// source package): its upstream version is inside NVD's range with an end for these CVEs, but the distribution backports fixes under its
// own release numbers, so the page says to check the distribution's security updates for the package and that NVD lists these CVEs for
// its upstream version, never that an update fixes them nor an upstream release (kind distro, Fixed "", DistroData DistroDataNone;
// Distro names the distribution when known). Version is the package release when known (the one a person gave or the agent read), else
// the version. No item when no CVE is inside a range.
func pkgTierItem(a Asset, s Software, in swInfo, x *tierIndex, vulns []Vuln) (PlanItem, bool) {
	if len(vulns) == 0 {
		return PlanItem{}, false
	}
	basis := planVersion
	if s.Source == "agent" {
		basis = planAgent
	}
	it := PlanItem{Group: a.ID + "/" + s.ID + "/distro", AssetID: a.ID, SoftwareID: s.ID, Software: clean(s.Display),
		Version: clean(cmp.Or(strings.TrimSpace(s.PkgVersion), in.ver)), Kind: "distro", DistroData: DistroDataNone,
		Distro: distroLabel(linuxDistro(cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS, a.OS))), Basis: basis}
	if s.Source == "agent" {
		it.Reported = s.SeenAt
	}
	for _, v := range vulns {
		it.CVEs = append(it.CVEs, planCVE(x.tier[x.byName[v.CVE]], basis))
	}
	sortPlanCVEs(it.CVEs)
	return it, true
}

// newestUpdateItem is the item of a Windows release row below the newest monthly security update Microsoft lists for its release
// (core/winrel.Updates, feed windows-releases) when no analysed CVE gives the row an item: on Patch Tuesday every Windows device is one
// update behind, and NVD analyses that update's CVEs over the next weeks, so without it the plan says nothing while the update is
// out. The item names the update (its build and KB) with no CVE yet (awaitsNVD); once NVD analyses a CVE of it that the row is inside,
// tierItems gives the row its item instead, with the same target (winLatest) and a count. The release must still get monthly updates
// for the device: a release that ended gets none, unless its LTSC edition is still serviced and the device runs it, or Extended
// Security Updates continue it (LastFreeRev; then the item is kind esu when the newest update is above the last free one, as winFix).
// A device on a hotpatch is current to its month (winDevice: d.rev is that month's update). No item when an exploited-list entry
// already has the row (To fix names the same update, matchTiers), or when the newest update is older than AgeLimit (the feed has not
// been read for a year: nothing current to name). NVDLag is true while the update is younger than winNVDLagWindow ("its CVEs are not
// yet analysed by NVD"); after it the item stays, since the device is still behind, but says NVD lists no CVE of it for the release.
func newestUpdateItem(a Asset, s Software, in swInfo, d winDev, now time.Time) (PlanItem, bool) {
	if d.ended() && d.rel.LastFreeRev == 0 {
		return PlanItem{}, false
	}
	us := winrel.Updates(d.rel.Build, d.rel.Server)
	if len(us) == 0 || us[len(us)-1].Rev <= d.rev || now.Sub(us[len(us)-1].Day) > AgeLimit {
		return PlanItem{}, false
	}
	newest := us[len(us)-1]
	kind := "windows"
	if d.rel.LastFreeRev > 0 && newest.Rev > d.rel.LastFreeRev {
		kind = "esu"
	}
	it := PlanItem{Group: a.ID + "/" + s.ID, AssetID: a.ID, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(in.ver),
		Fixed: fmt.Sprintf("10.0.%d.%d", d.rel.Build, newest.Rev), Kind: kind, NVDLag: now.Sub(newest.Day) < winNVDLagWindow, KB: newest.KB, Basis: planVersion}
	if s.Source == "agent" {
		it.Basis, it.Reported = planAgent, s.SeenAt
	}
	return it, true
}

// awaitsNVD says the item is a Windows release's newest monthly update with none of its CVEs analysed by NVD yet (newestUpdateItem):
// it is listed with no CVE, under the tiers all and recent, and ranks after every item with a CVE (no severity or EPSS to rank by).
func awaitsNVD(it PlanItem) bool {
	return len(it.CVEs) == 0 && (it.Kind == "windows" || it.Kind == "esu")
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
func tierItems(a Asset, s Software, in swInfo, win bool, x *tierIndex, vulns []Vuln, now time.Time) []PlanItem {
	if len(vulns) == 0 {
		return nil
	}
	group := func(vs []Vuln) *GroupFix {
		if win {
			return windowsGroupFix(in, vs, now)
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
		it := PlanItem{Group: base + suffix, AssetID: a.ID, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(in.ver), Fixed: g.Fixed, Kind: kind, NVDLag: win && g.NVDLag, KB: g.KB}
		basis := planVersion
		if s.Source == "agent" {
			basis, it.Reported = planAgent, s.SeenAt
		}
		it.Basis = basis
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
// distroItems or pkgTierItem).
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
