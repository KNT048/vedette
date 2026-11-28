package findings

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/oui"
)

// Platform limits (KF-4, KF-5). Some exploited CVEs affect a product only on some platforms: CVE-2026-123158 is
// OpenSSH built with musl libc and without PAM (Alpine), not Ubuntu's or Debian's glibc+PAM build of the same upstream version.
// No feed Vedette reads says so in a form a program can use (KEV: "on Linux"; CVE.org: platform "Linux"; NVD: the product
// only), so content/catalog/platform-limits.json holds a short reviewed list. For a CVE on it:
//   - the device's OS (for an agent row, or the OS an SNMP device states for its SNMP row: platformOS), the software's own
//     version or banner text, or an agent's deb/rpm package database names another platform, and nothing names one it
//     affects → proved not affected (no finding; an open one closes by auto-resolve, reason not_affected_version with a platform
//     audit detail). The distribution's own word is read first and wins;
//   - the platform is not known (nothing names a platform) → no finding: the CVE is "Could not be checked" (reason
//     platform_unknown) with the entry's question, and an open suspected finding closes into that list (MatchResult.Asked; one a safe
//     check or a person confirmed stays open); the person's answer (the device's OS, inventory INV-41) decides at the next match;
//   - the platform is one it affects and the entry has the distribution's fixed list: the package release decides. At or above
//     the fix of the device's branch → proved not affected (closes by auto-resolve); below it → a version finding; no release yet →
//     "Could not be checked" (reason package_unknown) asking for it, unless the version is older than every fix (a finding);
//   - the platform is one it affects, no fixed list → the finding as for any CVE.

type platformLimit struct {
	Only    []string `json:"only"`
	Affects string   `json:"affects"`
	Check   string   `json:"check"`
	// Ask is the question for a device whose platform is not known ("{device}" its name): the CVE is then "Could not be checked"
	// with this question, not a finding.
	Ask    string       `json:"ask"`
	Source string       `json:"source"`
	Fixed  *platformFix `json:"fixed,omitempty"`
}

// platformFix is the distribution's first fixed package release per branch: once a row's platform is that distribution,
// its package release decides the CVE. Only Alpine's apk releases are read (apkver.go). The catalog names the package; the releases
// come from the distribution's own data, the feed alpine-osv (Vuln.Distro), never from a hand copy (distroFixes).
type platformFix struct {
	Distro  string `json:"distro"`  // the platform id of Only it is about ("alpine")
	Package string `json:"package"` // the package as the device's package manager names it ("openssh-server")
	// SourcePackage is the package the distribution's security data lists the fix under ("openssh", the origin of openssh-server).
	SourcePackage string `json:"source_package"`
	Command       string `json:"command"` // what prints its release on the device ("apk info -e -v openssh-server" → "openssh-server-10.2_p1-r1")
	// BranchCommand prints the device's branch ("cat /etc/alpine-release" → "3.23.2"), for the platform question (review r2 L4 of #961).
	BranchCommand string `json:"branch_command"`
	// HandReleases must stay empty: a release list copied by hand is refused, the feed gives them.
	HandReleases map[string]string `json:"releases"`
	Releases     map[string]string `json:"-"` // branch ("3.23") -> first fixed release ("10.2_p1-r1"), from the feed (distroFixes)
	Source       string            `json:"source"`
}

var branchKeyRE = regexp.MustCompile(`^(edge|\d{1,2}\.\d{1,3})$`)

var platformLimits, platformLimitErr = loadPlatformLimits(catalogdata.PlatformLimits)

func loadPlatformLimits(data []byte) (map[string]platformLimit, error) {
	var rows map[string]json.RawMessage
	out := map[string]platformLimit{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return out, err // TestPlatformLimits_DataIsValid fails on it; the matcher only loses the limits
	}
	for k, raw := range rows {
		if k == "_about" {
			continue
		}
		var l platformLimit
		if err := json.Unmarshal(raw, &l); err != nil {
			return map[string]platformLimit{}, fmt.Errorf("%s: %w", k, err) // none rather than a random part of the file
		}
		if !ValidCVE(k) || len(l.Only) == 0 || l.Affects == "" || l.Check == "" || !strings.HasPrefix(l.Source, "https://") {
			return map[string]platformLimit{}, fmt.Errorf("%s: needs a CVE id, only, affects, check and an https source", k)
		}
		for _, p := range l.Only {
			if platformName(p) == "" {
				return map[string]platformLimit{}, fmt.Errorf("%s: unknown platform %q", k, p)
			}
		}
		if !strings.Contains(l.Ask, "{device}") || !strings.HasSuffix(l.Ask, "?") {
			return map[string]platformLimit{}, fmt.Errorf("%s: ask is a question naming {device}", k)
		}
		if err := l.Fixed.valid(l.Only); err != nil {
			return map[string]platformLimit{}, fmt.Errorf("%s: fixed: %w", k, err)
		}
		out[k] = l
	}
	return out, nil
}

// platformWords are the platforms Vedette recognises in an OS name ("Ubuntu 26.04.1 LTS") or in the version and banner a service
// sends ("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "7.4p1 Debian 10+deb9u7"): whole words, any case.
var platformWords = []struct {
	id, name string
	re       *regexp.Regexp
}{
	{"alpine", "Alpine Linux", regexp.MustCompile(`(?i)\balpine\b`)},
	{"ubuntu", "Ubuntu", regexp.MustCompile(`(?i)\bubuntu\b`)},
	{"debian", "Debian", regexp.MustCompile(`(?i)\b(debian|raspbian)\b`)},
	{"rhel", "Red Hat Enterprise Linux or a rebuild of it", regexp.MustCompile(`(?i)\b(red ?hat|rhel|centos|rocky|almalinux|oracle linux|fedora|amazon linux)\b`)},
	{"suse", "SUSE", regexp.MustCompile(`(?i)\b(open)?suse\b|\bsles\b`)},
	{"windows", "Windows", regexp.MustCompile(`(?i)\bwindows\b`)},
	{"macos", "macOS", regexp.MustCompile(`(?i)\b(mac ?os|os x)\b`)},
	{"bsd", "a BSD", regexp.MustCompile(`(?i)\b(freebsd|openbsd|netbsd)\b`)},
	{"junos", "Juniper Junos OS", regexp.MustCompile(`(?i)\bjunos\b`)},
}

// networkOS are the platforms of network gear whose own statement of its OS also says what a service a scan sees on it runs on:
// a Junos switch does not forward its management address to an Alpine container. Only Junos for now: RouterOS and Cisco IOS XE
// can host containers, so a service seen on them may still be one; so can Junos OS Evolved ("…-EVO"), which runs Docker (review r1 #4).
var networkOS = []string{"junos"}

// junosEvolved matches Junos OS Evolved in a system description ("JUNOS 21.4R1.12-EVO", "Junos OS Evolved").
var junosEvolved = regexp.MustCompile(`(?i)-evo\b|\bevolved\b`)

// networkStated is the OS the device states for every row of it: a networkOS platform, not Junos Evolved, on a device no
// agent reports another OS for, stated either
//   - in the device's answer to Vedette's own SNMP read of its address (Asset.SNMPOS), or
//   - when there is no SNMP answer, in an LLDP frame (StatedOS, source passive: LLDP's system description is the only passive source
//     of a Junos OS), on a device whose own MAC at its address is one IEEE assigned to Juniper Networks (juniperMAC). An LLDP frame alone
//     can be forged with another device's MAC (review r1 #3 of #800); the forged claim then sits on a device whose network card
//     Juniper did not make, and is not read. A device with a Juniper card is Juniper gear, which runs no container behind its
//     management address (the EX4200 switch .47, stated over LLDP "JUNOS 15.1R7.9", MAC 3c:8a:b0:…).
//
// An SNMP answer naming another OS wins over any LLDP frame. "" otherwise.
func networkStated(a Asset) string {
	if a.AgentOS != "" {
		return ""
	}
	states := func(os string) bool {
		return os != "" && !junosEvolved.MatchString(os) &&
			slices.ContainsFunc(platformsIn(os), func(id string) bool { return slices.Contains(networkOS, id) })
	}
	switch {
	case a.SNMPOS != "":
		if states(a.SNMPOS) {
			return a.SNMPOS
		}
	case states(a.StatedOS) && juniperMAC(a.MAC):
		return a.StatedOS
	}
	return ""
}

// juniperOUI is how the IEEE table (content/oui) names Juniper Networks; "Juniper Systems" is another company.
const juniperOUI = "Juniper Networks"

// juniperMAC says whether mac (inventory's "3c:8a:b0:9c:85:ff") has an OUI IEEE assigned to Juniper Networks.
func juniperMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	v, ok := oui.Lookup([6]byte(hw))
	return ok && v == juniperOUI
}

func platformName(id string) string {
	for _, w := range platformWords {
		if w.id == id {
			return w.name
		}
	}
	return ""
}

// platformEvidence names what says which platform the software runs on, as a clause ("this device runs Ubuntu 26.04.1 LTS"),
// with the platform ids it names. Only evidence of a recognised platform counts; "Linux 5.4 - 5.15" says none.
type platformEvidence struct {
	ids  []string
	says []string
}

func (e *platformEvidence) add(ids []string, clause string) {
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if !slices.Contains(e.ids, id) {
			e.ids = append(e.ids, id)
		}
	}
	e.says = append(e.says, clause)
}

func platformsIn(text string) []string {
	var ids []string
	for _, w := range platformWords {
		if w.re.MatchString(text) {
			ids = append(ids, w.id)
		}
	}
	return ids
}

// platformOS is the device's OS when it is evidence of the platform the row was built for: only for a row the device's own
// software inventory gave, read against the OS that inventory states. An agent row (osquery, Wazuh, the box's own package list)
// takes the OS the agent itself reports (Asset.AgentOS), never the folded OS, which on a device the agent says nothing about can be
// a fingerprint or DHCP guess (review r2 of #790); an SNMP row takes only the OS the device states to Vedette's SNMP read of its address (Asset.SNMPOS).
// A row a scan saw on a port, a row a person typed and a row of unknown source say nothing about it: a Ubuntu host may run or forward
// the service from an Alpine container (CVE-2026-123158's references are Docker sshd images), so only the row's own text decides
// there (review r1 #1, #2). Exception: on network gear that states an OS of networkOS over SNMP, or over LLDP on a
// Juniper network card (a Junos switch, networkStated), that statement counts for every row, since such gear runs no container behind
// its own address.
//
// A person's answers. The OS a person set on the device (Asset.ManualOS, inventory INV-41) is the OS of an agent or SNMP row (as
// #950 already gives it). On a row a scan saw it only confirms a platform the CVE affects (platformCheck asks for the package release
// then); it never rules the row out, since a Ubuntu host may forward the port to an Alpine container (review r1 M1 of #961). A row whose
// package release a person gave (inventory's correction, a manual row with Software.PkgVersion) is an answer about that row: it takes
// the device's OS (the person's, its agent's, its SNMP answer).
func platformOS(s Software, a Asset) string {
	switch b := s.builtBy(); { // a person's correction of an agent or SNMP row keeps that row's evidence (review r1 M1 of #950)
	case b == "agent":
		return cmp.Or(a.ManualOS, a.AgentOS)
	case b == "snmp":
		return cmp.Or(a.ManualOS, a.SNMPOS) // the SNMP answer at the device's own address, never an LLDP frame (review r2)
	case s.Source == "manual" && s.PkgVersion != "":
		return cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS, networkStated(a))
	}
	return networkStated(a)
}

// debRPM is the evidence id of a row an agent read from a deb or rpm database: a Debian, Ubuntu, Red Hat or SUSE family build,
// never Alpine's apk. It counts as a platform a CVE affects when the CVE's list names one of those families (review r1 #3).
const debRPM = "deb-rpm"

var debRPMFamilies = []string{"debian", "ubuntu", "rhel", "suse"}

// otherPkg is the evidence id of a package release a person gave on the row that is not Alpine's apk format ("1:9.2p1-2+deb12u3"):
// the person's "another system" answer about that row (review r2 M-2 of #961), so it counts as any platform but Alpine. An apk release
// a person gave counts as Alpine (postmarketOS is Alpine-based).
const otherPkg = "other-pkg"

func evidenceOf(in swInfo) platformEvidence {
	var e platformEvidence
	if t := clean(strings.TrimSpace(in.platformOS)); t != "" {
		e.add(platformsIn(t), "this device runs "+t)
	}
	// Matched on the text shown, so the word that rules a CVE out is always in the sentence (review r1 #4).
	if t := clean(strings.TrimSpace(in.ver + " " + in.banner)); t != "" {
		e.add(platformsIn(t), "the software reports "+t)
	}
	if in.packaged || in.upstreamBuild {
		if _, t := apkRelease(in.pkgVer); t != "" {
			e.add([]string{"alpine"}, "an agent read the release "+clean(t)+" from the device's Alpine apk database")
		} else {
			e.add([]string{debRPM}, "an agent read it from the device's deb or rpm package database, not Alpine's apk")
		}
	}
	if p := in.personPkg; p != "" {
		if _, t := apkRelease(p); t != "" {
			e.add([]string{"alpine"}, "the package release a person gave, "+clean(t)+", is an Alpine apk release")
		} else {
			on := ""
			if t := clean(strings.TrimSpace(in.platformOS)); t != "" {
				on = " on " + t
			}
			e.add([]string{otherPkg}, "a person gave the package release "+clean(p)+on+", which is not an Alpine apk release")
		}
	}
	return e
}

// platformRuledOut says whether the evidence rules v out for the software: v is on the list, something names a platform,
// and nothing it names is one v affects. why is the sentence for the page ("CVE-… affects only …; this device runs Ubuntu 26.04.").
func platformRuledOut(in swInfo, cve string) (why string, out bool) {
	l, ok := platformLimits[cve]
	if !ok {
		return "", false
	}
	return ruledOut(l, evidenceOf(in), cve)
}

func ruledOut(l platformLimit, e platformEvidence, cve string) (string, bool) {
	if len(e.ids) == 0 || slices.ContainsFunc(e.ids, l.affects) {
		return "", false
	}
	return fmt.Sprintf("%s affects only %s; %s.", cve, l.Affects, strings.Join(e.says, ", and ")), true
}

// PlatformRuledOut says whether the platform rules prove the KEV entry (cve of vendor and product) does not affect the device:
// every software row keyed to it is ruled out by its platform (MatchAsset's OtherPlatform). The CVE page's "Do you have it?" (feeds)
// asks it so it agrees with the device's findings (KF-CVEPAGE): an Ubuntu box whose OpenSSH finding of an Alpine-only CVE is
// closed is not listed as running it. It reads no NVD range and no distribution data (feeds has the entry only): the distribution's
// word, which could say its own package is affected after all, is not read here; no entry of the list has such a word today.
// distro is the distributions' word on the CVE (feeds' rows of it): the package release a person gave is read against it.
func PlatformRuledOut(a Asset, cve, vendor, product string, distro []DistroFix, now time.Time) bool {
	if !HasPlatformLimit(cve) {
		return false
	}
	r := MatchAsset(a, []Vuln{{CVE: cve, Vendor: vendor, Product: product, Distro: distro}}, map[string]bool{cve: true}, now)
	return len(r.OtherPlatform) > 0
}

// HasPlatformLimit says whether the CVE is on the platform-limits list: only such a CVE can be ruled out by PlatformRuledOut, so a
// caller checks it before reading any device (review r1 #9).
func HasPlatformLimit(cve string) bool {
	_, ok := platformLimits[cve]
	return ok
}

// affects says whether evidence id (a platform, or debRPM for an agent's deb/rpm row) is one the entry affects.
func (l platformLimit) affects(id string) bool {
	switch id {
	case debRPM:
		return slices.ContainsFunc(debRPMFamilies, func(f string) bool { return slices.Contains(l.Only, f) })
	case otherPkg:
		return slices.ContainsFunc(l.Only, func(f string) bool { return f != "alpine" })
	}
	return slices.Contains(l.Only, id)
}

// valid checks a fixed list (nil is none).
func (f *platformFix) valid(only []string) error {
	if f == nil {
		return nil
	}
	if f.Distro != "alpine" || !slices.Contains(only, f.Distro) {
		return fmt.Errorf("distro %q: only alpine (apk releases), and one of only", f.Distro)
	}
	if f.Package == "" || f.SourcePackage == "" || f.Command == "" || f.BranchCommand == "" || !strings.HasPrefix(f.Source, "https://") || !strings.Contains(f.Source, "{branch}") {
		return errors.New("needs package, source_package, command, branch_command and an https source naming {branch}")
	}
	if len(f.HandReleases) > 0 {
		return errors.New("releases come from the distribution's feed, not from the catalog")
	}
	return nil
}

// distroFixes is the distribution's first fixed release per branch of a platform-limited CVE, nil when none. The one place the
// decision reads that data from: the catalog's package (platform-limits.json `fixed`) with the releases the distribution's feed
// gives for its source package (rows: Vuln.Distro, feeds' alpine-osv: every branch OSV.dev lists, which has no edge), each the full
// release (upstream and -rN) unchanged. A branch the feed has no fixed release for has none here (secdb's "not affected" included: no
// proof is read from it); no release at all is nil, as for a CVE without a fixed list (NVD decides), never a guess.
func distroFixes(cve string, rows []DistroFix) *platformFix {
	spec := platformLimits[cve].Fixed
	if spec == nil {
		return nil
	}
	f := *spec
	f.Releases = map[string]string{}
	for _, r := range rows {
		if _, ok := parseAPK(r.Fixed); ok && r.Distro == f.Distro && r.Package == f.SourcePackage && r.Status == "fixed" && branchKeyRE.MatchString(r.Release) {
			f.Releases[r.Release] = r.Fixed
		}
	}
	if len(f.Releases) == 0 {
		return nil
	}
	return &f
}

// branches are the fixed list's branches, newest first ("edge", "3.24", …).
func (f *platformFix) branches() []string { return branchesOf(f.Releases) }

// How alpineFixBranch chose the branch whose fix a release is compared with.
const (
	branchNone    = iota // no branch's fix can judge the release: NVD's range decides
	branchOwn            // the device's branch
	branchOther          // the device's branch has no fix, and the release is older than every branch's fix on its release line: it is below
	branchUnnamed        // the device's OS names no branch, and the release is older than every branch's fix on its release line: it is below
)

// alpineFixBranch is the branch of releases (branch → first fixed release) whose fix an Alpine package release is compared with. A
// package release ("-rN") counts within its branch only, so a release proves fixed only against the device's own branch's fix of the
// SAME upstream version (review r2 H-1 of #961): a package from another branch's repository (3.23's 10.2_p1-r0 on a 3.20 box), or a
// branch whose fix the data does not list yet, proves nothing. The device's branch's fix also shows a release of an older upstream
// version below it (3.21's 9.9_p1-r5 against 9.9_p2-r1: affected, never fixed). With no fix of the device's branch, other branches'
// fixes on the release's own upstream release line (apkLine: 3.12 of python3 3.12.16; 3.24's 3.14.7 fix says nothing about it) only
// ever show a release below them, never fixed: when its upstream version is older than every one of theirs (the nearest of them is the
// one to install). Else none: NVD's range decides (it carries each line's fix). The exploited path (platformCheck) and the distribution's word
// (alpineData.choose) use it.
func alpineFixBranch(releases map[string]string, osBranch string, rel apkVer, relText string) (string, int) {
	if fx, ok := parseAPK(releases[osBranch]); ok && osBranch != "" {
		if apkUpstream(releases[osBranch]) == apkUpstream(relText) || upstreamOrder(rel, fx) < 0 {
			return osBranch, branchOwn
		}
		return "", branchNone
	}
	branch := ""
	var near apkVer
	for _, b := range branchesOf(releases) {
		if apkLine(releases[b]) != apkLine(relText) { // a fix on another release line says nothing about this one
			continue
		}
		fx, ok := parseAPK(releases[b])
		if !ok || upstreamOrder(rel, fx) >= 0 {
			return "", branchNone
		}
		if branch == "" || compareAPK(fx, near) < 0 {
			branch, near = b, fx
		}
	}
	switch {
	case branch == "":
		return "", branchNone
	case osBranch != "":
		return branch, branchOther
	}
	return branch, branchUnnamed
}

// branchesOf are the branches of a fixed list, newest first ("edge", "3.24", …).
func branchesOf(releases map[string]string) []string {
	var out []string
	for b := range releases {
		out = append(out, b)
	}
	slices.SortFunc(out, func(x, y string) int {
		switch {
		case x == y:
			return 0
		case x == "edge":
			return -1
		case y == "edge":
			return 1
		}
		o, _ := CompareVersions(y, x)
		return o
	})
	return out
}

// fixList is the list as a sentence: "10.6_p2-r0 (edge), 10.3_p1-r2 (3.24), …".
func (f *platformFix) fixList() string {
	var parts []string
	for _, b := range f.branches() {
		parts = append(parts, f.Releases[b]+" ("+b+")")
	}
	return strings.Join(parts, ", ")
}

// sourceFor is the source of one branch's release ("https://secdb.alpinelinux.org/v3.23/main.json").
// It names the data's licence and the way it came (CC BY-SA 4.0 asks for the attribution where the data decides).
func (f *platformFix) sourceFor(branch string) string {
	if branch != "edge" {
		branch = "v" + branch
	}
	return platformName(f.Distro) + "'s security database, " + strings.ReplaceAll(f.Source, "{branch}", branch) + " (CC BY-SA 4.0), through OSV.dev"
}

// belowEvery says whether the release is below every branch's fixed release that speaks of it, when the device's branch has none (its
// own fix decides otherwise, alpineFixBranch): the fixes of other branches on its release line, by upstream version only (-rN counts
// within its branch only; a fix on another release line says nothing about this one).
func (f *platformFix) belowEvery(rel apkVer, relText, osBranch string) bool {
	if osBranch != "" && f.Releases[osBranch] != "" {
		return false
	}
	n := 0
	for _, r := range f.Releases {
		if apkLine(r) != apkLine(relText) {
			continue
		}
		n++
		if fix, _ := parseAPK(r); upstreamOrder(rel, fix) >= 0 {
			return false
		}
	}
	return n > 0
}

// alpineBranchRE reads the branch from an OS name: "Alpine Linux v3.23", "Alpine Linux 3.23.2", "alpine 3.21" → 3.23, 3.23, 3.21;
// "Alpine Linux edge" → edge.
var alpineBranchRE = regexp.MustCompile(`(?i)\balpine(?:\s+linux)?\s+(?:v?(\d{1,2}\.\d{1,3})\b|(edge)\b)`)

func alpineBranch(os string) string {
	m := alpineBranchRE.FindStringSubmatch(os)
	if m == nil {
		return ""
	}
	return cmp.Or(m[1], strings.ToLower(m[2]))
}

// askKind is what a platform-limited CVE still needs from a person on a row.
type askKind string

const (
	askNone     askKind = ""
	askPlatform askKind = "platform" // which system (and, with a fixed list, which branch) the device runs
	askPackage  askKind = "package"  // the package release
)

// platformState is how a platform-limited CVE stands on a row that its platform does not rule out (platformCheck).
type platformState struct {
	ask   askKind
	bad   string // askPackage: the release a person gave that is no Alpine release (the question says so)
	fixed bool   // the package release is at or above the branch's fix: not affected
	below bool   // the package release (or the version) is below every fix that could apply: affected
	note  string // fixed: why it is not affected; below: why it is affected; otherwise a sentence the finding adds (no fix listed)
}

// apkRelease reads an Alpine package release: the bare release ("10.2_p1-r1") or the line `apk info -e -v` prints
// ("openssh-server-10.2_p1-r1", the package name before it). text is the release, "" when t is neither.
func apkRelease(t string) (v apkVer, text string) {
	t = strings.TrimSpace(t)
	if v, ok := parseAPK(t); ok {
		return v, t
	}
	for j := 0; j+1 < len(t); j++ {
		if t[j] == '-' && isDigit(t[j+1]) {
			if v, ok := parseAPK(t[j+1:]); ok {
				return v, t[j+1:]
			}
		}
	}
	return apkVer{}, ""
}

// pkgRelease is the row's package release in Alpine's shape: the one a person gave (inventory's correction), else an agent's version
// when it is one (osquery's apk_packages reports "10.2_p1-r1"). given is a person's text that is no such release (the question then
// says Vedette could not read it, review r1 M2 of #961); never an agent's (review r2 L2).
func pkgRelease(s Software, in swInfo) (rel apkVer, text, given string) {
	if v, t := apkRelease(s.PkgVersion); t != "" {
		return v, t, ""
	}
	if s.Source == "manual" {
		given = strings.TrimSpace(s.PkgVersion)
	}
	if v, t := apkRelease(in.ver); t != "" {
		return v, t, ""
	}
	return apkVer{}, "", given
}

// platformCheck is the state of a platform-limited CVE on a row platformRuledOut did not rule out. Not on the list: zero.
// Every outcome ends in a finding, a proof, or a question one of its answers settles (review r1 H1 of #961: never the same question
// again after an answer).
// rows and loading are the distributions' word on the CVE (Vuln.Distro) and the distributions whose feed is on but holds no row yet
// (Vuln.DistroLoading).
func platformCheck(a Asset, s Software, in swInfo, cve string, rows []DistroFix, loading map[string]bool) platformState {
	l, ok := platformLimits[cve]
	if !ok {
		return platformState{}
	}
	ids, osText := evidenceOf(in).ids, in.platformOS
	if !slices.ContainsFunc(ids, l.affects) {
		// nothing names the row's platform (one naming another would have ruled it out). The device's own OS (a person's, its agent's,
		// its SNMP answer) may confirm a platform the CVE affects: on to the package release. It never rules the row out (platformOS).
		dev := cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS)
		if ids = platformsIn(dev); !slices.ContainsFunc(ids, l.affects) {
			return platformState{ask: askPlatform}
		}
		osText = dev
	}
	f := distroFixes(cve, rows)
	if f == nil && l.Fixed != nil && slices.Contains(ids, l.Fixed.Distro) && loading[l.Fixed.Distro] {
		// the distribution's feed is on but its fixed releases are not loaded yet (never filled, or every pull
		// failed): only they can decide, so the question stays; NVD decides only once the feed is off. A device that does not state Alpine
		// itself (only the software's own text names it) is asked its OS: the answer is what lets feeds fetch the data (StatesAlpine).
		if !StatesAlpine(a) {
			return platformState{ask: askPlatform}
		}
		return platformState{ask: askPackage}
	}
	if f == nil || !slices.Contains(ids, f.Distro) {
		return platformState{} // a platform it affects, no fixed list (or its feed off): like any CVE (NVD decides)
	}
	name, pkg, dist := clean(a.Name), clean(f.Package), platformName(f.Distro)
	osBranch := alpineBranch(osText)
	rel, relText, bad := pkgRelease(s, in)
	if relText == "" {
		unread := ""
		if bad != "" {
			unread = fmt.Sprintf(" Vedette could not read the package release you entered (%q); enter it as %s prints it.", clean(bad), f.Command)
		}
		switch {
		case older(in.ver, f): // a finding stays a finding whatever the answer (review r2 L1)
			return platformState{below: true, note: fmt.Sprintf("%s runs %s %s on %s. %s affects only %s, and %s is older than every release %s fixed it in (%s).%s",
				name, clean(s.Display), clean(in.ver), clean(osText), cve, l.Affects, clean(in.ver), dist, f.fixList(), unread)}
		case bad != "":
			return platformState{ask: askPackage, bad: bad}
		case osBranch != "" && f.Releases[osBranch] == "":
			return platformState{note: noFixNote(cve, dist, osBranch, f)}
		}
		return platformState{ask: askPackage}
	}
	if f.belowEvery(rel, relText, osBranch) {
		return platformState{below: true, note: fmt.Sprintf("%s runs %s %s. %s affects only %s, and %s is older than every release %s fixed it in (%s).",
			name, pkg, clean(relText), cve, l.Affects, clean(relText), dist, f.fixList())}
	}
	// A release proves fixed only against the device's branch's fix of the SAME upstream version (review r2 H-1 of #961); it is below
	// the device's branch's fix of a later upstream version, or another branch's (alpineFixBranch); else NVD's range decides, with why.
	up := apkUpstream(relText)
	branch, by := alpineFixBranch(f.Releases, osBranch, rel, relText)
	how := ""
	switch by {
	case branchNone:
		own := fmt.Sprintf("the device's OS names no branch, and no branch's fix on the release line %s is of a later upstream version", apkLine(relText))
		switch {
		case osBranch != "" && f.Releases[osBranch] != "":
			own = fmt.Sprintf("%s %s fixed an older upstream version than %s", dist, osBranch, up)
		case osBranch != "":
			own = fmt.Sprintf("%s %s has no fix of it, and no other branch's fix on the release line %s is of a later upstream version", dist, osBranch, apkLine(relText))
		}
		return platformState{note: fmt.Sprintf(" %s fixed it in %s; a package release counts within its own branch only, and %s, so NVD's range decides for the release %s.",
			dist, f.fixList(), own, clean(relText))}
	case branchOther:
		how = fmt.Sprintf(" (%s %s lists no fix; the upstream version %s is older than every branch's fix)", dist, osBranch, up)
	case branchUnnamed:
		how = fmt.Sprintf(" (the device's OS names no branch; the upstream version %s is older than every branch's fix)", up)
	}
	fix := f.Releases[branch]
	want, _ := parseAPK(fix)
	who := "the package release a person gave"
	if s.Source == "agent" {
		who = "the release the device's agent reports"
	}
	branchName := dist + " " + branch
	if compareAPK(rel, want) >= 0 {
		return platformState{fixed: true, note: fmt.Sprintf("%s affects only %s. %s fixed it in %s %s%s, and %s has %s %s (%s). Source: %s.",
			cve, l.Affects, branchName, pkg, fix, how, name, pkg, clean(relText), who, f.sourceFor(branch))}
	}
	return platformState{below: true, note: fmt.Sprintf("%s runs %s %s (%s). %s affects only %s; %s fixed it in %s %s%s. Update %s to %s or later. Source: %s.",
		name, pkg, clean(relText), who, cve, l.Affects, branchName, pkg, fix, how, pkg, fix, f.sourceFor(branch))}
}

// noFixNote is what a finding adds when the distribution lists no fixed release for the device's branch.
func noFixNote(cve, dist, branch string, f *platformFix) string {
	return fmt.Sprintf(" %s %s has no fixed release of %s for %s (%s fixed it in %s): move to a supported %s release.", dist, branch, f.Package, cve, dist, f.fixList(), dist)
}

// older says the version's upstream number is below that of every fixed release ("8.8" against 9.0_p1-r6 and later).
func older(ver string, f *platformFix) bool {
	if !versionKnown(ver) {
		return false
	}
	for _, r := range f.Releases {
		num := apkUpstream(r)
		if i := strings.IndexAny(num, "_abcdefghijklmnopqrstuvwxyz"); i > 0 {
			num = num[:i]
		}
		if o, ok := CompareVersions(ver, num); !ok || o >= 0 {
			return false
		}
	}
	return true
}

// platformAnswers are the answers to the platform question of a CVE (UncheckedItem.question): one click per platform it affects (per
// branch of the fixed list: the device's OS, which on a scanned row confirms the platform and leads to the package release), then
// "another system", where the person gives the device's OS and the row's package release, which is what rules the row out.
func platformAnswers(l platformLimit, f *platformFix) []UncheckedAnswer {
	var out []UncheckedAnswer
	for _, id := range l.Only {
		if f != nil && f.Distro == id {
			for _, b := range f.branches() {
				os := platformName(id) + " " + b
				out = append(out, UncheckedAnswer{Label: os, OS: &os})
			}
			continue
		}
		os := platformName(id)
		out = append(out, UncheckedAnswer{Label: os, OS: &os})
	}
	return append(out, UncheckedAnswer{Label: "Another system", Ask: []string{"os", "pkg_version"}})
}

// platformQuestion is the question of an unchecked CVE of reason platform_unknown or package_unknown on a device; nil for
// another reason or a CVE not on the list. answer is the release a person gave that Vedette could not read, "" when none.
func platformQuestion(cve, device string, reason UncheckedReason, answer string, rows []DistroFix) *UncheckedQuestion {
	l, ok := platformLimits[cve]
	if !ok {
		return nil
	}
	f := distroFixes(cve, rows)
	device = cmp.Or(clean(device), "this device")
	switch reason {
	case UncheckedPlatformUnknown:
		q := &UncheckedQuestion{Text: strings.ReplaceAll(l.Ask, "{device}", device) + " " + cve + " affects only " + l.Affects + ".", Answers: platformAnswers(l, f)}
		if f != nil {
			cmd := f.BranchCommand
			q.Command = &cmd
			q.Text += fmt.Sprintf(" Choose the %s release it runs (%s prints it), or Another system to give its OS and the OpenSSH package release (that settles it).", platformName(f.Distro), cmd)
		}
		return q
	case UncheckedPackageUnknown:
		if f == nil {
			if l.Fixed == nil {
				return nil
			}
			// the feed is on and not loaded yet (a question only stays then)
			cmd := l.Fixed.Command
			q := &UncheckedQuestion{
				Text: fmt.Sprintf("%s's fixed releases of %s are not loaded yet (the built-in feed \"%s\" in Settings → Feeds); Vedette decides as soon as they are. Which %s package release does %s have?",
					platformName(l.Fixed.Distro), cve, alpineFeedName, l.Fixed.Package, device),
				Command: &cmd, Answers: []UncheckedAnswer{{Label: "Enter the package release", Ask: []string{"pkg_version"}}},
			}
			if answer != "" {
				e := fmt.Sprintf("Vedette could not read the release you entered (%q): enter it as %s prints it.", clean(answer), cmd)
				q.Error = &e
			}
			return q
		}
		cmd := f.Command
		q := &UncheckedQuestion{
			Text:    fmt.Sprintf("Which %s package release does %s have? %s fixed %s in %s.", f.Package, device, platformName(f.Distro), cve, f.fixList()),
			Command: &cmd, Answers: []UncheckedAnswer{{Label: "Enter the package release", Ask: []string{"pkg_version"}}},
		}
		if answer != "" {
			e := fmt.Sprintf("Vedette could not read the release you entered (%q): enter it as %s prints it, for example %s-%s or %s.",
				clean(answer), cmd, f.Package, f.Releases[f.branches()[0]], f.Releases[f.branches()[0]])
			q.Error = &e
		}
		return q
	}
	return nil
}

// AskedNote starts the note of a finding closed because only a person's answer can decide it (MatchResult.Asked);
// ReopenOnMatch and SettleAsked recognise it.
const AskedNote = "Closed: needs your answer."

// askGap says, in the closing note, what is not known.
func askGap(k askKind, cve string, f *platformFix) string {
	switch spec := platformLimits[cve].Fixed; {
	case k == askPackage && f != nil:
		return fmt.Sprintf("the device runs %s, so the %s package release decides (%s fixed it in %s)", platformName(f.Distro), f.Package, platformName(f.Distro), f.fixList())
	case k == askPackage && spec != nil: // the feed on, not loaded yet
		return fmt.Sprintf("the device runs %s, and %s's fixed releases are not loaded yet (the built-in feed \"%s\")", platformName(spec.Distro), platformName(spec.Distro), alpineFeedName)
	}
	return "nothing Vedette reads says which system or build this software runs on"
}

// alpineFeedName is how Settings → Feeds names feeds' alpine-osv.
const alpineFeedName = "Alpine fixed versions"

// reason is the could-not-check reason of a question.
func (k askKind) reason() UncheckedReason {
	if k == askPackage {
		return UncheckedPackageUnknown
	}
	return UncheckedPlatformUnknown
}

// AskedWhy is, for a match of MatchResult.Asked, why no row decides it ("CVE-… affects only …; nothing … says which …: check …"); ""
// otherwise. Exposure gives it as the reason a public port is not listed.
func (m Match) AskedWhy() string {
	l, ok := platformLimits[m.CVE]
	if !ok || m.ask == askNone {
		return ""
	}
	return fmt.Sprintf("%s affects only %s, and %s: %s", m.CVE, l.Affects, askGap(m.ask, m.CVE, m.fix), l.Check)
}
