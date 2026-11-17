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

// Platform limits (D-547, KF-4, KF-5). Some exploited CVEs affect a product only on some platforms: CVE-2026-123158 is
// OpenSSH built with musl libc and without PAM (Alpine), not Ubuntu's or Debian's glibc+PAM build of the same upstream version.
// No feed Vedette reads says so in a form a program can use (KEV: "on Linux"; CVE.org: platform "Linux"; NVD: the product
// only), so content/catalog/platform-limits.json holds a short reviewed list. For a CVE on it:
//   - the device's OS (for an agent row, or the OS an SNMP device states for its SNMP row: platformOS), the software's own
//     version or banner text, or an agent's deb/rpm package database names another platform, and nothing names one it
//     affects → proved not affected (no finding; an open one closes, D-530 path, reason not_affected_version with a D-547
//     audit detail). The distribution's own word (D-516) is read first and wins;
//   - the platform is not known (nothing names a platform, D-604) → no finding: the CVE is "Could not be checked" (reason
//     platform_unknown) with the entry's question, and an open finding closes into that list (MatchResult.Asked); the person's
//     answer (the device's OS, inventory INV-39) decides at the next match;
//   - the platform is one it affects and the entry has the distribution's fixed list (D-604): the package release decides. At or above
//     the fix of the device's branch → proved not affected (closes, D-530 path); below it → a version finding; no release yet →
//     "Could not be checked" (reason package_unknown) asking for it, unless the version is older than every fix (a finding);
//   - the platform is one it affects, no fixed list → the finding as for any CVE.

type platformLimit struct {
	Only    []string `json:"only"`
	Affects string   `json:"affects"`
	Check   string   `json:"check"`
	// Ask is the question for a device whose platform is not known ("{device}" its name): the CVE is then "Could not be checked"
	// with this question, not a finding (D-604).
	Ask    string       `json:"ask"`
	Source string       `json:"source"`
	Fixed  *platformFix `json:"fixed,omitempty"`
}

// platformFix is the distribution's first fixed package release per branch (D-604): once a row's platform is that distribution,
// its package release decides the CVE. Only Alpine's apk releases are read (apkver.go).
type platformFix struct {
	Distro   string            `json:"distro"`   // the platform id of Only it is about ("alpine")
	Package  string            `json:"package"`  // the package as the device's package manager names it ("openssh-server")
	Command  string            `json:"command"`  // what shows its release on the device ("apk info -v openssh-server")
	Releases map[string]string `json:"releases"` // branch ("3.23", "edge") -> first fixed release ("10.2_p1-r1")
	Source   string            `json:"source"`
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

// networkOS are the platforms of network gear whose own statement of its OS also says what a service a scan sees on it runs on (D-549,
// N47-1): a Junos switch does not forward its management address to an Alpine container. Only Junos for now: RouterOS and Cisco IOS XE
// can host containers, so a service seen on them may still be one; so can Junos OS Evolved ("…-EVO"), which runs Docker (review r1 #4).
var networkOS = []string{"junos"}

// junosEvolved matches Junos OS Evolved in a system description ("JUNOS 21.4R1.12-EVO", "Junos OS Evolved").
var junosEvolved = regexp.MustCompile(`(?i)-evo\b|\bevolved\b`)

// networkStated is the OS the device states for every row of it (D-549, D-620): a networkOS platform, not Junos Evolved, on a device no
// agent reports another OS for, stated either
//   - in the device's answer to Vedette's own SNMP read of its address (Asset.SNMPOS), or
//   - when there is no SNMP answer, in an LLDP frame (StatedOS, source passive: LLDP's system description is the only passive source
//     of a Junos OS), on a device whose own MAC at its address is one IEEE assigned to Juniper Networks (juniperMAC). An LLDP frame alone
//     can be forged with another device's MAC (review r1 #3 of #800); the forged claim then sits on a device whose network card
//     Juniper did not make, and is not read. A device with a Juniper card is Juniper gear, which runs no container behind its
//     management address (N47-1: the EX4200 switch .47, stated over LLDP "JUNOS 15.1R7.9", MAC 3c:8a:b0:…).
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
// there (review r1 #1, #2). Exception (D-549, D-620, N47-1): on network gear that states an OS of networkOS over SNMP, or over LLDP on a
// Juniper network card (a Junos switch, networkStated), that statement counts for every row, since such gear runs no container behind
// its own address.
//
// D-604: two answers of a person count too. The OS a person set on the device (Asset.ManualOS, inventory INV-39) is evidence for every
// row: Vedette asked the person which system the device runs ("Could not be checked"), and a person's value wins (INV-1). A row whose
// package release a person gave (a manual row with Software.PkgVersion, inventory's correction) takes the OS the device states (its
// agent, its SNMP answer): the person read the release from the device's own package manager, so that package is the device's.
func platformOS(s Software, a Asset) string {
	switch b := s.builtBy(); { // a person's correction of an agent or SNMP row keeps that row's evidence (review r1 M1 of #950)
	case a.ManualOS != "":
		return a.ManualOS
	case b == "agent":
		return a.AgentOS
	case b == "snmp":
		return a.SNMPOS // the SNMP answer at the device's own address, never an LLDP frame (review r2)
	case s.Source == "manual" && s.PkgVersion != "": // a person's release on a row a scan saw (or typed by hand): the device's own OS
		return cmp.Or(a.AgentOS, a.SNMPOS, networkStated(a))
	}
	return networkStated(a)
}

// debRPM is the evidence id of a row an agent read from a deb or rpm database: a Debian, Ubuntu, Red Hat or SUSE family build,
// never Alpine's apk. It counts as a platform a CVE affects when the CVE's list names one of those families (review r1 #3).
const debRPM = "deb-rpm"

var debRPMFamilies = []string{"debian", "ubuntu", "rhel", "suse"}

func evidenceOf(in swInfo) platformEvidence {
	var e platformEvidence
	if t := clean(strings.TrimSpace(in.platformOS)); t != "" {
		e.add(platformsIn(t), "this device runs "+t)
	}
	// Matched on the text shown, so the word that rules a CVE out is always in the sentence (review r1 #4).
	if t := clean(strings.TrimSpace(in.ver + " " + in.banner)); t != "" {
		e.add(platformsIn(t), "the software reports "+t)
	}
	if in.packaged {
		e.add([]string{debRPM}, "an agent read it from the device's deb or rpm package database, not Alpine's apk")
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
	affects := func(id string) bool {
		if id == debRPM {
			return slices.ContainsFunc(debRPMFamilies, func(f string) bool { return slices.Contains(l.Only, f) })
		}
		return slices.Contains(l.Only, id)
	}
	if len(e.ids) == 0 || slices.ContainsFunc(e.ids, affects) {
		return "", false
	}
	return fmt.Sprintf("%s affects only %s; %s.", cve, l.Affects, strings.Join(e.says, ", and ")), true
}

// PlatformRuledOut says whether the platform rules of D-547 prove the KEV entry (cve of vendor and product) does not affect the device:
// every software row keyed to it is ruled out by its platform (MatchAsset's OtherPlatform). The CVE page's "Do you have it?" (feeds)
// asks it so it agrees with the device's findings (D-549, KF-CVEPAGE): an Ubuntu box whose OpenSSH finding of an Alpine-only CVE is
// closed is not listed as running it. It reads no NVD range and no distribution data (feeds has the entry only): the distribution's
// word (D-516), which could say its own package is affected after all, is not read here; no entry of the list has such a word today.
func PlatformRuledOut(a Asset, cve, vendor, product string, now time.Time) bool {
	if !HasPlatformLimit(cve) {
		return false
	}
	r := MatchAsset(a, []Vuln{{CVE: cve, Vendor: vendor, Product: product}}, map[string]bool{cve: true}, now)
	return len(r.OtherPlatform) > 0
}

// HasPlatformLimit says whether the CVE is on the platform-limits list (D-547): only such a CVE can be ruled out by PlatformRuledOut, so a
// caller checks it before reading any device (review r1 #9).
func HasPlatformLimit(cve string) bool {
	_, ok := platformLimits[cve]
	return ok
}

// valid checks a fixed list (nil is none).
func (f *platformFix) valid(only []string) error {
	if f == nil {
		return nil
	}
	if f.Distro != "alpine" || !slices.Contains(only, f.Distro) {
		return fmt.Errorf("distro %q: only alpine (apk releases), and one of only", f.Distro)
	}
	if f.Package == "" || f.Command == "" || len(f.Releases) == 0 || !strings.HasPrefix(f.Source, "https://") {
		return errors.New("needs package, command, releases and an https source")
	}
	for b, r := range f.Releases {
		if _, ok := parseAPK(r); !branchKeyRE.MatchString(b) || !ok {
			return fmt.Errorf("release %q: %q is not a branch and an apk release", b, r)
		}
	}
	return nil
}

// branches are the fixed list's branches, newest first ("edge", "3.24", …).
func (f *platformFix) branches() []string {
	var out []string
	for b := range f.Releases {
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

// askKind is what a platform-limited CVE still needs from a person on a row (D-604).
type askKind string

const (
	askNone     askKind = ""
	askPlatform askKind = "platform" // which system (and, with a fixed list, which branch) the device runs
	askPackage  askKind = "package"  // the package release
)

// platformState is how a platform-limited CVE stands on a row that its platform does not rule out (D-604, platformCheck).
type platformState struct {
	ask   askKind
	fixed bool   // the package release is at or above the branch's fix: not affected
	below bool   // the package release (or the version) is below the fix: affected
	note  string // fixed: why it is not affected; below: why it is affected
}

// pkgRelease is the row's package release in Alpine's shape: the one a person gave (inventory's correction), else an agent's
// version when it is one (osquery's apk_packages reports "10.2_p1-r1"). "" when none.
func pkgRelease(s Software, in swInfo) string {
	for _, r := range []string{s.PkgVersion, in.ver} {
		if _, ok := parseAPK(r); ok {
			return strings.TrimSpace(r)
		}
	}
	return ""
}

// platformCheck is the state of a platform-limited CVE on a row platformRuledOut did not rule out (D-604). Not on the list: zero.
func platformCheck(a Asset, s Software, in swInfo, cve string) platformState {
	l, ok := platformLimits[cve]
	if !ok {
		return platformState{}
	}
	ids := evidenceOf(in).ids
	if !slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(l.Only, id) }) {
		// nothing names the row's platform (one naming another would have ruled it out). A device that states the fixed list's
		// distribution itself (its agent, its SNMP answer) is asked for the package release: the release a person then gives is read
		// against that OS (platformOS), while the OS alone never decides a row a scan saw (it may forward the port to a container).
		if l.Fixed != nil && slices.Contains(platformsIn(cmp.Or(a.AgentOS, a.SNMPOS)), l.Fixed.Distro) {
			return platformState{ask: askPackage}
		}
		return platformState{ask: askPlatform}
	}
	f := l.Fixed
	if f == nil || !slices.Contains(ids, f.Distro) {
		return platformState{} // a platform it affects, no fixed list: like any CVE
	}
	name, pkg := clean(a.Name), clean(f.Package)
	rel := pkgRelease(s, in)
	if rel == "" {
		// a version older than every fixed release is affected whatever the release (no branch has a fix for it)
		if older(in.ver, f) {
			return platformState{below: true, note: fmt.Sprintf("%s runs %s %s on %s. %s affects only %s, and %s is older than every release %s fixed it in (%s).",
				name, clean(s.Display), clean(in.ver), clean(in.platformOS), cve, l.Affects, clean(in.ver), platformName(f.Distro), f.fixList())}
		}
		return platformState{ask: askPackage}
	}
	have, _ := parseAPK(rel)
	branch := alpineBranch(in.platformOS)
	how := ""
	if branch == "" { // the OS names no branch: the one branch whose fix has the release's upstream version
		for _, b := range f.branches() {
			if apkUpstream(f.Releases[b]) == apkUpstream(rel) {
				if branch != "" {
					branch = ""
					break
				}
				branch = b
			}
		}
		how = " (the branch whose fixed release has the same upstream version; the device's OS names no branch)"
	}
	fix, ok := f.Releases[branch]
	if !ok {
		return platformState{ask: askPlatform} // which branch: the release alone does not say
	}
	want, _ := parseAPK(fix)
	who := "the package release a person gave"
	if s.Source == "agent" && s.PkgVersion == "" {
		who = "the release the device's agent reports"
	}
	dist := platformName(f.Distro) + " " + branch
	if compareAPK(have, want) >= 0 {
		return platformState{fixed: true, note: fmt.Sprintf("%s affects only %s. %s fixed it in %s %s%s, and %s has %s %s (%s). Source: %s.",
			cve, l.Affects, dist, pkg, fix, how, name, pkg, clean(rel), who, f.Source)}
	}
	return platformState{below: true, note: fmt.Sprintf("%s runs %s %s (%s). %s affects only %s; %s fixed it in %s %s%s. Update %s to %s or later. Source: %s.",
		name, pkg, clean(rel), who, cve, l.Affects, dist, pkg, fix, how, pkg, fix, f.Source)}
}

// older says the version's upstream number is below that of every fixed release ("9.7" against 9.9_p2-r1 and later).
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

// platformAnswers are the one-click answers to the platform question of a CVE (UncheckedItem.question): each platform it affects
// (per branch of the fixed list), then "another system", which the person names.
func platformAnswers(l platformLimit) []UncheckedAnswer {
	var out []UncheckedAnswer
	for _, id := range l.Only {
		if f := l.Fixed; f != nil && f.Distro == id {
			for _, b := range f.branches() {
				os := platformName(id) + " " + b
				out = append(out, UncheckedAnswer{Label: os, OS: &os})
			}
			continue
		}
		os := platformName(id)
		out = append(out, UncheckedAnswer{Label: os, OS: &os})
	}
	return append(out, UncheckedAnswer{Label: "Another system", Ask: "os"})
}

// platformQuestion is the question of an unchecked CVE of reason platform_unknown or package_unknown on a device (D-604); nil for
// another reason or a CVE not on the list.
func platformQuestion(cve, device string, reason UncheckedReason) *UncheckedQuestion {
	l, ok := platformLimits[cve]
	if !ok {
		return nil
	}
	device = cmp.Or(clean(device), "this device")
	switch reason {
	case UncheckedPlatformUnknown:
		q := &UncheckedQuestion{Text: strings.ReplaceAll(l.Ask, "{device}", device) + " " + cve + " affects only " + l.Affects + ".", Answers: platformAnswers(l)}
		if l.Fixed != nil {
			q.Text += " Choose the " + platformName(l.Fixed.Distro) + " release it runs."
		}
		return q
	case UncheckedPackageUnknown:
		if l.Fixed == nil {
			return nil
		}
		cmd := l.Fixed.Command
		return &UncheckedQuestion{
			Text:    fmt.Sprintf("Which %s package release does %s have? %s fixed %s in %s.", l.Fixed.Package, device, platformName(l.Fixed.Distro), cve, l.Fixed.fixList()),
			Command: &cmd, Answers: []UncheckedAnswer{{Label: "Enter the package release", Ask: "pkg_version"}},
		}
	}
	return nil
}

// AskedNote starts the note of a finding closed because only a person's answer can decide it (D-604, MatchResult.Asked);
// ReopenOnMatch and SettleAsked recognise it.
const AskedNote = "Closed: needs your answer."

// askGap says, in the closing note, what is not known.
func askGap(k askKind, l platformLimit) string {
	if k == askPackage && l.Fixed != nil {
		return fmt.Sprintf("the device runs %s, so the %s package release decides (%s fixed it in %s)", platformName(l.Fixed.Distro), l.Fixed.Package, platformName(l.Fixed.Distro), l.Fixed.fixList())
	}
	return "nothing Vedette reads says which system or build this software runs on"
}

// reason is the could-not-check reason of a question.
func (k askKind) reason() UncheckedReason {
	if k == askPackage {
		return UncheckedPackageUnknown
	}
	return UncheckedPlatformUnknown
}

// platformSettled says whether the platform condition of a CVE is no longer open for the row: the CVE is not platform-limited, or the
// row's evidence names a platform it affects (an agent reporting Alpine). The plan lists only such CVEs (D-547, review r1 #5).
func platformSettled(in swInfo, cve string) bool {
	l, ok := platformLimits[cve]
	if !ok {
		return true
	}
	return slices.ContainsFunc(evidenceOf(in).ids, func(id string) bool { return slices.Contains(l.Only, id) })
}

// AskedWhy is, for a match of MatchResult.Asked, why no row decides it ("CVE-… affects only …; nothing … says which …: check …"); ""
// otherwise. Exposure gives it as the reason a public port is not listed (D-604).
func (m Match) AskedWhy() string {
	l, ok := platformLimits[m.CVE]
	if !ok || m.ask == askNone {
		return ""
	}
	return fmt.Sprintf("%s affects only %s, and %s: %s", m.CVE, l.Affects, askGap(m.ask, l), l.Check)
}
