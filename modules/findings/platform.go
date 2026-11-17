package findings

import (
	"encoding/json"
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
//   - otherwise (platform not known, or one it affects) → the finding as before, with "It affects only …; check …".

type platformLimit struct {
	Only    []string `json:"only"`
	Affects string   `json:"affects"`
	Check   string   `json:"check"`
	Source  string   `json:"source"`
}

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
func platformOS(s Software, a Asset) string {
	switch s.builtBy() { // a person's correction of an agent or SNMP row keeps that row's evidence (review r1 M1 of #950)
	case "agent":
		return a.AgentOS
	case "snmp":
		return a.SNMPOS // the SNMP answer at the device's own address, never an LLDP frame (review r2)
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

// platformCondition is the sentence a finding of a platform-limited CVE carries when the platform is not ruled out (KF-5):
// "It affects only …: check …". "" for a CVE not on the list.
func platformCondition(cve string) string {
	l, ok := platformLimits[cve]
	if !ok {
		return ""
	}
	return fmt.Sprintf(" It affects only %s: %s (%s).", l.Affects, l.Check, l.Source)
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

// platformSettled says whether the platform condition of a CVE is no longer open for the row: the CVE is not platform-limited, or the
// row's evidence names a platform it affects (an agent reporting Alpine). A row whose platform is unknown leaves the person a check
// to make, so its finding is not called a detection (D-548, review r1 #5).
func platformSettled(in swInfo, cve string) bool {
	l, ok := platformLimits[cve]
	if !ok {
		return true
	}
	return slices.ContainsFunc(evidenceOf(in).ids, func(id string) bool { return slices.Contains(l.Only, id) })
}
