package capture

import (
	"regexp"
	"strings"
)

// The LLDP system description is free text the device writes about itself (untrusted, INV-4). Walk 4 showed a
// Juniper switch's whole description ("Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9,
// Build date … Copyright …") as the device's name and make/model. So only a description that matches a known
// vendor's layout gives a model and an OS, each a short token; any other description gives nothing, except a
// description that is one short token with a digit (a bare model name like "GS308T"), which is the model.
//
// ponytail: six layouts (Juniper, Cisco IOS/IOS XE, HP/Aruba ProCurve, MikroTik RouterOS, lldpd on Linux, and net-snmp's
// uname layout on Linux); a new vendor is one more row here with a test.

// maxBareDesc is the longest description taken as the model itself (one token, at least one digit).
const maxBareDesc = 40

var (
	// "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: …"
	descJuniper = regexp.MustCompile(`^Juniper Networks, Inc\. ([A-Za-z0-9][A-Za-z0-9-]{1,31}) [^,]{0,60}, kernel (JUNOS [0-9][A-Za-z0-9.-]{0,30})`)
	// "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE5, RELEASE SOFTWARE (fc1) …"
	// "Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.6.4, RELEASE …"
	descCisco = regexp.MustCompile(`^Cisco IOS Software( \[[A-Za-z0-9 .-]{1,30}\])?, ([A-Za-z0-9][A-Za-z0-9 /-]{0,39}?) Software \(([A-Za-z0-9_-]{1,40})\), Version ([0-9][A-Za-z0-9().]{0,30})`)
	// "HP J9772A 2530-48G-PoE+ Switch, revision YA.16.04.0008, ROM …", "Aruba JL261A 2930F-24G-PoE+-4SFP Switch, revision WC.16.10.0011, …"
	descAruba = regexp.MustCompile(`^(?:HP|HPE|Aruba|ProCurve) [A-Z]{1,2}[0-9]{3,5}[A-Z]? ([A-Za-z0-9][A-Za-z0-9+-]{1,39}) Switch, revision ([A-Z]{1,3}\.[0-9][0-9.]{1,20})`)
	// "MikroTik RouterOS 6.49.10 (long-term) CRS326-24G-2S+"
	descMikroTik = regexp.MustCompile(`^MikroTik RouterOS ([0-9][0-9.]{0,15}(?:beta[0-9]{1,3}|rc[0-9]{1,3})?) \([a-z -]{1,20}\) ([A-Za-z0-9][A-Za-z0-9+-]{1,39})$`)
	// lldpd: "Ubuntu 22.04.3 LTS Linux 5.15.0-91-generic #101-Ubuntu SMP …"
	descLinux = regexp.MustCompile(`^((?:Ubuntu|Debian GNU/Linux|Debian|Fedora Linux|Fedora|Rocky Linux|AlmaLinux|Red Hat Enterprise Linux|CentOS Stream|CentOS Linux|Alpine Linux|openSUSE Leap|Arch Linux|Raspbian GNU/Linux|OpenWrt) [0-9][A-Za-z0-9 .()-]{0,30}?) Linux [0-9][A-Za-z0-9._+-]{0,60} #`)
	// net-snmp on Linux answers sysDescr with uname -a: "Linux BN340 6.18.63-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2026-11-11 01:31:28
	// x86_64" (BN340, n82). Only the kernel's own build marks name a distribution (unameDistros); the host name is skipped.
	descUname = regexp.MustCompile(`^Linux [A-Za-z0-9][A-Za-z0-9._-]{0,62} ([0-9][A-Za-z0-9._+~-]{0,80}) (#.*)$`)
	// what a bare model looks like: one token of letters, digits and a few separators, with at least one digit
	descBare  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._/-]*$`)
	descDigit = regexp.MustCompile(`[0-9]`)
)

// ParseSysDesc is parseSysDesc for sensor-active's SNMP reads (D-512): the LLDP system description is the device's MIB-2 sysDescr,
// so one set of layouts reads both. The caller cleans the text first (core, SYS-6), as the capture does.
func ParseSysDesc(desc string) (model, os string) { return parseSysDesc(desc) }

// parseSysDesc returns the model and OS that a known layout of an LLDP system description states; empty strings when
// the description says neither in a form the box recognises.
func parseSysDesc(desc string) (model, os string) {
	if m := descJuniper.FindStringSubmatch(desc); m != nil {
		return strings.ToUpper(m[1]), m[2]
	}
	if m := descCisco.FindStringSubmatch(desc); m != nil {
		// IOS XE names its train in brackets ("[Denali]") and its image CAT9K_IOSXE or similar; classic IOS does neither.
		if m[1] != "" || strings.Contains(strings.ToUpper(m[3]), "IOSXE") {
			return "", "Cisco IOS XE " + m[4] // "Catalyst L3 Switch" is a family, not a model
		}
		return strings.TrimSpace(m[2]), "Cisco IOS " + m[4]
	}
	if m := descAruba.FindStringSubmatch(desc); m != nil {
		return m[1], "ArubaOS-Switch " + m[2]
	}
	if m := descMikroTik.FindStringSubmatch(desc); m != nil {
		return m[2], "RouterOS " + m[1]
	}
	if m := descLinux.FindStringSubmatch(desc); m != nil {
		return "", strings.TrimSpace(m[1])
	}
	if m := descUname.FindStringSubmatch(desc); m != nil {
		return "", unameOS(m[1], m[2])
	}
	if len(desc) <= maxBareDesc && descBare.MatchString(desc) && descDigit.MatchString(desc) {
		return desc, ""
	}
	return "", ""
}

// unameDistros are the marks a distribution's kernel build leaves in uname's release and version, in order: the first that matches
// names the OS, with the release number only when the mark carries it (Fedora's fc39, Enterprise Linux's el9, a Debian backport's
// deb11). A kernel with no such mark (a vanilla or vendor build, Raspberry Pi's "6.1.21-v8+") says no distribution: "".
var unameDistros = []struct {
	re   *regexp.Regexp // matched against release + " " + version
	name string         // "%s" is the first group
}{
	// Alpine: "6.18.63-0-lts #1-Alpine SMP …": only the build mark every Alpine kernel carries. The release's "-0-lts" shape is not
	// Alpine's alone (Arch's linux-lts is "6.6.63-1-lts #1 SMP …", review r1 M2 of #950).
	{regexp.MustCompile(`#[0-9]{1,6}-Alpine(?: |$)`), "Alpine Linux"},
	// Ubuntu: "5.15.0-91-generic #101-Ubuntu SMP …"; the kernel's ABI does not say which Ubuntu release, so no number.
	{regexp.MustCompile(`#[0-9]{1,6}(?:~[0-9.]{1,10})?-Ubuntu(?: |$)`), "Ubuntu"},
	// A Debian backport kernel names the release it was built for: "6.1.0-0.deb11.17-amd64".
	{regexp.MustCompile(`[.+]deb([0-9]{1,2})(?:u[0-9]{1,3})?\b`), "Debian %s"},
	// Debian: "6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)".
	{regexp.MustCompile(`\bDebian [0-9]`), "Debian"},
	// Fedora: "6.5.6-300.fc39.x86_64".
	{regexp.MustCompile(`\.fc([0-9]{2})\b`), "Fedora Linux %s"},
	// Red Hat Enterprise Linux and its rebuilds (Rocky, AlmaLinux, CentOS, Oracle): "4.18.0-513.5.1.el8_9.x86_64", "5.14.0-362.8.1.el9_3".
	// The kernel does not say which of them.
	{regexp.MustCompile(`\.el([0-9]{1,2})(?:_[0-9]{1,2})?\b`), "Enterprise Linux %s (RHEL or a rebuild)"},
	// Arch Linux: "6.6.1-arch1-1".
	{regexp.MustCompile(`^[0-9.]+-arch[0-9]{1,3}-[0-9]{1,3} `), "Arch Linux"},
	// SUSE names itself only in a build string that says so.
	{regexp.MustCompile(`\b(?:open)?SUSE\b`), "SUSE Linux"},
}

// unameOS is the distribution a uname release and version prove ("" when none).
func unameOS(release, version string) string {
	text := release + " " + version
	for _, d := range unameDistros {
		m := d.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if strings.Contains(d.name, "%s") {
			return strings.Replace(d.name, "%s", m[1], 1)
		}
		return d.name
	}
	return ""
}
