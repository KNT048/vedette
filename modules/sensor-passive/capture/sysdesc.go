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
// ponytail: five layouts (Juniper, Cisco IOS/IOS XE, HP/Aruba ProCurve, MikroTik RouterOS, lldpd on Linux); a new
// vendor is one more row here with a test.

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
	// what a bare model looks like: one token of letters, digits and a few separators, with at least one digit
	descBare  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._/-]*$`)
	descDigit = regexp.MustCompile(`[0-9]`)
)

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
	if len(desc) <= maxBareDesc && descBare.MatchString(desc) && descDigit.MatchString(desc) {
		return desc, ""
	}
	return "", ""
}
