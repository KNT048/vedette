package nmapargv

import (
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/modules/scan/commonports"
)

// The extra ports of a LAN identification (kf-scan item 1). The normal and versions shapes scan nmap's --top-ports 1000, which
// misses services moved off their usual port: a test network's firewall answered SSH on 22222 and nothing found it. So every normal
// or versions scan of a device is followed by an Extra run (-sS -sV and the same four scripts) over ExtraPorts, the union of:
//
//   - commonports.List: the 99 ports often exposed to the Internet (exposure's surface scan); about a third of them are not in nmap's
//     top 1000 (9443, 10443, 6379, 27017, the MikroTik API…);
//   - AdminPortList: alternate remote-access and management ports, reviewed one by one below.
//
// nmap's top 1000 is not copied here: it comes from nmap-services (NPSL), which the project does not ship or embed (see
// THIRD_PARTY_NOTICES: "The GPL/NPSL lists of Wireshark and Nmap are not used"); --top-ports reads it from the nmap the box
// installed. A port in both lists is probed twice (about 80 SYNs more per device). Nessus scans about 4,790 ports by default,
// Greenbone about 5,000, Qualys' standard list about 2,800, and all three offer every port as an option;
// this stays near nmap's 1000, and the weekly AllPorts run of each device that is not fragile finds the rest.

// AdminPort is one port of AdminPorts and why it is there.
type AdminPort struct {
	Number int
	Why    string // what usually listens there, and the source
}

// AdminPortList is the alternate remote-access and management ports scanned after nmap's top 1000, with commonports. A
// device's administrator moves SSH, RDP or a web console to one of these to keep it off the default port; an attacker scans them
// anyway. Sources: IANA's service registry (https://www.iana.org/assignments/service-names-port-numbers), the vendors' own port
// lists named in each line, and CISA KEV entries for management services that ship on these ports.
var AdminPortList = []AdminPort{
	{1311, "Dell OpenManage Server Administrator web console (Dell OMSA documentation)"},
	{2022, "SSH moved off 22 (common alternate; IANA lists 2022 as down, unused by it)"},
	{2200, "SSH moved off 22 (common alternate)"},
	{2222, "SSH moved off 22 (common alternate; also in commonports)"},
	{2223, "SSH moved off 22 (common alternate)"},
	{2443, "HTTPS admin moved off 443 (common alternate)"},
	{4433, "HTTPS admin moved off 443 (common alternate)"},
	{4443, "HTTPS admin moved off 443 (Sophos, Fortinet and others; also in commonports)"},
	{4444, "Sophos Firewall web admin console (Sophos documentation: default admin port 4444)"},
	{4786, "Cisco Smart Install, unauthenticated switch management (Cisco advisory; CISA KEV CVE-2018-0171)"},
	{4848, "Eclipse GlassFish / Payara admin console (GlassFish documentation)"},
	{5480, "VMware appliance management (VAMI) of vCenter and others (VMware documentation; CISA KEV vCenter entries)"},
	{5800, "VNC over HTTP, display 0 (RealVNC / TightVNC Java viewer port)"},
	{5801, "VNC over HTTP, display 1"},
	{5900, "VNC display 0 (IANA rfb; also in commonports)"},
	{5901, "VNC display 1 (also in commonports)"},
	{5902, "VNC display 2"},
	{5903, "VNC display 3"},
	{5985, "WinRM over HTTP (Microsoft WinRM documentation; also in commonports)"},
	{5986, "WinRM over HTTPS (Microsoft WinRM documentation; also in commonports)"},
	{6080, "noVNC web console (Proxmox, OpenStack and others)"},
	{7071, "Zimbra admin console (Zimbra documentation; CISA KEV Zimbra entries)"},
	{7443, "UniFi Network / UniFi Protect HTTPS (Ubiquiti port list)"},
	{8020, "ManageEngine Desktop Central / Endpoint Central (Zoho documentation; CISA KEV CVE-2021-44515)"},
	{8022, "SSH moved off 22 (common alternate)"},
	{8080, "HTTP admin moved off 80 (IANA http-alt)"},
	{8081, "HTTP admin moved off 80"},
	{8082, "HTTP admin moved off 80"},
	{8083, "HTTP admin moved off 80"},
	{8084, "HTTP admin moved off 80"},
	{8085, "HTTP admin moved off 80"},
	{8086, "HTTP admin moved off 80"},
	{8087, "HTTP admin moved off 80"},
	{8088, "HTTP admin moved off 80"},
	{8089, "HTTPS admin (Splunk management port; Splunk documentation)"},
	{8090, "HTTP admin moved off 80 (Confluence default; Atlassian documentation; CISA KEV Confluence entries)"},
	{8161, "Apache ActiveMQ web console (ActiveMQ documentation)"},
	{8181, "HTTP admin moved off 80"},
	{8291, "MikroTik Winbox (MikroTik RouterOS documentation; also in commonports)"},
	{8383, "ManageEngine products' HTTPS console (Zoho documentation; CISA KEV ManageEngine entries)"},
	{8443, "HTTPS admin moved off 443 (IANA pcsync-https; most appliances; also in commonports)"},
	{8444, "HTTPS admin moved off 443"},
	{8530, "Windows Server Update Services over HTTP (Microsoft WSUS documentation; CISA KEV CVE-2025-59287)"},
	{8531, "Windows Server Update Services over HTTPS (Microsoft WSUS documentation; CISA KEV CVE-2025-59287)"},
	{8728, "MikroTik RouterOS API (MikroTik documentation; also in commonports)"},
	{8729, "MikroTik RouterOS API over TLS (MikroTik documentation; also in commonports)"},
	{8843, "UniFi guest portal HTTPS (Ubiquiti port list)"},
	{9080, "HTTP admin moved off 80 (WebSphere and others)"},
	{9091, "Openfire admin console over HTTPS (Openfire documentation; CISA KEV CVE-2023-32315)"},
	{9440, "Nutanix Prism web console (Nutanix port reference)"},
	{9443, "HTTPS admin moved off 443 (VMware, Portainer and others; also in commonports)"},
	{9444, "HTTPS admin moved off 443"},
	{9990, "WildFly / JBoss EAP management console (Red Hat documentation)"},
	{10000, "Webmin (Webmin documentation; also in commonports)"},
	{10022, "SSH moved off 22 (seen open from outside on a test network)"},
	{10443, "HTTPS admin and SSL-VPN moved off 443 (Fortinet documentation; also in commonports)"},
	{11080, "HTTP admin moved off 80 (seen in testing: a deep scan found it, a LAN scan did not)"},
	{11443, "HTTPS admin moved off 443 (seen in testing: a deep scan found it, a LAN scan did not)"},
	{12443, "HTTPS admin moved off 443"},
	{13389, "RDP moved off 3389 (common alternate)"},
	{16992, "Intel AMT web console over HTTP (Intel documentation; CISA KEV CVE-2017-5689)"},
	{16993, "Intel AMT web console over HTTPS (Intel documentation; CISA KEV CVE-2017-5689)"},
	{17988, "HPE iLO virtual media (HPE iLO port list)"},
	{17990, "HPE iLO remote console (HPE iLO port list)"},
	{18080, "HTTP admin moved off 80"},
	{18443, "HTTPS admin moved off 443"},
	{22222, "SSH moved off 22 (seen in testing: a firewall's own SSH listened here and no LAN scan found it)"},
	{33890, "RDP moved off 3389 (common alternate)"},
	{61616, "Apache ActiveMQ OpenWire broker (ActiveMQ documentation; CISA KEV CVE-2023-46604)"},
}

// ExtraPortNumbers is every port of the Extra shape, ascending: commonports and AdminPortList.
var ExtraPortNumbers = func() []int {
	out := commonports.Numbers()
	for _, p := range AdminPortList {
		out = append(out, p.Number)
	}
	slices.Sort(out)
	return slices.Compact(out)
}()

// ExtraPorts is the -p value of the Extra shape: ExtraPortNumbers as nmap's ranges ("21-23,25,…").
var ExtraPorts = rangesOf(ExtraPortNumbers)

// rangesOf writes ascending distinct ports as nmap's -p ranges.
func rangesOf(ns []int) string {
	var b strings.Builder
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ns[i]))
		if j > i {
			b.WriteString("-" + strconv.Itoa(ns[j]))
		}
		i = j + 1
	}
	return b.String()
}
