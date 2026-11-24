package mitigation

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

func hardeningRow(ip, kind, vendor, product string) findings.Row {
	return findings.Row{ID: "f-1", CVE: "CVE-2024-6387", Asset: &findings.AssetView{ID: "a-1", Name: "web01", IP: ip, Kind: kind},
		Kev: &findings.KevInfo{Vendor: vendor, Product: product}}
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s: %q missing", what, sub)
		}
	}
}

func TestContract_INV8_ChecksArePerFamilyAndClaimNothingAboutTheCVE(t *testing.T) {
	t.Parallel()
	cases := []struct{ kind, vendor, product, family, want string }{
		{"pc", "Microsoft", "Windows", "Windows", "Get-WinEvent"},
		{"server", "Microsoft", "Exchange Server", "Windows web server (IIS)", "C:\\inetpub"},
		{"server", "Linux", "Kernel", "Linux", "sudo ss -tulpn"},
		{"server", "OpenBSD", "OpenSSH", "OpenSSH", "sshd -T"},
		{"server", "Apache", "HTTP Server", "Web server", "/var/log/apache2/access.log"},
		{"server", "Adobe", "ColdFusion", "Web server", "C:\\inetpub"}, // r1 M5: often on Windows, so both
		{"server", "Progress", "MOVEit Transfer", "Windows web server (IIS)", "w3wp.exe"},
		{"server", "Veeam", "Backup & Replication", "Windows", "Get-WinEvent"},
		{"router", "Cisco", "IOS XR", "Network device", "Compare the running configuration"},      // r1 L4
		{"switch", "Juniper", "Junos OS", "Juniper Junos OS", "show system rollback 1 compare 0"}, // r1 L3
		{"firewall", "Fortinet", "FortiOS", "Fortinet FortiOS", "show system admin"},
		{"router", "MikroTik", "RouterOS", "MikroTik RouterOS", "/system scheduler print"},
		{"router", "Cisco", "IOS XE Software", "Cisco IOS", "show control-plane host open-ports"},
		{"firewall", "Palo Alto Networks", "PAN-OS", "Network device", "Compare the running configuration"},
		{"nas", "QNAP", "Photo Station", "General", "software's own user list"},
		{"server", "VMware", "ESXi", "VMware ESXi", "esxcli software vib signature verify"},
		{"nas", "Synology", "DiskStation Manager (DSM)", "Synology DSM", "Task Scheduler"},
	}
	for _, c := range cases {
		h := generalHardening(hardeningRow("10.0.0.9", c.kind, c.vendor, c.product))
		if h.Family != c.family || h.Checks == nil {
			t.Errorf("%s %s: family %q, checks %v", c.vendor, c.product, h.Family, h.Checks != nil)
			continue
		}
		if strings.Count(strings.TrimPrefix(h.Checks.Summary, "General checks"), c.family) > 1 { // "General checks for Juniper Junos OS (Juniper Junos OS)"
			t.Errorf("%s: the family is named twice: %s", c.product, h.Checks.Summary)
		}
		all := h.Checks.Summary
		for _, in := range h.Checks.Indicators {
			all += in.Title + in.Detail
			for _, cm := range in.Commands {
				all += cm.Code
			}
		}
		mustContain(t, c.product, all, c.want, "not specific to CVE-2024-6387", "vendor advisory", "call home")
		if strings.Contains(strings.ToLower(all), "confirmed") || strings.Contains(all, "10.0.0.9") {
			t.Errorf("%s: the general checks must not claim confirmation nor carry device values: %s", c.product, all)
		}
		if len(h.Checks.IfFound) == 0 {
			t.Errorf("%s: no if-found steps", c.product)
		}
	}
}

// A KEV display name without the vendor says the family too.
func TestSummaryForNamesTheFamilyOnce(t *testing.T) {
	t.Parallel()
	for sw, fam := range map[string]string{"Junos OS": "Juniper Junos OS", "FortiOS": "Fortinet FortiOS", "RouterOS": "MikroTik RouterOS", "Cisco IOS XE Software": "Cisco IOS", "OpenSSH": "OpenSSH"} {
		if got := summaryFor(fam, sw, "CVE-1"); !strings.HasPrefix(got, "General checks for "+sw+": ") {
			t.Errorf("%s: %s", sw, got)
		}
	}
	if got := summaryFor("Web server", "Apache HTTP Server", "CVE-1"); !strings.HasPrefix(got, "General checks for Apache HTTP Server (Web server): ") {
		t.Errorf("web: %s", got)
	}
}

// POST-1: a confirmed pack's own compromise signs win; otherwise the general checks fill in. No firewall config is ever generated,
// whatever the pack holds.
func TestContract_INV8_TheConfirmedPackWinsWhereItHasItsOwn(t *testing.T) {
	t.Parallel()
	row := hardeningRow("10.0.0.5", "server", "OpenBSD", "OpenSSH")
	if h := hardening(row, &findings.CompromiseCheck{}); h != nil {
		t.Fatalf("pack with its own signs = %+v", h)
	}
	if h := hardening(row, nil); h == nil || h.Checks == nil || h.Family != "OpenSSH" {
		t.Fatalf("pack without signs = %+v", h)
	}
}

// POST-1 end to end: a finding without a pack carries the general checks on GET /findings/{id}, and nothing of a firewall config or an
// admin network.
func TestContract_INV8_FindingWithoutPackShowsGeneralChecksOnly(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	code, b := r.call("GET", "/findings/"+r.ids[otherCVE], "viewer", "")
	if code != 200 || b["pack"] != nil {
		t.Fatalf("%d %v", code, b)
	}
	h, _ := b["hardening"].(map[string]any)
	if h == nil || h["checks"] == nil || h["family"] == nil {
		t.Fatalf("hardening = %v", b["hardening"])
	}
	for _, gone := range []string{"firewall", "target", "ports", "ports_from", "admin_example", "box", "viewer", "self"} {
		if _, ok := h[gone]; ok {
			t.Errorf("hardening still has %q: %v", gone, h)
		}
	}
}

// The class "Have I been hit? does not know the software": the findings of one test round (six vendors, three of them on no exploited
// list) and the family and software name their general checks get. Before, ESXi, DSM and vCenter fell to the catch-all family, and
// the three findings on no list (nginx, Java, the Linux kernel) were "General checks for the software". Now only the products no
// family is written for stay General, and every one names its software.
func TestHardeningCount_EveryWalkedFindingNamesItsSoftware(t *testing.T) {
	t.Parallel()
	type walked struct{ kind, vendor, product, known, family string }
	cases := []walked{
		{"server", "VMware", "ESXi", "", "VMware ESXi"},
		{"switch", "Juniper", "Junos OS", "", "Juniper Junos OS"},
		{"nas", "Synology", "DiskStation Manager (DSM)", "", "Synology DSM"},
		{"server", "VMware", "vCenter Server", "", "General"},
		{"server", "", "", "nginx", "Web server"},
		{"server", "", "", "Eclipse Temurin JRE", "General"},
		{"server", "", "", "Linux kernel", "Linux"},
	}
	general, unnamed := 0, 0
	for _, c := range cases {
		r := findings.Row{ID: "f-1", CVE: "CVE-2026-0001", Asset: &findings.AssetView{ID: "a-1", Name: "dev", Kind: c.kind}}
		if c.vendor != "" {
			r.Kev = &findings.KevInfo{Vendor: c.vendor, Product: c.product}
		} else {
			r.Known = &findings.KnownVersion{Software: c.known, Version: "1.0", Source: findings.VersionByAgent}
		}
		h := generalHardening(r)
		if h.Family == "General" {
			general++
		}
		if h.Software == "the software" {
			unnamed++
		}
		if h.Family != c.family {
			t.Errorf("%s%s: family %q, want %q", c.product, c.known, h.Family, c.family)
		}
		if c.known != "" && h.Software != c.known {
			t.Errorf("%s: software %q, want the finding's software line", c.known, h.Software)
		}
	}
	t.Logf("walked findings %d: General family %d (before 6), \"the software\" %d (before 3)", len(cases), general, unnamed)
	if general != 2 || unnamed != 0 {
		t.Errorf("General %d, unnamed %d; want 2 and 0", general, unnamed)
	}
}
