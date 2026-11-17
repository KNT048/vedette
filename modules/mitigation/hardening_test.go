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
	}
	for _, c := range cases {
		h := generalHardening(hardeningRow("10.0.0.9", c.kind, c.vendor, c.product))
		if h.Family != c.family || h.Checks == nil {
			t.Errorf("%s %s: family %q, checks %v", c.vendor, c.product, h.Family, h.Checks != nil)
			continue
		}
		if strings.Count(strings.TrimPrefix(h.Checks.Summary, "General checks"), c.family) > 1 { // W76-2: "General checks for Juniper Junos OS (Juniper Junos OS)"
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

// W76-2 r1 L1: a KEV display name without the vendor says the family too.
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

// POST-1: a confirmed pack's own compromise signs win; otherwise the general checks fill in. No firewall config is ever generated
// (D-629, kien 2026-11-17), whatever the pack holds.
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
// admin network (D-629).
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
