package ai

import (
	"context"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// formsData is the box's own data as the read tools of "Ask your data" see it, with the forms that are full of digits: record ids,
// timestamps, versions, ports, a UUID, a hash, an AS number, links with article numbers and CVE ids written without "CVE-".
type formsData struct{ assets []AssetRow }

func (d formsData) Assets(context.Context) ([]AssetRow, error) { return d.assets, nil }
func (formsData) Findings(context.Context) ([]FindingRow, error) {
	return []FindingRow{formsFinding}, nil
}
func (formsData) Finding(context.Context, string) (FindingRow, bool, error) {
	return formsFinding, true, nil
}
func (formsData) IOC(context.Context, string, string) (IOCFact, bool, error) {
	return IOCFact{}, false, nil
}

var formsFinding = FindingRow{ID: store.NewID("fnd"), AssetID: store.NewID("dev"), Asset: "FW-HQ", AssetIP: "192.168.1.1", CVE: "CVE-2023-36844", Status: "confirmed",
	Severity: "critical", Basis: "scan", Confidence: 0.95, FirstSeen: "2026-11-02T08:15:42.120Z", LastSeen: "2026-11-13T05:23:29.123Z",
	Evidence: "nuclei template juniper-j-web-rce (also CVE-2023-36845, CVE-2023-36846) matched at 2026-11-13 05:23:29; certificate sha256 9f3a123456789e0b44c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3; announced by AS401234567; agent e2b0c1d4-5f6a-4b7c-8d9e-000123456789"}

type formsFacts struct{}

func (formsFacts) CVE(context.Context, string) (CVEFacts, bool, error) {
	return CVEFacts{CVE: "CVE-2023-36844", Vendor: "Juniper", Product: "Junos OS", Name: "Juniper Junos OS EX Series PHP External Variable Modification Vulnerability",
		Description:    "Juniper Junos OS on EX Series contains a PHP external variable modification vulnerability (chained with CVE-2023-36845 and CVE-2023-36846) that allows an attacker to control an important environment variable.",
		RequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", DateAdded: "2023-11-13",
		Links: []string{"https://supportportal.juniper.net/s/article/000087042", "https://nvd.nist.gov/vuln/detail/CVE-2023-36844", "https://kb.example.com/s/article/000087042?language=en_US#steps"}}, true, nil
}

func (formsFacts) AffectedAssets(context.Context, string) ([]AssetFact, error) {
	return []AssetFact{{Name: "FW-HQ", IP: "192.168.1.1", Kind: "firewall", Basis: "version", Status: "confirmed"}}, nil
}

// Beta 0.1.0-beta.1 item 19: "give me solution of currently status" (no number in it) came back with "the box held back the inventory
// lookup under a company rule about personal data". The real outputs of the inventory, findings and exploited-list tools on data like
// a real box's go through the personal-data hook without a block; the same digits standing alone as an ID number are still blocked.
func TestToolOutputsAreNotIDNumbers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := formsData{assets: []AssetRow{
		{ID: store.NewID("dev"), Name: "FW-HQ", IP: "192.168.1.1", Kind: "firewall", Vendor: "Juniper", Model: "EX2300-24P", OS: "Junos OS 21.4R3-S5", Approved: true,
			Ports: []string{"22/tcp ssh", "443/tcp https", "8443/tcp https-alt", "9100/tcp jetdirect"}, Software: []string{"Junos OS 21.4R3-S5", "OpenSSH 9.6p1"},
			FirstSeen: "2026-11-02T08:15:42.120Z", LastSeen: "2026-11-13T05:23:29.123Z", Origin: "discovered", SeenBy: "scan"},
		{ID: store.NewID("dev"), Name: "PC-ACCOUNTS-03", IP: "fe80::1c2b:3a4d:5e6f:7081", Kind: "workstation", Vendor: "Dell", Model: "OptiPlex 7010", OS: "Windows 11 Pro 10.0.22631.4460",
			Ports: []string{"135/tcp msrpc", "445/tcp microsoft-ds", "3389/tcp ms-wbt-server"}, Software: []string{"Microsoft Visual C++ 2015-2022 Redistributable (x64) 14.38.33135", "Google Chrome 131.0.6778.86", "KB5034441"},
			FirstSeen: "2026-10-30T23:59:59.999Z", LastSeen: "2026-11-13T05:20:00.000Z", Origin: "manual", SeenBy: "osquery"},
		{ID: store.NewID("dev"), Name: "Vedette", IP: "10.0.0.5", Kind: "server", Model: "N100", OS: "Ubuntu 24.04.1 LTS", Approved: true, IsBox: true,
			Software: []string{"vedette 0.1.0-beta.1", "linux-image 6.8.0-48-generic"}, FirstSeen: "2026-11-01T00:00:00.000Z", LastSeen: "2026-11-13T05:23:30.000Z", Origin: "discovered", SeenBy: "box"},
	}}
	var outs []string
	for _, run := range []func() (toolOut, error){
		func() (toolOut, error) { return toolSearchAssets(ctx, d, map[string]any{}) },
		func() (toolOut, error) { return toolListFindings(ctx, d, map[string]any{"status": "any"}) },
		func() (toolOut, error) { return toolGetFinding(ctx, d, map[string]any{"id": formsFinding.ID}) },
		func() (toolOut, error) {
			return toolLookupCVE(ctx, formsFacts{}, map[string]any{"cve": "CVE-2023-36844"})
		},
	} {
		out, err := run()
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out.Text)
	}
	r := runner(t, nil)
	digitRuns := 0
	for _, text := range outs {
		digitRuns += len(idRuns(blankIPs(text, false, false))) // what the detector read before the forms were blanked
		if res := run(t, r, BeforeAI, text); res.Outcome == OutcomeBlocked || res.Outcome == OutcomeHeld {
			t.Errorf("tool output blocked as %+v:\n%s", res.Hits, text)
		}
	}
	if digitRuns == 0 {
		t.Fatal("the fixture has no ID-shaped digit run: it does not test the forms")
	}
}

func TestIDNumbersAndTheFormsTheyAreNot(t *testing.T) {
	t.Parallel()
	notID := []string{
		"CVE-2023-36844", "cve-2023-36844", "see CVE-2023-36845 and CVE-2024-123456",
		"550e8400-e29b-41d4-a716-446655440000", "E2B0C1D4-5F6A-4B7C-8D9E-000123456789",
		"dev-" + "aaaabbbb22223333444455556667"[:26], "fnd-2345672345672345672345672a",
		"192.168.100.200", "fe80::1c2b:3a4d:5e6f:7081", "2001:db8::1234:5678", "00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E", "001a.2b3c.4d5e",
		"version 10.0.19045.3693", "Chrome 131.0.6778.86", "Junos 21.4R3-S5", "openssl 3.0.2-0ubuntu1.18",
		"2026-11-13", "2026-11-13T05:23:29.123456789Z", "2026-11-13 05:23:29", "13/11/2026", "2026-11-13T05:23:29+07:00",
		"22/tcp ssh, 443/tcp https, 3389/tcp rdp", "ports 443 3389 22 open",
		"AS401234567", "ASN401234567", "AS13335",
		"sha256 9f3a123456789e0b44c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3", "md5 123456789abcdef0123456789abcdef0",
		"https://supportportal.juniper.net/s/article/000087042", "https://supportportal.juniper.net/s/article/000087042?language=en_US#top",
		"Cisco ISR4321/K9", "model C1234567 in stock", // a passport shape without a passport label is a part number
	}
	for _, s := range notID {
		if got := findIDNumbers(s); len(got) > 0 {
			t.Errorf("%q read as an ID number at %v", s, got)
		}
	}
	isID := []string{
		"CCCD 079012345678", "CMND 123456789", "my ID is 123456789.", "CCCD: 0790.1234.5678", "CCCD 079 012 345 678", "id 123-456-789.",
		`{"note":"CCCD 079012345678"}`, `"079012345678"`, "CVE-2023-36844 belongs to citizen 079012345678",
		"0790.1234.5678", "device 192.168.1.20 owner 123456789", "2026-11-13 CMND 123456789",
		"https://kb.example.com/a 079012345678",
		// the Opus review of D-481: each was blocked before the forms were blanked, and must still be
		"CCCD079201234567", "CMND 123456789abcdef0", "CMND 2012-34567", "CMND 1912-34567", "CCCD 0792-2012-3456", "CMND AS 201234567",
		"referer https://x.vn/a,CCCD:079201234567", "passport https://x.vn/?so=123456789", "https://kb.example.com/view?id=123456789012",
		"2023-36844", "AS 201234567", "cccd079201234567abcdef", "căn cước công dân số 079201234567", "can cuoc: 079201234567", "số định danh 079201234567",
		"hộ chiếu C1234567", "passport no. B7654321", "ho chieu: N1234567", `{"id":"079201234567"}`, "ID:079201234567abc",
	}
	for _, s := range isID {
		if got := findIDNumbers(s); len(got) == 0 {
			t.Errorf("%q: the ID number is not found", s)
		}
	}
}
