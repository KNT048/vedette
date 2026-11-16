package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
)

func obs(v string) *inventory.Observed { return &inventory.Observed{Value: v} }

// M2-2 (walk n74): the mitigation-config answer for a Juniper EX4200 said "the data on this box does not list affected versions" and
// named no firewall, while the page showed the version, the range "before 20.4" and FortiGate was in Devices. The AI now gets the
// facts the page has.
func TestAIFindingData_M2_2_TheAIGetsThePageFacts(t *testing.T) {
	ver, http := "15.1R7.9", "J-Web"
	host := "core-switch"
	req := mitigation.AIRequest{
		Skill: mitigation.SkillConfig,
		Finding: findings.Row{
			CVE: "CVE-2023-36845", Status: "suspected", Severity: "critical", Basis: "version", Confidence: 0.7,
			Asset: &findings.AssetView{Name: "Juniper Networks EX4200-48T", IP: "192.168.18.47", Kind: "switch", Display: "Juniper Junos OS"},
			Kev:   &findings.KevInfo{Vendor: "Juniper", Product: "Junos OS", Name: "Junos OS PHP External Variable Modification", Links: []string{"https://supportportal.juniper.net/JSA72300"}},
			CVSS:  &findings.CVSS{Score: 9.8, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		FixedIn: &findings.FixedIn{Kind: "branches", Branches: []findings.FixedBranch{{Branch: "21.2", Fixed: "21.2R3-S7"}, {Branch: "20.4", Fixed: "20.4R3-S9"}}, More: 3, Source: "NVD affected versions"},
	}
	// the evidence type is findings' own: set it the way the page gets it, from JSON
	if err := json.Unmarshal([]byte(`{"evidence":{"summary":"Juniper Networks EX4200-48T runs Juniper Junos OS 15.1R7.9. Its version is inside the range affected by CVE-2023-36845 (before 20.4).","checked_at":"2026-11-16T00:00:00Z"}}`), &req.Finding); err != nil {
		t.Fatal(err)
	}
	dev := inventory.Device{AssetCore: inventory.AssetCore{IP: "192.168.18.47", Hostname: &host, Kind: "switch", Vendor: obs("Juniper Networks"), Model: obs("EX4200-48T"), OS: obs("JUNOS 15.1R7.9"),
		Services: []inventory.ServiceRow{{Port: 443, Proto: "tcp", Name: "https", Product: &http}, {Port: 22, Proto: "tcp", Name: "ssh"}}},
		Software: []inventory.Software{{Display: "Juniper Junos OS", Version: &ver}}}
	walls := []inventory.Device{
		{AssetCore: inventory.AssetCore{IP: "192.168.18.2", Kind: "firewall", Vendor: obs("Fortinet"), Model: obs("FortiGate 60F"), OS: obs("FortiOS 7.2.5")}},
		{AssetCore: inventory.AssetCore{IP: "192.168.18.1", Kind: "firewall"}},
	}
	blocks := aiFindingData(req, &dev, walls)
	if len(blocks) != 3 {
		t.Fatalf("blocks = %d, want feed, device and network", len(blocks))
	}
	all := blocks[0].Text + blocks[1].Text + blocks[2].Text
	for _, want := range []string{
		"15.1R7.9", "before 20.4", // the installed version and the affected range (the Evidence)
		"21.2 fixed in 21.2R3-S7", "20.4 fixed in 20.4R3-S9", "3 more release lines", // the fix of each release line
		"Vendor: Juniper Networks", "Model: EX4200-48T", "Operating system: JUNOS 15.1R7.9", "192.168.18.47",
		"443/tcp https (J-Web)", "22/tcp ssh", // the open ports
		"matched by version, confidence 0.70", "CVSS 3.1 base score: 9.8",
		"Vendor: Fortinet; Model: FortiGate 60F; Operating system: FortiOS 7.2.5", // the firewall in Devices
		"192.168.18.1, kind firewall; vendor not known",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the AI's data lacks %q:\n%s", want, all)
		}
	}
	if blocks[1].Kind != "inventory" || blocks[2].Kind != "inventory" || blocks[0].Kind != ai.DataFeed {
		t.Fatalf("kinds = %s %s %s", blocks[0].Kind, blocks[1].Kind, blocks[2].Kind)
	}

	// explain gets the device facts but not the firewalls; no firewall in Devices is said, not left out
	req.Skill = mitigation.SkillExplain
	if b := aiFindingData(req, &dev, nil); len(b) != 2 || !strings.Contains(b[1].Text, "before 20.4") {
		t.Fatalf("explain blocks = %+v", b)
	}
	req.Skill, req.FixedIn = mitigation.SkillConfig, nil
	b := aiFindingData(req, nil, nil)
	if !strings.Contains(b[2].Text, "No firewall or router is in the inventory.") || !strings.Contains(b[1].Text, "NVD's affected versions name none") {
		t.Fatalf("no device, no firewall: %+v", b)
	}
}
