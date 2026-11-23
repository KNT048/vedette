package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/mitigation"
)

// The class: one finding, several answers. The finding page, the assistant's context, its tools, the MCP tools and the device updates
// each used to assemble the fix and the confirmation from their own reading, so a person was told one fixed release by the page and
// another by the assistant, and a finding a person confirmed read "matched by person, confidence 0.85" with no word of who. They now
// read one case (findingCase: the finding's view and the CVE's brief). This counts, over the cases below, per reader:
//   - findings whose fixed release the reader does not carry equal to the page's (the stored fix of the view);
//   - findings whose reader says "no fixed release" while the view names one;
//   - findings a person confirmed whose reader says "not confirmed", or does not say who confirmed it (the MCP reader says "a person").
//
// Every total is 0; measured before the change on the same cases through the readers of that time (the PR body has the numbers).

type countCase struct {
	name    string
	fix     findings.Fix
	verify  findings.Verified
	basis   findings.DetectionBasis
	by      string // the person who confirmed it
	trains  []feeds.BriefFix
	product string
}

func countCases() []countCase {
	esxi := []feeds.BriefFix{{Vendor: "vmware", Product: "esxi", Origin: feeds.OriginCNA, Train: "8.0 U3", Release: "8.0 U3d (build 24585383)"},
		{Vendor: "vmware", Product: "esxi", Origin: feeds.OriginCNA, Train: "8.0 U2", Release: "8.0 U2d (build 24585300)"},
		{Vendor: "vmware", Product: "esxi", Origin: feeds.OriginCNA, Train: "7.0 U3", Release: "7.0 U3s (build 24585291)"}}
	return []countCase{
		// the reported case: ESXi on 8.0 U3, NVD lists exact versions with no fix, VMware states the build of each train; a person confirmed it
		{"CVE-2025-22225 on ESXi 8.0 U3, confirmed by a person", findings.Fix{Kind: findings.FixUpdate, Version: "8.0 U3d (build 24585383)"}, findings.VerifiedPerson, findings.DetectPerson, "it@example.com", esxi, "VMware ESXi"},
		{"CVE-2025-22225 on ESXi 8.0 U2, found by version", findings.Fix{Kind: findings.FixUpdate, Version: "8.0 U2d (build 24585300)"}, findings.VerifiedNo, findings.DetectBannerVersion, "", esxi, "VMware ESXi"},
		{"CVE-2024-21762 on FortiOS 7.2.5, the device reports it", findings.Fix{Kind: findings.FixUpdate, Version: "7.2.7"}, findings.VerifiedDevice, findings.DetectDeviceVersion, "", nil, "FortiOS"},
		{"CVE-2024-6387 on OpenSSH, a distribution package", findings.Fix{Kind: findings.FixDistroUpdate, Version: "1:9.6p1-3ubuntu13.5"}, findings.VerifiedDevice, findings.DetectPackage, "", nil, "OpenSSH"},
		{"CVE-2025-21333 on Windows 11, the monthly update", findings.Fix{Kind: findings.FixOSUpdate, Version: "10.0.26100.2894", Ref: "KB5050009"}, findings.VerifiedScan, findings.DetectScan, "", nil, "Windows 11"},
		{"CVE-2024-30088 on Windows 10 21H2, a feature update", findings.Fix{Kind: findings.FixFeatureUpdate, Version: "22H2"}, findings.VerifiedDevice, findings.DetectDeviceVersion, "", nil, "Windows 10"},
		{"CVE-2023-36845 on Junos, no fixed release yet, confirmed by a person", findings.Fix{Kind: findings.FixNoneYet}, findings.VerifiedPerson, findings.DetectPerson, "ops@example.com", nil, "Junos OS"},
		{"CVE-2023-20198 on IOS XE, the fix is not known", findings.Fix{Kind: findings.FixUnknown}, findings.VerifiedNo, findings.DetectBannerVersion, "", nil, "IOS XE"},
		{"CVE-2025-0108 on PAN-OS, confirmed by a person", findings.Fix{Kind: findings.FixUpdate, Version: "10.2.13-h3"}, findings.VerifiedPerson, findings.DetectPerson, "it@example.com", nil, "PAN-OS"},
		{"CVE-2024-3400 on PAN-OS, confirmed by a person", findings.Fix{Kind: findings.FixUpdate, Version: "11.1.2-h3"}, findings.VerifiedPerson, findings.DetectPerson, "it@example.com", nil, "PAN-OS"},
		{"CVE-2024-1086 on the Linux kernel, a distribution package, confirmed by a person", findings.Fix{Kind: findings.FixDistroUpdate}, findings.VerifiedPerson, findings.DetectPerson, "ops@example.com", nil, "Linux kernel"},
	}
}

func (c countCase) built() findingCase {
	cve := strings.Fields(c.name)[0]
	fc := caseOf(aiSubject{CVE: cve, AssetName: "host-1", AssetIP: "192.0.2.10"})
	f := &fc.View.Finding
	f.ID, f.AssetID, f.Fix, f.Verified, f.Basis = "f-"+cve, "a1", c.fix, c.verify, c.basis
	f.FirstSeen = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	fc.View.Line = &findings.Line{ID: "s1", Display: c.product, Version: "1.0"}
	if c.verify != findings.VerifiedNo {
		fc.View.Events = []findings.Event{{Kind: findings.EvConfirmed, Actor: c.by, TS: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)}}
	}
	fc.Brief.Fixes = c.trains
	fc.Brief.Ranges = []feeds.BriefRange{{Counts: true, Versions: "7.0 update_1"}}
	return fc
}

// readerSays is what each reader of a finding carries of it, as one text per reader.
func readerSays(fc findingCase) map[string]string {
	req := mitigation.AIRequest{Skill: mitigation.SkillExplain, FindingID: fc.View.Finding.ID}
	blocks, _ := aiFindingData(req, fc, nil, aiFirewalls{})
	var ctx strings.Builder
	for _, b := range blocks {
		ctx.WriteString(b.Text)
	}
	row := aiFindingRow(fc, nil)
	m := mcpFinding(fc)
	return map[string]string{
		"assistant context": ctx.String(),
		"assistant tools":   row.Fix + " " + row.Confirmation,
		"mcp":               m.Fix + " " + m.Verification,
	}
}

func TestCount_ReadersAgreeOnTheFixAndWhoConfirmed(t *testing.T) {
	t.Parallel()
	var notEqual, noFixWhileNamed, notConfirmed int
	readers := map[string]bool{}
	for _, c := range countCases() {
		fc := c.built()
		page := fc.View.Finding.Fix.Version // the fix the finding page shows is the stored fix of the view
		for reader, text := range readerSays(fc) {
			readers[reader] = true
			if page != "" && !strings.Contains(text, page) {
				notEqual++
				t.Errorf("%s: %s does not carry the page's fix %q: %q", c.name, reader, page, text)
			}
			if page != "" && (strings.Contains(text, "No fixed release") || strings.Contains(text, "not known for this device")) {
				noFixWhileNamed++
				t.Errorf("%s: %s says no fixed release while the page names %q", c.name, reader, page)
			}
			if c.verify == findings.VerifiedPerson {
				who := c.by
				if reader == "mcp" {
					who = "a person"
				}
				if strings.Contains(text, "Not confirmed") || !strings.Contains(text, "Confirmed by "+who) {
					notConfirmed++
					t.Errorf("%s: %s does not say confirmed by %s: %q", c.name, reader, who, text)
				}
			}
			if strings.Contains(strings.ToLower(text), "why there is no") {
				t.Errorf("%s: %s explains an absence: %q", c.name, reader, text)
			}
		}
	}
	if len(readers) != 3 {
		t.Fatalf("readers = %v", readers)
	}
	t.Logf("cases %d; fixed release not equal to the page's %d; 'no fixed release' while the page names one %d; person-confirmed not read as confirmed %d",
		len(countCases()), notEqual, noFixWhileNamed, notConfirmed)
	if notEqual+noFixWhileNamed+notConfirmed != 0 {
		t.Fatal("a reader of a finding does not agree with the page")
	}
}

// The ESXi case in words: the context names the build of the device's own train and no other, says who confirmed it, and offers the
// vendor's advisory by number; the other trains' builds are in the brief for what it states, labelled with their train.
func TestCount_TheESXiFindingReadsTheSameEverywhere(t *testing.T) {
	t.Parallel()
	c := countCases()[0]
	fc := c.built()
	fc.Brief.References = []feeds.Reference{{URL: "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390", Group: "vendor-advisory"}}
	req := mitigation.AIRequest{Skill: mitigation.SkillExplain}
	blocks, links := aiFindingData(req, fc, nil, aiFirewalls{})
	device := blocks[1].Text
	for _, want := range []string{"Fix for this device: Update VMware ESXi to 8.0 U3d (build 24585383).", "Confirmation: Confirmed by it@example.com on 2026-11-20"} {
		if !strings.Contains(device, want) {
			t.Errorf("device block lacks %q:\n%s", want, device)
		}
	}
	if !strings.Contains(blocks[0].Text, "release train 8.0 U2 is fixed in 8.0 U2d (build 24585300)") || len(links) == 0 || !strings.Contains(blocks[0].Text, "Reference [1]: Vendor advisory, https://support.broadcom.com") {
		t.Errorf("brief block:\n%s", blocks[0].Text)
	}
}

// On the real wiring: three findings of one FortiGate, each confirmed by a person, read through the readers of the box (the assistant's
// context for the finding page's AI button, its tools, the MCP tools) and through the finding's view. Before this change the context
// said "matched by person, confidence 0.95" and never who: 3 of 3.
func TestCount_RealReadersSayWhoConfirmedAndTheStoredFix(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	for _, c := range []string{"CVE-2026-7001", "CVE-2026-7002", "CVE-2026-7003"} {
		s.kev(c, "Fortinet", "FortiOS")
	}
	id := s.addFortiGate()
	vs, err := s.d.Findings.Views(ctx, findings.ViewFilter{AssetID: id})
	if err != nil || len(vs) != 3 {
		t.Fatalf("views = %d, %v", len(vs), err)
	}
	cases := caseSource{findings: s.d.Findings}
	ask := aiAsk{findings: s.d.Findings, cases: cases, inv: s.d.Inventory}
	s.setModule("findings", true)
	mcp := mcpSource{reg: s.d.Reg, cases: cases}
	bad := 0
	for _, v := range vs {
		if _, err := s.d.Findings.Verify(ctx, v.Finding.ID, "I read the version on the device.", "it@acme.example"); err != nil {
			t.Fatal(err)
		}
		fc, err := cases.One(ctx, v.Finding.ID)
		if err != nil {
			t.Fatal(err)
		}
		blocks, _ := aiFindingData(mitigation.AIRequest{Skill: mitigation.SkillExplain, FindingID: v.Finding.ID}, fc, nil, aiFirewalls{})
		row, ok, err := ask.Finding(ctx, v.Finding.ID)
		if err != nil || !ok {
			t.Fatalf("assistant tool: %v %v", ok, err)
		}
		m, ok, err := mcp.Finding(ctx, v.Finding.ID)
		if err != nil || !ok {
			t.Fatalf("mcp: %v %v", ok, err)
		}
		for reader, text := range map[string]string{"context": blocks[0].Text + blocks[1].Text, "tools": row.Confirmation + " " + row.Fix, "mcp": m.Verification + " " + m.Fix} {
			who := "Confirmed by it@acme.example"
			if reader == "mcp" {
				who = "Confirmed by a person"
			}
			if !strings.Contains(text, who) || strings.Contains(text, "Not confirmed") || !strings.Contains(text, fc.View.FixText()) {
				bad++
				t.Errorf("%s of %s: %q", reader, v.Finding.CVE, text)
			}
		}
	}
	t.Logf("person-confirmed findings 3, readers 3: not read as confirmed or not carrying the page's fix: %d", bad)
}

// lookup_cve answers for any CVE the catalogue holds: a CVE no exploited list has still carries its title, score, affected versions,
// fixed releases and workaround, with listed false; the exploited-list entry's words come with a list.
func TestMCPEntryOfABriefWithAndWithoutAList(t *testing.T) {
	t.Parallel()
	b := feeds.Brief{CVE: "CVE-2025-22225", Title: "ESXi arbitrary write", Display: "vmware esxi", NVDStatus: "Analyzed",
		CVSS:   vectorOf("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"),
		Ranges: []feeds.BriefRange{{Counts: true, Versions: "from 8.0 before 8.0 U3d"}, {Versions: "ignored: the row does not count"}},
		Fixes:  []feeds.BriefFix{{Train: "8.0 U3", Release: "8.0 U3d (build 24585383)"}}, RangesFrom: feeds.OriginNVD}
	e := mcpEntry(b)
	if e.Source != "" || e.Title != "ESXi arbitrary write" || len(e.AffectedVersions) != 1 || len(e.FixedReleases) != 1 || e.FixedReleases[0].Release != "8.0 U3d (build 24585383)" ||
		e.Workaround != "No workaround is published: install the fix." || e.CVSS == nil || e.CVSS.AttackVector != "local" || e.AffectedFrom != "nvd" {
		t.Fatalf("entry without a list = %+v", e)
	}
	b.Lists = []feeds.ListEntry{{Source: "cisa-kev", Vendor: "VMware", Product: "ESXi", Name: "VMware ESXi Arbitrary Write Vulnerability", DateAdded: "2025-03-04", RequiredAction: "Apply updates.", Links: []string{"https://example.com/a"}}}
	e = mcpEntry(b)
	if e.Source != "cisa-kev" || e.Vendor != "VMware" || e.DateAdded != "2025-03-04" || len(e.Links) != 1 || e.Name != "VMware ESXi Arbitrary Write Vulnerability" {
		t.Fatalf("entry with a list = %+v", e)
	}
}
