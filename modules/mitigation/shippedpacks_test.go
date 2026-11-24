package mitigation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// The confirmed packs that ship in the core image (content/mitigation/packs). Every command in them is taken from a page that was
// read while writing the pack, and that page is listed in the pack's sources, so a reviewer can check each line against its source.

const shippedPackDir = "../../content/mitigation/packs/"

var packURL = regexp.MustCompile(`https?://[^\s"),]+`)

// shippedPacks reads every pack of the shipped directory with the box's own parser.
func shippedPacks(t *testing.T) map[string]packDoc {
	t.Helper()
	names, err := filepath.Glob(shippedPackDir + "*.json")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]packDoc{}
	for _, n := range names {
		data, err := os.ReadFile(n) //nolint:gosec // test: a file of the repository
		if err != nil {
			t.Fatal(err)
		}
		p, err := parsePack(data)
		if err != nil {
			t.Fatalf("%s: the box would refuse it: %v", filepath.Base(n), err)
		}
		if filepath.Base(n) != p.CVE+".json" {
			t.Fatalf("%s holds the pack of %s", filepath.Base(n), p.CVE)
		}
		out[p.CVE] = p
	}
	return out
}

// urlsIn returns the links a text names, without the sentence's closing punctuation.
func urlsIn(s string) []string {
	var out []string
	for _, m := range packURL.FindAllString(s, -1) {
		out = append(out, strings.TrimRight(m, ".;:"))
	}
	return out
}

func TestShippedPacks_CoverTheExploitedCVEsOfThisRelease(t *testing.T) {
	t.Parallel()
	packs := shippedPacks(t)
	for _, cve := range []string{
		"CVE-2025-22224", "CVE-2025-22226", "CVE-2026-41709", // VMware ESXi
		"CVE-2026-123890", "CVE-2026-59310", "CVE-2026-59309", // VMware vCenter
		"CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", // Juniper Junos J-Web
		"CVE-2024-10441", "CVE-2026-13639", "CVE-2026-13684", "CVE-2026-76954", // Synology DSM
		"CVE-2026-114938",                    // OpenJDK
		"CVE-2026-123007", "CVE-2026-123633", // nginx
	} {
		if _, ok := packs[cve]; !ok {
			t.Errorf("no confirmed pack for %s", cve)
		}
	}
}

// Every command line a pack shows (a firewall step, its verify and undo steps, a "Have I been hit?" command, the recheck command)
// carries the link of the page it was taken from, and every link a pack names is one of its listed sources.
func TestShippedPacks_EveryCommandCitesItsSource(t *testing.T) {
	t.Parallel()
	for cve, p := range shippedPacks(t) {
		listed := map[string]bool{}
		for _, s := range p.Sources {
			listed[s.URL] = true
		}
		cited := func(where, text string) {
			if len(urlsIn(text)) == 0 {
				t.Errorf("%s %s: a command without the link of its source", cve, where)
			}
		}
		codeSteps := func(where string, steps []findings.CodeStep) {
			for _, s := range steps {
				if strings.TrimSpace(s.Code) != "" {
					cited(where+"["+s.Title+"]", s.Note)
				}
			}
		}
		for _, g := range p.Firewall {
			codeSteps(g.Vendor+".steps", g.Steps)
			codeSteps(g.Vendor+".verify", g.Verify)
			codeSteps(g.Vendor+".undo", g.Undo)
			if g.Alternative != nil {
				codeSteps(g.Vendor+".alternative", g.Alternative.Steps)
			}
		}
		if p.Compromise != nil {
			for _, in := range p.Compromise.Indicators {
				if len(in.Commands) > 0 {
					cited("compromise["+in.Title+"]", in.Detail)
				}
			}
		}
		if p.Recheck != nil && strings.TrimSpace(p.Recheck.Code) != "" {
			cited("recheck", strings.Join(p.Recheck.Steps, " "))
		}
		body, err := json.Marshal(struct {
			Patch      findings.Patch
			Workaround findings.Workaround
			Firewall   []findings.FirewallGuide
			Checklist  []string
			Recheck    *findings.Recheck
			Compromise *findings.CompromiseCheck
		}{p.Patch, p.Workaround, p.Firewall, p.Checklist, p.Recheck, p.Compromise})
		if err != nil {
			t.Fatal(err)
		}
		for _, link := range urlsIn(string(body)) {
			if !listed[link] {
				t.Errorf("%s names %s, which is not in its sources", cve, link)
			}
		}
		if !listed[p.Patch.URL] {
			t.Errorf("%s: the patch link %s is not in its sources", cve, p.Patch.URL)
		}
	}
}

// Each pack fills the four steps of the finding page: the fix with its fixed versions, the workaround (or why there is none), a
// firewall step with something to do or a stated reason, and a checklist.
func TestShippedPacks_FillTheFourSteps(t *testing.T) {
	t.Parallel()
	for cve, p := range shippedPacks(t) {
		if p.Patch.Fixed == "" || len(p.Patch.Steps) == 0 || p.Patch.SideEffect == "" {
			t.Errorf("%s: the fix step is incomplete", cve)
		}
		if p.Workaround.SideEffect == "" || len(p.Workaround.Steps) == 0 {
			t.Errorf("%s: the workaround step is incomplete", cve)
		}
		if len(p.Firewall) == 0 {
			t.Errorf("%s: no firewall step", cve)
		}
		for _, g := range p.Firewall {
			if g.Intro == "" || len(g.Steps) == 0 && len(g.Plain) == 0 {
				t.Errorf("%s %s: the firewall guide shows nothing to do and no reason", cve, g.Vendor)
			}
		}
		if len(p.Checklist) < 3 {
			t.Errorf("%s: the checklist has %d items", cve, len(p.Checklist))
		}
	}
}

// The finding page of an exploited vCenter flaw, through the real loader and the real GET /findings/{id}: the confirmed pack's four
// steps with the device's address in the commands, its own "Have I been hit?" signs and no general checks beside them.
func TestShippedPacks_FindingPageShowsTheFourSteps(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var docs []Doc
	names, err := filepath.Glob(shippedPackDir + "*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		data, err := os.ReadFile(n) //nolint:gosec // test: a file of the repository
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, Doc{Name: filepath.Base(n), Data: data})
	}
	res, err := r.loader.Install(t.Context(), Update{Version: "2026.11.24.1", Docs: docs})
	if err != nil || res.Loaded != len(docs) || len(res.Rejected) != 0 {
		t.Fatalf("install: %+v %v", res, err)
	}
	r.inv.mu.Lock()
	r.inv.assets["a-2"] = findings.AssetView{ID: "a-2", Hostname: ptr("vcenter01"), IP: "198.51.100.20", Kind: "server", Display: "VMware vCenter"}
	r.inv.mu.Unlock()
	const cve = "CVE-2026-123890"
	sw := []findings.Software{{ID: "s-2", Display: "VMware vCenter", Vendor: "VMware", Product: "vCenter", Version: "8.0.3", KevKeys: []string{"vmware|vcenter"}}}
	up, err := r.svc.UpsertFromMatch(t.Context(), findings.Asset{ID: "a-2", Name: "vcenter01", Software: sw}, []findings.Vuln{{CVE: cve, Vendor: "VMware", Product: "vCenter", HasTemplate: true}})
	if err != nil || len(up.Created) != 1 {
		t.Fatalf("seed finding: %+v %v", up, err)
	}
	code, b := r.call("GET", "/findings/"+up.Created[0], "viewer", "")
	if code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	page := string(mustJSON(t, b))
	if strings.Contains(page, "{IP}") || strings.Contains(page, "{HOST}") {
		t.Fatal("a placeholder is left in the page")
	}
	pack, _ := b["pack"].(map[string]any)
	if pack == nil || pack["cve"] != cve {
		t.Fatalf("pack = %v", b["pack"])
	}
	patch := pack["patch"].(map[string]any)
	if !strings.Contains(patch["fixed"].(string), "8.0 U3m") || patch["summary"] == "" {
		t.Fatalf("step 1, the fix: %v", patch)
	}
	if w := pack["workaround"].(map[string]any); !strings.Contains(w["summary"].(string), "2012") {
		t.Fatalf("step 2, the workaround: %v", w)
	}
	var vendors []string
	var fortigate map[string]any
	for _, g := range pack["firewall"].([]any) {
		gm := g.(map[string]any)
		vendors = append(vendors, gm["vendor"].(string))
		if gm["vendor"] == "fortigate" {
			fortigate = gm
		}
	}
	if !slices.Equal(vendors, []string{"fortigate", "mikrotik", "generic"}) || fortigate == nil {
		t.Fatalf("step 3, the firewall: %v", vendors)
	}
	if first := fortigate["steps"].([]any)[0].(map[string]any)["code"].(string); !strings.Contains(first, "set subnet 198.51.100.20 255.255.255.255") {
		t.Fatalf("the device's address is not in the firewall command: %s", first)
	}
	if svc := fortigate["steps"].([]any)[1].(map[string]any)["code"].(string); !strings.Contains(svc, "set tcp-portrange 2012 443 5480 22") {
		t.Fatalf("the firewall guide does not limit the ports of the advisory: %s", svc)
	}
	if list := pack["checklist"].([]any); len(list) < 3 || !strings.Contains(list[0].(string), "vcenter01") {
		t.Fatalf("step 4, the checklist: %v", list)
	}
	if b["compromise"] == nil || b["hardening"] != nil {
		t.Fatalf("the pack's own signs must replace the general checks: compromise=%v hardening=%v", b["compromise"], b["hardening"])
	}
}

// Junos names the interface list of web-management http and https "interface" (CLI reference: http and https (Web Management));
// an older page's "interfaces" is a syntax error on the releases these packs are for, so a customer could not apply the workaround.
func TestShippedPacks_JunosWebManagementUsesTheInterfaceKeyword(t *testing.T) {
	t.Parallel()
	bad := regexp.MustCompile(`web-management https? interfaces\b`)
	for cve, p := range shippedPacks(t) {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if m := bad.FindString(string(b)); m != "" {
			t.Errorf("%s: %q: the Junos statement is \"interface [ interface-names ]\"", cve, m)
		}
	}
}
