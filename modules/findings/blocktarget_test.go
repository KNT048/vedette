package findings

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// blockLine is a software line of product (vendor/product as a CPE writes them) at version, as the device itself reports it.
func blockLine(id, vendor, product, version string) Software {
	return Software{ID: id, Display: product, Vendor: vendor, Product: product, Version: version,
		CPE: "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*", Source: "snmp"}
}

// rangedCVE is a catalogue CVE of product with these ranges (each "start-end", end exclusive; "start-=end" an inclusive end).
func rangedCVE(cve, vendor, product string, ranges ...string) Vuln {
	v := Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD}
	for _, r := range ranges {
		start, end, _ := strings.Cut(r, "-")
		vr := VersionRange{StartIncl: start, EndExcl: end}
		if e, ok := strings.CutPrefix(end, "="); ok {
			vr = VersionRange{StartIncl: start, EndIncl: e}
		}
		v.Affected = append(v.Affected, Affected{CPE: "cpe:2.3:a:" + vendor + ":" + product + ":*:*:*:*:*:*:*:*", Range: vr})
	}
	return v
}

// blockDevice is one device of the block target fixture: one line of its own product, and the CVEs of that product.
type blockDevice struct {
	id, vendor, product, version string
	vulns                        []Vuln
}

// blockDevices is the fixture of the block target count: lines whose CVEs need different releases. Each device runs a product of its
// own, so the CVEs of one never reach another.
//
//   - web-01 runs nginx 1.30.5, shaped like a real box: thirteen CVEs affect 1.30.0-<1.30.7 and again 1.31.0-<1.31.9, one only fixes in
//     1.31.6 (affected from 1.25.0), one in 1.30.6. The highest per-CVE fix, 1.31.6, leaves the thirteen open; 1.30.7 leaves the one;
//     1.31.9 clears all fifteen.
//   - web-02 runs an edge proxy 1.30.5 whose later train has no fix: one CVE affects 1.30.0-<1.30.7 and 1.31.0 up to 1.31.8 inclusive (no
//     fixed release named), the other only fixes in 1.31.6. No release the data names clears both: two blocks.
//   - mail-01 runs a mail relay 1.28.0 with two CVEs whose highest fix clears both (1.28.2 and 1.28.4): the old answer is already right.
//   - dns-01 runs a DNS cache 1.26.1 with two CVEs of one fix (1.26.3): one release, nothing to combine.
func blockDevices() []blockDevice {
	nginx := func(cve string, ranges ...string) Vuln { return rangedCVE(cve, "f5", "nginx", ranges...) }
	var web01 []Vuln
	for i := range 13 {
		web01 = append(web01, nginx(fmt.Sprintf("CVE-2026-901%02d", i), "1.30.0-1.30.7", "1.31.0-1.31.9"))
	}
	web01 = append(web01, nginx("CVE-2026-90439", "1.25.0-1.31.6"), nginx("CVE-2026-90440", "1.30.0-1.30.6"))
	proxy := func(cve string, ranges ...string) Vuln { return rangedCVE(cve, "example", "edge_proxy", ranges...) }
	relay := func(cve string, ranges ...string) Vuln { return rangedCVE(cve, "example", "mail_relay", ranges...) }
	cache := func(cve string, ranges ...string) Vuln { return rangedCVE(cve, "example", "dns_cache", ranges...) }
	return []blockDevice{
		{"web-01", "f5", "nginx", "1.30.5", web01},
		{"web-02", "example", "edge_proxy", "1.30.5", []Vuln{proxy("CVE-2026-90501", "1.30.0-1.30.7", "1.31.0-=1.31.8"), proxy("CVE-2026-90502", "1.20.0-1.31.6")}},
		{"mail-01", "example", "mail_relay", "1.28.0", []Vuln{relay("CVE-2026-90601", "1.28.0-1.28.2"), relay("CVE-2026-90602", "1.27.0-1.28.4")}},
		{"dns-01", "example", "dns_cache", "1.26.1", []Vuln{cache("CVE-2026-90701", "1.26.0-1.26.3"), cache("CVE-2026-90702", "1.26.0-1.26.3")}},
	}
}

// blockTargetWorld matches the fixture's devices with the real match pass, so every finding stores the fix the one resolver reads.
func blockTargetWorld(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.feeds.vulns = nil
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for i, d := range blockDevices() {
		e.feeds.vulns = append(e.feeds.vulns, d.vulns...)
		e.inv.assets[d.id] = AssetView{ID: d.id, Hostname: ptr(d.id), IP: fmt.Sprintf("192.0.2.%d", 10+i), Kind: "server", Approved: true}
		e.inv.match[d.id] = Asset{ID: d.id, Name: d.id, Software: []Software{blockLine("s-"+d.id, d.vendor, d.product, d.version)}}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

// listedBlock is one block a list names: a device, a line, the release it names and the CVEs it says the release fixes.
type listedBlock struct {
	asset, software, key, version string
	cves                          []string
}

// listedBlocks reads the blocks every reader names (ListedFixes: By device, By fix, Home and the report read the same combination).
func listedBlocks(t *testing.T, e *env) []listedBlock {
	t.Helper()
	ctx := t.Context()
	listed, err := e.svc.ListedFixes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[[3]string]*listedBlock{}
	for id := range e.inv.match {
		fs, err := e.svc.Findings(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			l, ok := listed[f.ID]
			if !f.Open() || !ok {
				continue
			}
			k := [3]string{f.AssetID, f.SoftwareID, l.Key}
			b := by[k]
			if b == nil {
				b = &listedBlock{asset: f.AssetID, software: f.SoftwareID, key: l.Key, version: l.Fix.Version}
				by[k] = b
			}
			b.cves = append(b.cves, f.CVE)
		}
	}
	out := make([]listedBlock, 0, len(by))
	for _, b := range by {
		slices.Sort(b.cves)
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b listedBlock) int { return strings.Compare(a.asset+a.key, b.asset+b.key) })
	return out
}

// stillOpen is the CVEs of b that the matcher still finds on the line once it runs the block's release: the device matched again with
// the line at that version, independently of how the release was chosen.
func stillOpen(e *env, b listedBlock) []string {
	a := e.inv.match[b.asset]
	a.Software = slices.Clone(a.Software)
	for i, s := range a.Software {
		if s.ID == b.software {
			a.Software[i] = blockLine(s.ID, s.Vendor, s.Product, b.version)
		}
	}
	have := map[string]bool{}
	for _, c := range b.cves {
		have[c] = true
	}
	res := MatchAsset(a, e.feeds.vulns, have, t0)
	var open []string
	for _, m := range slices.Concat(res.New, res.Existing) {
		if m.SoftwareID == b.software && have[m.CVE] {
			open = append(open, m.CVE)
		}
	}
	return open
}

// Class count: of the blocks the lists name, how many name a release that leaves a CVE of the block open. Before the target was
// chosen against the CVEs' ranges: 2 of 4 blocks (web-01 "1.31.6" left 13 of its 15 CVEs open, web-02 "1.31.6" left 1 of 2). After: 0 of 5.
func TestBlockTarget_Count_TargetsThatLeaveAListedCVEOpen(t *testing.T) {
	t.Parallel()
	e := blockTargetWorld(t)
	blocks := listedBlocks(t, e)
	wrong, open := 0, 0
	for _, b := range blocks {
		if left := stillOpen(e, b); len(left) > 0 {
			wrong++
			open += len(left)
			t.Logf("%s: %s %s leaves %d of %d CVEs open: %v", b.asset, b.software, b.version, len(left), len(b.cves), left)
		}
	}
	t.Logf("blocks whose release leaves a listed CVE open: %d of %d (%d CVEs)", wrong, len(blocks), open)
	if wrong != 0 {
		t.Errorf("%d of %d blocks name a release that leaves %d listed CVEs open", wrong, len(blocks), open)
	}
}

// The release a block names is the lowest one the data names that clears every CVE of the block; when none clears them all, the
// block splits, each part with a release that clears all of its own CVEs.
func TestBlockTarget_LowestReleaseThatClearsEveryCVE(t *testing.T) {
	t.Parallel()
	e := blockTargetWorld(t)
	type want struct {
		version string
		n       int
	}
	wants := map[string][]want{
		"web-01":  {{"1.31.9", 15}},               // not 1.31.6 (13 open) nor 1.30.7 (CVE-2026-90439 open)
		"web-02":  {{"1.30.7", 1}, {"1.31.6", 1}}, // no release clears both: two blocks
		"mail-01": {{"1.28.4", 2}},                // the highest fix already clears both
		"dns-01":  {{"1.26.3", 2}},
	}
	product := map[string]string{}
	for _, d := range blockDevices() {
		product[d.id] = productid.Key(d.vendor, d.product)
	}
	got := map[string][]want{}
	for _, b := range listedBlocks(t, e) {
		got[b.asset] = append(got[b.asset], want{b.version, len(b.cves)})
		if b.key != FixKey(product[b.asset], Fix{Kind: FixUpdate, Version: b.version}) {
			t.Errorf("%s: block key %q does not name its release %s", b.asset, b.key, b.version)
		}
	}
	for id, w := range wants {
		g := got[id]
		slices.SortFunc(g, func(a, b want) int { return strings.Compare(a.version, b.version) })
		if !slices.Equal(g, w) {
			t.Errorf("%s: blocks %v, want %v", id, g, w)
		}
	}
	// By device names the same releases as the report's ListedFixes
	cards, err := e.svc.ByDevice(t.Context(), ListFilter{Device: "web-01"}, Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(cards.Items) != 1 || len(cards.Items[0].Blocks) != 1 || cards.Items[0].Blocks[0].Fix.Version == nil ||
		*cards.Items[0].Blocks[0].Fix.Version != "1.31.9" || len(cards.Items[0].Blocks[0].Findings) != 15 {
		t.Fatalf("web-01 By device: %+v", cards.Items)
	}
	fx, err := e.svc.ByFix(t.Context(), ListFilter{}, Page{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range fx.Items {
		names = append(names, fmt.Sprintf("%s:%d", *c.Fix.Version, c.Findings))
	}
	slices.Sort(names)
	if w := []string{"1.26.3:2", "1.28.4:2", "1.30.7:1", "1.31.6:1", "1.31.9:15"}; !slices.Equal(names, w) {
		t.Errorf("By fix %v, want %v", names, w)
	}
	// handling a block from By device handles exactly its findings
	ids, err := e.svc.FixFindings(t.Context(), "web-01", "s-web-01", FixKey("f5|nginx", Fix{Kind: FixUpdate, Version: "1.31.9"}))
	if err != nil || len(ids) != 15 {
		t.Errorf("FixFindings of web-01's block: %d ids, %v", len(ids), err)
	}
}
