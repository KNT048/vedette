package findings

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// By device filtered by one CVE or by a set of devices answers exactly on a network with more devices than one page holds: the CVE
// filter keeps only that CVE's rows (not a longer id the search would also match), its totals count every device, and the devices
// filter returns the cards of exactly those devices, wherever they fall in the unfiltered order. Ignored devices stay out unless
// ignored=true, as without the filters.
func TestModelAPI_DevicesFilteredByCVEOrDevicesBeyondOnePage(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	const n = PageMax + 20
	e.inv.mu.Lock()
	e.inv.assets = map[string]AssetView{}
	e.inv.lines = map[string]Line{}
	for i := range n {
		id := fmt.Sprintf("a-%03d", i)
		e.inv.assets[id] = AssetView{ID: id, Name: fmt.Sprintf("host-%03d", i), IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Kind: "server", Approved: true}
		e.inv.lines["s-"+id] = Line{ID: "s-" + id, AssetID: id, Display: "OpenSSH", ProductKey: "openbsd|openssh", Version: "9.6p1"}
	}
	e.inv.ignored = map[string]bool{"a-000": true}
	e.inv.mu.Unlock()
	ctx := t.Context()
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		for i := range n {
			id := fmt.Sprintf("a-%03d", i)
			cves := []string{"CVE-2026-10010"} // the longer id a search for CVE-2026-1001 also matches
			if i%2 == 0 {
				cves = append(cves, "CVE-2026-1001")
			}
			for _, c := range cves {
				f := Finding{ID: "f-" + id + "-" + c, AssetID: id, CVE: c, SoftwareID: "s-" + id, Fix: Fix{Kind: FixUpdate, Version: "10.6"}, Urgency: 2,
					Verified: VerifiedNo, Basis: DetectBannerVersion, FirstSeen: t0.Add(-48 * time.Hour)}
				f.FixKey = FixKey("openbsd|openssh", f.Fix)
				if err := writeTestFinding(ctx, tx, f); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// one CVE: 60 devices have it, one of them ignored
	_, b := e.call("GET", "/findings/devices?cve=CVE-2026-1001&limit=100", "viewer", "")
	if b["total"].(float64) != n/2-1 || b["findings"].(float64) != n/2-1 {
		t.Fatalf("cve filter: total %v findings %v, want %d", b["total"], b["findings"], n/2-1)
	}
	for _, c := range b["items"].([]any) {
		for _, bl := range c.(map[string]any)["blocks"].([]any) {
			for _, f := range bl.(map[string]any)["findings"].([]any) {
				if cve := f.(map[string]any)["cve"]; cve != "CVE-2026-1001" {
					t.Fatalf("cve filter returned %v", cve)
				}
			}
		}
	}
	_, b = e.call("GET", "/findings/devices?cve=CVE-2026-10010&limit=100", "viewer", "")
	if b["total"].(float64) != n-1 || len(b["items"].([]any)) != PageMax {
		t.Fatalf("cve filter on every device: total %v, %d items", b["total"], len(b["items"].([]any)))
	}

	// a set of devices: the last ones in the unfiltered order, one of them ignored
	var ids []string
	for i := n - 30; i < n; i++ {
		ids = append(ids, fmt.Sprintf("a-%03d", i))
	}
	ids = append(ids, "a-000")
	_, b = e.call("GET", "/findings/devices?limit=100&devices="+strings.Join(ids, ","), "viewer", "")
	got := map[string]float64{}
	for _, c := range b["items"].([]any) {
		m := c.(map[string]any)
		got[m["device"].(map[string]any)["id"].(string)] = m["findings"].(float64)
	}
	if len(got) != 30 || b["total"].(float64) != 30 {
		t.Fatalf("devices filter: %d cards, total %v, want 30", len(got), b["total"])
	}
	for i := n - 30; i < n; i++ {
		id := fmt.Sprintf("a-%03d", i)
		want := 1.0
		if i%2 == 0 {
			want = 2
		}
		if got[id] != want {
			t.Errorf("%s: %v findings, want %v", id, got[id], want)
		}
	}
	if _, ok := got["a-000"]; ok {
		t.Error("an ignored device is listed without ignored=true")
	}
	_, b = e.call("GET", "/findings/devices?ignored=true&devices=a-000,a-001", "viewer", "")
	if b["total"].(float64) != 1 {
		t.Errorf("ignored tab with devices: total %v, want 1", b["total"])
	}

	// more ids than one page, an empty id: bad_filter
	var many []string
	for i := range PageMax + 1 {
		many = append(many, fmt.Sprintf("a-%03d", i))
	}
	if code, b := e.call("GET", "/findings/devices?devices="+strings.Join(many, ","), "viewer", ""); code != 400 || errCode(b) != "bad_filter" {
		t.Errorf("101 devices: %d %v", code, b)
	}
	if code, _ := e.call("GET", "/findings/devices?devices=a-001,,a-002", "viewer", ""); code != 400 {
		t.Errorf("an empty id: %d, want 400", code)
	}
	if code, _ := e.call("GET", "/findings/devices?cve=not-a-cve", "viewer", ""); code != 400 {
		t.Errorf("a bad CVE: %d, want 400", code)
	}
}
