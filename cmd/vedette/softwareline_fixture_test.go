package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/inventory"
)

// The same device says the same software at the same version wherever it is read: the device page, the CSV export and the device
// data an assistant gets (the Ask context); the Devices list, which carries no lines, counts as many as the page shows. The fixture is an anonymised test-network inventory replayed through the
// write paths (modules/inventory/testdata/software_lines.json, the same file the inventory's own line tests replay). For every device
// the test builds, per surface, the set of "<name> <version>" the surface says the device runs, and counts the devices where two
// surfaces disagree.
func TestSoftwareLine_Fixture_SameVersionOnEverySurface(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	devices, host := replaySoftwareLines(t, s)

	type runs map[string]bool // "<name> <version>" a surface says the device runs
	text := func(display string, version any) string {
		v, _ := version.(string)
		return strings.TrimSpace(display + " " + v)
	}
	// installed says whether a software row of the API is one the device runs: not a line a person said is not installed.
	installed := func(sw any) bool {
		if at(sw, "not_installed") == true {
			return false
		}
		return at(sw, "correction", "not_installed") != true
	}
	surfaces := map[string]map[string]runs{"page": {}, "export": {}, "assistant": {}}
	add := func(surface, device, s string) {
		if surfaces[surface][device] == nil {
			surfaces[surface][device] = runs{}
		}
		surfaces[surface][device][s] = true
	}

	code, list := s.do("GET", "/inventory/devices", "viewer", "")
	if code != 200 {
		t.Fatalf("list: %d %v", code, list)
	}
	// the list carries no lines, only how many the device has: the page's count
	listCount := map[string]int{}
	for _, d := range at(list, "items").([]any) {
		id, _ := at(d, "id").(string)
		listCount[id] = int(at(d, "software_count").(float64))
	}
	pageCount := map[string]int{}
	// the device page's source rows come from the server, through the real wiring
	if code, v := s.do("GET", "/inventory/devices/"+devices[0]+"/sources", "viewer", ""); code != 200 || len(at(v, "rows").([]any)) != 3 {
		t.Fatalf("sources: %d %v", code, v)
	}
	for _, id := range devices {
		code, page := s.do("GET", "/inventory/devices/"+id, "viewer", "")
		if code != 200 {
			t.Fatalf("page %s: %d %v", id, code, page)
		}
		pageCount[id] = len(at(page, "asset", "software").([]any))
		for _, sw := range at(page, "asset", "software").([]any) {
			if installed(sw) {
				add("page", id, text(at(sw, "display").(string), at(sw, "version")))
			}
		}
	}
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, server.Prefix+"/inventory/export.csv", nil)
	r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "viewer", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body)
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(w.Body.Bytes(), []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]string{}
	for id, h := range host {
		byHost[h] = id
	}
	col := slices.Index(rows[0], "software")
	cells := map[string]string{}
	for _, r := range rows[1:] {
		cells[byHost[r[0]]] = r[col]
	}
	// A software name may hold "; " itself (an nmap OS guess: "J2320 or MX5-T router; or EX2200 ... switch"), so the cell is not split:
	// each line the page shows is taken out of it; what is left is what the export adds. A line a person said is not installed is
	// marked so in the export and is not something the device runs.
	for id, cell := range cells {
		rest := "; " + cell + "; "
		for s := range surfaces["page"][id] {
			if strings.Contains(rest, "; "+s+"; ") {
				add("export", id, s)
				rest = strings.Replace(rest, "; "+s+"; ", "; ", 1)
			}
		}
		for _, sw := range strings.Split(rest, "; ") {
			if sw != "" && !strings.HasSuffix(sw, inventory.NotInstalledMark) {
				add("export", id, sw)
			}
		}
	}
	assets, err := aiAsk{inv: s.d.Inventory}.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range assets {
		for _, sw := range a.Software {
			add("assistant", a.ID, sw)
		}
	}

	differ, lines := 0, 0
	for _, id := range devices {
		want := surfaces["page"][id]
		lines += len(want)
		var bad []string
		if listCount[id] != pageCount[id] {
			bad = append(bad, fmt.Sprintf("list counts %d lines, the page shows %d", listCount[id], pageCount[id]))
		}
		for _, name := range []string{"export", "assistant"} {
			got := surfaces[name][id]
			for s := range want {
				if !got[s] {
					bad = append(bad, name+" lacks "+s)
				}
			}
			for s := range got {
				if !want[s] {
					bad = append(bad, name+" adds "+s)
				}
			}
		}
		if len(bad) > 0 {
			differ++
			slices.Sort(bad)
			t.Logf("%s: %s", id, strings.Join(bad[:min(len(bad), 6)], "; "))
		}
	}
	t.Logf("devices whose software or version differs between the list, the page, the export and the assistant's data: %d of %d (%d lines on the page)", differ, len(devices), lines)
	if differ != 0 || lines < 1000 {
		t.Fatalf("%d devices differ (want 0); %d lines (want the fixture's lines)", differ, lines)
	}
}

// replaySoftwareLines replays the anonymised test-network inventory (modules/inventory/testdata/software_lines.json, the file the
// inventory's own line tests replay) through the write paths of the stack: each device, every source's software list, then the
// people's corrections. It returns the devices in the fixture's order and the host name each was given.
func replaySoftwareLines(t *testing.T, s *stack) ([]string, map[string]string) {
	t.Helper()
	ctx := t.Context()
	raw, err := os.ReadFile("../../modules/inventory/testdata/software_lines.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Devices []struct{ ID string }
		Rows    []struct {
			Asset, Source, Vendor, Product, Display, Version, CPE string
			PkgVersion                                            string `json:"pkg_version"`
			PkgSource                                             string `json:"pkg_source"`
			Packaged                                              bool
			NotInstalled                                          bool `json:"not_installed"`
			Corrects                                              *struct{ Source, Version string }
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	host := map[string]string{} // the export names a device by its host name
	for i, d := range f.Devices {
		host[d.ID] = fmt.Sprintf("host-%02d", i+1)
		s.exec(`INSERT INTO inv_asset (id, hostname, kind, origin, approved, first_seen, last_seen) VALUES (?, ?, 'unknown', 'discovered', 1, '2026-11-20T08:00:00.000Z', '2026-11-20T08:00:00.000Z')`, d.ID, host[d.ID])
		// the host name column follows its observation, as every software write folds the device's columns again
		s.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, first_seen) VALUES (?, ?, 'hostname', ?, 'passive', 0.8, '2026-11-20T08:00:00.000Z', '2026-11-20T08:00:00.000Z')`, "o-"+d.ID, d.ID, host[d.ID])
	}
	agent := func(src string) bool { return src == "osquery" || src == "wazuh" || src == "box" }
	lists := map[[2]string][]inventory.SoftwareItem{}
	var order [][2]string
	for _, r := range f.Rows {
		if r.Source == "manual" {
			continue
		}
		it := inventory.SoftwareItem{Display: r.Display, Vendor: r.Vendor, Product: r.Product, Version: r.Version, CPE: r.CPE, Confidence: 0.9, Packaged: r.Packaged,
			PkgVersion: r.PkgVersion, PkgSource: r.PkgSource, Guess: r.Source == "nmap" && r.Version == "" && strings.HasPrefix(r.CPE, "cpe:/o:")}
		if agent(r.Source) { // named as today's agent names it (the inventory line tests do the same)
			if p, ok := productid.ResolveStored(r.Vendor, r.Product, r.Display, r.CPE); ok && p.ID != "" {
				it.Vendor, it.Product, it.KevKeys = p.Vendor, p.Product, p.KEV
				if p.VersionNotOwn {
					it.Version = p.Version
				}
			}
		}
		k := [2]string{r.Asset, r.Source}
		if _, ok := lists[k]; !ok {
			order = append(order, k)
		}
		lists[k] = append(lists[k], it)
	}
	for _, k := range order {
		if err := s.d.Inventory.UpsertSoftware(ctx, k[0], lists[k], k[1]); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	for _, r := range f.Rows { // a person's version or "not installed", on the line the corrected reading is on
		if r.Source != "manual" {
			continue
		}
		var line string
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT s.id FROM inv_software s JOIN inv_software_reading g ON g.software_id = s.id
			WHERE s.asset_id = ? AND g.source = ? AND ifnull(g.version, '') = ? LIMIT 1`, r.Asset, r.Corrects.Source, r.Corrects.Version).Scan(&line); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		e := inventory.SoftwareEdit{NotInstalled: r.NotInstalled}
		if !r.NotInstalled {
			v, p := r.Version, r.PkgVersion
			e.Version, e.PkgVersion = &v, &p
		}
		if err := s.d.Inventory.EditSoftware(ctx, "person@example.com", r.Asset, line, e); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
	}

	devices := make([]string, len(f.Devices))
	for i, d := range f.Devices {
		devices[i] = d.ID
	}
	return devices, host
}
