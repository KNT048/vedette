package inventory

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/pkgrel"
)

// TestClassImpact measures the correction rule over every software line and every OS line of a set of devices (INV-52): for each
// line, the version the device shows under the rule before this change and under the rule now, and how many lines differ, grouped by
// kind (app, os, firmware) and by the source the line is read from before and after.
//
// It runs on testdata/class_fixture.json, a synthetic set of devices (no real data). When VEDETTE_INV_DB names a Vedette database
// file, it runs on that file too (opened read-only); the counts are printed with t.Log and nothing is written anywhere. Run:
//
//	VEDETTE_INV_DB=/path/to/copy.db go test ./modules/inventory -run TestClassImpact -v
//
// On a database made before first_seen existed, a reading counts as new when its seen_at is after the correction: an over-estimate.

//go:embed testdata/class_fixture.json
var classFixture []byte

type classDevice struct {
	id       string
	software []EffectiveSoftware
	first    map[string]string // software row id -> when a source first reported it ("" unknown)
	os       []classOS
	want     int // fixture only: how many lines are expected to change
}

type classOS struct {
	obs   obs
	first string
}

func fixtureDevices(t *testing.T) []classDevice {
	t.Helper()
	var f struct {
		Devices []struct {
			ID, Scenario, Vendor, Product string
			ExpectChanged                 int `json:"expect_changed"`
			Software                      []struct {
				Source, Version, Pkg, Seen string
				FirstSeen                  string `json:"first_seen"`
				CorrectsSource             string `json:"corrects_source"`
				CorrectsVersion            string `json:"corrects_version"`
			}
			OS []struct {
				Source, Value, Seen string
				FirstSeen           string `json:"first_seen"`
			}
		}
	}
	if err := json.Unmarshal(classFixture, &f); err != nil {
		t.Fatal(err)
	}
	var out []classDevice
	for _, d := range f.Devices {
		cd := classDevice{id: d.ID + " " + d.Scenario, first: map[string]string{}, want: d.ExpectChanged}
		for i, s := range d.Software {
			e := EffectiveSoftware{ID: fmt.Sprintf("%s-s%d", d.ID, i), Vendor: d.Vendor, Product: d.Product, Display: d.Product, Version: s.Version, PkgVersion: s.Pkg,
				Source: s.Source, SeenAt: s.Seen}
			e.key = rowKeyOf(s.Source, d.Vendor, d.Product, s.Version)
			if s.CorrectsSource != "" {
				e.corrects = rowKeyOf(s.CorrectsSource, d.Vendor, d.Product, s.CorrectsVersion)
			}
			cd.first[e.ID] = s.FirstSeen
			cd.software = append(cd.software, e)
		}
		for i, o := range d.OS {
			cd.os = append(cd.os, classOS{obs: obs{id: fmt.Sprintf("%s-o%d", d.ID, i), field: "os", value: o.Value, source: o.Source, confidence: 0.9, seenAt: o.Seen}, first: o.FirstSeen})
		}
		out = append(out, cd)
	}
	return out
}

func rowKeyOf(source, vendor, product, version string) string {
	return source + "\x1f" + strings.ToLower(vendor) + "\x1f" + strings.ToLower(product) + "\x1f" + version
}

func databaseDevices(t *testing.T, path string) []classDevice {
	t.Helper()
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	hasFirst := func(table string) bool {
		rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == "first_seen" {
				return true
			}
		}
		return false
	}
	swFirst, osFirst := "s.seen_at", "o.seen_at"
	if hasFirst("inv_software") {
		swFirst = "ifnull(s.first_seen, '')"
	}
	if hasFirst("inv_observation") {
		osFirst = "ifnull(o.first_seen, '')"
	}
	devs := map[string]*classDevice{}
	get := func(id string) *classDevice {
		if devs[id] == nil {
			devs[id] = &classDevice{id: id, first: map[string]string{}}
		}
		return devs[id]
	}
	//nolint:gosec // G202: swFirst is one of two constant column expressions
	rows, err := db.QueryContext(ctx, `SELECT s.asset_id, s.id, s.vendor, s.product, s.display, ifnull(s.version, ''), ifnull(s.pkg_version, ''), ifnull(s.cpe, ''), s.source,
		ifnull(s.set_by, ''), s.seen_at, ifnull(s.corrects, ''), `+rowKey("s")+`, `+swFirst+`
		FROM inv_software s WHERE s.not_installed = 0 AND NOT `+hiddenGuess+` AND NOT `+notInstalledSW+` ORDER BY s.seen_at DESC, s.id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var asset, first string
		var e EffectiveSoftware
		if err := rows.Scan(&asset, &e.ID, &e.Vendor, &e.Product, &e.Display, &e.Version, &e.PkgVersion, &e.CPE, &e.Source, &e.SetBy, &e.SeenAt, &e.corrects, &e.key, &first); err != nil {
			t.Fatal(err)
		}
		d := get(asset)
		d.software = append(d.software, e)
		d.first[e.ID] = first
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	orows, err := db.QueryContext(ctx, `SELECT o.asset_id, o.id, o.value, o.source, o.confidence, o.seen_at, `+osFirst+` FROM inv_observation o WHERE o.field = 'os'`)
	if err != nil {
		t.Fatal(err)
	}
	for orows.Next() {
		var asset string
		var c classOS
		c.obs.field = "os"
		if err := orows.Scan(&asset, &c.obs.id, &c.obs.value, &c.obs.source, &c.obs.confidence, &c.obs.seenAt, &c.first); err != nil {
			t.Fatal(err)
		}
		d := get(asset)
		d.os = append(d.os, c)
	}
	if err := orows.Close(); err != nil {
		t.Fatal(err)
	}
	out := make([]classDevice, 0, len(devs))
	for _, d := range devs {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b classDevice) int { return strings.Compare(a.id, b.id) })
	return out
}

// classKinds is app, os or firmware: the catalog marks a whole operating system or firmware product (declared.go).
func classKind(vendor, product string) string {
	p, ok := osProducts[osKey(vendor, product)]
	switch {
	case !ok:
		return "app"
	case p.model != "":
		return "firmware"
	}
	return "os"
}

// oldTop is the line's reading under the rule before INV-52: the strongest source wins (agent, a person's entry, SNMP, a scan), an
// entry that corrects an agent's row ranks with the agent, the row an entry corrects is not a candidate, and nothing ever lapses.
func oldTop(rows []EffectiveSoftware) (EffectiveSoftware, int) {
	corrected := map[int]bool{}
	agentCorrected := map[int]bool{}
	for c := range rows {
		if rows[c].corrects == "" {
			continue
		}
		for r := range rows {
			if r != c && rows[r].key == rows[c].corrects && rows[r].Source != "manual" {
				corrected[r] = true
				if rows[r].Source == "agent" {
					agentCorrected[c] = true
				}
			}
		}
	}
	rank := func(i int) int {
		if agentCorrected[i] {
			return softwareRank("agent")
		}
		return softwareRank(rows[i].Source)
	}
	var cand []int
	for i := range rows {
		if !corrected[i] {
			cand = append(cand, i)
		}
	}
	slices.SortStableFunc(cand, func(a, b int) int { return rank(b) - rank(a) })
	lines := 0 // every row of the strongest rank was a line of its own
	for _, i := range cand {
		if rank(i) == rank(cand[0]) {
			lines++
		}
	}
	return rows[cand[0]], lines
}

type classTally struct{ lines, changed, changedRelease, shownBefore, shownNow int }

// classSets splits a device's rows into software identities (the name or the CPE application), as effectiveOf does.
func classSets(rows []EffectiveSoftware) [][]EffectiveSoftware {
	parent := make([]int, len(rows))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			i = parent[i]
		}
		return i
	}
	seen := map[string]int{}
	for i, r := range rows {
		for _, k := range []string{"n" + strings.ToLower(r.Vendor) + "\x1f" + strings.ToLower(r.Product), "c" + cpeApp(r.CPE)} {
			if k == "c" {
				continue
			}
			if j, ok := seen[k]; ok {
				parent[find(i)] = find(j)
			} else {
				seen[k] = i
			}
		}
	}
	by := map[int][]EffectiveSoftware{}
	var order []int
	for i, r := range rows {
		root := find(i)
		if _, ok := by[root]; !ok {
			order = append(order, root)
		}
		by[root] = append(by[root], r)
	}
	var out [][]EffectiveSoftware
	for _, root := range order {
		out = append(out, by[root])
	}
	return out
}

func TestClassImpact(t *testing.T) {
	t.Run("fixture", func(t *testing.T) { measureClass(t, fixtureDevices(t), true) })
	t.Run("database", func(t *testing.T) {
		path := os.Getenv("VEDETTE_INV_DB")
		if path == "" {
			t.Skip("VEDETTE_INV_DB is not set")
		}
		measureClass(t, databaseDevices(t, path), false)
	})
}

func measureClass(t *testing.T, devices []classDevice, check bool) {
	t.Helper()
	tally := map[string]*classTally{}
	add := func(group string, changed, sameRelease bool, shownBefore, shownNow int) {
		c := tally[group]
		if c == nil {
			c = &classTally{}
			tally[group] = c
		}
		c.lines++
		c.shownBefore += shownBefore
		c.shownNow += shownNow
		if changed {
			c.changed++
			if !sameRelease {
				c.changedRelease++
			}
		}
	}
	for _, d := range devices {
		got := 0
		for _, class := range classSets(d.software) {
			old, oldLines := oldTop(class)
			var corrections, readings []swFacts
			for _, r := range class {
				f := swFacts{id: r.ID, display: r.Display, vendor: r.Vendor, product: r.Product, cpe: r.CPE, version: r.Version, pkg: r.PkgVersion, source: r.Source}
				if r.corrects != "" {
					f.setAt = r.SeenAt
					corrections = append(corrections, f)
				} else if r.Source != "manual" {
					f.setAt = d.first[r.ID]
					readings = append(readings, f)
				}
			}
			lapsed := lapsingReadings(corrections, readings)
			var rest []EffectiveSoftware
			for _, r := range class {
				if _, gone := lapsed[r.ID]; !gone {
					rest = append(rest, r)
				}
			}
			nowAll := effectiveOf(rest)
			now := nowAll[0]
			changed := old.Version != now.Version || old.PkgVersion != now.PkgVersion
			if changed {
				got++
			}
			why := "rank"
			if len(lapsed) > 0 {
				why = "lapse"
			}
			if !changed {
				why = "-"
			}
			add(fmt.Sprintf("%-8s %-7s -> %-7s %s", classKind(old.Vendor, old.Product), old.Source, now.Source, why), changed, pkgrel.Same(old.Version, old.PkgVersion, now.Version, now.PkgVersion), oldLines, len(nowAll))
		}
		if len(d.os) > 0 {
			var all, rest []obs
			var person *classOS
			for i := range d.os {
				all = append(all, d.os[i].obs)
				if d.os[i].obs.source == "manual" {
					person = &d.os[i]
				}
			}
			old := winners(slices.Clone(all))["os"]
			lapsedOS := false
			for _, o := range d.os {
				if person != nil && o.obs.source != "manual" && o.first != "" && o.first > person.obs.seenAt && osNewer(o.obs.value, person.obs.value) {
					lapsedOS = true
				}
			}
			for _, o := range d.os {
				if !lapsedOS || o.obs.source != "manual" {
					rest = append(rest, o.obs)
				}
			}
			now := winners(rest)["os"]
			changed := old.value != now.value
			if changed {
				got++
			}
			why := "-"
			if changed {
				why = "lapse"
			}
			add(fmt.Sprintf("%-8s %-7s -> %-7s %s", "os-field", old.source, now.source, why), changed, sameOS(old.value, now.value), 1, 1)
		}
		if check && got != d.want {
			t.Errorf("%s: %d lines change, want %d", d.id, got, d.want)
		}
	}
	var groups []string
	var total classTally
	for g, c := range tally {
		groups = append(groups, g)
		total.lines += c.lines
		total.changed += c.changed
		total.changedRelease += c.changedRelease
		total.shownBefore += c.shownBefore
		total.shownNow += c.shownNow
	}
	sort.Strings(groups)
	t.Logf("%d devices, %d software (and OS fields), %d change their version (%d of them to another release, the rest the same release written another way); lines shown before %d, now %d",
		len(devices), total.lines, total.changed, total.changedRelease, total.shownBefore, total.shownNow)
	for _, g := range groups {
		c := tally[g]
		t.Logf("  %-34s software %5d  changed %5d  another release %5d  shown before %5d  now %5d", g, c.lines, c.changed, c.changedRelease, c.shownBefore, c.shownNow)
	}
}
