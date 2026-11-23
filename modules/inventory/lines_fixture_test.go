package inventory

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// testdata/software_lines.json is the software of an anonymised test network as the old model stored it: one row per source and
// version, a person's correction as a manual row naming the reading it corrected. The tests below replay it through the write paths
// of the new model and count what the old model got wrong (the class this model fixes): several rows for one software on one device,
// and software ids that change when a version moves.

//go:embed testdata/software_lines.json
var softwareLinesFixture []byte

type fixtureRow struct {
	Asset, Source, Vendor, Product, Display, Version, CPE string
	PkgVersion                                            string `json:"pkg_version"`
	PkgSource                                             string `json:"pkg_source"`
	Packaged                                              bool
	NotInstalled                                          bool `json:"not_installed"`
	Corrects                                              *struct{ Source, Version string }
}

type replayed struct {
	svc  *Service
	db   *store.DB
	now  *time.Time
	rows []fixtureRow
}

func (r *replayed) tick() { *r.now = r.now.Add(time.Minute) }

// replayFixture stores the fixture's devices, sends each device's list of each source through UpsertSoftware, then sets the
// corrections as a person would (EditSoftware).
func replayFixture(t *testing.T) *replayed {
	t.Helper()
	var f struct {
		Devices []struct{ ID string }
		Rows    []fixtureRow
	}
	if err := json.Unmarshal(softwareLinesFixture, &f); err != nil {
		t.Fatal(err)
	}
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
	now := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	r := &replayed{db: db, now: &now, rows: f.Rows}
	svc, err := New(Config{DB: db, Audit: audit.New(nil), Clock: func() time.Time { return *r.now }})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	ctx := t.Context()
	for _, d := range f.Devices {
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, first_seen, last_seen) VALUES (?, 'unknown', 'discovered', 1, ?, ?)`, d.ID, svc.now(), svc.now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	lists := map[[2]string][]SoftwareItem{}
	var order [][2]string
	for _, row := range f.Rows {
		if row.Source == sourceManual {
			continue
		}
		k := [2]string{row.Asset, row.Source}
		if _, ok := lists[k]; !ok {
			order = append(order, k)
		}
		lists[k] = append(lists[k], row.item())
	}
	for _, k := range order {
		r.tick()
		if err := svc.UpsertSoftware(ctx, k[0], lists[k], k[1]); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	for _, row := range f.Rows {
		if row.Source != sourceManual {
			continue
		}
		r.tick()
		id := r.lineOfRow(t, row)
		e := SoftwareEdit{NotInstalled: row.NotInstalled}
		if !row.NotInstalled {
			v, p := row.Version, row.PkgVersion
			e.Version, e.PkgVersion = &v, &p
		}
		if err := svc.EditSoftware(ctx, "person@example.com", row.Asset, id, e); err != nil {
			t.Fatalf("%+v: %v", row, err)
		}
	}
	return r
}

// item is the row as its source sends it today. The fixture comes from an agent that did not yet name programs with core/productid
// (it sent "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)" at 21.0.7.6 as a product of its own): an agent row is named here as
// today's agent names it, with the catalogue's product, its match keys and the release its name states.
func (row fixtureRow) item() SoftwareItem {
	it := SoftwareItem{Display: row.Display, Vendor: row.Vendor, Product: row.Product, Version: row.Version, CPE: row.CPE, Confidence: 0.9, Packaged: row.Packaged,
		PkgVersion: row.PkgVersion, PkgSource: row.PkgSource, Guess: row.Source == "nmap" && row.Version == "" && strings.HasPrefix(row.CPE, "cpe:/o:")}
	if agentSource(row.Source) {
		if p, ok := productid.ResolveStored(row.Vendor, row.Product, row.Display, row.CPE); ok && p.ID != "" {
			it.Vendor, it.Product, it.KevKeys = p.Vendor, p.Product, p.KEV
			if p.VersionNotOwn {
				it.Version = p.Version
			}
		}
	}
	return it
}

// lineOfRow is the line a fixture row landed on.
func (r *replayed) lineOfRow(t *testing.T, row fixtureRow) string {
	t.Helper()
	id, _ := identify(row.item(), row.Source)
	var lineID string
	if err := r.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_software WHERE asset_id = ? AND product_key = ? AND line = ?`, row.Asset, id.productKey, id.line).Scan(&lineID); err != nil {
		t.Fatalf("no line for %+v (%s, %q): %v", row, id.productKey, id.line, err)
	}
	return lineID
}

func (r *replayed) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := r.db.Reader().QueryRowContext(t.Context(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// The class this model fixes, counted on the fixture: before, a device carried several rows of one software (one per source and
// version, a person's correction one more); after, every (device, product, train) is one line, and each line's stored value is what
// the resolver says. The products one source reports twice on one device that the catalogue does not split into trains are listed:
// they are one line with two readings, and the candidates for a train rule.
func TestSoftwareLines_Fixture_OneLinePerProductAndTrain(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	ctx := t.Context()

	before := map[string]int{}
	for _, row := range r.rows {
		before[row.Asset+" "+productid.Key(row.Vendor, row.Product)]++
	}
	groups := 0
	for _, n := range before {
		if n > 1 {
			groups++
		}
	}
	after := r.count(t, `SELECT count(*) FROM (SELECT 1 FROM inv_software GROUP BY asset_id, product_key, line HAVING count(*) > 1)`)
	t.Logf("(device, product) groups with more than one row: before %d; (device, product, train) groups with more than one line after: %d", groups, after)
	if groups != 15 || after != 0 {
		t.Fatalf("before %d groups (want the fixture's 15), after %d (want 0)", groups, after)
	}
	// every old group of rows is one line now, unless the catalogue splits it into trains
	for k, n := range before {
		if n < 2 {
			continue
		}
		var lines []string
		for _, row := range r.rows {
			if row.Asset+" "+productid.Key(row.Vendor, row.Product) == k && !slices.Contains(lines, r.lineOfRow(t, row)) {
				lines = append(lines, r.lineOfRow(t, row))
			}
		}
		if len(lines) != 1 {
			t.Errorf("%s: %d lines, want one", k, len(lines))
		}
	}

	rows, err := r.db.Reader().QueryContext(ctx, `SELECT s.display, r.source, count(*) FROM inv_software s JOIN inv_software_reading r ON r.software_id = s.id
		WHERE r.source <> 'manual' AND r.instance <> 'os_guess' GROUP BY s.id, r.source HAVING count(*) > 1 ORDER BY s.display`)
	if err != nil {
		t.Fatal(err)
	}
	var twice []string
	for rows.Next() {
		var display, source string
		var n int
		if err := rows.Scan(&display, &source, &n); err != nil {
			t.Fatal(err)
		}
		twice = append(twice, fmt.Sprintf("%s (%s, %d readings)", display, source, n))
	}
	_ = rows.Close()
	t.Logf("products one source reports twice on one device, without a train rule (%d):\n  %s", len(twice), strings.Join(twice, "\n  "))

	var invs []selfcheck.Invariant
	for _, inv := range selfcheck.Registered() {
		if strings.HasPrefix(inv.Name, "inventory.") {
			invs = append(invs, inv)
		}
	}
	for _, res := range selfcheck.Run(ctx, r.db.Reader(), invs) {
		if res.Failed() {
			t.Errorf("%s: %d (%v)", res.Name, res.Count, res.Err)
		}
	}
	assertResolved(t, r)
}

// assertResolved checks every line with the selfcheck's own code (inventory.line_value_is_the_resolvers and
// inventory.line_is_the_train_of_its_readings), naming each line that breaks a rule.
func assertResolved(t *testing.T, r *replayed) {
	t.Helper()
	lines := 0
	if err := eachStoredLine(t.Context(), r.db.Reader(), func(l storedLine) {
		lines++
		for _, broken := range []string{l.trainBreak(), l.resolveBreak()} {
			if broken != "" {
				t.Error(broken)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if lines == 0 {
		t.Fatal("no software line to check")
	}
}

// The line check reads the lines a page at a time: a page of one line reads every line with every reading, as one page of all does.
func TestSoftwareLines_Fixture_CheckReadsEveryLineAcrossPages(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	read := func(size int) (lines, readings int, all string) {
		t.Helper()
		var b strings.Builder
		if err := eachStoredLineBy(t.Context(), r.db.Reader(), size, func(l storedLine) {
			lines++
			readings += len(l.readings)
			fmt.Fprintf(&b, "%s %d %s|", l.id, len(l.readings), l.resolveBreak()+l.trainBreak())
		}); err != nil {
			t.Fatal(err)
		}
		return lines, readings, b.String()
	}
	lines, readings, all := read(storedLinesPage)
	if lines != r.count(t, `SELECT count(*) FROM inv_software`) || readings != r.count(t, `SELECT count(*) FROM inv_software_reading`) {
		t.Fatalf("read %d lines and %d readings, the tables hold %d and %d", lines, readings, r.count(t, `SELECT count(*) FROM inv_software`),
			r.count(t, `SELECT count(*) FROM inv_software_reading`))
	}
	if l1, r1, all1 := read(1); l1 != lines || r1 != readings || all1 != all {
		t.Fatalf("pages of one line: %d lines, %d readings; one page: %d, %d", l1, r1, lines, readings)
	}
}

// The cases named in the fixture: OpenSSH read by the agent, a scan and a person (who gave the release the agent reads), and the Linux kernel at two versions with a
// person's "not installed" on each, are one line each; Oracle Java 8 and Temurin 21 on one host are two lines of one product.
func TestSoftwareLines_Fixture_NamedCases(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	lines := func(asset, key string) []string {
		t.Helper()
		rows, err := r.db.Reader().QueryContext(t.Context(), `SELECT line || ':' || ifnull(version, '') || ':' || source || ':' || state || ':' ||
			(SELECT count(*) FROM inv_software_reading g WHERE g.software_id = s.id) FROM inv_software s WHERE asset_id = ? AND product_key = ? ORDER BY line`, asset, key)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatal(err)
			}
			out = append(out, l)
		}
		return out
	}
	// line : version : source : state : readings
	for _, c := range []struct {
		asset, key string
		want       []string
	}{
		{"a-vxnn74laban2c2lvkeiox43ifi", "openbsd|openssh", []string{":10.2p1:osquery:present:3"}},                                     // the agent, the scan and the person's entry, which the agent confirms
		{"a-wd3vuu2d47qhjeguk4nqrnlzmm", "openbsd|openssh", []string{":10.2p1:osquery:present:2"}},                                     // the package and the banner
		{"a-ot3k5ec3apwaoms7ica4dn4xem", "linux|kernel", []string{":6.12.117:osquery:not_installed:2"}},                                // two kernels, "not installed"
		{"a-vhfl735qwfyal6aeac32adngsy", "oracle|java se", []string{"21:21.0.7:osquery:present:1", "8:8.0.4910.10:osquery:present:1"}}, // two trains
	} {
		if got := lines(c.asset, c.key); !slices.Equal(got, c.want) {
			t.Errorf("%s %s: %v, want %v", c.asset, c.key, got, c.want)
		}
	}
}

// A version move keeps the software's id: every line's id still resolves after each source reads a newer release, so a finding
// that names a software id never dangles (the old model gave the row a new id, as its version was part of its key). Updating Java 21
// leaves Java 8 as it was, and the history says what moved.
func TestSoftwareLines_Fixture_VersionMoveKeepsIDs(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	ctx := t.Context()
	ids := map[string]string{} // id -> asset|product_key|line
	rows, err := r.db.Reader().QueryContext(ctx, `SELECT id, asset_id || '|' || product_key || '|' || line FROM inv_software WHERE state <> 'removed'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, k string
		if err := rows.Scan(&id, &k); err != nil {
			t.Fatal(err)
		}
		ids[id] = k
	}
	_ = rows.Close()
	versioned := 0 // rows whose id the old model derived from their version
	lists := map[[2]string][]SoftwareItem{}
	for _, row := range r.rows {
		if row.Source == sourceManual {
			continue
		}
		it := row.item()
		if it.Version != "" && !it.Guess {
			versioned++
			it.Version += ".1" // a newer release of the same train
			if it.PkgVersion != "" {
				it.PkgVersion += ".1"
			}
		}
		k := [2]string{row.Asset, row.Source}
		lists[k] = append(lists[k], it)
	}
	for k, items := range lists {
		r.tick()
		if err := r.svc.UpsertSoftware(ctx, k[0], items, k[1]); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	dangling := 0
	for id := range ids {
		if r.count(t, `SELECT count(*) FROM inv_software WHERE id = ? AND state = 'present'`, id) != 1 {
			dangling++
		}
	}
	moved := r.count(t, `SELECT count(DISTINCT software_id) FROM inv_software_event WHERE kind = 'version_changed'`)
	t.Logf("software ids after every source read a newer release: %d of %d resolve (%d dangling); the old model gave %d rows a new id; %d lines moved",
		len(ids)-dangling, len(ids), dangling, versioned, moved)
	if dangling != 0 || moved == 0 {
		t.Fatalf("%d ids dangle, %d lines moved", dangling, moved)
	}
	assertResolved(t, r)

	// Java 21 alone is updated: Java 8 keeps its version and its history
	java := func(line string) (id, version string) {
		t.Helper()
		if err := r.db.Reader().QueryRowContext(ctx, `SELECT id, version FROM inv_software WHERE asset_id = 'a-vhfl735qwfyal6aeac32adngsy' AND product_key = 'oracle|java se' AND line = ?`, line).
			Scan(&id, &version); err != nil {
			t.Fatal(err)
		}
		return id, version
	}
	id8, v8 := java("8")
	id21, _ := java("21")
	k := [2]string{"a-vhfl735qwfyal6aeac32adngsy", "osquery"}
	items := lists[k]
	for i, it := range items {
		if strings.Contains(it.Display, "Temurin") { // the agent names the update as it names the program (the release its name states)
			items[i].Display, items[i].Version = "Eclipse Temurin JDK with Hotspot 21.0.9+10 (x64)", "21.0.9"
		}
	}
	events8 := r.count(t, `SELECT count(*) FROM inv_software_event WHERE software_id = ?`, id8)
	r.tick()
	if err := r.svc.UpsertSoftware(ctx, k[0], items, k[1]); err != nil {
		t.Fatal(err)
	}
	if id, v := java("8"); id != id8 || v != v8 || r.count(t, `SELECT count(*) FROM inv_software_event WHERE software_id = ?`, id8) != events8 {
		t.Fatalf("Java 8 moved: %s %s", id, v)
	}
	if id, v := java("21"); id != id21 || v != "21.0.9" {
		t.Fatalf("Java 21: %s %s, want the same line at 21.0.9", id, v)
	}
	if r.count(t, `SELECT count(*) FROM inv_software_event WHERE software_id = ? AND kind = 'version_changed' AND to_version = '21.0.9'`, id21) != 1 {
		t.Fatal("the history of Java 21 does not say it moved to 21.0.9")
	}
}
