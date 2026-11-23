package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// identifyOld is the identification of an older catalogue: it did not know Apache HTTP Server (an item of it was a product of its
// own names) and had no release trains for Java and Node.js. The tests store lines under it, then start with this build's.
func identifyOld(it SoftwareItem, source string) (lineIdentity, string) {
	id, v := identify(it, source)
	switch id.productKey {
	case "apache|http server":
		id.productKey, id.line = productid.Key(it.Vendor, it.Product), ""
	case "oracle|java se", "node.js|node.js":
		id.line = ""
	}
	return id, v
}

// kevOf serves the embedded product pairs and one exploited CVE of Apache HTTP Server.
type kevOf struct{ EmbeddedKEV }

func (kevOf) CVEIndex(context.Context) (KEVIndex, error) {
	return func(keys []string) []string {
		if slices.Contains(keys, "apache|http server") {
			return []string{"CVE-2024-38475"}
		}
		return nil
	}, nil
}

// boxStart is one database that services of two builds start on, as a box updated in place.
type boxStart struct {
	t   *testing.T
	db  *store.DB
	now time.Time

	mu     sync.Mutex
	events []Event
}

func newBoxStart(t *testing.T) *boxStart {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
	return &boxStart{t: t, db: db, now: time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)}
}

// start is a start of a build: old is the older catalogue (identifyOld), else this build's.
func (b *boxStart) start(old bool) *Service {
	b.t.Helper()
	pub := PublisherFunc(func(_ context.Context, e Event) error {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.events = append(b.events, e)
		return nil
	})
	svc, err := New(Config{DB: b.db, Audit: audit.New(nil), Events: pub, KEV: kevOf{}, Clock: func() time.Time {
		b.now = b.now.Add(time.Second)
		return b.now
	}})
	if err != nil {
		b.t.Fatal(err)
	}
	if old {
		svc.ident, svc.catRev = identifyOld, "older-catalogue"
	}
	if err := svc.ReidentifyLines(b.t.Context()); err != nil { // the job's first run
		b.t.Fatal(err)
	}
	return svc
}

// taken returns the events published since the last call, as "name asset [cve]".
func (b *boxStart) taken() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, e := range b.events {
		switch d := e.Data.(type) {
		case AssetEvent:
			out = append(out, e.Name+" "+d.AssetID)
		case MatchEvent:
			out = append(out, e.Name+" "+d.AssetID+" "+d.CVE)
		}
	}
	b.events = nil
	slices.Sort(out)
	return out
}

// line is the product key, train, version and state of a device's line by id, and the line ids of a device by product key.
func (b *boxStart) line(id string) string {
	b.t.Helper()
	var key, train, version, state string
	if err := b.db.Reader().QueryRowContext(b.t.Context(), `SELECT product_key, line, ifnull(version, ''), state FROM inv_software WHERE id = ?`, id).
		Scan(&key, &train, &version, &state); err != nil {
		b.t.Fatalf("line %s: %v", id, err)
	}
	return fmt.Sprintf("%s/%s %s %s", key, train, version, state)
}

func (b *boxStart) lines(asset string) map[string]string {
	b.t.Helper()
	rows, err := b.db.Reader().QueryContext(b.t.Context(), `SELECT id, product_key, line FROM inv_software WHERE asset_id = ? AND state <> 'removed'`, asset)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, key, train string
		if err := rows.Scan(&id, &key, &train); err != nil {
			b.t.Fatal(err)
		}
		out[key+"/"+train] = id
	}
	return out
}

func (b *boxStart) count(q string, args ...any) int {
	b.t.Helper()
	var n int
	if err := b.db.Reader().QueryRowContext(b.t.Context(), q, args...).Scan(&n); err != nil {
		b.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// checks runs the self-check's inventory invariants and fails on any that counts.
func (b *boxStart) checks() {
	b.t.Helper()
	var invs []selfcheck.Invariant
	for _, inv := range selfcheck.Registered() {
		if strings.HasPrefix(inv.Name, "inventory.") {
			invs = append(invs, inv)
		}
	}
	for _, r := range selfcheck.Run(b.t.Context(), b.db.Reader(), invs) {
		if r.Failed() {
			b.t.Errorf("self-check %s: %d (%v)", r.Name, r.Count, r.Err)
		}
	}
}

// javaItem is a Java install as the agent names it (agent-intake reads the program name with the catalogue).
func javaItem(t *testing.T, display string) observe.Software {
	t.Helper()
	p, ok := productid.ResolveStored("Eclipse Adoptium", display, display, "")
	if !ok {
		t.Fatalf("no product for %q", display)
	}
	return observe.Software{Display: display, Vendor: p.Vendor, Product: p.Product, Version: p.Version, KevKeys: p.KEV, Confidence: 0.9}
}

// stored is what the older build stored of the test network: a server an agent and a scan read, with a person's version of what the
// scan read, and a device a person added with its software.
type stored struct {
	server, desk string
	java, apache string // line ids on the server
	javaShown    string // the train of the release the older line showed: the line keeps its id there
	node         string // line id on the desk
}

func storeUnderOld(t *testing.T, b *boxStart, svc *Service) stored {
	t.Helper()
	ctx := t.Context()
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.10")}
	if err := svc.ReplaceSoftware(ctx, hint, observe.Osquery, nil, []observe.Software{
		javaItem(t, "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)"), javaItem(t, "Eclipse Temurin JDK with Hotspot 8u452-b09 (x64)"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReplaceSoftware(ctx, hint, observe.Nmap, nil, []observe.Software{
		{Display: "Apache httpd 2.4.58", Vendor: "Apache", Product: "httpd", Version: "2.4.58", CPE: "cpe:/a:apache:http_server:2.4.58", Instance: "tcp/80", Confidence: 0.8},
	}); err != nil {
		t.Fatal(err)
	}
	var st stored
	if err := b.db.Reader().QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE ip = '192.0.2.10'`).Scan(&st.server); err != nil {
		t.Fatal(err)
	}
	l := b.lines(st.server)
	st.java, st.apache = l["oracle|java se/"], l["apache|httpd/"]
	if st.java == "" || st.apache == "" || len(l) != 2 {
		t.Fatalf("the older catalogue stored %v", l)
	}
	v := "2.4.62"
	if err := svc.EditSoftware(ctx, "person@example.com", st.server, st.apache, SoftwareEdit{Version: &v}); err != nil { // a person's version of the scan's line
		t.Fatal(err)
	}
	var shown string
	if err := b.db.Reader().QueryRowContext(ctx, `SELECT version FROM inv_software WHERE id = ?`, st.java).Scan(&shown); err != nil {
		t.Fatal(err)
	}
	st.javaShown = trainOf("oracle|java se", shown)
	r, err := svc.AddDevice(ctx, "person@example.com", AddInput{Vendor: "Node.js", Product: "Node.js", Version: "20.11.1", IP: "192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	st.desk = r.ID
	l = b.lines(st.desk)
	st.node = l["node.js|node.js/"]
	if st.node == "" || len(l) != 1 {
		t.Fatalf("the older catalogue stored %v", l)
	}
	return st
}

// A box updated to a build whose catalogue knows more: at start, every stored line is what this build's catalogue says of what its
// sources sent (the agent's, the scan's, a person's entry), with the line ids kept, and findings are told once per changed device.
// A second start changes nothing.
func TestReidentify_StoredLinesFollowTheCatalogueAfterAnUpdate(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	st := storeUnderOld(t, b, b.start(true))
	b.taken()

	b.start(false) // the update
	server := b.lines(st.server)
	if len(server) != 3 || server["oracle|java se/"+st.javaShown] != st.java || server["apache|http server/"] != st.apache {
		t.Fatalf("server lines after the update: %v (java %s on %s, apache %s)", server, st.java, st.javaShown, st.apache)
	}
	if got := b.line(server["oracle|java se/21"]); got != "oracle|java se/21 21.0.7 present" {
		t.Errorf("the agent's line: %s", got)
	}
	if got := b.line(server["oracle|java se/8"]); got != "oracle|java se/8 1.8.0_452 present" {
		t.Errorf("the agent's second install: %s", got)
	}
	if got := b.line(st.apache); got != "apache|http server/ 2.4.62 present" { // the person's version still holds, on the product
		t.Errorf("the scan's line: %s", got)
	}
	if got := b.line(st.node); got != "node.js|node.js/20 20.11.1 present" {
		t.Errorf("the person's entry: %s", got)
	}
	if n := b.count(`SELECT count(*) FROM inv_software_reading r JOIN inv_software s ON s.id = r.software_id WHERE s.asset_id = ? AND r.source = 'osquery' AND r.instance = ''`, st.server); n != 2 {
		t.Errorf("an install alone on its train needs no release in its instance: %d of 2 readings without", n)
	}
	want := []string{
		EventMatchChanged + " " + st.server + " CVE-2024-38475", // the key the scan's line gained: the device is matched again on it alone
		EventSoftwareChanged + " " + st.desk,
	}
	slices.Sort(want)
	if got := b.taken(); !slices.Equal(got, want) {
		t.Errorf("events: %v, want %v", got, want)
	}
	b.checks()
	if got := b.count(`SELECT count(*) FROM inv_software_event WHERE kind = 'identified_again'`); got != 3 {
		t.Errorf("%d lines record that they were identified again, want 3 (java, apache, node)", got)
	}
	var rev, target string
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT revision, target FROM inv_catalogue_pass`).Scan(&rev, &target); err != nil || rev != catalogueRevision() || target != "" {
		t.Fatalf("pass state %q %q %v", rev, target, err)
	}

	// a second start: the revision is the same, nothing is read or written
	history, audits := b.count(`SELECT count(*) FROM inv_software_event`), b.count(`SELECT count(*) FROM core_audit`)
	b.start(false)
	// and a pass forced over the same catalogue finds every line where it is
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE inv_catalogue_pass SET revision = ''`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	b.start(false)
	if got := b.taken(); len(got) != 0 {
		t.Errorf("a start with the same catalogue published %v", got)
	}
	if h, a := b.count(`SELECT count(*) FROM inv_software_event`), b.count(`SELECT count(*) FROM core_audit`); h != history || a != audits {
		t.Errorf("a start with the same catalogue wrote history %d → %d, audit %d → %d", history, h, audits, a)
	}
}

// A pass stopped after its first device (a restart, a crash) goes on from the next device: every device is changed once, and the
// result is the uninterrupted pass's.
func TestReidentify_AStoppedPassGoesOnWhereItWas(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	st := storeUnderOld(t, b, b.start(true))
	b.taken()

	svc, err := New(Config{DB: b.db, Audit: audit.New(nil), Clock: func() time.Time { return b.now }})
	if err != nil {
		t.Fatal(err)
	}
	if done, err := svc.reidentifyStep(t.Context(), 1, &passRun{}); err != nil || done { // one device, then the box stops
		t.Fatalf("first step: done %v, %v", done, err)
	}
	var rev, target, after string
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT revision, target, after FROM inv_catalogue_pass`).Scan(&rev, &target, &after); err != nil {
		t.Fatal(err)
	}
	first := min(st.server, st.desk)
	if rev != "older-catalogue" || target != catalogueRevision() || after != first {
		t.Fatalf("after a stop: revision %q target %q after %q, want the older revision, this build's target and %s", rev, target, after, first)
	}
	history := b.count(`SELECT count(*) FROM inv_software_event WHERE asset_id = ?`, first)

	b.start(false) // the restart
	if h := b.count(`SELECT count(*) FROM inv_software_event WHERE asset_id = ?`, first); h != history {
		t.Errorf("the device done before the stop was changed again: history %d → %d", history, h)
	}
	if got := b.line(st.node); got != "node.js|node.js/20 20.11.1 present" {
		t.Errorf("the person's entry: %s", got)
	}
	if got := b.line(st.apache); got != "apache|http server/ 2.4.62 present" {
		t.Errorf("the scan's line: %s", got)
	}
	b.checks()
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT revision, target, after FROM inv_catalogue_pass`).Scan(&rev, &target, &after); err != nil ||
		rev != catalogueRevision() || target != "" || after != "" {
		t.Fatalf("pass state %q %q %q %v", rev, target, after, err)
	}
}

// A reading that keeps no item (one an earlier build wrote) follows its line: it takes its line's train of its version under this
// build's catalogue, and stays on its line's product.
func TestReidentify_AReadingWithoutItsItemFollowsItsLine(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	st := storeUnderOld(t, b, b.start(true))
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE inv_software_reading SET item_vendor = NULL, item_product = NULL, item_version = NULL, item_kev = NULL, item_instance = NULL`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	b.start(false)
	server := b.lines(st.server)
	if server["oracle|java se/"+st.javaShown] != st.java || server["oracle|java se/8"] == "" || server["oracle|java se/21"] == "" || server["apache|httpd/"] != st.apache || len(server) != 3 {
		t.Fatalf("server lines: %v", server)
	}
	if got := b.line(st.node); got != "node.js|node.js/20 20.11.1 present" {
		t.Errorf("the person's entry: %s", got)
	}
	b.checks()
}

// The fixture network, stored by this build: a pass over the catalogue that stored it moves nothing.
func TestReidentify_TheCatalogueThatStoredTheLinesMovesNothing(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	lines := 0
	ids, err := devicesWithSoftware(t.Context(), r.db.Reader(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		sw, err := deviceSoftware(t.Context(), r.db.Reader(), id)
		if err != nil {
			t.Fatal(err)
		}
		lines += len(sw)
		if p := r.svc.planIdentities(sw); p.changes() {
			t.Errorf("device %s: renames %v, moves %+v", id, p.renames, p.moves)
		}
	}
	if lines == 0 {
		t.Fatal("no line")
	}
}

// Two lines of a device that trade places: one takes the identity the other leaves. Whatever the order of their ids, both are
// renamed in place (each keeps its id and history) and every reading stays with its install.
func TestReidentify_ALineTakesTheIdentityAnotherLeaves(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	byName := func(m map[string]string) identifier {
		return func(it SoftwareItem, source string) (lineIdentity, string) {
			id, v := identify(it, source)
			if k, ok := m[it.Product]; ok {
				id.productKey, id.line = k, ""
			}
			return id, v
		}
	}
	start := func(rev string, m map[string]string) *Service {
		svc, err := New(Config{DB: b.db, Audit: audit.New(nil), Clock: func() time.Time { b.now = b.now.Add(time.Second); return b.now }})
		if err != nil {
			t.Fatal(err)
		}
		svc.ident, svc.catRev = byName(m), rev
		if err := svc.ReidentifyLines(t.Context()); err != nil {
			t.Fatal(err)
		}
		return svc
	}
	svc := start("one", map[string]string{"Foo": "acme|one", "Bar": "acme|two"})
	type pair struct{ foo, bar string }
	var devices []pair
	for i := range 6 { // ids are random: six devices give both orders of the two lines
		hint := observe.AssetHint{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)})}
		if err := svc.ReplaceSoftware(t.Context(), hint, observe.Nmap, nil, []observe.Software{
			{Display: "Foo 1.0", Vendor: "Acme", Product: "Foo", Version: "1.0", Instance: "tcp/1", Confidence: 0.8},
			{Display: "Bar 2.0", Vendor: "Acme", Product: "Bar", Version: "2.0", Instance: "tcp/2", Confidence: 0.8},
		}); err != nil {
			t.Fatal(err)
		}
		var asset string
		if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_asset WHERE ip = ?`, hint.IP.String()).Scan(&asset); err != nil {
			t.Fatal(err)
		}
		l := b.lines(asset)
		devices = append(devices, pair{l["acme|one/"], l["acme|two/"]})
	}
	start("two", map[string]string{"Foo": "acme|three", "Bar": "acme|one"})
	for _, d := range devices {
		if got := b.line(d.foo); got != "acme|three/ 1.0 present" {
			t.Errorf("Foo's line %s: %s", d.foo, got)
		}
		if got := b.line(d.bar); got != "acme|one/ 2.0 present" {
			t.Errorf("Bar's line %s: %s", d.bar, got)
		}
	}
	if n := b.count(`SELECT count(*) FROM inv_software`); n != 12 {
		t.Errorf("%d lines, want the 12 there were", n)
	}
	b.checks()
}

// A device that cannot be identified again does not stop the pass: it is logged and skipped, the devices after it are identified
// again, the revision is not stored, and the next run identifies the failed device.
func TestReidentify_AFailingDeviceIsSkippedAndTriedAgain(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	st := storeUnderOld(t, b, b.start(true))
	failing := min(st.server, st.desk) // the first device of the pass
	exec := func(q string) {
		t.Helper()
		if err := b.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TRIGGER planted_failure BEFORE INSERT ON inv_software_event WHEN NEW.asset_id = '` + failing + `' BEGIN SELECT RAISE(ABORT, 'planted'); END`)

	b.start(false)
	if got := b.line(st.node); got != "node.js|node.js/20 20.11.1 present" && st.desk != failing {
		t.Errorf("the device after the failing one: %s", got)
	}
	if got := b.line(st.apache); got != "apache|http server/ 2.4.62 present" && st.server != failing {
		t.Errorf("the device after the failing one: %s", got)
	}
	if n := b.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND product_key IN ('apache|httpd', 'node.js|node.js') AND line = ''`, failing); n != 1 {
		t.Errorf("the failing device changed: %d of its old lines left", n)
	}
	var rev, target, after string
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT revision, target, after FROM inv_catalogue_pass`).Scan(&rev, &target, &after); err != nil ||
		rev != "older-catalogue" || target != catalogueRevision() || after != "" {
		t.Fatalf("after a failure: revision %q target %q after %q (%v), want the pass open from the first device", rev, target, after, err)
	}

	exec(`DROP TRIGGER planted_failure`)
	b.start(false) // the next run
	if got := b.line(st.node); got != "node.js|node.js/20 20.11.1 present" {
		t.Errorf("the person's entry: %s", got)
	}
	if got := b.line(st.apache); got != "apache|http server/ 2.4.62 present" {
		t.Errorf("the scan's line: %s", got)
	}
	b.checks()
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT revision, target, after FROM inv_catalogue_pass`).Scan(&rev, &target, &after); err != nil ||
		rev != catalogueRevision() || target != "" || after != "" {
		t.Fatalf("pass state %q %q %q %v", rev, target, after, err)
	}
}
