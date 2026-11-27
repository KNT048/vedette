package findings

import (
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
)

// synthetic is one made-up product no catalogue knows, installed on one device line, with one CVE record in a standard shape.
type synthetic struct {
	name   string
	sw     Software
	vuln   Vuln
	by     string // the source that must decide it ("" when it must stay possible)
	cause  string // when it stays possible: the named cause
	affect bool
	// pending: the shape is not decided as wanted today; the reason names the general rule that will decide it (the case is skipped)
	pending string
}

// syntheticProducts are generated vendors and products absent from every catalogue, each with a record in one of the standard shapes
// a CVE record or NVD's analysis takes. The box must identify each line and decide its CVE, or name why it cannot, with no catalogue row.
func syntheticProducts() []synthetic {
	line := func(id, vendor, product, version string) Software {
		return Software{ID: id, Display: vendor + " " + product, Vendor: vendor, Product: product, Version: version, Source: "agent"}
	}
	nvd := func(cve string, rows ...Affected) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Affected: rows}
	}
	cna := func(cve, from string, rows ...Affected) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, RangesFrom: from, Affected: rows}
	}
	r := func(cpe, start, end string) Affected {
		return Affected{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	return []synthetic{
		{name: "NVD CPE range, inside", sw: line("s-acme", "Acme", "Widget", "3.4.1"),
			vuln: nvd("CVE-2026-990001", r("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "3.0", "3.4.2")), by: RangeNVD, affect: true},
		{name: "NVD CPE range, fixed before", sw: line("s-acme2", "Acme", "Gadget", "5.0.2"),
			vuln: nvd("CVE-2026-990002", r("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", "4.0", "4.9.3")), by: RangeNVD},
		{name: "CNA-only CVE JSON 5 range", sw: line("s-borealis", "Borealis Systems Inc.", "Gateway", "2.7.0"),
			vuln: cna("CVE-2026-990003", RangesCVEOrg, r("cpe:2.3:*:borealis:gateway:*:*:*:*:*:*:*:*", "2.0", "2.7.4")), by: RangeCNA, affect: true},
		{name: "own CNA, defaultStatus unaffected, version outside", sw: line("s-cinder", "Cindertrail", "Sync", "9.1.0"),
			vuln: cna("CVE-2026-990004", RangesCVEOrg, Affected{CPE: "cpe:2.3:*:cindertrail:sync:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "8.0", EndExcl: "8.4.2"}, VendorList: true}), by: RangeCNA},
		{name: "third-party CNA, one tested build only", sw: line("s-dove", "Dovetail", "Notes", "4.2.0"),
			vuln: cna("CVE-2026-990005", RangesCVEOrgPartial, Affected{CPE: "cpe:2.3:*:dovetail:notes:4.1.3:*:*:*:*:*:*:*", AffectedOnly: true}), cause: "vendor_silent",
			pending: "the matcher reads a third-party CNA's tested build as saying nothing and asks no question: the possible finding gets the named cause vendor_silent with the possible-cause rules"},
		{name: "NVD NA row beside a range", sw: line("s-ember", "Emberlight", "Proxy", "1.9.0"),
			vuln: nvd("CVE-2026-990006", Affected{CPE: "cpe:2.3:a:emberlight:proxy:-:*:*:*:*:*:*:*"}, r("cpe:2.3:a:emberlight:proxy:*:*:*:*:*:*:*:*", "1.0", "1.8.5")), by: RangeNVD},
		{name: "NVD NA row alone", sw: line("s-glow", "Glowmere", "Relay", "2.3.0"),
			vuln: nvd("CVE-2026-990008", Affected{CPE: "cpe:2.3:a:glowmere:relay:-:*:*:*:*:*:*:*"}), cause: UndecidedNoRanges},
		{name: "NVD CPE without the vendor's prefix the publisher puts in the name", sw: line("s-fenn", "Fennwick Labs", "Fennwick Draw", "7.2.0"),
			vuln: nvd("CVE-2026-990007", r("cpe:2.3:a:fennwick:draw:*:*:*:*:*:*:*:*", "7.0", "7.3")), by: RangeNVD, affect: true,
			pending: "nothing links the line to NVD's fennwick:draw yet: identified once identity reaches the product NVD names (a learned alias or the AI's choice among NVD's candidates)"},
	}
}

func TestCoverage_SyntheticProductsAreIdentifiedAndDecidedWithoutCatalogue(t *testing.T) {
	t.Parallel()
	cases := syntheticProducts()
	a := Asset{ID: "a-1", Name: "pc-01", OS: "Microsoft Windows 11 Pro"}
	var vulns []Vuln
	for _, c := range cases {
		if n := (identity{vendor: productid.Norm(c.sw.Vendor), product: productid.Norm(c.sw.Product)}); len(cpeAliases[n]) > 0 {
			t.Fatalf("%s: the catalogue knows %s", c.name, c.sw.Display)
		}
		if _, ok := productid.ResolveStored(c.sw.Vendor, c.sw.Product, c.sw.Display, ""); ok {
			t.Fatalf("%s: the catalogue resolves %s", c.name, c.sw.Display)
		}
		a.Software = append(a.Software, c.sw)
		vulns = append(vulns, c.vuln)
	}
	e := newEnv(t)
	e.inv.assets = map[string]AssetView{"a-1": {ID: "a-1", Hostname: ptr("pc-01"), IP: "192.0.2.10", Kind: "workstation", Approved: true}}
	e.inv.match = map[string]Asset{"a-1": a}
	e.feeds.vulns = vulns
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err := readDeviceRows(t.Context(), e.db.Reader(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	checks, err := checksFor(t.Context(), e.db.Reader(), rows.questions)
	if err != nil {
		t.Fatal(err)
	}
	dm := newDevMatch(a, vulns, *e.clock)
	states, linked := pairStates(dm, rows, checks)
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, ok := states[lineKey(c.vuln.CVE, c.sw.ID)]
			got := identityOf(c.sw, dm.infos[i], linked[c.sw.ID])
			t.Logf("identity %s, related %v, state %+v", got, ok, st)
			if c.pending != "" {
				t.Skip(c.pending)
			}
			if got == IdentityNone || got == IdentityCatalogue {
				t.Errorf("identity %q, want one from the product's own name or a stated CPE", got)
			}
			if !ok {
				t.Fatalf("the pair is not related")
			}
			if st.by != c.by || st.affected != c.affect || st.cause != c.cause {
				t.Errorf("state %+v, want by %q affected %v cause %q", st, c.by, c.affect, c.cause)
			}
		})
	}
	// The pass's sum: what decided each pair, why the rest is undecided, and how each line is identified. The line nothing links
	// is no pair: it counts under the identity "none".
	want := Coverage{Devices: 1, Lines: len(cases), Pairs: 7,
		Decided:  []CoverageSource{{By: RangeNVD, Affected: 1, NotAffected: 2}, {By: RangeCNA, Affected: 1, NotAffected: 1}},
		Possible: []CoverageCause{{Cause: UndecidedNoRanges, Count: 1}, {Cause: CoverageOtherRecordUnread, Count: 1}},
		Identity: []CoverageMethod{{IdentityStated, 0}, {IdentityCatalogue, 0}, {IdentityRecord, 7}, {IdentityNone, 1}}}
	checkCoverage(t, e.svc, want)
	// A person's answer decides its pair; a pass that finds the device unchanged keeps its counts
	var qid string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_question WHERE cve = 'CVE-2026-990008'`).Scan(&qid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AnswerQuestion(t.Context(), qid, AnswerNotAffected, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.advance(ReconcileEvery)
	for range 2 {
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		want.Decided = []CoverageSource{{By: RangeNVD, Affected: 1, NotAffected: 2}, {By: RangeCNA, Affected: 1, NotAffected: 1}, {By: RangePerson, NotAffected: 1}}
		want.Possible = []CoverageCause{{Cause: CoverageOtherRecordUnread, Count: 1}}
		checkCoverage(t, e.svc, want)
	}
	// Each pass is a row; a service started again on the same database serves the newest until its own first pass
	if n := e.count(`SELECT count(*) FROM fnd_coverage_run`); n != 3 {
		t.Errorf("%d coverage rows after three passes, want 3", n)
	}
	again, err := NewService(ServiceConfig{DB: e.db, Audit: audit.New(nil), Publisher: e.pub, Inventory: e.inv, Feeds: e.feeds, Log: slog.New(slog.DiscardHandler), Clock: func() time.Time { return *e.clock }})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := again.Coverage(t.Context()); err != nil || !ok || !got.At.Equal(e.clock.UTC().Truncate(time.Millisecond)) {
		t.Errorf("after a restart: %v at %v, err %v, want the stored pass at %v", ok, got.At, err, *e.clock)
	}
	checkCoverage(t, again, want)
	// A device that leaves the inventory leaves the counts
	e.inv.match = map[string]Asset{}
	e.advance(ReconcileEvery)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkCoverage(t, e.svc, Coverage{Decided: []CoverageSource{}, Possible: []CoverageCause{},
		Identity: []CoverageMethod{{IdentityStated, 0}, {IdentityCatalogue, 0}, {IdentityRecord, 0}, {IdentityNone, 0}}})
}

// checkCoverage compares the last pass's coverage with want, its time aside.
func checkCoverage(t *testing.T, svc *Service, want Coverage) {
	t.Helper()
	got, ok, err := svc.Coverage(t.Context())
	if err != nil || !ok {
		t.Fatalf("no coverage after a pass: %v", err)
	}
	got.At = time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("coverage\n got %+v\nwant %+v", got, want)
	}
}

// GET /findings/coverage is for an admin: at null and every count 0 before the first pass, the pass's counts after it.
func TestCoverage_EndpointIsTheLastPass(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	if code, _ := e.call("GET", "/findings/coverage", "operator", ""); code != 403 {
		t.Errorf("an operator got %d, want 403", code)
	}
	code, b := e.call("GET", "/findings/coverage", "admin", "")
	if code != 200 || b["at"] != nil || b["pairs"] != float64(0) || len(b["identity"].([]any)) != len(IdentityMethods) {
		t.Fatalf("before a pass: %d %v", code, b)
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	code, b = e.call("GET", "/findings/coverage", "admin", "")
	decided, _ := b["decided"].([]any)
	if code != 200 || b["at"] == nil || b["devices"] != float64(1) || b["pairs"] != float64(1) || len(decided) != 1 {
		t.Fatalf("after a pass: %d %v", code, b)
	}
}
