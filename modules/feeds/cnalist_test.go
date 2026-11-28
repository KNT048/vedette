package feeds

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// cnaListOf is a CNA list in the CVE Program's published form (CNAsList.json) with the given entries: short name, organization
// name, scope text and types; every other field of the real file is there but read by nothing.
func cnaListOf(t *testing.T, entries ...[4]string) []byte {
	t.Helper()
	var out []map[string]any
	for _, e := range entries {
		out = append(out, map[string]any{
			"shortName": e[0], "cnaID": "CNA-2026-0001", "organizationName": e[1], "scope": e[2],
			"contact":            []any{map[string]any{"email": []any{map[string]any{"label": "Email", "emailAddr": "psirt@example.com"}}}},
			"securityAdvisories": map[string]any{"advisories": []any{}},
			"CNA":                map[string]any{"isRoot": false, "type": strings.Split(e[3], ","), "roles": []any{map[string]any{"role": "CNA"}}},
			"country":            "USA",
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// orgsOf is what readRanges reads of a list: the organization of each CNA that may be a vendor.
func orgsOf(rows []cnaRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		if r.Vendor {
			out[r.Short] = r.Org
		}
	}
	return out
}

// The CNA list says which organization each CNA is. A record's CNA is the vendor's own when its organization name and the vendor the
// entry names (or the row's CPE vendor) are one name once case, punctuation, a leading "The", a part in parentheses and the trailing
// legal-form words of a company are set aside: the CNA "zz" of "Zenith Widgets, Inc." is the vendor "Zenith Widgets", which its short
// name alone does not say. A CNA the list types only as a researcher, CERT, bug bounty or hosting service, or whose scope takes the
// reports no other CNA covers (a coordinator), is never the vendor by its name. A short name two CNAs share says nothing. Without the
// list, the rules of before stand.
func TestOwnCNA_TheCNAListNamesTheOrganization(t *testing.T) {
	t.Parallel()
	rows, err := parseCNAList(strings.NewReader(string(cnaListOf(t,
		[4]string{"zz", "Zenith Widgets, Inc.", "Zenith Widgets products only.", "Vendor"},
		[4]string{"orbit", "The Orbit Group S.A.", "All Orbit products.", "Vendor,Open Source"},
		[4]string{"hx", "Helix Robotics AB (HXR)", "Helix issues only.", "Vendor"},
		[4]string{"pj", "Quill Project", "Quill and its libraries.", "Open Source"},
		[4]string{"labx", "Labx Security Research", "Vulnerabilities discovered by Labx that are not in another CNA’s scope.", "Researcher"},
		[4]string{"kite", "Kite Corporation", "All Kite products, as well as vulnerabilities in third-party software discovered by Kite that are not covered by the scope of another CNA.", "Vendor,Researcher"},
		[4]string{"natcert", "National CERT", "Vulnerabilities reported to National CERT.", "CERT"},
		[4]string{"Dup", "Dupont Tools", "Dupont products.", "Vendor"},
		[4]string{"DUP", "Duplex Systems", "Duplex products.", "Vendor"},
	))), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Errorf("list holds %d short names, want 7 (a short name two CNAs share is left out)", len(rows))
	}
	list := orgsOf(rows)
	names := productVendors(nil)
	for _, c := range []struct {
		assigner, vendor string
		want             bool
	}{
		{"zz", "Zenith Widgets", true},            // the organization without its legal form
		{"zz", "Zenith Widgets Inc", true},        //
		{"ZZ", "zenith widgets", true},            // case of either name
		{"zz", "zenithwidgets", true},             // a vendor stored normalised
		{"zz", "zenith_widgets", true},            // a CPE vendor
		{"zz", "Zenith", false},                   // a shorter name is another name
		{"zz", "Zenith Widgets Labs", false},      //
		{"orbit", "Orbit Group", true},            // a leading "The" and "S.A."
		{"orbit", "The Orbit Group", true},        //
		{"orbit", "theorbitgroupsa", true},        // stored normalised
		{"hx", "Helix Robotics", true},            // the part in parentheses and "AB"
		{"hx", "helixroboticsab", true},           //
		{"pj", "Quill Project", true},             // an open-source project
		{"labx", "Labx Security Research", false}, // a researcher CNA is never the vendor by its organization name
		{"kite", "Kite", true},                    // its short name is the vendor: the rule of before
		{"kite", "Kite Corporation", true},        // by the rule of before too (company words)
		{"natcert", "National CERT", false},       // a CERT
		{"dup", "Dupont Tools", false},            // a short name two CNAs share
		{"zz", "n/a", false},                      // an entry that names no vendor
		{"nobody", "Zenith Widgets", false},       // a CNA the list does not hold
		{"", "Zenith Widgets", false},             //
	} {
		if got := ownCNAIn(names, c.assigner, c.vendor, list[strings.ToLower(c.assigner)]); got != c.want {
			t.Errorf("ownCNA(%q, %q) = %v, want %v", c.assigner, c.vendor, got, c.want)
		}
	}
	// a coordinator's organization name is never the vendor, even where it equals the entry's vendor
	coordinator, err := parseCNAList(strings.NewReader(string(cnaListOf(t,
		[4]string{"kitecna", "Kite Corporation", "All Kite products and vulnerabilities discovered by Kite that are not within another CNA's scope.", "Vendor,Researcher"},
	))), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if ownCNAIn(names, "kitecna", "Kite Corporation", orgsOf(coordinator)["kitecna"]) {
		t.Error("a CNA whose scope takes the reports of no other CNA was read as the vendor by its organization name")
	}
	// without the list (missing, stale): the rules of before
	if ownCNAIn(names, "zz", "Zenith Widgets", "") || !ownCNAIn(names, "zz", "ZZ Inc", "") {
		t.Error("without a CNA list the short-name rule must stand alone")
	}
}

// The list is untrusted input: over the byte cap, not a JSON array, or holding too few usable entries to be the CVE Program's list,
// it is refused whole (the list kept before stays). An entry without a short name or organization, or with one over its bound, is
// passed over; nothing but the short name, the organization and whether it may be a vendor is kept (no contact).
func TestParseCNAList_RefusesWhatIsNotTheList(t *testing.T) {
	t.Parallel()
	good := cnaListOf(t, [4]string{"zz", "Zenith Widgets, Inc.", "Zenith products.", "Vendor"})
	if _, err := parseCNAList(strings.NewReader(string(good)), 16); err == nil {
		t.Error("a list over the byte cap was read")
	}
	for name, body := range map[string]string{
		"not json":     "<html>",
		"an object":    `{"shortName":"zz"}`,
		"empty":        `[]`,
		"no usable":    `[{"shortName":"","organizationName":"X"},{"shortName":"y","organizationName":""}]`,
		"trailing":     string(good) + `[]`,
		"a long short": `[{"shortName":"` + strings.Repeat("a", 65) + `","organizationName":"X"}]`,
	} {
		if _, err := parseCNAList(strings.NewReader(body), 1<<20); err == nil {
			t.Errorf("%s: read as a CNA list", name)
		}
	}
	l, err := parseCNAList(strings.NewReader(string(cnaListOf(t,
		[4]string{"zz", "Zenith Widgets, Inc.", "Zenith products.", "Vendor"},
		[4]string{"", "Nameless", "x", "Vendor"},
		[4]string{"long", strings.Repeat("o", 201), "x", "Vendor"},
	))), 1<<20)
	if err != nil || len(l) != 1 {
		t.Fatalf("list %v %v, want the one usable entry", l, err)
	}
	if want := (cnaRow{Short: "zz", Org: "Zenith Widgets, Inc.", Vendor: true}); l[0] != want {
		t.Errorf("entry %+v, want %+v", l[0], want)
	}
}

// asRead is a parsed record's ranges as a reader of the stored rows sees them (trustRow, without a CNA list): what the conversion
// stores keeps the record's word, the reader weighs it by who wrote it.
func asRead(rec CVERecord) CVERecord {
	rec.Ranges = slices.Clone(rec.Ranges)
	for i := range rec.Ranges {
		trustRow(&rec.Ranges[i], rec.Assigner, "")
	}
	return rec
}
