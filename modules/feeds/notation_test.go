package feeds

import (
	"slices"
	"testing"
)

// Versions written in a notation other than CVE JSON 5's fields: GitHub's advisory comparators in "version", the product's name in
// front of the version, a list of per-train fixes after lessThan. Each is read into the rows the fields would give; anything the
// grammar does not cover keeps the product unusable (skipped), as before.
func TestParseCVERecord_RecordNotation(t *testing.T) {
	t.Parallel()
	const u, k = DefaultUnaffected, DefaultUnknown
	for _, c := range []struct {
		name, affected string
		want           []span
		skipped        int
	}{
		// GitHub's advisory grammar (vulnerable_version_range): "=", "<", "<=", ">", ">=", a comma joins two clauses (AND)
		{"= is one version", `{"vendor":"acme","product":"ledger","versions":[{"version":"= 8.9.6.1","status":"affected"}]}`,
			[]span{{si: "8.9.6.1", ei: "8.9.6.1", def: k}}, 0},
		{"< is below a fix", `{"vendor":"acme","product":"ledger","versions":[{"version":"< 8.9.6.4","status":"affected"}]}`,
			[]span{{ee: "8.9.6.4", def: k}}, 0},
		{">= and < joined by a comma", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 2.0, < 2.3.1","status":"affected"}]}`,
			[]span{{si: "2.0", ee: "2.3.1", def: k}}, 0},
		{"<= is up to a release", `{"vendor":"acme","product":"ledger","versions":[{"version":"<= 0.6.0","status":"affected"}]}`,
			[]span{{ei: "0.6.0", def: k}}, 0},
		{"> starts after a release", `{"vendor":"acme","product":"ledger","versions":[{"version":"> 3.0.0, < 3.90.0","status":"affected"}]}`,
			[]span{{se: "3.0.0", ee: "3.90.0", def: k}}, 0},
		{">= alone is every later version", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 1.2.0","status":"affected"}]}`,
			[]span{{si: "1.2.0", def: k}}, 0},
		{"clauses without blanks or comma, upper bound first", `{"vendor":"acme","product":"ledger","versions":[{"version":">=4.16.0 <4.16.1","status":"affected"},{"version":"<5.2, >=5.0","status":"affected"}]}`,
			[]span{{si: "4.16.0", ee: "4.16.1", def: k}, {si: "5.0", ee: "5.2", def: k}}, 0},
		{"two ranges of one product", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 5.43.0, < 5.121.0","status":"affected"},{"version":">= 6.0.0, < 6.15.0","status":"affected"}]}`,
			[]span{{si: "5.43.0", ee: "5.121.0", def: k}, {si: "6.0.0", ee: "6.15.0", def: k}}, 0},

		// the product's own name in front of the version
		{"product name and comparators", `{"vendor":"acme","product":"Ledger","versions":[{"version":"ledger  >= 7.0.0, < 7.12.0","status":"affected"}]}`,
			[]span{{si: "7.0.0", ee: "7.12.0", def: k}}, 0},
		{"product name joined by a hyphen", `{"vendor":"acme","product":"Ledger","defaultStatus":"unaffected","versions":[{"version":"ledger-1.1.0","lessThan":"ledger-1.1.0h","status":"affected"},{"version":"Ledger-3.0.0","status":"affected"}]}`,
			[]span{{si: "3.0.0", ei: "3.0.0", def: k}}, 0},
		{"product name after unspecified", `{"vendor":"acme","product":"Ledger OS","versions":[{"version":"unspecified","lessThan":"Ledger OS 12.3","status":"affected","versionType":"custom"}]}`,
			[]span{{ee: "12.3", def: k}}, 0},
		{"vendor and product name", `{"vendor":"Acme","product":"Ledger","versions":[{"version":"Acme Ledger <1.10.11","status":"affected"}]}`,
			[]span{{ee: "1.10.11", def: k}}, 0},
		{"an npm package's scope", `{"vendor":"acme","product":"ledger","versions":[{"version":"ledger <= 0.6.0","status":"affected"},{"version":"@ledgerjs/ledger < 0.8.12","status":"affected"}]}`,
			[]span{{ei: "0.6.0", def: k}, {ee: "0.8.12", def: k}}, 0},
		{"a release with a package revision after the product's name", `{"vendor":"acme","product":"Ledger","versions":[{"version":"ledger-9.3.1-2.1","status":"affected"}]}`,
			[]span{{si: "9.3.1-2.1", ei: "9.3.1-2.1", def: k}}, 0},
		{"product name at a change", `{"vendor":"acme","product":"Ledger","versions":[{"version":"ledger-1.0","lessThan":"ledger-2.0","status":"affected","changes":[{"at":"ledger-2.0","status":"unaffected"}]}]}`,
			[]span{{si: "1.0", ee: "2.0", fixed: "2.0", def: k}}, 0},

		// a list of fixes after lessThan, one per release train
		{"one fix per train", `{"vendor":"acme","product":"stream","defaultStatus":"unaffected","versions":[{"version":"1.15.0","lessThan":"1.20.4,2.0.2,2.1.2,2.2.1","status":"affected","versionType":"semver"}]}`,
			[]span{{si: "1.15.0", ee: "1.20.4", def: u}, {si: "1.21", ee: "2.0.2", def: u}, {si: "2.1", ee: "2.1.2", def: u}, {si: "2.2", ee: "2.2.1", def: u}}, 0},
		{"fixes on date-numbered trains", `{"vendor":"acme","product":"stream","defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"2025.11.7, 2026.1.3","status":"affected"}]}`,
			[]span{{ee: "2025.11.7", def: u}, {si: "2025.12", ee: "2026.1.3", def: u}}, 0},
		{"last affected release per train", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThanOrEqual":"1.43.6, 1.44.3","status":"affected"}]}`,
			[]span{{ei: "1.43.6", def: k}, {si: "1.44", ei: "1.44.3", def: k}}, 0},
		{"a fix that is its train's first release", `{"vendor":"acme","product":"stream","defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"1.43.9, 1.45.4, 1.46.0","status":"affected"}]}`,
			[]span{{ee: "1.43.9", def: u}, {si: "1.44", ee: "1.45.4", def: u}}, 0},
		{"a last affected release that is its train's first", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThanOrEqual":"1.9.5, 1.10.0","status":"affected"}]}`,
			[]span{{ei: "1.9.5", def: k}, {si: "1.10.0", ei: "1.10.0", def: k}}, 0},

		// what the grammar does not cover keeps the product unusable
		{"a list of one train (another component's numbers)", `{"vendor":"acme","product":"Acme Runtime","versions":[{"version":"10.0.0","lessThan":"10.0.111, 10.0.400","status":"affected","versionType":"custom"}]}`, nil, 1},
		{"a list of one train, sorted apart", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThan":"1.20.4, 2.0.2, 1.20.9","status":"affected"}]}`, nil, 1},
		{"a list newest first (two products' numbers)", `{"vendor":"acme","product":"Assist","versions":[{"version":"0","lessThanOrEqual":"3.11.4, 3.2.0","status":"affected"}]}`, nil, 1},
		{"a list newest first", `{"vendor":"acme","product":"stream","defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"1.46.0, 1.45.4, 1.43.9","status":"affected"}]}`, nil, 1},
		{"a list out of train order", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThan":"7.14.2, 7.12.14, 8.4.2","status":"affected"}]}`, nil, 1},
		{"a list with a patch-level item", `{"vendor":"acme","product":"stream","defaultStatus":"unaffected","versions":[{"version":"0","lessThanOrEqual":"2.4.9, 2.4.8-p5, 2.4.7-p10","status":"affected"}]}`, nil, 1},
		{"a list of mixed lengths", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThan":"1.20.4, 2.0","status":"affected"}]}`, nil, 1},
		{"a list with a trailing comma", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThan":"01.00.0400,","status":"affected"}]}`, nil, 1},
		{"a list starting above its first fix", `{"vendor":"acme","product":"stream","versions":[{"version":"2.0.0","lessThan":"1.20.4, 2.0.2","status":"affected"}]}`, nil, 1},
		{"a list with a change at its end", `{"vendor":"acme","product":"stream","versions":[{"version":"0","lessThan":"1.20.4, 2.0.2","status":"affected","changes":[{"at":"1.20.4","status":"unaffected"}]}]}`, nil, 1},
		{"a comma item that is no clause", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 5.1.0, 5.21.5","status":"affected"}]}`, nil, 1},
		{"or", `{"vendor":"acme","product":"ledger","versions":[{"version":"< 1.0 || >= 2.0","status":"affected"}]}`, nil, 1},
		{"a version before its comparator", `{"vendor":"acme","product":"ledger","versions":[{"version":"12.2 <= 13.0","status":"affected"}]}`, nil, 1},
		{"two lower bounds", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 1.0, > 2.0","status":"affected"}]}`, nil, 1},
		{"= with another clause", `{"vendor":"acme","product":"ledger","versions":[{"version":"= 1.0, < 2.0","status":"affected"}]}`, nil, 1},
		{"two upper bounds", `{"vendor":"acme","product":"ledger","versions":[{"version":"< 2.3, < 1.5","status":"affected"}]}`, nil, 1},
		{"three clauses", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 1.0, < 2.0, < 3.0","status":"affected"}]}`, nil, 1},
		{"a reversed comparator range", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 3.0, < 2.0","status":"affected"}]}`, nil, 1},
		{"an empty exclusive range", `{"vendor":"acme","product":"ledger","versions":[{"version":"> 2.0, <= 2.0","status":"affected"}]}`, nil, 1},
		{"a commit", `{"vendor":"acme","product":"ledger","versions":[{"version":"< c14231d801407640bc42c2dcf92783409ea6a7c7","status":"affected"}]}`, nil, 1},
		{"a commit starting with a digit", `{"vendor":"acme","product":"ledger","versions":[{"version":"< 6a0e7f7","status":"affected"}]}`, nil, 1},
		{"a branch name", `{"vendor":"acme","product":"ledger","versions":[{"version":"< master-764-e22272e","status":"affected"}]}`, nil, 1},
		{"a comparator after lessThan", `{"vendor":"acme","product":"ledger","versions":[{"version":"1.0","lessThan":"< 2.0","status":"affected"}]}`, nil, 1},
		{"a comparator beside lessThan", `{"vendor":"acme","product":"ledger","versions":[{"version":">= 1.0","lessThan":"2.0","status":"affected"}]}`, nil, 1},
		{"another package's versions", `{"vendor":"acme","product":"ledger","versions":[{"version":"@acme/portal >= 2.29.1, < 2.51.5","status":"affected"},{"version":"ledger >= 5.43.0, < 5.121.0","status":"affected"}]}`, nil, 1},
		{"an edition's name, not a release", `{"vendor":"acme","product":"Ledger","defaultStatus":"unaffected","versions":[{"version":"Ledger 2016","status":"affected"}]}`, nil, 1},
		{"a range after the product's name, written with a hyphen", `{"vendor":"acme","product":"Ledger","versions":[{"version":"Ledger 1.0-1.23","status":"affected"}]}`, nil, 1},
		{"a fixed release with the product's name inside an affected range", `{"vendor":"acme","product":"Ledger","versions":[{"version":"2.0","lessThan":"3.0","status":"affected"},{"version":"Ledger 2.4.1","status":"unaffected"}]}`, nil, 1},
		{"a name that is not the product's", `{"vendor":"acme","product":"Ledger OS","versions":[{"version":"unspecified","lessThan":"Ledger OS Mojave 10.14.5","status":"affected"}]}`, nil, 1},
	} {
		got, err := ParseCVERecord(record(c.affected), "CVE-2026-1000")
		if err != nil || !slices.Equal(spansOf(genericRows(got.Ranges)), append([]span{}, c.want...)) || got.Skipped != c.skipped {
			t.Errorf("%s: %+v skipped %d %v, want %+v skipped %d", c.name, spansOf(genericRows(got.Ranges)), got.Skipped, err, c.want, c.skipped)
		}
	}
}

// A product unusable for the generic comparison keeps the version as written in its vendor rows (statedRows), so nothing of what
// the record says is lost.
func TestParseCVERecord_RecordNotationKeptAsWritten(t *testing.T) {
	t.Parallel()
	got, err := ParseCVERecord(record(`{"vendor":"acme","product":"Acme Runtime","versions":[{"version":"10.0.0","lessThan":"10.0.111, 10.0.400","status":"affected","versionType":"custom"}]}`), "CVE-2026-1000")
	if err != nil || len(genericRows(got.Ranges)) != 0 || len(got.Ranges) != 1 || got.Ranges[0].EndExcl != "10.0.111, 10.0.400" || got.Ranges[0].Generic() {
		t.Fatalf("%+v %v", got.Ranges, err)
	}
}
