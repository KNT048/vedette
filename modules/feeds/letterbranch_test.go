package feeds

import "testing"

// A letter-release branch ("1.1.1" before "1.1.1zk") is left out alone only where the product's version scheme cannot read it: a
// product whose scheme reads the range keeps the old rule (the product's rows are kept as the vendor states them, which its scheme
// reads), so no vendor row the scheme could match is lost.
func TestEntryRows_LetterBranchOnlyWhereTheSchemeCannotReadIt(t *testing.T) {
	t.Parallel()
	end := "1.1.1zk"
	a := cnaAffected{Vendor: "Acme", Product: "Gateway", DefaultStatus: "unaffected", Versions: []cnaVersion{
		{Version: "3.5.0", Status: "affected", LessThan: ptr("3.5.10")},
		{Version: "1.1.1", Status: "affected", LessThan: &end},
	}}
	rows, complete, ok := entryRows(a, nil)
	if !ok || complete || len(rows) != 1 || rows[0].StartIncl != "3.5.0" {
		t.Fatalf("no scheme: %+v complete %v ok %v", rows, complete, ok)
	}
	never := func(string, string, bool) bool { return false }
	if rows, _, ok := entryRows(a, never); !ok || len(rows) != 1 {
		t.Fatalf("a scheme that cannot read it: %+v ok %v", rows, ok)
	}
	reads := func(start, end string, incl bool) bool { return start == "1.1.1" && end == "1.1.1zk" && !incl }
	if _, _, ok := entryRows(a, reads); ok {
		t.Fatal("a scheme that reads the range: the entry must stay as the vendor states it (unusable for the generic rules)")
	}
}

func ptr(s string) *string { return &s }
