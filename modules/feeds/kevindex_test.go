package feeds

import (
	"database/sql"
	"slices"
	"testing"
	"time"
)

// The index of the exploited-list CVEs by product key is kept while the lists do not change (a device page or an agent report reads
// one small stamp, not every entry) and is read again as soon as a pull adds, changes or drops an entry, or a feed is purged.
func TestKevIndex_KeptUntilTheListsChange(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ctx := t.Context()
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	lookup := func(keys ...string) []string {
		t.Helper()
		idx, err := s.KevIndex(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return idx.CVEs(keys)
	}
	if got := lookup("fortinet|fortios"); got == nil || len(got) != 0 {
		t.Fatalf("empty lists: %v", got)
	}
	applyV(t, db, at, "cisa-kev", []Vuln{
		vuln("CVE-2026-0001", "Fortinet", "FortiOS", "2026-11-01"),
		vuln("CVE-2026-0002", "Fortinet", "Multiple Products", "2026-11-02"),
	}, true)
	if got := lookup("fortinet|fortios", "fortinet|fortios"); !slices.Equal(got, []string{"CVE-2026-0001", "CVE-2026-0002"}) {
		t.Fatalf("after a pull: %v (the vendor's Multiple products entry matches every product of the vendor)", got)
	}
	first, err := s.KevIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.KevIndex(ctx); err != nil || again != first {
		t.Fatalf("the index was read again with no change to the lists: %v", err)
	}

	// a pull that changes the product of an entry
	at = at.Add(time.Hour)
	applyV(t, db, at, "cisa-kev", []Vuln{
		vuln("CVE-2026-0001", "Fortinet", "FortiProxy", "2026-11-01"),
		vuln("CVE-2026-0002", "Fortinet", "Multiple Products", "2026-11-02"),
	}, true)
	if got := lookup("fortinet|fortiproxy"); !slices.Equal(got, []string{"CVE-2026-0001", "CVE-2026-0002"}) {
		t.Errorf("after a changed product: %v", got)
	}
	if got := lookup("fortinet|fortios"); !slices.Equal(got, []string{"CVE-2026-0002"}) {
		t.Errorf("the old product after the change: %v", got)
	}

	// a pull that drops an entry
	at = at.Add(time.Hour)
	applyV(t, db, at, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "Fortinet", "FortiProxy", "2026-11-01")}, true)
	if got := lookup("fortinet|fortiproxy"); !slices.Equal(got, []string{"CVE-2026-0001"}) {
		t.Errorf("after a dropped entry: %v", got)
	}

	// a custom feed's entry is never in the index
	addCustom(t, db, "custom-1", "Partner CVEs", KindVulnerabilities)
	applyV(t, db, at.Add(time.Hour), "custom-1", []Vuln{vuln("CVE-2026-0009", "Fortinet", "FortiProxy", "2026-11-03")}, false)
	if got := lookup("fortinet|fortiproxy"); !slices.Equal(got, []string{"CVE-2026-0001"}) {
		t.Errorf("with a custom feed's entry: %v", got)
	}

	// the CISA feed purged (what turning a feed off does): nothing is left
	write(t, db, func(tx *sql.Tx) error { return purgeLoaded(ctx, tx, "cisa-kev") })
	if got := lookup("fortinet|fortiproxy"); len(got) != 0 {
		t.Errorf("after a purge: %v", got)
	}
}
