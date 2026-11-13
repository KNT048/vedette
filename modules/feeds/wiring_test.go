package feeds

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"
)

// settleInv is a fake inventory that also settles transactions, like the real one.
type settleInv struct {
	*fakeInv
	fail    error
	settled []bool
}

func (s *settleInv) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, d ManualDevice) (string, error) {
	if s.fail != nil {
		return "", s.fail
	}
	return s.fakeInv.AddManualDevice(ctx, tx, actor, d)
}

func (s *settleInv) Settle(_ context.Context, tx *sql.Tx, committed bool) {
	if tx == nil {
		panic("Settle without a transaction")
	}
	s.settled = append(s.settled, committed)
}

// The inventory is told how the transaction of "I have it" ended: committed once, or rolled back (issue #39).
func TestIHaveItSettlesTheInventoryTransaction(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	si := &settleInv{fakeInv: e.inv}
	e.svc.Inventory = si
	id := "synology%7Cdiskstation%20manager"
	if c, b, _ := e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"have"}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if !slices.Equal(si.settled, []bool{true}) {
		t.Fatalf("after a commit: settled %v", si.settled)
	}
	// the second click creates no device, so there is nothing to settle for the inventory but the transaction ran
	e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"have"}`)
	if len(e.inv.added) != 1 {
		t.Fatalf("%d devices", len(e.inv.added))
	}
	// a failing inventory rolls the answer back and the inventory hears it
	si.fail = errors.New("inventory refused")
	c, _, _ := e.do("POST", "/feeds/weekly/"+"fortinet%7Cfortios", "operator", `{"answer":"have"}`)
	if c != 500 || si.settled[len(si.settled)-1] {
		t.Errorf("after a failure: %d, settled %v", c, si.settled)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_weekly_answer WHERE key = 'fortinet|fortios'`); n != 0 {
		t.Errorf("the answer of a failed declaration was stored")
	}
}

// D-78: a custom feed's rows do not make the first pull of the CISA list a normal one.
func TestBaselineIsAboutTheCISAListOnly(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	addCustom(t, e.db, "custom-1", "Partner CVEs", KindVulnerabilities)
	applyV(t, e.db, e.clock(), "custom-1", []Vuln{vuln("CVE-2026-30001", "Partner", "Thing", "2026-11-01")}, false)
	if c, b := e.fetch("cisa-kev"); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if n, base := len(e.pub.named(EventNewKEV)), e.pub.named(EventSyncBaseline); n != 0 || len(base) != 1 {
		t.Errorf("new_kev %d, baseline %v", n, base)
	}
}

func TestKevReadsForOtherModules(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	v0, none, err := s.KevProducts(t.Context())
	if err != nil || len(none) != 0 {
		t.Fatalf("empty: %v %v", none, err)
	}
	applyV(t, db, now, "cisa-kev", []Vuln{
		vuln("CVE-2026-0001", "Fortinet", "FortiOS", "2026-11-01"),
		vuln("CVE-2026-0002", "Fortinet", "FortiOS", "2026-11-02"),
		vuln("CVE-2026-0003", "Fortinet", "Multiple Products", "2026-11-02"),
		vuln("CVE-2026-0004", "MikroTik", "RouterOS", "2026-11-03"),
	}, false)
	addCustom(t, db, "custom-1", "Partner CVEs", KindVulnerabilities)
	applyV(t, db, now, "custom-1", []Vuln{vuln("CVE-2026-0005", "Fortinet", "FortiOS", "2026-11-03")}, false)

	v1, list, err := s.KevProducts(t.Context())
	if err != nil || v1 == v0 {
		t.Fatalf("version %q after %q, %v", v1, v0, err)
	}
	want := []ProductCount{{"Fortinet", "FortiOS", 2}, {"Fortinet", "Multiple Products", 1}, {"MikroTik", "RouterOS", 1}}
	if !slices.Equal(list, want) {
		t.Errorf("products %v, want %v (a custom feed's CVE is not counted)", list, want)
	}

	got, err := s.KevCVEsByKeys(t.Context(), []string{"fortinet|fortios"})
	if err != nil || !slices.Equal(got, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}) {
		t.Errorf("by key: %v %v (the Multiple products entry of the vendor matches too, the custom feed's CVE does not)", got, err)
	}
	if got, _ = s.KevCVEsByKeys(t.Context(), []string{"mikrotik|routeros", "nobody|none"}); !slices.Equal(got, []string{"CVE-2026-0004"}) { //nolint:misspell // RouterOS is the product name
		t.Errorf("by key: %v", got)
	}
	if got, err = s.KevCVEsByKeys(t.Context(), nil); err != nil || got == nil || len(got) != 0 {
		t.Errorf("no keys: %v %v", got, err)
	}

	all, err := s.KevVulns(t.Context())
	if err != nil || len(all) != 4 {
		t.Errorf("KevVulns: %d %v", len(all), err)
	}
	rows, err := s.KevVulnsByCVE(t.Context(), []string{"CVE-2026-0001", "CVE-2026-0005", "CVE-2026-9999"})
	if err != nil || len(rows) != 1 || rows[0].CVE != "CVE-2026-0001" {
		t.Errorf("KevVulnsByCVE: %v %v", rows, err)
	}
}
