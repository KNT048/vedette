package inventory_test

import (
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

func okSafety() inventory.SafetyInput {
	return inventory.SafetyInput{
		LANRanges: []string{"192.168.18.5/24"}, Confirmed: true, Days: []int{5, 1, 1}, From: "21:00", To: "04:00",
		PacketsPerS: 80, RequestsPerS: 8, Exclusions: []string{"192.168.18.9"}, FragileKinds: []string{"printer"}, RegularScanKinds: []string{},
	}
}

// INV-32 (#850): PUT /scanning/safety stores the whole shared block in the one store, keeps the switch of active discovery as it
// is, normalizes the ranges, and publishes inventory.settings.changed; its own limits come on top of INV-7's.
func TestContract_INV32_SaveSafety(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24") // active scanning on
	e.ev.reset()
	saved, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", okSafety())
	if err != nil {
		t.Fatal(err)
	}
	a := saved.Active
	if !a.Enabled || !slices.Equal(a.Days, []int{1, 5}) || a.From != "21:00" || a.To != "04:00" || a.Rate != 80 || a.CheckRate != 8 || !slices.Equal(a.Exclusions, []string{"192.168.18.9"}) {
		t.Fatalf("active = %+v", a)
	}
	if !slices.Equal(saved.LANRanges, []string{"192.168.18.0/24"}) || len(saved.Adjusted) != 1 || saved.ScopeConfirmedAt == nil {
		t.Fatalf("saved = %+v", saved)
	}
	if n := len(e.ev.named(inventory.EventSettingsChanged)); n != 1 {
		t.Fatalf("settings.changed = %d", n)
	}
	st, err := e.svc.Settings(e.ctx())
	if err != nil || st.Active.Checks() != 8 {
		t.Fatalf("stored check rate %d, %v", st.Active.Checks(), err)
	}
	for _, c := range []struct {
		name string
		mut  func(*inventory.SafetyInput)
		code string
	}{
		{"no day", func(in *inventory.SafetyInput) { in.Days = nil }, "no_days"},
		{"check rate 0", func(in *inventory.SafetyInput) { in.RequestsPerS = 0 }, "bad_rate"},
		{"check rate 21", func(in *inventory.SafetyInput) { in.RequestsPerS = 21 }, "bad_rate"},
		{"packets 1001", func(in *inventory.SafetyInput) { in.PacketsPerS = 1001 }, "bad_rate"},
		{"201 exclusions", func(in *inventory.SafetyInput) {
			in.Exclusions = nil
			for i := range 201 {
				in.Exclusions = append(in.Exclusions, "10.1."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250))
			}
		}, "too_many_exclusions"},
		{"host bits in an exclusion", func(in *inventory.SafetyInput) { in.Exclusions = []string{"192.168.18.5/28"} }, "bad_exclusion"},
		{"discovery on, scope not ticked", func(in *inventory.SafetyInput) { in.Confirmed = false }, "scope_not_confirmed"},
		{"same start and end", func(in *inventory.SafetyInput) { in.To = in.From }, "bad_window"},
	} {
		in := okSafety()
		c.mut(&in)
		_, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", in)
		wantAPIError(t, err, 400, c.code)
	}
	// with discovery off the attestation may stay unticked; the scope is then not confirmed
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	in := okSafety()
	in.Confirmed = false
	saved, err = e.svc.SaveSafety(e.ctx(), "admin@acme.example", in)
	if err != nil || saved.Active.Enabled || saved.ScopeConfirmedAt != nil {
		t.Fatalf("discovery off: %+v, %v", saved, err)
	}
}

// INV-32: the nmap-discovery switch is active.enabled alone; on needs the confirmed scope (INV-7), and it is audited.
func TestContract_INV32_SetDiscovery(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	wantAPIError(t, e.svc.SetDiscovery(e.ctx(), "admin@acme.example", true), 400, "no_ranges")
	in := okSettings("192.168.18.0/24")
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	wantAPIError(t, e.svc.SetDiscovery(e.ctx(), "admin@acme.example", true), 400, "scope_not_confirmed")
	in.ScopeConfirmed = true
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	e.ev.reset()
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", true); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Settings(e.ctx())
	if !st.Active.Enabled || st.Active.From != "23:00" || st.ScopeConfirmedAt == nil {
		t.Fatalf("settings = %+v", st)
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 1 || e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail = 'active scanning on'`) != 1 {
		t.Fatal("no event or audit row")
	}
}

// INV-32: PUT /scans/config writes the window, the check rate and the exclusions into the one store inside the scan module's
// transaction (exclusions with host bits reduced to their network, as nuclei read them); the event goes out only when that
// transaction committed. PUT /inventory/settings keeps the check rate and does not show it.
func TestContract_INV32_ScanWritesThrough(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24")
	write := func(in inventory.ChecksInput, commit bool) error {
		var serr error
		var tx *sql.Tx
		err := e.db.Write(e.ctx(), func(wtx *sql.Tx) error {
			tx = wtx
			if serr = e.svc.SaveChecks(e.ctx(), wtx, "admin@acme.example", in); serr != nil {
				return serr
			}
			if !commit {
				return sql.ErrTxDone
			}
			return nil
		})
		if tx != nil {
			e.svc.Settle(e.ctx(), tx, err == nil)
		}
		return serr
	}
	e.ev.reset()
	if err := write(inventory.ChecksInput{Days: []int{7, 6}, From: "20:00", To: "02:00", CheckRate: 12, Exclusions: []string{"192.168.18.5/28", "192.168.18.9", "192.168.18.9"}}, true); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Settings(e.ctx())
	if a := st.Active; !a.Enabled || !slices.Equal(a.Days, []int{6, 7}) || a.From != "20:00" || a.CheckRate != 12 || a.Rate != 50 ||
		!slices.Equal(a.Exclusions, []string{"192.168.18.0/28", "192.168.18.9"}) {
		t.Fatalf("active = %+v", a)
	}
	if n := len(e.ev.named(inventory.EventSettingsChanged)); n != 1 {
		t.Fatalf("settings.changed after a commit = %d", n)
	}
	e.ev.reset()
	if err := write(inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "02:00", CheckRate: 3}, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.Active.CheckRate != 12 || len(e.ev.named(inventory.EventSettingsChanged)) != 0 {
		t.Fatalf("a rolled-back save: check rate %d, %d events", st.Active.CheckRate, len(e.ev.named(inventory.EventSettingsChanged)))
	}
	for _, c := range []struct {
		in   inventory.ChecksInput
		code string
	}{
		{inventory.ChecksInput{From: "20:00", To: "02:00", CheckRate: 3}, "bad_days"},
		{inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "20:00", CheckRate: 3}, "bad_window"},
		{inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "02:00", CheckRate: 21}, "bad_rate"},
		{inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "02:00", CheckRate: 3, Exclusions: []string{"printer"}}, "bad_exclusion"},
	} {
		wantAPIError(t, write(c.in, true), 400, c.code)
	}
	// PUT /inventory/settings carries no check rate: a save keeps it
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings("192.168.18.0/24")); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.Active.CheckRate != 12 {
		t.Fatalf("check rate after PUT /inventory/settings = %d", st.Active.CheckRate)
	}
	h := inventory.NewHandlers(e.svc)
	got, err := h.InventoryGetInventorySettings(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "check_rate") {
		t.Fatalf("GET /inventory/settings shows the check rate: %s", raw)
	}
}

// INV-32: the one-time merge of the scan module's own copy: the check rate, the union of both exclusion lists (normalized, each once),
// the inventory's window kept, one audit row naming both windows when a person had saved a different one; then never again.
func TestContract_INV32_MergeLegacyChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	in := okSettings("192.168.18.0/24")
	in.Active.Exclusions = []string{"192.168.18.9", "192.168.18.64/28"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.Active.CheckRate != 0 || st.Active.Checks() != inventory.DefaultCheckRate {
		t.Fatalf("before the merge: %d / %d", st.Active.CheckRate, st.Active.Checks())
	}
	e.ev.reset()
	legacy := inventory.LegacyChecks{Days: []int{6, 7}, From: "22:00", To: "05:00", Rate: 9, Exclusions: []string{"192.168.18.9", "192.168.18.70/28", "10.0.0.1"}, SavedBy: "it@acme.example", SavedAt: "2026-11-01T00:00:00.000Z"}
	merged, err := e.svc.MergeLegacyChecks(e.ctx(), legacy)
	if err != nil || !merged {
		t.Fatalf("merge: %v %v", merged, err)
	}
	st, _ := e.svc.Settings(e.ctx())
	if a := st.Active; a.CheckRate != 9 || a.From != "23:00" || !slices.Equal(a.Days, []int{1, 2, 3, 4, 5, 6, 7}) ||
		!slices.Equal(a.Exclusions, []string{"192.168.18.9", "192.168.18.64/28", "10.0.0.1"}) {
		t.Fatalf("merged = %+v", a)
	}
	var detail string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT detail FROM core_audit WHERE action = 'scanning.safety.merged'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kept":{"days":[1,2,3,4,5,6,7],"from":"23:00","to":"05:00"}`, `"dropped":{"days":[6,7],"from":"22:00","to":"05:00"}`, `"dropped_by":"it@acme.example"`, `"exclusions_added":1`} {
		if !strings.Contains(detail, want) {
			t.Errorf("audit detail %s lacks %s", detail, want)
		}
	}
	if n := len(e.ev.named(inventory.EventSettingsChanged)); n != 1 {
		t.Fatalf("settings.changed = %d", n)
	}
	// the same copy at the next start: nothing
	if merged, err := e.svc.MergeLegacyChecks(e.ctx(), legacy); err != nil || merged || e.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged'`) != 1 {
		t.Fatalf("second merge: %v %v", merged, err)
	}
	// review #857 M1: a copy saved after the merge (a version before #850 after a rollback) is taken in again at the next start, and a
	// save of the shared block in between does not mark it taken in
	if _, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", inventory.SafetyInput{LANRanges: []string{"192.168.18.0/24"}, Confirmed: true,
		Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "23:00", To: "05:00", PacketsPerS: 50, RequestsPerS: 9, Exclusions: st.Active.Exclusions}); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	rolled := legacy
	rolled.SavedAt, rolled.Exclusions, rolled.Days, rolled.From, rolled.To = "2099-01-01T00:00:00.000Z", append(slices.Clone(legacy.Exclusions), "192.168.18.50"), []int{1, 2, 3, 4, 5, 6, 7}, "23:00", "05:00"
	if merged, err := e.svc.MergeLegacyChecks(e.ctx(), rolled); err != nil || !merged {
		t.Fatalf("a newer copy: %v %v", merged, err)
	}
	if st, _ := e.svc.Settings(e.ctx()); !slices.Contains(st.Active.Exclusions, "192.168.18.50") {
		t.Fatalf("the rollback's exclusion is not in the one store: %v", st.Active.Exclusions)
	}
	// review #857 r2 L1: that merge was stamped by a copy from the future (a clock that ran ahead); a later rollback edit stamped
	// earlier is still taken in, since only equality counts
	again := rolled
	again.SavedAt, again.Exclusions = "2026-12-01T00:00:00.000Z", append(slices.Clone(rolled.Exclusions), "192.168.18.51")
	if merged, err := e.svc.MergeLegacyChecks(e.ctx(), again); err != nil || !merged {
		t.Fatalf("an edit stamped before the merge stamp: %v %v", merged, err)
	}
	if st, _ := e.svc.Settings(e.ctx()); !slices.Contains(st.Active.Exclusions, "192.168.18.51") {
		t.Fatalf("the later rollback edit is not in the one store: %v", st.Active.Exclusions)
	}
	if merged, _ := e.svc.MergeLegacyChecks(e.ctx(), again); merged {
		t.Fatal("the same copy was taken in twice")
	}
	// L10: the same window, but exclusions added: an audit row all the same
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged' AND detail LIKE '%"exclusions_added":1%'`); n != 3 {
		t.Fatalf("merge rows with one exclusion added = %d", n)
	}

	// a copy nobody saved (the install's defaults) merges silently; a rate out of range gives the default
	e2 := newEnv(t)
	if merged, err := e2.svc.MergeLegacyChecks(e2.ctx(), inventory.LegacyChecks{Days: []int{1}, From: "01:00", To: "02:00", Rate: 0}); err != nil || !merged {
		t.Fatalf("defaults: %v %v", merged, err)
	}
	if merged, err := e2.svc.MergeLegacyChecks(e2.ctx(), inventory.LegacyChecks{Days: []int{1}, From: "01:00", To: "02:00", Rate: 0}); err != nil || merged {
		t.Fatalf("defaults twice: %v %v", merged, err)
	}
	if st, _ := e2.svc.Settings(e2.ctx()); st.Active.CheckRate != inventory.DefaultCheckRate || e2.count(`SELECT count(*) FROM core_audit WHERE action = 'scanning.safety.merged'`) != 0 {
		t.Fatalf("defaults merged into %+v", st.Active)
	}
}

func TestFragileCount(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if n, err := e.svc.FragileCount(e.ctx()); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
}

// review #857 L7, L8: a list over 200 left by a merge saves when it does not grow, and growing it is refused; the save keeps the
// switch of active discovery as stored when its transaction reads it.
func TestContract_INV32_LongListsAndTheStoredSwitch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	long := make([]string, 0, 210)
	for i := range 210 {
		long = append(long, "10."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)+".1")
	}
	in := okSettings("192.168.18.0/24")
	in.Active.Exclusions = long
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil { // the discovery page has no cap; a merge may add more
		t.Fatal(err)
	}
	safety := okSafety()
	safety.Exclusions = long
	saved, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", safety)
	if err != nil || len(saved.Active.Exclusions) != 210 || saved.Active.Enabled {
		t.Fatalf("the same long list: %v, %d, enabled %v", err, len(saved.Active.Exclusions), saved.Active.Enabled)
	}
	safety.Exclusions = append(slices.Clone(long), "192.168.18.77")
	_, err = e.svc.SaveSafety(e.ctx(), "admin@acme.example", safety)
	wantAPIError(t, err, 400, "too_many_exclusions")
	var tx *sql.Tx
	werr := e.db.Write(e.ctx(), func(w *sql.Tx) error {
		tx = w
		return e.svc.SaveChecks(e.ctx(), w, "admin@acme.example", inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "02:00", CheckRate: 3, Exclusions: long})
	})
	e.svc.Settle(e.ctx(), tx, werr == nil)
	if werr != nil {
		t.Fatalf("the scan module's save of the same long list: %v", werr)
	}
	// the switch: turned on between the page's read and its save, it stays on
	e.confirmScope("192.168.18.0/24")
	safety.Exclusions = long[:5]
	if saved, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", safety); err != nil || !saved.Active.Enabled {
		t.Fatalf("the stored switch: %v, enabled %v", err, saved.Active.Enabled)
	}
}

// INV-32 (#842): POST /scanning/safety/ranges adds one range in one transaction with the rules of a PUT, needs the attestation and
// records it as a PUT does, changes nothing for a range already covered, and is audited and announced like the PUT.
func TestContract_INV32_AddRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24")
	for _, c := range []struct{ raw, code string }{
		{"192.168.20.7", "no_prefix"},
		{"bogus", "bad_cidr"},
		{"", "bad_cidr"},
		{"8.8.8.0/24", "public_range"},
		{"192.168.0.0/16", "overlap_range"}, // it contains the stored one
	} {
		_, err := e.svc.AddRange(e.ctx(), "admin@acme.example", c.raw, true)
		wantAPIError(t, err, 400, c.code)
	}
	_, err := e.svc.AddRange(e.ctx(), "admin@acme.example", "192.168.20.0/24", false)
	wantAPIError(t, err, 400, "scope_not_confirmed")
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'added range%'`); n != 0 {
		t.Fatalf("a refused add was audited: %d", n)
	}

	e.now = e.now.Add(time.Hour)
	e.ev.reset()
	saved, err := e.svc.AddRange(e.ctx(), "it@acme.example", " 192.168.20.9/24 ", true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(saved.LANRanges, []string{"192.168.18.0/24", "192.168.20.0/24"}) || len(saved.Adjusted) != 1 || saved.Adjusted[0].To != "192.168.20.0/24" {
		t.Fatalf("saved = %+v", saved)
	}
	if saved.ScopeConfirmedBy == nil || *saved.ScopeConfirmedBy != "it@acme.example" || *saved.ScopeConfirmedAt != "2026-11-09T11:00:00.000Z" || !saved.Active.Enabled {
		t.Fatalf("attestation = %v %v", saved.ScopeConfirmedAt, saved.ScopeConfirmedBy)
	}
	st, _ := e.svc.Settings(e.ctx())
	if !slices.Equal(st.LANRanges, saved.LANRanges) || st.ScopeConfirmedAt == nil || *st.ScopeConfirmedAt != *saved.ScopeConfirmedAt {
		t.Fatalf("stored = %+v", st)
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 1 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND user = 'it@acme.example' AND target = 'scan scope' AND detail = 'added range 192.168.20.0/24: 2 ranges, active scanning on'`) != 1 {
		t.Fatal("no event or audit row naming the range")
	}

	// covered: nothing changes, nothing is audited or announced
	e.ev.reset()
	rows := e.count(`SELECT count(*) FROM core_audit`)
	for _, raw := range []string{"192.168.20.0/24", "192.168.20.128/25", "192.168.18.64/26"} {
		again, err := e.svc.AddRange(e.ctx(), "admin@acme.example", raw, true)
		if err != nil || !slices.Equal(again.LANRanges, saved.LANRanges) || *again.ScopeConfirmedBy != "it@acme.example" {
			t.Fatalf("%s again: %+v, %v", raw, again, err)
		}
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 0 || e.count(`SELECT count(*) FROM core_audit`) != rows {
		t.Fatal("an add that changed nothing was announced or audited")
	}

	// covered while the scope is not confirmed: the attestation is recorded for the stored ranges, as a PUT of them would
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	in := okSafety()
	in.LANRanges, in.Confirmed = saved.LANRanges, false
	if _, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	again, err := e.svc.AddRange(e.ctx(), "admin@acme.example", "192.168.20.0/24", true)
	if err != nil || again.ScopeConfirmedAt == nil || !slices.Equal(again.LANRanges, saved.LANRanges) {
		t.Fatalf("covered, unconfirmed: %+v, %v", again, err)
	}

	// at most 16 ranges
	for i := 21; len(again.LANRanges) < 16; i++ {
		if again, err = e.svc.AddRange(e.ctx(), "admin@acme.example", "192.168."+strconv.Itoa(i)+".0/24", true); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.svc.AddRange(e.ctx(), "admin@acme.example", "10.9.0.0/16", true)
	wantAPIError(t, err, 400, "too_many_ranges")
}

// INV-32 (#842): POST /scanning/safety/exclusions adds one exclusion in one transaction with the rule of a PUT, changes nothing for
// an entry already covered, refuses growing past 200 with 409, keeps the attestation, and is audited and announced like the PUT.
func TestContract_INV32_AddExclusion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24")
	for _, raw := range []string{"192.168.18.5/28", "bogus", "", "fe80::1"} {
		_, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", raw)
		wantAPIError(t, err, 400, "bad_exclusion")
	}
	before, _ := e.svc.Settings(e.ctx())
	e.ev.reset()
	saved, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", " 192.168.18.64/28 ")
	if err != nil || !slices.Equal(saved.Active.Exclusions, []string{"192.168.18.64/28"}) || !saved.Active.Enabled {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if saved.ScopeConfirmedAt == nil || *saved.ScopeConfirmedAt != *before.ScopeConfirmedAt {
		t.Fatalf("the attestation moved: %v", saved.ScopeConfirmedAt)
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 1 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail = 'added exclusion 192.168.18.64/28: 1 exclusions'`) != 1 {
		t.Fatal("no event or audit row naming the exclusion")
	}
	e.ev.reset()
	rows := e.count(`SELECT count(*) FROM core_audit`)
	for _, raw := range []string{"192.168.18.64/28", "192.168.18.70", "192.168.18.72/29"} {
		again, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", raw)
		if err != nil || !slices.Equal(again.Active.Exclusions, saved.Active.Exclusions) {
			t.Fatalf("%s again: %+v, %v", raw, again.Active.Exclusions, err)
		}
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 0 || e.count(`SELECT count(*) FROM core_audit`) != rows {
		t.Fatal("an add that changed nothing was announced or audited")
	}
	st, _ := e.svc.Settings(e.ctx())
	if a := st.Active; a.CheckRate != before.Active.CheckRate || a.From != before.Active.From || a.Rate != before.Active.Rate {
		t.Fatalf("other settings moved: %+v", a)
	}

	// the 200th lands, the 201st is 409; one already covered is still 200
	for i := len(st.Active.Exclusions); i < inventory.MaxExclusions; i++ {
		if _, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", "10.1."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)); err != nil {
			t.Fatalf("exclusion %d: %v", i+1, err)
		}
	}
	_, err = e.svc.AddExclusion(e.ctx(), "admin@acme.example", "192.168.18.9")
	wantAPIError(t, err, 409, "too_many_exclusions")
	if _, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", "192.168.18.65"); err != nil {
		t.Fatalf("a covered entry at the limit: %v", err)
	}
}

// INV-32 (#842): two adds at once both land: each reads, appends and stores in one transaction, so neither overwrites the other.
func TestContract_INV32_ConcurrentAddsKeepBoth(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24")
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := range n {
		wg.Go(func() {
			_, err := e.svc.AddRange(e.ctx(), "admin@acme.example", "10."+strconv.Itoa(i)+".0.0/16", true)
			errs <- err
		})
		wg.Go(func() {
			_, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", "192.168.18."+strconv.Itoa(i+1))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	st, _ := e.svc.Settings(e.ctx())
	if len(st.LANRanges) != n+1 || len(st.Active.Exclusions) != n {
		t.Fatalf("lost an add: ranges %v, exclusions %v", st.LANRanges, st.Active.Exclusions)
	}
	if got := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND (detail LIKE 'added range%' OR detail LIKE 'added exclusion%')`); got != 2*n {
		t.Fatalf("audit rows = %d", got)
	}
}
