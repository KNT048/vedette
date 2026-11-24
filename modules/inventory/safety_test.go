package inventory_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// version is the stored block's version, as GET /scanning shows it.
func (e *env) version() string {
	e.t.Helper()
	st, err := e.svc.Settings(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return st.Version
}

// addRange is "+ New range" from a dialog opened just now: it shows the stored confirmation, and shown as the ranges.
func (e *env) addRange(actor, raw string, shown []string, confirmed bool) (inventory.SavedSettings, error) {
	st, err := e.svc.Settings(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return e.svc.AddRange(e.ctx(), actor, inventory.RangeAdd{Range: raw, Shown: shown, ShownConfirmedAt: st.ScopeConfirmedAt, Confirmed: confirmed})
}

// saveSafety is PUT /scanning/safety from a page that read the block just now.
func (e *env) saveSafety(in inventory.SafetyInput) (inventory.SavedSettings, error) {
	in.Version = e.version()
	return e.svc.SaveSafety(e.ctx(), "admin@acme.example", in)
}

func okSafety() inventory.SafetyInput {
	return inventory.SafetyInput{
		LANRanges: []string{"10.142.0.5/24"}, Confirmed: true, Days: []int{5, 1, 1}, From: "21:00", To: "04:00",
		PacketsPerS: 80, RequestsPerS: 8, Exclusions: []string{"10.142.0.9"}, FragileKinds: []string{"printer"}, RegularScanKinds: []string{},
	}
}

// INV-32 (#850): PUT /scanning/safety stores the whole shared block in the one store, keeps the switch of active discovery as it
// is, normalizes the ranges, and publishes inventory.settings.changed; its own limits come on top of INV-7's.
func TestContract_INV32_SaveSafety(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.142.0.0/24") // active scanning on
	e.ev.reset()
	saved, err := e.saveSafety(okSafety())
	if err != nil {
		t.Fatal(err)
	}
	a := saved.Active
	if !a.Enabled || !slices.Equal(a.Days, []int{1, 5}) || a.From != "21:00" || a.To != "04:00" || a.Rate != 80 || a.CheckRate != 8 || !slices.Equal(a.Exclusions, []string{"10.142.0.9"}) {
		t.Fatalf("active = %+v", a)
	}
	if !slices.Equal(saved.LANRanges, []string{"10.142.0.0/24"}) || len(saved.Adjusted) != 1 || saved.ScopeConfirmedAt == nil {
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
		{"host bits in an exclusion", func(in *inventory.SafetyInput) { in.Exclusions = []string{"10.142.0.5/28"} }, "bad_exclusion"},
		{"discovery on, scope not ticked", func(in *inventory.SafetyInput) { in.Confirmed = false }, "scope_not_confirmed"},
		{"same start and end", func(in *inventory.SafetyInput) { in.To = in.From }, "bad_window"},
	} {
		in := okSafety()
		c.mut(&in)
		_, err := e.saveSafety(in)
		wantAPIError(t, err, 400, c.code)
	}
	// with discovery off the attestation may stay unticked; the scope is then not confirmed
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	in := okSafety()
	in.Confirmed = false
	saved, err = e.saveSafety(in)
	if err != nil || saved.Active.Enabled || saved.ScopeConfirmedAt != nil {
		t.Fatalf("discovery off: %+v, %v", saved, err)
	}
}

// INV-32: the nmap-discovery switch is active.enabled alone; on needs the confirmed scope (INV-7), and it is audited.
func TestContract_INV32_SetDiscovery(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	wantAPIError(t, e.svc.SetDiscovery(e.ctx(), "admin@acme.example", true), 400, "no_ranges")
	in := okSettings("10.142.0.0/24")
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
	e.confirmScope("10.142.0.0/24")
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
	if err := write(inventory.ChecksInput{Days: []int{7, 6}, From: "20:00", To: "02:00", CheckRate: 12, Exclusions: []string{"10.142.0.5/28", "10.142.0.9", "10.142.0.9"}}, true); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Settings(e.ctx())
	if a := st.Active; !a.Enabled || !slices.Equal(a.Days, []int{6, 7}) || a.From != "20:00" || a.CheckRate != 12 || a.Rate != 50 ||
		!slices.Equal(a.Exclusions, []string{"10.142.0.0/28", "10.142.0.9"}) {
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
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings("10.142.0.0/24")); err != nil {
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
	in := okSettings("10.142.0.0/24")
	in.Active.Exclusions = long
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil { // the discovery page has no cap; a merge may add more
		t.Fatal(err)
	}
	safety := okSafety()
	safety.Exclusions = long
	saved, err := e.saveSafety(safety)
	if err != nil || len(saved.Active.Exclusions) != 210 || saved.Active.Enabled {
		t.Fatalf("the same long list: %v, %d, enabled %v", err, len(saved.Active.Exclusions), saved.Active.Enabled)
	}
	safety.Exclusions = append(slices.Clone(long), "10.142.0.77")
	_, err = e.saveSafety(safety)
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
	e.confirmScope("10.142.0.0/24")
	safety.Exclusions = long[:5]
	if saved, err := e.saveSafety(safety); err != nil || !saved.Active.Enabled {
		t.Fatalf("the stored switch: %v, enabled %v", err, saved.Active.Enabled)
	}
}

// INV-32 (#842, review #860 H1): POST /scanning/safety/ranges adds one range in one transaction with the rules of a PUT; the tick
// is the attestation and covers only the ranges the dialog showed (409 scope_changed otherwise, nothing stored); a range already
// covered changes nothing; it is audited and announced like the PUT.
func TestContract_INV32_AddRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.142.0.0/24")
	shown := []string{"10.142.0.0/24"}
	for _, c := range []struct{ raw, code string }{
		{"192.168.20.7", "no_prefix"},
		{"bogus", "bad_cidr"},
		{"", "bad_cidr"},
		{"8.8.8.0/24", "public_range"},
		{"10.142.0.0/16", "overlap_range"}, // it contains the stored one
	} {
		_, err := e.addRange("admin@acme.example", c.raw, shown, true)
		wantAPIError(t, err, 400, c.code)
	}
	_, err := e.addRange("admin@acme.example", "192.168.20.0/24", shown, false)
	wantAPIError(t, err, 400, "scope_not_confirmed")
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'added range%'`); n != 0 {
		t.Fatalf("a refused add was audited: %d", n)
	}

	e.now = e.now.Add(time.Hour)
	e.ev.reset()
	v0 := e.version()
	saved, err := e.addRange("it@acme.example", " 192.168.20.9/24 ", shown, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(saved.LANRanges, []string{"10.142.0.0/24", "192.168.20.0/24"}) || len(saved.Adjusted) != 1 || saved.Adjusted[0].To != "192.168.20.0/24" {
		t.Fatalf("saved = %+v", saved)
	}
	if saved.ScopeConfirmedBy == nil || *saved.ScopeConfirmedBy != "it@acme.example" || *saved.ScopeConfirmedAt != "2026-11-09T11:00:00.000Z" || !saved.Active.Enabled {
		t.Fatalf("attestation = %v %v", saved.ScopeConfirmedAt, saved.ScopeConfirmedBy)
	}
	if saved.Version == v0 || saved.Version != e.version() {
		t.Fatalf("version %q after the add, %q before, %q stored", saved.Version, v0, e.version())
	}
	st, _ := e.svc.Settings(e.ctx())
	if !slices.Equal(st.LANRanges, saved.LANRanges) || st.ScopeConfirmedAt == nil || *st.ScopeConfirmedAt != *saved.ScopeConfirmedAt {
		t.Fatalf("stored = %+v", st)
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 1 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND user = 'it@acme.example' AND target = 'scan scope' AND detail = 'added range 192.168.20.0/24: 2 ranges, active scanning on'`) != 1 {
		t.Fatal("no event or audit row naming the range")
	}

	// covered: nothing changes, nothing is audited or announced, whatever the dialog showed
	e.ev.reset()
	rows := e.count(`SELECT count(*) FROM core_audit`)
	for _, raw := range []string{"192.168.20.0/24", "192.168.20.128/25", "10.142.0.64/26"} {
		again, err := e.addRange("admin@acme.example", raw, nil, true)
		if err != nil || !slices.Equal(again.LANRanges, saved.LANRanges) || *again.ScopeConfirmedBy != "it@acme.example" {
			t.Fatalf("%s again: %+v, %v", raw, again, err)
		}
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 0 || e.count(`SELECT count(*) FROM core_audit`) != rows {
		t.Fatal("an add that changed nothing was announced or audited")
	}

	// a dialog that showed another list (stale, or blind) confirms nothing: 409 scope_changed with the current block
	for _, stale := range [][]string{nil, shown, {"10.142.0.0/24", "192.168.20.0/24", "10.0.0.0/8"}} {
		_, err := e.addRange("admin@acme.example", "192.168.30.0/24", stale, true)
		wantAPIError(t, err, 409, "scope_changed")
		var ch *inventory.Changed
		if !errors.As(err, &ch) || !slices.Equal(ch.Current.LANRanges, saved.LANRanges) || ch.Current.Version != e.version() {
			t.Fatalf("%v: the refusal does not carry the current block: %v", stale, err)
		}
	}
	if e.count(`SELECT count(*) FROM core_audit`) != rows {
		t.Fatal("a refused add was audited")
	}

	// review #860 H1 scenario 1: an admin withdrew the attestation (discovery off, unticked); a later inline add confirms only
	// when its dialog showed the stored ranges, and its audit row says it confirmed a scope that was not confirmed
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	in := okSafety()
	in.LANRanges, in.Confirmed = []string{"10.0.0.0/8", "192.168.20.0/24"}, false
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	_, err = e.addRange("admin@acme.example", "192.168.50.0/24", []string{"192.168.20.0/24"}, true)
	wantAPIError(t, err, 409, "scope_changed")
	if st, _ := e.svc.Settings(e.ctx()); st.ScopeConfirmedAt != nil || len(st.LANRanges) != 2 {
		t.Fatalf("a dialog that did not show 10.0.0.0/8 confirmed it: %+v", st)
	}
	again, err := e.addRange("admin@acme.example", "192.168.50.0/24", []string{"192.168.20.0/24", "10.0.0.0/8"}, true)
	if err != nil || again.ScopeConfirmedAt == nil || !slices.Equal(again.LANRanges, []string{"10.0.0.0/8", "192.168.20.0/24", "192.168.50.0/24"}) {
		t.Fatalf("shown and confirmed: %+v, %v", again, err)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail = 'added range 192.168.50.0/24 and confirmed the scope, which was not confirmed (10.0.0.0/8, 192.168.20.0/24 were shown): 3 ranges, active scanning off'`) != 1 {
		t.Fatal("the audit row does not say the add confirmed the scope")
	}
	// covered while unconfirmed: the tick confirms the shown list, and says so
	in.LANRanges = again.LANRanges
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	if again, err = e.addRange("admin@acme.example", "192.168.50.0/25", again.LANRanges, true); err != nil || again.ScopeConfirmedAt == nil || len(again.LANRanges) != 3 {
		t.Fatalf("covered, unconfirmed: %+v, %v", again, err)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail LIKE 'confirmed the scope, which was not confirmed (%; 192.168.50.0/25 is inside it): 3 ranges%'`) != 1 {
		t.Fatal("no audit row for the confirmation")
	}

	// at most 16 ranges
	for i := 21; len(again.LANRanges) < 16; i++ {
		if again, err = e.addRange("admin@acme.example", "192.168."+strconv.Itoa(i)+".0/24", again.LANRanges, true); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.addRange("admin@acme.example", "172.16.0.0/16", again.LANRanges, true)
	wantAPIError(t, err, 400, "too_many_ranges")
}

// review #860 M1: a full save carries the version it was built on: PUT /scanning/safety must, PUT /inventory/settings and PUT
// /scans/config may. A page opened before an inline add is refused with 409 safety_changed and the current block, so it never
// drops the exclusion; nothing is stored.
func TestContract_INV32_FullSavesNeverDropAnInlineAdd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.142.0.0/24")
	opened := e.version()                                                                          // the page loads
	if _, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", "10.142.0.40"); err != nil { // another tab excludes the PLC
		t.Fatal(err)
	}
	stale := okSafety()
	stale.LANRanges, stale.Exclusions, stale.Version = []string{"10.142.0.0/24"}, []string{}, opened
	_, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", stale)
	wantAPIError(t, err, 409, "safety_changed")
	var ch *inventory.Changed
	if !errors.As(err, &ch) || !slices.Contains(ch.Current.Active.Exclusions, "10.142.0.40") {
		t.Fatalf("the refusal does not carry the current block: %v", err)
	}
	stale.Version = ""
	_, err = e.svc.SaveSafety(e.ctx(), "admin@acme.example", stale)
	wantAPIError(t, err, 409, "safety_changed") // required on this writer

	old := okSettings("10.142.0.0/24")
	old.ScopeConfirmed, old.Active.Enabled, old.Version = true, true, opened
	_, err = e.svc.SaveSettings(e.ctx(), "admin@acme.example", old)
	wantAPIError(t, err, 409, "safety_changed")
	var tx *sql.Tx
	werr := e.db.Write(e.ctx(), func(w *sql.Tx) error {
		tx = w
		return e.svc.SaveChecks(e.ctx(), w, "admin@acme.example", inventory.ChecksInput{Days: []int{1}, From: "20:00", To: "02:00", CheckRate: 3, Exclusions: []string{}, Version: opened})
	})
	e.svc.Settle(e.ctx(), tx, werr == nil)
	wantAPIError(t, werr, 409, "safety_changed")
	if st, _ := e.svc.Settings(e.ctx()); !slices.Equal(st.Active.Exclusions, []string{"10.142.0.40"}) || st.Active.From != "23:00" {
		t.Fatalf("a refused save stored something: %+v", st.Active)
	}

	// the current version saves; the version is the values, so a save of the same values keeps it
	stale.Version, stale.Exclusions = e.version(), []string{"10.142.0.40"}
	saved, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", stale)
	if err != nil || saved.Version != e.version() {
		t.Fatalf("current version: %v, %q vs %q", err, saved.Version, e.version())
	}
	stale.Version = saved.Version
	if again, err := e.svc.SaveSafety(e.ctx(), "admin@acme.example", stale); err != nil || again.Version != saved.Version {
		t.Fatalf("the same values again: %v, %q vs %q", err, again.Version, saved.Version)
	}
	// review #860 r2 L1: the discovery switch is part of the version, so a Settings › Scanning › Safety page loaded with it on cannot turn it
	// back on after another admin turned it off
	scopePage := okSettings("10.142.0.0/24")
	scopePage.ScopeConfirmed, scopePage.Active.Enabled, scopePage.Active.Exclusions, scopePage.Version = true, true, []string{"10.142.0.40"}, e.version()
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil || e.version() == saved.Version {
		t.Fatalf("the discovery switch did not change the version: %v", err)
	}
	_, err = e.svc.SaveSettings(e.ctx(), "admin@acme.example", scopePage)
	wantAPIError(t, err, 409, "safety_changed")
	if st, _ := e.svc.Settings(e.ctx()); st.Active.Enabled {
		t.Fatal("a stale Settings › Scanning › Safety save turned discovery back on")
	}
	old.Version = ""
	old.Active.Exclusions = []string{"10.142.0.40"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", old); err != nil { // optional there: the old page sends none
		t.Fatalf("PUT /inventory/settings without a version: %v", err)
	}
}

// INV-32 (#842): POST /scanning/safety/exclusions adds one exclusion in one transaction with the rule of a PUT, changes nothing for
// an entry already covered, refuses growing past 200 with 409, keeps the attestation, and is audited and announced like the PUT.
func TestContract_INV32_AddExclusion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.142.0.0/24")
	for _, raw := range []string{"10.142.0.5/28", "bogus", "", "fe80::1"} {
		_, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", raw)
		wantAPIError(t, err, 400, "bad_exclusion")
	}
	before, _ := e.svc.Settings(e.ctx())
	e.ev.reset()
	saved, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", " 10.142.0.64/28 ")
	if err != nil || !slices.Equal(saved.Active.Exclusions, []string{"10.142.0.64/28"}) || !saved.Active.Enabled {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if saved.ScopeConfirmedAt == nil || *saved.ScopeConfirmedAt != *before.ScopeConfirmedAt {
		t.Fatalf("the attestation moved: %v", saved.ScopeConfirmedAt)
	}
	if len(e.ev.named(inventory.EventSettingsChanged)) != 1 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND detail = 'added exclusion 10.142.0.64/28: 1 exclusions'`) != 1 {
		t.Fatal("no event or audit row naming the exclusion")
	}
	e.ev.reset()
	rows := e.count(`SELECT count(*) FROM core_audit`)
	for _, raw := range []string{"10.142.0.64/28", "10.142.0.70", "10.142.0.72/29"} {
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
	_, err = e.svc.AddExclusion(e.ctx(), "admin@acme.example", "10.142.0.9")
	wantAPIError(t, err, 400, "too_many_exclusions")
	if _, err := e.svc.AddExclusion(e.ctx(), "admin@acme.example", "10.142.0.65"); err != nil {
		t.Fatalf("a covered entry at the limit: %v", err)
	}
}

// INV-32 (#842): adds at once never overwrite each other. Exclusions all land. A range add confirms only the list its dialog
// showed (review #860 H1), so of eight range adds built on the same list one lands and the others are refused with 409
// scope_changed and nothing stored; resent with the list they now show, each lands.
func TestContract_INV32_ConcurrentAddsKeepBoth(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.142.0.0/24")
	const n = 8
	var wg sync.WaitGroup
	rangeErrs := make([]error, n)
	exclErrs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			_, rangeErrs[i] = e.addRange("admin@acme.example", "10."+strconv.Itoa(i)+".0.0/16", []string{"10.142.0.0/24"}, true)
		})
		wg.Go(func() {
			_, exclErrs[i] = e.svc.AddExclusion(e.ctx(), "admin@acme.example", "10.142.0."+strconv.Itoa(i+1))
		})
	}
	wg.Wait()
	landed := 0
	for i := range n {
		if exclErrs[i] != nil {
			t.Fatal(exclErrs[i])
		}
		if rangeErrs[i] == nil {
			landed++
			continue
		}
		wantAPIError(t, rangeErrs[i], 409, "scope_changed")
	}
	st, _ := e.svc.Settings(e.ctx())
	if landed != 1 || len(st.LANRanges) != 2 || len(st.Active.Exclusions) != n {
		t.Fatalf("landed %d: ranges %v, exclusions %v", landed, st.LANRanges, st.Active.Exclusions)
	}
	for i := range n {
		if rangeErrs[i] == nil {
			continue
		}
		saved, err := e.addRange("admin@acme.example", "10."+strconv.Itoa(i)+".0.0/16", st.LANRanges, true)
		if err != nil {
			t.Fatal(err)
		}
		st = saved.Settings
	}
	if len(st.LANRanges) != n+1 {
		t.Fatalf("lost an add: ranges %v", st.LANRanges)
	}
	if got := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.settings' AND (detail LIKE 'added range%' OR detail LIKE 'added exclusion%')`); got != 2*n {
		t.Fatalf("audit rows = %d", got)
	}
}

// review #860 r2 M1: the dialog echoes the confirmation it showed. The same list, unconfirmed or confirmed again by another admin
// since the dialog opened, is 409 scope_changed: the tick never re-confirms a scope someone withdrew while the dialog was open.
func TestContract_INV32_AddRangeEchoesTheConfirmationShown(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("10.0.0.0/8", "192.168.10.0/24")
	opened, _ := e.svc.Settings(e.ctx())                // 09:00: B's dialog shows the scope confirmed by A
	shown := []string{"192.168.10.5/24", " 10.0.0.0/8"} // any order, as networks (r2 I1)
	add := inventory.RangeAdd{Range: "192.168.50.0/24", Shown: shown, ShownConfirmedAt: opened.ScopeConfirmedAt, Confirmed: true}

	// 10:00: A withdraws the attestation for the same ranges
	if err := e.svc.SetDiscovery(e.ctx(), "admin@acme.example", false); err != nil {
		t.Fatal(err)
	}
	in := okSafety()
	in.LANRanges, in.Confirmed = opened.LANRanges, false
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	// 11:00: B's add from the open dialog is refused, nothing stored
	_, err := e.svc.AddRange(e.ctx(), "b@acme.example", add)
	wantAPIError(t, err, 409, "scope_changed")
	var ch *inventory.Changed
	if !errors.As(err, &ch) || ch.Current.ScopeConfirmedAt != nil {
		t.Fatalf("the refusal does not carry the current block: %v", err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.ScopeConfirmedAt != nil || len(st.LANRanges) != 2 {
		t.Fatalf("the withdrawn scope was confirmed again: %+v", st)
	}
	// a dialog that showed it unconfirmed may confirm it, and says so
	add.ShownConfirmedAt = nil
	saved, err := e.svc.AddRange(e.ctx(), "b@acme.example", add)
	if err != nil || saved.ScopeConfirmedAt == nil || *saved.ScopeConfirmedBy != "b@acme.example" || len(saved.LANRanges) != 3 {
		t.Fatalf("shown unconfirmed: %+v, %v", saved, err)
	}
	// unconfirmed and confirmed again by someone else since the dialog opened (another time): refused too
	in.LANRanges, in.Confirmed = saved.LANRanges, false
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour)
	in.Confirmed = true
	if again, err := e.saveSafety(in); err != nil || *again.ScopeConfirmedAt == *saved.ScopeConfirmedAt {
		t.Fatalf("confirmed again: %+v, %v", again, err)
	}
	_, err = e.svc.AddRange(e.ctx(), "b@acme.example", inventory.RangeAdd{Range: "192.168.60.0/24", Shown: saved.LANRanges, ShownConfirmedAt: saved.ScopeConfirmedAt, Confirmed: true})
	wantAPIError(t, err, 409, "scope_changed")
}
