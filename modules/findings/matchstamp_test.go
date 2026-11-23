package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/winrel"
)

// twin is two databases fed the same devices and catalogue: one service keeps its match stamps from pass to pass (it skips the
// devices nothing changed for), the other is made afresh before every pass (it matches every device). After every pass both must
// hold the same rows: a device skipped wrongly would differ.
type twin struct {
	t          *testing.T
	inv        *fakeInv
	feeds      *fakeFeeds
	skip, full *env
	svc        *Service // skip's service, kept from pass to pass
}

func newTwin(t *testing.T) *twin {
	t.Helper()
	assets := equivAssets(t)
	inv := &fakeInv{match: map[string]Asset{}, assets: map[string]AssetView{}}
	for _, a := range assets {
		inv.match[a.ID] = a
		inv.assets[a.ID] = AssetView{ID: a.ID, IP: "192.0.2.1", Kind: "server", Display: a.Name}
	}
	feeds := &fakeFeeds{vulns: equivPassVulns(t, assets)}
	w := &twin{t: t, inv: inv, feeds: feeds, skip: newEnv(t), full: newEnv(t)}
	for _, e := range []*env{w.skip, w.full} {
		e.inv, e.feeds = inv, feeds
	}
	w.svc = w.skip.reconciler(w.skip.pub, inv)
	return w
}

// pass runs both passes and compares the rows; it returns the stamped service's result.
func (w *twin) pass() ReconcileResult {
	w.t.Helper()
	r, err := w.svc.Reconcile(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.full.reconciler(w.full.pub, w.inv).Reconcile(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
	got, want := w.skip.passRows(), w.full.passRows()
	g, _ := json.Marshal(got)
	f, _ := json.Marshal(want)
	if string(g) != string(f) {
		w.t.Fatalf("the pass that skips unchanged devices left other rows than a full pass (%d/%d findings, %d/%d events, %d/%d questions)",
			len(got.Findings), len(want.Findings), len(got.Events), len(want.Events), len(got.Questions), len(want.Questions))
	}
	return r
}

func (w *twin) advance(d time.Duration) {
	w.skip.advance(d)
	w.full.advance(d)
}

// change edits device id in the inventory both databases read.
func (w *twin) change(id string, edit func(*Asset)) {
	w.inv.mu.Lock()
	defer w.inv.mu.Unlock()
	a := w.inv.match[id]
	a.Software = slices.Clone(a.Software)
	edit(&a)
	w.inv.match[id] = a
}

// both runs fn on each database's own service.
func (w *twin) both(fn func(e *env, svc *Service)) {
	fn(w.skip, w.svc)
	fn(w.full, w.full.reconciler(w.full.pub, w.inv))
}

// The hourly pass matches no device again when nothing it reads moved: the second pass finds every device up to date and writes the
// same rows a full pass writes; a day later every device is matched in full again.
func TestMatchStamp_AnUnchangedDeviceIsNotMatchedAgain(t *testing.T) {
	t.Parallel()
	w := newTwin(t)
	n := len(w.inv.match)
	if r := w.pass(); r.Devices != n || r.Unchanged != 0 {
		t.Fatalf("first pass: %+v, want %d devices matched in full", r, n)
	}
	w.advance(time.Hour)
	if r := w.pass(); r.Devices != n || r.Unchanged != n {
		t.Fatalf("an hour later, nothing changed: %+v, want all %d unchanged", r, n)
	}
	w.advance(25 * time.Hour)
	if r := w.pass(); r.Unchanged != 0 {
		t.Fatalf("a day later: %+v, want every device matched in full", r)
	}
	// A service that starts afresh (the stamps live in memory) matches every device.
	w.svc = w.skip.reconciler(w.skip.pub, w.inv)
	w.advance(time.Hour)
	if r := w.pass(); r.Unchanged != 0 {
		t.Fatalf("after a restart: %+v, want every device matched in full", r)
	}
}

// Every change a device's match reads makes the pass match that device again, and the rows are those of a full pass: its software (a
// version moved, a line removed, a line added), its OS, it being ignored and watched again, a merge into it, a person's decision on one
// of its findings, and the catalogue (an entry's range, a new entry, an entry gone). A device nothing touched stays unchanged.
func TestMatchStamp_EveryChangeMatchesTheDeviceAgain(t *testing.T) {
	t.Parallel()
	w := newTwin(t)
	n := len(w.inv.match)
	w.pass()
	w.advance(time.Hour)
	w.pass()
	step := func(name string, want []string, do func()) { // passes 10 minutes apart: no step crosses midnight (a new day matches all)
		t.Helper()
		w.advance(10 * time.Minute)
		do()
		r := w.pass()
		if r.Devices-r.Unchanged != len(want) {
			t.Fatalf("%s: %d of %d devices matched again (%+v), want %d: %v", name, r.Devices-r.Unchanged, r.Devices, r, len(want), want)
		}
		w.advance(10 * time.Minute)
		if r := w.pass(); r.Unchanged != r.Devices {
			t.Fatalf("%s: the pass after it matched %d devices again, want none", name, r.Devices-r.Unchanged)
		}
	}
	step("version moved", []string{"eq-fortigate"}, func() {
		w.change("eq-fortigate", func(a *Asset) {
			a.Software[0].Version, a.Software[0].CPE = "7.4.8", "cpe:2.3:o:fortinet:fortios:7.4.8:*:*:*:*:*:*:*"
		})
	})
	step("line removed", []string{"eq-ubuntu"}, func() {
		w.change("eq-ubuntu", func(a *Asset) { a.Software = slices.Delete(a.Software, 1, 2) })
	})
	step("line added", []string{"eq-ssh"}, func() {
		w.change("eq-ssh", func(a *Asset) {
			a.Software = append(a.Software, Software{ID: "s-photo", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station",
				Version: "6.0.0", Source: "agent", KevKeys: []string{"qnap|photo station"}})
		})
	})
	step("OS changed", []string{"eq-debian"}, func() {
		w.change("eq-debian", func(a *Asset) { a.OS = "Ubuntu 24.04.1 LTS" })
	})
	var kept Asset
	step("ignored", nil, func() {
		w.inv.mu.Lock()
		kept = w.inv.match["eq-iphone"]
		delete(w.inv.match, "eq-iphone")
		w.inv.ignored = map[string]bool{"eq-iphone": true}
		w.inv.mu.Unlock()
	})
	step("watched again", []string{"eq-iphone"}, func() {
		w.inv.mu.Lock()
		w.inv.match["eq-iphone"] = kept
		w.inv.ignored = nil
		w.inv.mu.Unlock()
	})
	step("merged", []string{"eq-fortigate"}, func() {
		w.inv.mu.Lock()
		from, into := w.inv.match["eq-forti-nmap"], w.inv.match["eq-fortigate"]
		into.Software = append(slices.Clone(into.Software), from.Software...)
		w.inv.match["eq-fortigate"] = into
		delete(w.inv.match, "eq-forti-nmap")
		w.inv.mu.Unlock()
		m := lifecycle.Merge{From: "eq-forti-nmap", Into: "eq-fortigate", FromName: "eq-forti-nmap", IntoName: "eq-fortigate"}
		w.both(func(e *env, svc *Service) {
			if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return svc.DeviceMerged(t.Context(), tx, m) }); err != nil {
				t.Fatal(err)
			}
			svc.MergeCommitted(t.Context(), m)
		})
	})
	step("a person's decision", []string{"eq-office"}, func() {
		w.both(func(e *env, svc *Service) {
			var id string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = 'eq-office' AND state = 'open' ORDER BY cve LIMIT 1`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.mark(t.Context(), id, "false_positive", "not exposed on this device", "anna"); err != nil {
				t.Fatal(err)
			}
		})
	})
	// An exploited-list entry is compared with every device, so its change matches every device again; a catalogue CVE on no list only
	// the devices whose rows its ranges' vendors name.
	all := func() []string {
		w.inv.mu.Lock()
		defer w.inv.mu.Unlock()
		return slices.Sorted(maps.Keys(w.inv.match))
	}
	reading := func(cve string) []string { // the devices whose entries include cve
		w.inv.mu.Lock()
		defer w.inv.mu.Unlock()
		set := newMatchSet(w.feeds.vulns)
		var out []string
		for id, a := range w.inv.match {
			if slices.ContainsFunc(set.forDevice(a), func(v Vuln) bool { return v.CVE == cve }) {
				out = append(out, id)
			}
		}
		return out
	}
	step("an exploited-list entry's range changed", all(), func() {
		vulns := slices.Clone(w.feeds.vulns)
		i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.Vendor == "Fortinet" && v.Product == "FortiOS" && len(v.Affected) > 0 })
		vulns[i].Affected = []Affected{{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.0.0", EndExcl: "7.9.9"}}}
		w.feeds.vulns = vulns
	})
	ssh := "CVE-2026-900005" // the OpenSSH catalogue CVE on no list (equivVulns)
	if r := reading(ssh); len(r) == 0 || len(r) == len(all()) {
		t.Fatalf("the catalogue CVE is read by %v: the step would test nothing", r)
	}
	step("a catalogue entry's range changed", reading(ssh), func() {
		vulns := slices.Clone(w.feeds.vulns)
		i := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == ssh })
		vulns[i].Affected = []Affected{{CPE: vulns[i].Affected[0].CPE, Range: VersionRange{EndExcl: "99.0"}}}
		w.feeds.vulns = vulns
	})
	step("a catalogue entry added", reading(ssh), func() {
		v := catalogueOnly("CVE-2026-9990003", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "", "99.0")
		w.feeds.vulns = append(slices.Clone(w.feeds.vulns), v)
	})
	step("a catalogue entry gone", reading("CVE-2026-9990003"), func() {
		w.feeds.vulns = slices.DeleteFunc(slices.Clone(w.feeds.vulns), func(v Vuln) bool { return v.CVE == "CVE-2026-9990003" })
	})
	step("an exploited-list entry added", all(), func() {
		w.feeds.vulns = append(slices.Clone(w.feeds.vulns), Vuln{CVE: "CVE-2026-9990002", Vendor: "QNAP", Product: "Photo Station", DateAdded: t0,
			NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}}})
	})
	if r := w.pass(); r.Devices != n-1 { // eq-forti-nmap was merged away
		t.Fatalf("devices: %+v", r)
	}
}

// What Vedette learns of Microsoft's Windows releases and monthly updates is read by the match of every device: learning it again
// matches every device again. Not parallel: it sets the learned updates every test reads.
func TestMatchStamp_LearnedWindowsUpdatesMatchAgain(t *testing.T) {
	w := newTwin(t)
	t.Cleanup(func() { winrel.LearnUpdates(nil) })
	w.pass()
	w.advance(10 * time.Minute)
	if r := w.pass(); r.Unchanged != r.Devices {
		t.Fatalf("nothing changed: %+v", r)
	}
	w.advance(10 * time.Minute)
	winrel.LearnUpdates([]winrel.Update{{Build: 26100, Rev: 9999, KB: "KB5099999", Day: t0.Add(-24 * time.Hour)}})
	if r := w.pass(); r.Unchanged != 0 {
		t.Fatalf("after Windows updates were learned: %+v, want every device matched again", r)
	}
}

// Windows updates learned while a device is being matched (after its match was computed, before its stamp is kept) are not in that
// match: the stamp must say so, and the next pass matches the device again. Not parallel: it sets the learned updates every test reads.
func TestMatchStamp_WindowsUpdatesLearnedDuringAMatchMatchAgain(t *testing.T) {
	w := newTwin(t)
	t.Cleanup(func() { winrel.LearnUpdates(nil) })
	var once sync.Once
	svc, err := NewService(ServiceConfig{DB: w.skip.db, Audit: audit.New(func() time.Time { return *w.skip.clock }), Publisher: w.skip.pub,
		Inventory: w.inv, Feeds: w.feeds, Log: slog.New(slog.DiscardHandler), Clock: func() time.Time { return *w.skip.clock },
		Backlog: func(ctx context.Context) context.Context {
			once.Do(func() { // the first device's match is computed; its writes have not run yet
				winrel.LearnUpdates([]winrel.Update{{Build: 26100, Rev: 9999, KB: "KB5099999", Day: t0.Add(-24 * time.Hour)}})
			})
			return context.WithValue(ctx, baselineKey{}, true)
		}})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	if _, err := svc.Reconcile(t.Context()); err != nil { // its first device was matched with the updates as they were before
		t.Fatal(err)
	}
	w.advance(10 * time.Minute)
	r, err := svc.Reconcile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if r.Unchanged == r.Devices {
		t.Fatalf("after updates were learned during the last pass: %+v, want the device matched before them matched again", r)
	}
}
