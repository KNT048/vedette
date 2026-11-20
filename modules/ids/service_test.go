package ids

import (
	"context"
	"errors"
	"database/sql"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// The test network: the attacked devices of the fixtures (documentation and private addresses only).
var testDevices = map[string]struct{ id, name string }{
	"10.0.10.21":  {"a-nas", "nas-01"},
	"10.0.10.5":   {"a-app", "app-01"},
	"10.0.10.10":  {"a-dc", "dc-01"},
	"10.0.10.113": {"a-pc", "pc-113"},
}

type fakeInventory struct{}

func (fakeInventory) DevicesAt(_ context.Context, ips []string) (map[string]string, error) {
	out := map[string]string{}
	for _, ip := range ips {
		if d, ok := testDevices[ip]; ok {
			out[ip] = d.id
		}
	}
	return out, nil
}

func (fakeInventory) Names(_ context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, d := range testDevices {
		if slices.Contains(ids, d.id) {
			out[d.id] = d.name
		}
	}
	return out, nil
}

// fakeFindings holds open findings by device and CVE: the NAS is affected by Log4Shell.
type fakeFindings struct{ open map[[2]string]string }

func (f fakeFindings) Linked(_ context.Context, asset string, cves []string) ([]LinkedFinding, error) {
	var out []LinkedFinding
	for _, c := range cves {
		if id, ok := f.open[[2]string{asset, c}]; ok {
			out = append(out, LinkedFinding{ID: id, CVE: c, Status: "under_attack", Affected: true})
		}
	}
	return out, nil
}

type fakeIncidents struct{}

func (fakeIncidents) Intrusion(_ context.Context, source, target string, _ time.Time) (IncidentRef, bool, error) {
	return IncidentRef{ID: "in-" + source + "|" + target, Status: "new"}, true, nil
}

type recorder struct {
	mu  sync.Mutex
	got []AlertEvent
}

func (r *recorder) Publish(_ context.Context, e events.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e.Name == EventAlertDetected {
		r.got = append(r.got, e.Data.(AlertEvent))
	}
	return nil
}

type switchModules struct{ off bool }

func (m *switchModules) Enabled(string) bool { return !m.off }

type env struct {
	t    *testing.T
	db   *store.DB
	svc  *Service
	now  time.Time
	ev   *recorder
	mods *switchModules
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: inventory.Migrations},
		storetest.Migration{Module: "ids", FS: Migrations})
	e := &env{t: t, db: db, now: time.Date(2026, 11, 20, 10, 30, 0, 0, time.UTC), ev: &recorder{}, mods: &switchModules{}}
	ts := store.FormatTS(e.now.Add(-48 * time.Hour))
	for ip, d := range testDevices {
		e.exec(`INSERT INTO inv_asset (id, ip, kind, origin, first_seen, last_seen) VALUES (?, ?, 'server', 'manual', ?, ?)`, d.id, ip, ts, ts)
	}
	e.exec(`INSERT INTO inv_asset (id, kind, origin, first_seen, last_seen) VALUES ('a-other', 'server', 'manual', ?, ?)`, ts, ts)
	svc, err := NewService(Config{DB: db, Inventory: fakeInventory{}, Findings: fakeFindings{open: map[[2]string]string{{"a-nas", "CVE-2021-44228"}: "f-nas-log4j"}},
		Incidents: fakeIncidents{}, Events: e.ev, Modules: e.mods, Clock: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if err := e.db.Write(e.t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.t.Context(), q, args...); return err }); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.t.Context(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// offer hands lines to the service as the logs module does, received at e.now minus ago.
func (e *env) offer(ago time.Duration, kindLines ...[2]string) {
	var ls []Line
	for _, kl := range kindLines {
		ls = append(ls, Line{SourceID: "ls-1", SourceName: "fw-edge", Kind: kl[0], At: e.now.Add(-ago), Text: kl[1]})
	}
	e.svc.Offer(e.t.Context(), ls)
	if err := e.svc.Flush(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) fixtures() [][2]string {
	var out [][2]string
	for _, f := range fixtureLines(e.t) {
		out = append(out, [2]string{f.Kind, f.Line})
	}
	return out
}

// The done check of the module: the fixture lines of every vendor profile become alerts with their CVE ids, one per IPS line, none
// for the other lines; and an alert naming a CVE the attacked device is affected by is critical, its finding under attack.
func TestFixtureLinesBecomeAlertsWithTheirCVEs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.offer(time.Minute, e.fixtures()...)
	want, withCVE := 0, 0
	for _, f := range fixtureLines(t) {
		if f.Want != nil {
			want++
			if len(f.Want.CVEs) > 0 {
				withCVE++
			}
		}
	}
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != want {
		t.Fatalf("%d alerts, want %d (one per IPS line)", n, want)
	}
	if n := e.count(`SELECT count(DISTINCT alert_id) FROM ids_alert_cve`); n != withCVE {
		t.Fatalf("%d alerts with CVE ids, want %d", n, withCVE)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert WHERE source <> 'log'`); n != 0 {
		t.Fatalf("%d alerts with another source", n)
	}
	v, err := e.svc.List(t.Context(), Query{Window: "24h", CVE: "cve-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Total != 3 { // FortiGate (at the NAS), Suricata (at the app server), SonicWall (at the NAS)
		t.Fatalf("Log4Shell alerts %d: %+v", v.Total, v.Items)
	}
	nas := 0
	for _, a := range v.Items {
		if a.DstDevice != nil && a.DstDevice.ID == "a-nas" {
			nas++
			if a.Severity != "critical" || len(a.Findings) != 1 || a.Findings[0].ID != "f-nas-log4j" || a.Findings[0].Status != "under_attack" || a.Findings[0].Device.Name != "nas-01" {
				t.Errorf("alert at the affected NAS: %+v", a)
			}
		} else if a.Severity == "critical" || len(a.Findings) != 0 {
			t.Errorf("alert at a device that is not affected: %+v", a)
		}
		if a.Incident == nil || !strings.HasPrefix(a.Incident.ID, "in-"+a.SrcIP+"|cve:CVE-2021-44228") {
			t.Errorf("incident %+v", a.Incident)
		}
	}
	if nas != 2 {
		t.Fatalf("%d alerts at the NAS", nas)
	}
	// every stored alert was announced; the ones at the NAS as critical, with the device
	if len(e.ev.got) != want {
		t.Fatalf("%d events, want %d", len(e.ev.got), want)
	}
	for _, ev := range e.ev.got {
		atNAS := slices.ContainsFunc(ev.Devices, func(d DeviceRef) bool { return d.ID == "a-nas" })
		if atNAS && strings.Contains(ev.Target, "CVE-2021-44228") && ev.Severity != "critical" {
			t.Errorf("event at the affected NAS not critical: %+v", ev)
		}
		if !strings.HasPrefix(ev.Link, "/detection/alerts/ida-") || len([]rune(ev.Title)) > 200 || ev.Source == "" || ev.Target == "" {
			t.Errorf("event %+v", ev)
		}
	}
}

// findingsLayerOne stands in for the findings module's consumer of the port (its urgency function, layer 1): an open finding is under
// attack when an alert in the last 14 days names its CVE aimed at its device, or at any address while the device is affected.
func findingsLayerOne(attacks []Attack, now time.Time, device, cve string, open bool) string {
	if !open {
		return "handled"
	}
	for _, a := range attacks {
		if a.CVE == cve && now.Sub(a.LastSeen) <= AttackWindow {
			return "under_attack"
		}
	}
	return "exploited"
}

func TestAttackedPortRaisesAnAffectedFindingToUnderAttack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fortigate := fixtureLines(t)[0] // Log4Shell at the NAS
	smb := fixtureLines(t)[1]       // no CVE
	e.offer(time.Hour, [2]string{fortigate.Kind, fortigate.Line}, [2]string{smb.Kind, smb.Line})
	attacks, err := e.svc.Attacked(t.Context(), e.now.Add(-AttackWindow))
	if err != nil {
		t.Fatal(err)
	}
	if len(attacks) != 1 || attacks[0].CVE != "CVE-2021-44228" || attacks[0].DstIP != "10.0.10.21" || attacks[0].DstAssetID != "a-nas" || attacks[0].Events != 1 || attacks[0].LastAlertID == "" {
		t.Fatalf("attacks %+v", attacks)
	}
	if got := findingsLayerOne(attacks, e.now, "a-nas", "CVE-2021-44228", true); got != "under_attack" {
		t.Fatalf("the NAS's Log4Shell finding is %s", got)
	}
	if got := findingsLayerOne(attacks, e.now, "a-other", "CVE-2021-44228", true); got != "under_attack" {
		t.Fatalf("another affected device is %s (any address while affected)", got)
	}
	if got := findingsLayerOne(attacks, e.now, "a-nas", "CVE-2017-0144", true); got != "exploited" {
		t.Fatalf("a CVE nobody fired is %s", got)
	}
	// 15 days later the attack is no longer recent
	later, err := e.svc.Attacked(t.Context(), e.now.Add(15*24*time.Hour-AttackWindow))
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 0 {
		t.Fatalf("old attack still read: %+v", later)
	}
}

func TestOneAlertPerSignatureSourceDestinationAndHour(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	l := fixtureLines(t)[4] // Suricata Log4Shell at the app server
	e.offer(10*time.Minute, [2]string{l.Kind, l.Line}, [2]string{l.Kind, l.Line}, [2]string{l.Kind, l.Line})
	e.offer(5*time.Minute, [2]string{l.Kind, l.Line})
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 1 {
		t.Fatalf("%d alerts", n)
	}
	if n := e.count(`SELECT count FROM ids_alert`); n != 4 {
		t.Fatalf("count %d", n)
	}
	e.offer(2*time.Hour, [2]string{l.Kind, l.Line}) // an earlier hour
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 2 {
		t.Fatalf("%d alerts after another hour", n)
	}
	v, err := e.svc.List(t.Context(), Query{Window: "24h", Sort: "count"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Total != 2 || v.Items[0].Count != 4 || v.Items[1].Count != 1 {
		t.Fatalf("by count %+v", v.Items)
	}
}

func TestListFiltersSearchesAndPages(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.offer(time.Minute, e.fixtures()...)
	ctx := t.Context()
	all, err := e.svc.List(ctx, Query{Window: "7d"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSortedFunc(all.Items, func(a, b Alert) int { return strings.Compare(b.LastSeen, a.LastSeen) }) {
		t.Fatal("not newest first")
	}
	for q, want := range map[Query]int{
		{Window: "7d", Q: "nas-01"}:           2, // a device name
		{Window: "7d", Q: "log4"}:             6, // the signature
		{Window: "7d", Q: "2001:db8::10"}:     1, // an address
		{Window: "7d", Q: "cve-2021-42013"}:   1, // a CVE from the metadata only
		{Window: "7d", Device: "a-pc"}:        1, // the source device
		{Window: "7d", Device: "a-dc"}:        1, // the destination device
		{Window: "7d", CVE: "CVE-2022-26134"}: 1,
	} {
		v, err := e.svc.List(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if v.Total != want || len(v.Items) != want {
			t.Errorf("%+v: %d (%d items), want %d", q, v.Total, len(v.Items), want)
		}
	}
	p, err := e.svc.List(ctx, Query{Window: "7d", Offset: 2, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != all.Total || len(p.Items) != 3 || p.Items[0].ID != all.Items[2].ID {
		t.Fatalf("page %+v", p)
	}
	for q, code := range map[Query]string{{Window: "1y"}: "bad_window", {Window: "7d", CVE: "log4j"}: "invalid_cve"} {
		_, err := e.svc.List(ctx, q)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != code {
			t.Errorf("%+v: %v, want %s", q, err, code)
		}
	}
	a, err := e.svc.Get(ctx, all.Items[0].ID)
	if err != nil || a.ID != all.Items[0].ID {
		t.Fatalf("get %v %+v", err, a)
	}
	if _, err := e.svc.Get(ctx, "ida-none"); err == nil {
		t.Fatal("a missing alert was found")
	}
	sum, err := e.svc.Summarize(ctx, e.now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Alerts != all.Total || sum.Affected != 2 || sum.LastEvent.IsZero() {
		t.Fatalf("summary %+v", sum)
	}
}

func TestNothingIsReadWhileTheModuleIsOffAndTheBufferIsBounded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mods.off = true
	e.offer(time.Minute, e.fixtures()...)
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 0 {
		t.Fatalf("%d alerts while off", n)
	}
	e.mods.off = false
	// MaxPending distinct alerts wait at most; the events of more are dropped and counted, never stored late.
	var ls []Line
	for i := range MaxPending + 50 {
		line := strings.Replace(fixtureLines(t)[4].Line, "[1:2034647:2]", "[1:"+strconv.Itoa(1000000+i)+":2]", 1)
		ls = append(ls, Line{Kind: "pfsense", At: e.now, Text: line})
	}
	e.svc.Offer(t.Context(), ls)
	if err := e.svc.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != MaxPending {
		t.Fatalf("%d alerts, want %d", n, MaxPending)
	}
	if len(e.ev.got) != MaxAnnouncedPerFlush {
		t.Fatalf("%d announced, want %d", len(e.ev.got), MaxAnnouncedPerFlush)
	}
}

func TestMergeMovesAndRetentionDeletes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.offer(time.Minute, e.fixtures()...)
	before := e.count(`SELECT count(*) FROM ids_alert WHERE dst_asset_id = 'a-nas'`)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		return e.svc.DeviceMerged(t.Context(), tx, lifecycle.Merge{From: "a-nas", Into: "a-other"})
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert WHERE dst_asset_id = 'a-other'`); n != before || before == 0 {
		t.Fatalf("%d of %d moved", n, before)
	}
	e.exec(`DELETE FROM inv_asset WHERE id = 'a-other'`) // a deleted device leaves its alerts, without the device
	if n := e.count(`SELECT count(*) FROM ids_alert WHERE dst_ip = '10.0.10.21' AND dst_asset_id IS NULL`); n != before {
		t.Fatalf("%d alerts kept without the device, want %d", n, before)
	}
	total := e.count(`SELECT count(*) FROM ids_alert`)
	e.now = e.now.Add((RetentionDays + 1) * 24 * time.Hour)
	if err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 0 || total == 0 {
		t.Fatalf("%d alerts after the retention", n)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert_cve`); n != 0 {
		t.Fatalf("%d CVE rows left", n)
	}
}
