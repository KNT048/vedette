package ids

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
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
type fakeFindings struct {
	open  map[[2]string]string
	calls *atomic.Int32
}

func (f fakeFindings) Linked(_ context.Context, byDevice map[string][]string) (map[string][]LinkedFinding, error) {
	f.calls.Add(1)
	out := map[string][]LinkedFinding{}
	for asset, cves := range byDevice {
		for _, c := range cves {
			if id, ok := f.open[[2]string{asset, c}]; ok {
				out[asset] = append(out[asset], LinkedFinding{ID: id, CVE: c, Status: "under_attack", Affected: true})
			}
		}
	}
	return out, nil
}

// fakeIncidents answers as notify does: every key has an open incident, except the keys a test resolved (at that time).
type fakeIncidents struct {
	mu       sync.Mutex
	resolved map[[2]string]time.Time
}

func (*fakeIncidents) Intrusion(_ context.Context, source, target string, _ time.Time) (IncidentRef, bool, error) {
	return IncidentRef{ID: "in-" + source + "|" + target, Status: "new"}, true, nil
}

func (f *fakeIncidents) ResolvedSince(_ context.Context, ev AlertEvent, since time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.resolved[[2]string{ev.Source, ev.Target}]
	return ok && !at.Before(since), nil
}

// resolve is a person resolving the incident of a key at a time.
func (f *fakeIncidents) resolve(source, target string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolved == nil {
		f.resolved = map[[2]string]time.Time{}
	}
	f.resolved[[2]string{source, target}] = at
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
	inc  *fakeIncidents
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: inventory.Migrations},
		storetest.Migration{Module: "ids", FS: Migrations})
	e := &env{t: t, db: db, now: time.Date(2026, 11, 20, 10, 30, 0, 0, time.UTC), ev: &recorder{}, mods: &switchModules{}, inc: &fakeIncidents{}}
	ts := store.FormatTS(e.now.Add(-48 * time.Hour))
	for ip, d := range testDevices {
		e.exec(`INSERT INTO inv_asset (id, ip, kind, origin, first_seen, last_seen) VALUES (?, ?, 'server', 'manual', ?, ?)`, d.id, ip, ts, ts)
	}
	e.exec(`INSERT INTO inv_asset (id, kind, origin, first_seen, last_seen) VALUES ('a-other', 'server', 'manual', ?, ?)`, ts, ts)
	svc, err := NewService(Config{DB: db, Inventory: fakeInventory{}, Findings: fakeFindings{open: map[[2]string]string{{"a-nas", "CVE-2021-44228"}: "f-nas-log4j"}, calls: &atomic.Int32{}},
		Incidents: e.inc, Events: e.ev, Modules: e.mods, Clock: func() time.Time { return e.now }})
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

func (e *env) count(q string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.t.Context(), q).Scan(&n); err != nil {
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
func findingsLayerOne(attacks []Attack, now time.Time, cve string, open bool) string {
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
	if got := findingsLayerOne(attacks, e.now, "CVE-2021-44228", true); got != "under_attack" {
		t.Fatalf("the NAS's Log4Shell finding is %s", got)
	}
	if got := findingsLayerOne(attacks, e.now, "CVE-2021-44228", true); got != "under_attack" {
		t.Fatalf("another affected device is %s (any address while affected)", got)
	}
	if got := findingsLayerOne(attacks, e.now, "CVE-2017-0144", true); got != "exploited" {
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
	// The list folds the hours of one alert into one row with every event counted; the overview counts the same rows, and the
	// alert page shows the folded alert whichever hour its id names.
	v, err := e.svc.List(t.Context(), Query{Window: "24h", Sort: "count"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Total != 1 || len(v.Items) != 1 || v.Items[0].Count != 5 || v.Items[0].FirstSeen >= v.Items[0].LastSeen {
		t.Fatalf("folded %+v", v.Items)
	}
	sum, err := e.svc.Summarize(t.Context(), e.now.Add(-24*time.Hour))
	if err != nil || sum.Alerts != v.Total {
		t.Fatalf("summary %+v (%v), list %d rows", sum, err, v.Total)
	}
	var older string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM ids_alert ORDER BY last_ts LIMIT 1`).Scan(&older); err != nil {
		t.Fatal(err)
	}
	a, err := e.svc.Get(t.Context(), older)
	if err != nil || a.Count != 5 || a.ID != v.Items[0].ID || a.FirstSeen != v.Items[0].FirstSeen {
		t.Fatalf("get %+v %v", a, err)
	}
	// another destination is another alert
	other := strings.Replace(l.Line, "-> 10.0.10.5:", "-> 10.0.10.99:", 1)
	if other == l.Line {
		t.Fatal("the fixture line names another destination")
	}
	e.offer(time.Minute, [2]string{l.Kind, other})
	if v, _ = e.svc.List(t.Context(), Query{Window: "24h"}); v.Total != 2 {
		t.Fatalf("%d rows for two destinations", v.Total)
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
	if len(e.ev.got) != 1 { // one source naming one CVE: one incident key, announced once
		t.Fatalf("%d announced, want 1", len(e.ev.got))
	}
}

// fortiLine is a FortiGate IPS line (severity high: priority 2, a medium alert) from src to dst naming Log4Shell.
func fortiLine(src, dst string) [2]string {
	return [2]string{"fortigate", `<185>logid="0419016384" type="utm" subtype="ips" severity="high" srcip=` + src + ` dstip=` + dst +
		` proto=6 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" dstport=443 attackid=51006 cve="CVE-2021-44228"`}
}

// A forged flood: UDP syslog can be sent by any LAN host posing as the firewall, each line with another source address. Every alert is
// stored, but notify gets at most AlertEventsPerHour announcements in the hour and one summary; the alerts at an affected device are
// announced first, whatever the order the lines came in, and the order is the same every time.
func TestAFloodOfForgedSourcesIsAnnouncedWithinTheHourlyBudgetMostSevereFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var flood [][2]string
	for i := range 500 {
		flood = append(flood, fortiLine("198.51.100."+strconv.Itoa(i%250+1), "10.0.10."+strconv.Itoa(100+i/250)))
	}
	flood = append(flood, fortiLine("192.0.2.7", "10.0.10.21"), fortiLine("192.0.2.8", "10.0.10.21"))
	e.offer(time.Minute, flood...)
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 502 {
		t.Fatalf("%d alerts stored, want 502", n)
	}
	got := e.ev.got
	if len(got) != AlertEventsPerHour+1 {
		t.Fatalf("%d announced, want %d and one summary", len(got), AlertEventsPerHour)
	}
	if got[0].Severity != "critical" || got[1].Severity != "critical" || got[0].Source != "192.0.2.7" || got[1].Source != "192.0.2.8" {
		t.Fatalf("the alerts at the affected NAS are not first: %+v %+v", got[0], got[1])
	}
	last := got[len(got)-1]
	if last.Source != "ids" || !strings.HasPrefix(last.Target, summaryTarget+" ") || last.Link != "/detection" || last.Severity != "medium" ||
		!strings.HasPrefix(last.Title, "At least ") {
		t.Fatalf("summary %+v", last)
	}
	// more in the same hour: no announcement, no second summary
	e.offer(time.Minute, fortiLine("198.51.100.251", "10.0.10.110"))
	if len(e.ev.got) != AlertEventsPerHour+1 {
		t.Fatalf("%d announced after the budget ran out", len(e.ev.got))
	}
	// the next hour has a budget again
	e.now = e.now.Add(time.Hour)
	e.offer(0, fortiLine("198.51.100.252", "10.0.10.110"))
	if len(e.ev.got) != AlertEventsPerHour+2 {
		t.Fatalf("%d announced in the next hour", len(e.ev.got))
	}
}

// The budget is spent on forged medium alerts, then a real attack on the affected NAS comes in a later flush of the same hour. It is
// not announced one by one, but the hour's summary is announced again at critical (notify raises it), with the count kept current;
// a later medium leftover does not announce it again.
func TestACriticalAlertAfterTheBudgetRaisesTheHoursSummary(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var flood [][2]string
	for i := range AlertEventsPerHour + 1 {
		flood = append(flood, fortiLine("198.51.100."+strconv.Itoa(i+1), "10.0.10.150"))
	}
	e.offer(2*time.Minute, flood...)
	if n := len(e.ev.got); n != AlertEventsPerHour+1 || e.ev.got[n-1].Severity != "medium" || !strings.HasPrefix(e.ev.got[n-1].Title, "At least 1 more") {
		t.Fatalf("after the flood: %d announced, last %+v", n, e.ev.got[n-1])
	}
	summary := e.ev.got[AlertEventsPerHour]
	e.offer(time.Minute, fortiLine("192.0.2.66", "10.0.10.21"))
	if n := len(e.ev.got); n != AlertEventsPerHour+2 {
		t.Fatalf("%d announced after the attack on the affected NAS, want the summary again", n)
	}
	raised := e.ev.got[AlertEventsPerHour+1]
	if raised.Source != summary.Source || raised.Target != summary.Target || raised.Severity != "critical" ||
		!strings.HasPrefix(raised.Title, "At least 2 more intrusion alerts this hour, including attacks on affected devices") {
		t.Fatalf("raised summary %+v", raised)
	}
	e.offer(0, fortiLine("198.51.100.200", "10.0.10.150"))
	if n := len(e.ev.got); n != AlertEventsPerHour+2 {
		t.Fatalf("a medium leftover announced the summary again: %d", n)
	}
}

// One incident per (CVE, attacker): when the attacker hits a device that is not affected and the affected NAS, the incident is
// announced critical, in one flush (the affected alert is announced first and the other repeats it) and across flushes (a repeat
// whose severity rose is announced again, so notify raises the incident; one that did not rise is not).
func TestARepeatAtAnAffectedDeviceRaisesTheIncident(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.offer(time.Minute, fortiLine("198.51.100.9", "10.0.10.5"), fortiLine("198.51.100.9", "10.0.10.21"))
	if len(e.ev.got) != 1 || e.ev.got[0].Severity != "critical" {
		t.Fatalf("same flush: %+v", e.ev.got)
	}
	e2 := newEnv(t)
	e2.offer(time.Minute, fortiLine("198.51.100.9", "10.0.10.5"))
	e2.offer(time.Minute, fortiLine("198.51.100.9", "10.0.10.5")) // the same again: not announced
	e2.offer(0, fortiLine("198.51.100.9", "10.0.10.21"))
	sev := []string{}
	for _, ev := range e2.ev.got {
		sev = append(sev, ev.Severity)
	}
	if !slices.Equal(sev, []string{"medium", "critical"}) || e2.ev.got[0].Target != e2.ev.got[1].Target {
		t.Fatalf("across flushes: %v %+v", sev, e2.ev.got)
	}
}

// A person resolved the intrusion incident and the attacker goes on in the same clock hour: the repeat is announced again (notify opens a
// new incident and sends it), once; while that new incident is open the repeats wait again. Without the resolve nothing more is
// announced in the hour.
func TestARepeatAfterItsIncidentWasResolvedIsAnnouncedAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.offer(time.Minute, fortiLine("198.51.100.9", "10.0.10.5"))
	e.now = e.now.Add(5 * time.Second)
	e.offer(0, fortiLine("198.51.100.9", "10.0.10.5"))
	if len(e.ev.got) != 1 {
		t.Fatalf("%d announced while the incident is open, want 1", len(e.ev.got))
	}
	first := e.ev.got[0]
	e.now = e.now.Add(5 * time.Second)
	e.inc.resolve(first.Source, first.Target, e.now)
	e.now = e.now.Add(5 * time.Second)
	e.offer(0, fortiLine("198.51.100.9", "10.0.10.5"), fortiLine("198.51.100.9", "10.0.10.6"))
	if len(e.ev.got) != 2 || e.ev.got[1].Source != first.Source || e.ev.got[1].Target != first.Target {
		t.Fatalf("after the resolve: %d announced %+v, want the repeat announced once", len(e.ev.got), e.ev.got)
	}
	e.now = e.now.Add(5 * time.Second)
	e.offer(0, fortiLine("198.51.100.9", "10.0.10.5"))
	if len(e.ev.got) != 2 {
		t.Fatalf("%d announced while the new incident is open, want 2", len(e.ev.got))
	}
	if n := e.count(`SELECT sum(count) FROM ids_alert`); n != 5 {
		t.Fatalf("%d events counted, want 5", n)
	}
}

// The hourly budget holds for a repeat after a resolve: once AlertEventsPerHour announcements are spent, the repeat goes into the hour's
// summary like any other alert. A summary a person resolved while the flood goes on is announced again (a new incident), once per
// resolve.
func TestTheBudgetHoldsForARepeatAfterAResolveAndAResolvedSummaryComesBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var flood [][2]string
	for i := range AlertEventsPerHour {
		flood = append(flood, fortiLine("198.51.100."+strconv.Itoa(i+1), "10.0.10.150"))
	}
	e.offer(2*time.Minute, flood...)
	if len(e.ev.got) != AlertEventsPerHour {
		t.Fatalf("%d announced, want the whole budget", len(e.ev.got))
	}
	e.now = e.now.Add(time.Second)
	e.inc.resolve(e.ev.got[0].Source, e.ev.got[0].Target, e.now)
	e.now = e.now.Add(time.Second)
	e.offer(0, fortiLine("198.51.100.1", "10.0.10.150"))
	if n := len(e.ev.got); n != AlertEventsPerHour+1 || e.ev.got[n-1].Source != "ids" {
		t.Fatalf("%d announced, last %+v: want the repeat in the hour's summary", n, e.ev.got[n-1])
	}
	summary := e.ev.got[AlertEventsPerHour]
	e.now = e.now.Add(time.Second)
	e.offer(0, fortiLine("198.51.100.201", "10.0.10.150"))
	if n := len(e.ev.got); n != AlertEventsPerHour+1 {
		t.Fatalf("%d announced: the open summary is announced again", n)
	}
	e.now = e.now.Add(time.Second)
	e.inc.resolve(summary.Source, summary.Target, e.now)
	e.now = e.now.Add(time.Second)
	e.offer(0, fortiLine("198.51.100.202", "10.0.10.150"))
	if n := len(e.ev.got); n != AlertEventsPerHour+2 || e.ev.got[n-1].Target != summary.Target || !strings.HasPrefix(e.ev.got[n-1].Title, "At least 3 more") {
		t.Fatalf("%d announced, last %+v: want the resolved summary announced again", n, e.ev.got[n-1])
	}
	e.now = e.now.Add(time.Second)
	e.offer(0, fortiLine("198.51.100.203", "10.0.10.150"))
	if n := len(e.ev.got); n != AlertEventsPerHour+2 {
		t.Fatalf("%d announced: the new summary is open, nothing more", n)
	}
}

// A flush whose write fails keeps its alerts for the next one, and the findings are read once per page, not once per device.
func TestAFailedFlushKeepsItsAlertsAndFindingsAreReadOncePerPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Offer(t.Context(), []Line{{Kind: "fortigate", At: e.now, Text: fortiLine("198.51.100.9", "10.0.10.21")[1]}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.svc.Flush(ctx); err == nil {
		t.Fatal("a flush on a cancelled context wrote")
	}
	if err := e.svc.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM ids_alert`); n != 1 {
		t.Fatalf("%d alerts after the failed flush was retried", n)
	}
	e.offer(time.Minute, e.fixtures()...)
	calls := e.svc.cfg.Findings.(fakeFindings).calls
	calls.Store(0)
	if _, err := e.svc.List(t.Context(), Query{Window: "7d"}); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("findings read %d times for one page", n)
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

func TestContract_TablesUseThePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, ModuleID, Migrations, "ids_", storetest.Migration{Module: "core", FS: core.Migrations},
		storetest.Migration{Module: "inventory", FS: inventory.Migrations})
}

// An empty list answers an empty array, never null: the API schema says array, and a null made GET /detection/alerts answer 500
// right after the module was turned on (no alert yet), as it does for a search that matches nothing and a page past the end.
func TestAnEmptyAlertListIsAnEmptyArray(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	h := NewIDSHandlers(e.svc)
	for name, p := range map[string]oas.DetectionGetDetectionAlertsParams{
		"no alert yet":     {Window: oas.DetectionGetDetectionAlertsWindow7d},
		"a page past them": {Window: oas.DetectionGetDetectionAlertsWindow24h, Offset: oas.NewOptString("50")},
	} {
		out, err := h.DetectionGetDetectionAlerts(t.Context(), p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out.Items == nil || len(out.Items) != 0 || out.Total != 0 {
			t.Fatalf("%s: %+v", name, out)
		}
	}
}
