package notify_test

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
)

// firstRunAt moves when notify first ran on the box (the migration takes the real clock).
func (e *env) firstRunAt(at time.Time) {
	e.t.Helper()
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_box SET first_run_at = ?`, store.FormatTS(at))
		return err
	})
}

func (e *env) autoClose() {
	e.t.Helper()
	for _, j := range e.svc.Jobs() {
		if j.Name == "autoclose" {
			if j.Housekeeping || j.Every != time.Hour {
				e.t.Fatalf("job = %+v", j)
			}
			if err := j.Run(e.ctx()); err != nil {
				e.t.Fatal(err)
			}
			return
		}
	}
	e.t.Fatal("no autoclose job")
}

func (e *env) detail(id string) notify.Incident {
	e.t.Helper()
	d, err := e.svc.IncidentDetail(e.ctx(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return d.Incident
}

// INV-22 (D-550): approving a device in Devices (B9's inventory.asset.approved) closes its own new-device incident with the
// approver named and takes it off an open first-discovery summary, as a delete does (INV-20).
func TestApprovedDeviceClosesItsIncidentWithTheApprover(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.Devices = fakeDevices{"a1": "PC-01", "a2": "NAS-01", "a9": "LAPTOP-NEW"} })
	e.firstRunAt(e.clock.Now())
	e.svc.Subscribe(e.bus)
	publish := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, data)); err != nil {
			t.Fatal(err)
		}
	}
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a1", Notify: true})
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a2", Notify: true})
	publish(notify.EventAssetApproved, map[string]string{"asset_id": "a1", "actor": "an@acme.example"})
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Title != "1 device found on your network: approve it in Devices" || l[0].Status != notify.StatusNew {
		t.Fatalf("summary after approving a1 = %+v", l)
	}
	e.clock.Add(37 * time.Hour) // past the first discovery: a device has its own incident
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a9", Notify: true})
	publish(notify.EventAssetApproved, map[string]string{"asset_id": "a9", "actor": "an@acme.example\n\u202e"})
	l, _ = e.svc.Incidents(e.ctx())
	own := l[0]
	if own.Title != "A new unknown device appeared: LAPTOP-NEW" || own.Status != notify.StatusResolved || own.HandledBy == nil || *own.HandledBy != "system" ||
		own.ResolvedReason == nil || *own.ResolvedReason != "Closed by Vedette: the device was approved by an@acme.example." {
		t.Fatalf("own incident = %+v", own)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status' AND user = 'system' AND detail LIKE 'resolved: Closed by Vedette: the device was approved%'`); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	// a person reopening it makes it theirs: Vedette's reason goes
	if d, err := e.svc.HandleIncident(e.ctx(), "u-op", own.ID, notify.StatusNew, ""); err != nil || d.Incident.ResolvedReason != nil {
		t.Fatalf("reopened = %+v, %v", d.Incident, err)
	}
	publish(inventory.EventAssetDeleted, map[string]string{"asset_id": "a2"})
	if i := e.detail(l[1].ID); i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: every device on it was approved or deleted in Devices." {
		t.Fatalf("summary = %+v", i)
	}
}

// INV-22 (D-550): a trap or bad connection quiet for 7 days and a log anomaly quiet for 3 close themselves, acknowledged ones too; a
// repeat keeps an incident open, and a new hit after the close opens a new incident.
func TestQuietIncidentsCloseThemselves(t *testing.T) {
	e := newEnv(t)
	e.firstRunAt(e.clock.Now().AddDate(0, -1, 0)) // not a fresh box
	open := func(kind notify.IncidentKind, src string, sev notify.Severity) (string, bool) {
		t.Helper()
		id, created, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: kind, Source: src, Target: "t", Title: string(kind) + " from " + src, Severity: sev, What: "w", Action: "a", Link: "/logs"})
		if err != nil {
			t.Fatal(err)
		}
		return id, created
	}
	trap, _ := open(notify.IncidentTrap, "10.0.0.5", notify.Critical)
	bad, _ := open(notify.IncidentBadAddress, "logs", notify.High)
	logA, _ := open(notify.IncidentLogAnomaly, "FW-HQ", notify.Medium)
	if _, err := e.svc.HandleIncident(e.ctx(), "u-op", logA, notify.StatusAcknowledged, "looking"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(3*24*time.Hour + time.Minute)
	open(notify.IncidentBadAddress, "logs", notify.High) // a repeat: the bad connection is still happening
	e.autoClose()
	if i := e.detail(logA); i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: no new activity for 3 days after u-op acknowledged it." || i.Note == nil || *i.Note != "looking" {
		t.Fatalf("log anomaly = %+v", i)
	}
	if e.detail(trap).Status != notify.StatusNew || e.detail(bad).Status != notify.StatusNew {
		t.Fatal("a trap or bad connection closed before its week")
	}
	e.clock.Add(4 * 24 * time.Hour)
	e.autoClose()
	if i := e.detail(trap); i.Status != notify.StatusResolved || *i.ResolvedReason != "Closed by Vedette: no new activity for 7 days." {
		t.Fatalf("trap = %+v", i)
	}
	if e.detail(bad).Status != notify.StatusNew {
		t.Fatal("the bad connection seen 4 days ago closed")
	}
	// a person reopens it: the quiet window starts over from the reopen, not from the last hit
	if _, err := e.svc.HandleIncident(e.ctx(), "u-op", trap, notify.StatusNew, ""); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(time.Hour)
	e.autoClose()
	if e.detail(trap).Status != notify.StatusNew {
		t.Fatal("a reopened incident closed again within the hour")
	}
	e.clock.Add(7 * 24 * time.Hour)
	e.autoClose()
	if e.detail(trap).Status != notify.StatusResolved {
		t.Fatal("a reopened incident quiet for a week stayed open")
	}
	if id, created := open(notify.IncidentTrap, "10.0.0.5", notify.Critical); !created || id == trap {
		t.Fatalf("a new hit after the close: id %s created %v", id, created)
	}
	// a hit that carries an old time (a sensor's buffer) is new to the box: not closed in the hour it opens
	old, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "10.0.0.9", Title: "old", Severity: notify.Critical, What: "w", Action: "a", Link: "/logs",
		At: e.clock.Now().AddDate(0, 0, -30)})
	if err != nil {
		t.Fatal(err)
	}
	e.autoClose()
	if e.detail(old).Status != notify.StatusNew {
		t.Fatal("a hit with an old timestamp closed at once")
	}
}

// INV-23 (D-550): in the first 36 hours low and medium bad-connection and log incidents are recorded but told in one hourly summary;
// high, critical and trap incidents go out at once.
func TestFirstRunHoldsLowAndMediumIncidentsForOneSummary(t *testing.T) {
	e := newEnv(t)
	e.firstRunAt(e.clock.Now())
	e.telegram(notify.Low)
	e.plain()
	open := func(kind notify.IncidentKind, src string, sev notify.Severity) string {
		t.Helper()
		id, _, err := e.svc.OpenIncident(context.Background(), notify.IncidentInput{Kind: kind, Source: src, Title: string(kind) + " " + src, Severity: sev, What: "w", Action: "a", Link: "/logs"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	held := []string{open(notify.IncidentBadAddress, "a", notify.Medium), open(notify.IncidentLogAnomaly, "b", notify.Low), open(notify.IncidentLogAnomaly, "c", notify.Medium)}
	open(notify.IncidentBadAddress, "d", notify.High)
	open(notify.IncidentTrap, "e", notify.Medium)
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 2 {
		t.Fatalf("messages at once = %d, want the high one and the trap", n)
	}
	for _, id := range held {
		if i := e.detail(id); !i.FirstRunSummary || len(i.Sends) != 0 {
			t.Fatalf("held = %+v", i)
		}
	}
	e.autoClose()
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 3 || !strings.Contains(calls[2].Body, "First-run summary: 3 new incidents") || !strings.Contains(calls[2].Body, "1 connection to a known-bad address, 2 log anomalies") {
		t.Fatalf("calls = %d, last = %.400s", len(calls), calls[len(calls)-1].Body)
	}
	e.clock.Add(time.Hour)
	e.autoClose()
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 3 {
		t.Fatalf("messages = %d: nothing new was held", n)
	}
	e.clock.Add(36 * time.Hour) // the window is over: a medium incident is sent at once again
	if i := e.detail(open(notify.IncidentLogAnomaly, "f", notify.Medium)); i.FirstRunSummary {
		t.Fatalf("after the window = %+v", i)
	}
}

// INV-23 (D-550, Opus r1 MED-3, LOW-4, LOW-7): a second run in the same hour tells the incidents held since, never colliding with the
// first summary; a held incident that turns high is sent at once and leaves the summary; summaries waiting through quiet hours become
// one.
func TestFirstRunSummaryIsNeverLostAndWaitsAsOne(t *testing.T) {
	e := newEnv(t)
	e.firstRunAt(e.clock.Now())
	e.telegram(notify.Low)
	e.plain()
	open := func(src string, sev notify.Severity) string {
		t.Helper()
		id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentBadAddress, Source: src, Title: "bad " + src, Severity: sev, What: "w", Action: "a", Link: "/logs"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sent := func() []string {
		var out []string
		for _, c := range e.net.to("api.telegram.org") {
			out = append(out, c.Body)
		}
		return out
	}
	open("a", notify.Medium)
	e.autoClose()
	e.flush()
	raised := open("b", notify.Medium)
	open("c", notify.Low)
	open("b", notify.High) // a repeat of b turns it high: sent now, out of the summary
	e.autoClose()          // the same hour: a different set, a different summary
	e.flush()
	if m := sent(); len(m) != 3 || !strings.Contains(m[0], "First-run summary: 1 new incident") || !strings.Contains(m[1], "bad b") || !strings.Contains(m[2], "First-run summary: 1 new incident") {
		t.Fatalf("messages = %q", m)
	}
	if i := e.detail(raised); i.FirstRunSummary || i.Severity != notify.High {
		t.Fatalf("raised = %+v", i)
	}
	e.rules(notify.Quiet{Enabled: true, From: "09:00", To: "18:00"}, notify.Grouping{Enabled: false, WindowMin: 60}) // now is 10:00
	open("d", notify.Medium)
	e.autoClose()
	e.clock.Add(time.Hour)
	open("e", notify.Medium)
	e.autoClose()
	if n := e.count(`SELECT COUNT(*) FROM notify_pending WHERE notice_id GLOB 'fr-*'`); n != 1 {
		t.Fatalf("waiting summaries = %d, want one", n)
	}
	e.clock.Add(8 * time.Hour) // quiet hours are over
	e.flush()
	if m := sent(); len(m) != 4 || !strings.Contains(m[3], "First-run summary: 2 new incidents") {
		t.Fatalf("messages = %q", m)
	}
}

// INV-23 (Opus r2): a summary waiting through quiet hours whose incidents were all resolved meanwhile is dropped, not sent with a stale count.
func TestFirstRunSummaryOfResolvedIncidentsIsDropped(t *testing.T) {
	e := newEnv(t)
	e.firstRunAt(e.clock.Now())
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "09:00", To: "18:00"}, notify.Grouping{Enabled: false, WindowMin: 60}) // now is 10:00
	id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentBadAddress, Source: "a", Title: "bad a", Severity: notify.Medium, What: "w", Action: "a", Link: "/logs"})
	if err != nil {
		t.Fatal(err)
	}
	e.autoClose()
	if i := e.detail(id); i.NotSent == nil || i.NotSent.Reason != notify.UnsentFirstRun || !strings.Contains(i.NotSent.Text, "which no channel has delivered yet") {
		t.Fatalf("not sent = %+v", i.NotSent)
	}
	if _, err := e.svc.HandleIncident(e.ctx(), "u-op", id, notify.StatusResolved, ""); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(time.Hour)
	e.autoClose()
	e.clock.Add(8 * time.Hour)
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("messages = %d: the summary of a resolved incident went out", n)
	}
}

// stateDevices is a DeviceDirectory whose devices a test approves and renames.
type stateDevices struct {
	mu sync.Mutex
	m  map[string]notify.DeviceState
}

func (f *stateDevices) set(id string, st notify.DeviceState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = st
}

func (f *stateDevices) DeviceName(_ context.Context, id string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.m[id]
	return st.Name, ok, nil
}

func (f *stateDevices) DeviceState(_ context.Context, id string) (notify.DeviceState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.m[id]
	return st, ok, nil
}

// D-552 (W8-1, W8-2): a person's Approve publishes inventory.asset.updated, not B9's inventory.asset.approved. The update closes the
// device's own new-device incident and takes it off the first-discovery summary; an update before that renames the incident to the
// name Devices shows. B9's event afterwards names the approver in the reason, without a second close or audit row.
func TestApprovedInDevicesClosesTheNewDeviceIncident(t *testing.T) {
	devs := &stateDevices{m: map[string]notify.DeviceState{
		"a1":  {Name: "PC-01", Address: "10.0.0.1"},
		"a2":  {Name: "NAS-01", Address: "10.0.0.2"},
		"181": {Name: "Hon Hai Precision Ind. Co.,Ltd.", Address: "192.168.18.181"},
	}}
	e := newEnv(t, func(c *notify.Config) { c.Devices = devs })
	e.firstRunAt(e.clock.Now())
	e.svc.Subscribe(e.bus)
	publish := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, data)); err != nil {
			t.Fatal(err)
		}
	}
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a1", Notify: true})
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a2", Notify: true})
	devs.set("a1", notify.DeviceState{Name: "PC-01", Address: "10.0.0.1", Approved: true})
	publish(inventory.EventAssetUpdated, inventory.AssetEvent{AssetID: "a1"})
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Title != "1 device found on your network: approve it in Devices" || l[0].Status != notify.StatusNew ||
		len(l[0].Devices) != 1 || l[0].Devices[0].Name != "NAS-01 (10.0.0.2)" {
		t.Fatalf("summary after approving a1 = %+v", l)
	}
	e.clock.Add(37 * time.Hour) // past the first discovery: a device has its own incident
	publish(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "181", Notify: true})
	l, _ = e.svc.Incidents(e.ctx())
	if l[0].Title != "A new unknown device appeared: Hon Hai Precision Ind. Co.,Ltd. (192.168.18.181)" {
		t.Fatalf("title = %q", l[0].Title)
	}
	devs.set("181", notify.DeviceState{Name: "byn", Address: "192.168.18.181"}) // its host name arrived
	publish(inventory.EventAssetUpdated, inventory.AssetEvent{AssetID: "181"})
	own := e.detail(l[0].ID)
	if own.Status != notify.StatusNew || own.Title != "A new unknown device appeared: byn (192.168.18.181)" ||
		own.What != "A device that is not in your inventory joined the network: byn (192.168.18.181)." || own.Devices[0].Name != "byn (192.168.18.181)" {
		t.Fatalf("renamed = %+v", own)
	}
	devs.set("181", notify.DeviceState{Name: "byn", Address: "192.168.18.181", Approved: true})
	publish(inventory.EventAssetUpdated, inventory.AssetEvent{AssetID: "181"})
	publish(notify.EventAssetApproved, map[string]string{"asset_id": "181", "actor": "an@acme.example"}) // B9, after the update
	publish(inventory.EventAssetUpdated, inventory.AssetEvent{AssetID: "181"})
	own = e.detail(own.ID)
	if own.Status != notify.StatusResolved || own.HandledBy == nil || *own.HandledBy != "system" ||
		own.ResolvedReason == nil || *own.ResolvedReason != "Closed by Vedette: the device was approved by an@acme.example." {
		t.Fatalf("own incident = %+v", own)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status' AND target = ?`, own.Title); n != 1 {
		t.Fatalf("audit rows of the closed incident = %d, want 1", n)
	}
}

// D-552 (W8-1): devices approved before this version (no event will come) leave their new-device incidents on the next autoclose
// run; a device not approved stays open with its current name, and a device the inventory no longer has is left to INV-20.
func TestAutoCloseClosesNewDeviceIncidentsOfApprovedDevices(t *testing.T) {
	devs := &stateDevices{m: map[string]notify.DeviceState{
		"181":  {Name: "Hon Hai Precision Ind. Co.,Ltd.", Address: "192.168.18.181"},
		"145":  {Name: "192.168.18.145", Address: "192.168.18.145"},
		"gone": {Name: "old-phone"},
	}}
	e := newEnv(t, func(c *notify.Config) { c.Devices = devs })
	e.firstRunAt(e.clock.Now().AddDate(0, -1, 0)) // not a fresh box
	e.svc.Subscribe(e.bus)
	for _, id := range []string{"181", "145", "gone"} {
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})); err != nil {
			t.Fatal(err)
		}
	}
	devs.set("181", notify.DeviceState{Name: "byn", Address: "192.168.18.181", Approved: true}) // approved by the version before
	devs.set("145", notify.DeviceState{Name: "kiens-macbook-air", Address: "192.168.18.145"})
	devs.mu.Lock()
	delete(devs.m, "gone")
	devs.mu.Unlock()
	e.autoClose()
	got := map[string]notify.Incident{}
	l, _ := e.svc.Incidents(e.ctx())
	for _, i := range l {
		got[i.Devices[0].ID] = i
	}
	if i := got["181"]; i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: the device was approved in Devices." ||
		i.Title != "A new unknown device appeared: byn (192.168.18.181)" {
		t.Fatalf("approved device = %+v", i)
	}
	if i := got["145"]; i.Status != notify.StatusNew || i.Title != "A new unknown device appeared: kiens-macbook-air (192.168.18.145)" {
		t.Fatalf("device not approved = %+v", i)
	}
	if i := got["gone"]; i.Status != notify.StatusNew || i.Title != "A new unknown device appeared: old-phone" {
		t.Fatalf("device no longer in the inventory = %+v", i)
	}
	e.autoClose() // nothing changed: no second close
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status'`); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
}
