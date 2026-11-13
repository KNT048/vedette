package notify_test

import (
	"context"
	"database/sql"
	"strings"
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
	publish(notify.EventAssetApproved, map[string]string{"asset_id": "a9", "actor": "an@acme.example\n"})
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
	if i := e.detail(logA); i.Status != notify.StatusResolved || i.ResolvedReason == nil || *i.ResolvedReason != "Closed by Vedette: no new activity for 3 days." || i.Note == nil || *i.Note != "looking" {
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
	if id, created := open(notify.IncidentTrap, "10.0.0.5", notify.Critical); !created || id == trap {
		t.Fatalf("a new hit after the close: id %s created %v", id, created)
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
