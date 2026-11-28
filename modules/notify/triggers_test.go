package notify_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/notify"
)

// openKind opens an incident of a kind at a severity and returns its id.
func (e *env) openKind(kind notify.IncidentKind, source string, sev notify.Severity) string {
	e.t.Helper()
	id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: kind, Source: source, Target: "t", Title: string(kind) + " from " + source, Severity: sev,
		Link: "/incidents"})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) queued(id string) int {
	e.t.Helper()
	return e.count(`SELECT COUNT(*) FROM notify_pending WHERE notice_id = ?`, id)
}

func TestAlertTriggersDefaultsKeepTheNoiseOut(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	e.telegram(notify.Low)
	v, err := e.svc.Channels(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Vulnerability.On || !v.Vulnerability.DefaultOn {
		t.Fatalf("vulnerability trigger = %+v", v.Vulnerability)
	}
	want := map[string]string{"trap": "on low", "intrusion": "on high", "bad_address": "on high", "log_anomaly": "on high", "unknown_device": "off medium"}
	if len(v.Triggers) != len(want) {
		t.Fatalf("triggers = %+v", v.Triggers)
	}
	for _, tr := range v.Triggers {
		got := map[bool]string{true: "on", false: "off"}[tr.On] + " " + string(tr.Min)
		if want[tr.ID] != got || tr.DefaultOn != tr.On || tr.DefaultMin != tr.Min {
			t.Fatalf("trigger %s = %+v, want %s", tr.ID, tr, want[tr.ID])
		}
	}

	dev := e.openKind(notify.IncidentUnknownDevice, "as-phone", notify.Medium)
	wantReason(t, e.notSent(dev), notify.UnsentTriggerOff, "alerts of this kind are turned off in the alert settings")
	ids := e.openKind(notify.IncidentIntrusion, "203.0.113.9", notify.Medium)
	wantReason(t, e.notSent(ids), notify.UnsentTriggerOff, "it is medium, and the alert settings send this kind only from high")
	if e.queued(dev)+e.queued(ids) != 0 {
		t.Fatal("a held trigger was queued")
	}
	for _, id := range []string{e.openKind(notify.IncidentIntrusion, "203.0.113.10", notify.High), e.open("share", notify.Critical),
		e.openKind(notify.IncidentBadAddress, "as-nas", notify.High), e.openKind("printer_jam", "as-printer", notify.Low)} {
		if e.queued(id) != 1 {
			t.Fatalf("incident %s was not queued", id)
		}
	}
}

func TestAlertTriggersChangeHoldsFromTheNextEventAndIsAudited(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	e.telegram(notify.Low)
	before := e.openKind(notify.IncidentUnknownDevice, "as-1", notify.Medium)

	out, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", []notify.Trigger{{ID: "unknown_device", On: true, Min: notify.High}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range out.Triggers {
		if tr.ID == "unknown_device" && (!tr.On || tr.Min != notify.High || tr.DefaultOn) {
			t.Fatalf("saved = %+v", tr)
		}
		if tr.ID == "trap" && (!tr.On || tr.Min != notify.Low) {
			t.Fatalf("a trigger left out changed: %+v", tr)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.triggers_save' AND detail = 'new device seen: off -> on from high'`); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	// the incident opened before keeps its decision; the next ones follow the new rule
	wantReason(t, e.notSent(before), notify.UnsentTriggerOff, "turned off")
	wantReason(t, e.notSent(e.openKind(notify.IncidentUnknownDevice, "as-2", notify.Medium)), notify.UnsentTriggerOff, "only from high")
	if hi := e.openKind(notify.IncidentUnknownDevice, "as-3", notify.High); e.queued(hi) != 1 {
		t.Fatal("a high new device was not queued after the trigger was turned on")
	}

	// saving the same rule again writes nothing and audits nothing
	if _, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", []notify.Trigger{{ID: "unknown_device", On: true, Min: notify.High}}, nil); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.triggers_save'`); n != 1 {
		t.Fatalf("audit rows after a save that changed nothing = %d", n)
	}
	// the stored rule is read back by the next process
	v, err := e.svc.Channels(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range v.Triggers {
		if tr.ID == "unknown_device" && (!tr.On || tr.Min != notify.High) {
			t.Fatalf("stored = %+v", tr)
		}
	}
}

func TestAlertTriggersRefuseWhatIsNotARule(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	for name, in := range map[string][]notify.Trigger{
		"unknown_trigger":   {{ID: "everything", On: true, Min: notify.Low}},
		"duplicate_trigger": {{ID: "trap", On: true, Min: notify.Low}, {ID: "trap", On: false, Min: notify.Low}},
		"bad_min":           {{ID: "trap", On: true, Min: notify.Info}},
		"unknown_trigger ":  {{ID: "vulnerability", On: true, Min: notify.Low}}, // its own type, with no minimum
	} {
		_, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", in, nil)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != strings.TrimSpace(name) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_setting WHERE key = 'triggers'`); n != 0 {
		t.Fatalf("a refused save wrote %d rows", n)
	}
}

func TestAlertTriggersHoldVulnerabilityNoticesButNotSendNow(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	e.telegram(notify.Low)
	out, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", nil, &notify.VulnTrigger{On: false})
	if err != nil || out.Vulnerability.On || !out.Vulnerability.DefaultOn {
		t.Fatalf("saved = %+v, %v", out.Vulnerability, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.triggers_save' AND detail = 'vulnerability exploited in the wild: on -> off'`); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	if v := e.count(`SELECT COUNT(*) FROM notify_setting WHERE key = 'triggers' AND value = '[{"id":"vulnerability","on":false}]'`); v != 1 {
		t.Fatal("the vulnerability trigger was stored with a minimum")
	}
	n := notify.Notice{ID: "nt-f1-created", Kind: notify.KindVuln, Severity: notify.High, Product: "Photo Station", CVEs: []string{"CVE-2024-0001"},
		Devices: []string{"nas"}, Title: "Photo Station on nas: exploited", Layer: 2, Link: "https://vedette.example/findings/f1"}
	if err := e.svc.Publish(e.ctx(), n); err != nil {
		t.Fatal(err)
	}
	if e.queued(n.ID) != 0 || e.count(`SELECT COUNT(*) FROM notify_notice WHERE id = ? AND unsent = 'trigger_off'`, n.ID) != 1 {
		t.Fatal("a vulnerability notice of a trigger that is off was queued or not recorded")
	}
	n.ID, n.Forced = "nt-f2-created", true
	if err := e.svc.Publish(e.ctx(), n); err != nil {
		t.Fatal(err)
	}
	if e.queued(n.ID) != 1 {
		t.Fatal("a notice a person asked to send was held by its trigger")
	}
}

// Migration 0005 rebuilds notify_setting to allow the triggers key: the quiet-hours and grouping rows a box already has come through
// unchanged, and the table still refuses a key it does not know.
func TestMigrationKeepsTheStoredRulesAndAllowsTriggers(t *testing.T) {
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.MigrateTo(ctx, db, "notify", notify.Migrations, 4); err != nil {
		t.Fatal(err)
	}
	rows := [][4]string{
		{"grouping", `{"enabled":false,"window_min":240}`, "2026-11-20T08:00:00.000Z", "it@acme.example"},
		{"quiet", `{"enabled":true,"from":"21:30","to":"07:00","allow_critical":false}`, "2026-11-21T09:15:30.250Z", "admin@acme.example"},
	}
	read := func() [][4]string {
		t.Helper()
		rs, err := db.Reader().QueryContext(ctx, `SELECT key, value, updated_at, updated_by FROM notify_setting ORDER BY key`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rs.Close() }()
		var out [][4]string
		for rs.Next() {
			var r [4]string
			if err := rs.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	put := func(r [4]string) error {
		return db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO notify_setting (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)`, r[0], r[1], r[2], r[3])
			return err
		})
	}
	for _, r := range rows {
		if err := put(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := put([4]string{"triggers", `[]`, "2026-11-21T09:15:30.250Z", "it@acme.example"}); err == nil {
		t.Fatal("before 0005 the table took a triggers row")
	}
	if err := store.Migrate(ctx, db, "notify", notify.Migrations); err != nil {
		t.Fatal(err)
	}
	if got := read(); !reflect.DeepEqual(got, rows) {
		t.Fatalf("rows after the migration = %v, want %v", got, rows)
	}
	if err := put([4]string{"triggers", `[{"id":"unknown_device","on":true,"min":"high"}]`, "2026-11-26T10:00:00.000Z", "it@acme.example"}); err != nil {
		t.Fatalf("a triggers row after 0005: %v", err)
	}
	if err := put([4]string{"other", `{}`, "2026-11-26T10:00:00.000Z", "it@acme.example"}); err == nil {
		t.Fatal("the table took a key it does not know")
	}
}

// With the default triggers, the first-run window does not hold the medium known-bad and log incidents for its summary: their triggers
// send only from high, so they are not told at all, and no summary of them goes out. A kind whose trigger is on for them is still held.
func TestFirstRunSummaryLeavesOutWhatTheTriggersKeepOut(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	e.firstRunAt(e.clock.Now())
	e.telegram(notify.Low)
	e.plain()
	bad := e.openKind(notify.IncidentBadAddress, "as-a", notify.Medium)
	logs := e.openKind(notify.IncidentLogAnomaly, "as-b", notify.Low)
	for _, id := range []string{bad, logs} {
		if i := e.detail(id); i.FirstRunSummary {
			t.Fatalf("held for the summary although its trigger keeps it out: %+v", i)
		}
		wantReason(t, e.notSent(id), notify.UnsentTriggerOff, "the alert settings send this kind only from high")
	}
	e.autoClose()
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 0 {
		t.Fatalf("%d messages: a first-run summary told what the triggers keep out", n)
	}
	if _, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", []notify.Trigger{{ID: "log_anomaly", On: true, Min: notify.Low}}, nil); err != nil {
		t.Fatal(err)
	}
	if i := e.detail(e.openKind(notify.IncidentLogAnomaly, "as-c", notify.Medium)); !i.FirstRunSummary {
		t.Fatalf("a kind its trigger sends was not held for the summary: %+v", i)
	}
}

// Only the rules that differ from their default are stored, and a change of the minimum of a trigger that is off says both minimums.
func TestAlertTriggersStoreOnlyChangesAndSayAMinimumChange(t *testing.T) {
	e := newEnv(t)
	e.defaultTriggers()
	if _, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", []notify.Trigger{{ID: "trap", On: true, Min: notify.Low}, {ID: "unknown_device", On: false, Min: notify.High}}, nil); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_setting WHERE key = 'triggers' AND value = '[{"id":"unknown_device","on":false,"min":"high"}]'`); n != 1 {
		t.Fatal("the stored rule is not just the change")
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.triggers_save' AND detail = 'new device seen: off (from medium) -> off (from high)'`); n != 1 {
		t.Fatal("the audit does not say the minimum change of a trigger that is off")
	}
}

// A rule an earlier build stored for the vulnerability trigger still carries a lowest severity: it is read, its on or off kept, the
// minimum dropped, so an old config keeps working and the API never shows a minimum for it.
func TestAlertTriggersStoredVulnerabilityMinimumIsDroppedOnLoad(t *testing.T) {
	e := newEnv(t)
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_setting SET value = ? WHERE key = 'triggers'`,
			`[{"id":"vulnerability","on":false,"min":"critical"},{"id":"trap","on":true,"min":"high"}]`)
		return err
	})
	v, err := e.svc.Channels(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if v.Vulnerability.On || !v.Vulnerability.DefaultOn {
		t.Fatalf("vulnerability trigger = %+v, want off as stored", v.Vulnerability)
	}
	for _, tr := range v.Triggers {
		if tr.ID == notify.TriggerVuln {
			t.Fatalf("the vulnerability trigger is listed with the incident triggers: %+v", tr)
		}
		if tr.ID == "trap" && tr.Min != notify.High {
			t.Fatalf("trap = %+v", tr)
		}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"vulnerability_trigger":{"on":false,"default_on":true}`) == false {
		t.Fatalf("API shape: %s", raw)
	}
	// turned back on, it is stored without a minimum
	if _, err := e.svc.SaveTriggers(e.ctx(), "it@acme.example", nil, &notify.VulnTrigger{On: true}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_setting WHERE key = 'triggers' AND value LIKE '%vulnerability%'`); n != 0 {
		t.Fatal("the default vulnerability rule was stored again")
	}
}
