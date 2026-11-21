package sensoractive_test

import (
	"net/netip"
	"slices"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// runRow is the INSERT of a run of the module as core/run stores it.
func runRow(id, kind, trigger, status, queued string, subject string) string {
	sub := `NULL, NULL`
	if subject != "" {
		sub = `'device', '` + subject + `'`
	}
	lane := "nmap"
	if kind == sa.RunSNMP {
		lane = "snmp"
	}
	ended := `'` + queued + `'`
	if status == "running" || status == "waiting" || status == "queued" {
		ended = `NULL`
	}
	return `INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, status, total, done, queued_at, started_at, ended_at, updated_at)
		VALUES ('` + id + `', 'sensor-active', '` + kind + `', '` + lane + `', 'a run', '` + trigger + `', 'system', ` + sub + `, '` + status + `', 1, 1, '` + queued + `', '` + queued + `', ` + ended + `, '` + queued + `')`
}

func probeRow(at, runID, shape, targets, result string) string {
	return `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES ('` + at + `', '` + runID + `', '` + shape + `', 100, 1, '-sS', '` + targets + `', '` + result + `')`
}

func (e *env) exec(qs ...string) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		for _, q := range qs {
			if _, err := tx.ExecContext(e.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

// The history lists every LAN run of the module, newest first, with every probe it sent; a service scan for exposure is exposure's
// to list. Read only.
func TestJobs_ListsLANRunsNewestFirstWithTheirProbes(t *testing.T) {
	e := newEnv(t, fakeOpts{})
	e.exec(
		runRow("s1", sa.RunSweep, "schedule", "done", "2026-11-17T01:00:00.000Z", ""),
		runRow("d1", sa.RunCheck, "manual", "failed", "2026-11-17T03:18:00.000Z", "a-web"),
		runRow("x1", sa.RunService, "event", "done", "2026-11-17T04:00:00.000Z", ""),
		`UPDATE core_run SET error = 'nmap stopped' WHERE id = 'd1'`,
		`UPDATE core_run SET total = 254, done = 254 WHERE id = 's1'`,
		`INSERT INTO core_run_item (run_id, seq, subject_kind, label, outcome) VALUES ('s1', 1, 'host', '10.0.18.7', 'new'), ('s1', 2, 'host', '10.0.18.8', 'new'), ('s1', 3, 'host', '10.0.18.9', 'found')`,
		probeRow("2026-11-17T03:18:01.000Z", "d1", "normal", "10.0.18.20", "ok: 1 hosts up"),
		probeRow("2026-11-17T01:00:01.000Z", "s1", "sweep", "10.0.18.0/26", "ok: 3 hosts up"),
		probeRow("2026-11-17T01:02:01.000Z", "s1", "sweep", "10.0.18.64/26", "ok: 2 hosts up"),
	)
	got, err := e.svc.Jobs(e.ctx(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "d1" || got[1].ID != "s1" {
		t.Fatalf("jobs: %+v, want d1 then s1 (the service scan left out)", got)
	}
	if d := got[0]; d.Kind != sa.KindDevice || d.Reason != "scan_now" || d.Status != "failed" || d.Error != "nmap stopped" || d.AssetID != "a-web" ||
		len(d.Probes) != 1 || d.Probes[0] != (sa.JobProbe{Targets: "10.0.18.20", Result: "ok: 1 hosts up"}) {
		t.Errorf("device job: %+v", d)
	}
	if s := got[1]; s.Kind != sa.KindSweep || s.Targets != 254 || s.NewDevices != 2 || len(s.Probes) != 2 || s.Probes[1].Targets != "10.0.18.64/26" {
		t.Errorf("sweep: %+v", s)
	}
}

// The device page's Last checks reads the runs of one device: its checks (the runs whose subject it is) and, only while it has SNMP
// set up, the SNMP reads whose compact target list names its read address, a range included; never a sweep or another device's run.
func TestJobsOf_TheRunsOfOneDevice(t *testing.T) {
	e := newEnv(t, fakeOpts{})
	e.exec(
		runRow("s1", sa.RunSweep, "schedule", "done", "2026-11-17T05:00:00.000Z", ""),
		runRow("d1", sa.RunCheck, "manual", "done", "2026-11-17T03:18:00.000Z", "a-sw"),
		runRow("d2", sa.RunCheck, "event", "done", "2026-11-16T03:18:00.000Z", "a-sw"),
		runRow("d4", sa.RunAllPorts, "schedule", "done", "2026-11-15T04:00:00.000Z", "a-sw"),
		runRow("d5", sa.RunCheck, "manual", "done", "2026-11-14T04:00:00.000Z", "a-old"),
		runRow("n1", sa.RunSNMP, "schedule", "done", "2026-11-17T02:00:00.000Z", ""),
		runRow("n2", sa.RunSNMP, "manual", "done", "2026-11-17T06:00:00.000Z", "a-other"),
		`INSERT INTO core_run_item (run_id, seq, subject_kind, subject_id, label, outcome) VALUES ('d4', 1, 'check', 'a-sw', '10.0.18.9', 'all'), ('d4', 2, 'port', NULL, '22/tcp ssh', 'open')`,
		probeRow("2026-11-17T05:00:01.000Z", "s1", "sweep", "10.0.18.0/24", "ok: 9 hosts up"),
		probeRow("2026-11-17T03:18:01.000Z", "d1", "normal", "10.0.18.20", "ok: 1 hosts up"),
		probeRow("2026-11-17T02:00:01.000Z", "n1", "snmp", "10.0.18.1,10.0.18.18-10.0.18.21", "ok: 3 of 4 answered"),
		probeRow("2026-11-17T06:00:01.000Z", "n2", "snmp", "10.0.18.20", "ok: 0 of 1 answered"),
	)
	ids := func(id string, limit int) []string {
		t.Helper()
		got, err := e.svc.JobsOf(e.ctx(), id, netip.MustParseAddr("10.0.18.20"), limit)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, j := range got {
			out = append(out, j.ID)
		}
		return out
	}
	if got := ids("a-sw", 50); !slices.Equal(got, []string{"d1", "d2", "d4"}) {
		t.Fatalf("runs of a-sw without SNMP: %v, want d1, d2, d4; no sweep, no SNMP read, not d5 (another device)", got)
	}
	e.exec(`INSERT INTO sa_snmp_device (asset_id, read_from, read_from_default, version, secret_id, created_at, updated_at) VALUES ('a-sw', '10.0.18.19', 0, 'v2c', 'sec-x', '2026-11-17T01:00:00.000Z', '2026-11-17T01:00:00.000Z')`)
	if got := ids("a-sw", 50); !slices.Equal(got, []string{"d1", "n1", "d2", "d4"}) {
		t.Fatalf("runs of a-sw read at 10.0.18.19: %v, want d1, n1 (inside its range), d2, d4", got)
	}
	got, _ := e.svc.JobsOf(e.ctx(), "a-sw", netip.MustParseAddr("10.0.18.20"), 50)
	if got[0].Probes[0].Result != "ok: 1 hosts up" || got[1].Probes[0].Result != "ok: 3 of 4 answered" || got[0].Found != nil {
		t.Errorf("probes: %+v", got)
	}
	if f := got[3].Found; f == nil || f.Reach != "all" || f.Open != 1 || f.Ports[0] != (sa.FoundPort{Port: 22, Proto: "tcp", Name: "ssh"}) {
		t.Errorf("found of d4: %+v", f)
	}
	e.exec(`UPDATE core_run SET ended_at = '2026-11-17T02:01:00.000Z' WHERE id = 'n1'`, `UPDATE sa_snmp_device SET last_checked_at = '2026-11-17T02:00:30.000Z', last_status = 'no_answer' WHERE asset_id = 'a-sw'`)
	if got, _ := e.svc.JobsOf(e.ctx(), "a-sw", netip.MustParseAddr("10.0.18.20"), 50); got[1].ID != "n1" || got[1].Own != "no_answer" {
		t.Errorf("own result of n1: %+v", got[1])
	}
	if got := ids("a-sw", 1); !slices.Equal(got, []string{"d1", "n1"}) {
		t.Errorf("limit is per kind: %v", got)
	}
}
