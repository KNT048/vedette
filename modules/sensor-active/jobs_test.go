package sensoractive_test

import (
	"net/netip"
	"slices"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
)

// kien G7a: Settings › Scanning › History lists every run of active discovery, newest first, with the address and nmap's result of
// its first probe; external runs are exposure's to list. Read only.
func TestJobs_ListsLANRunsNewestFirstWithTheirFirstProbe(t *testing.T) {
	e := newEnv(t, fakeOpts{})
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		for _, q := range []string{
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets, new_devices) VALUES ('s1', 'sweep', NULL, '2026-11-17T01:00:00.000Z', '2026-11-17T01:05:00.000Z', 'done', 254, 2)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets, error) VALUES ('d1', 'device', 'scan_now', '2026-11-17T03:18:00.000Z', '2026-11-17T03:19:00.000Z', 'failed', 1, 'nmap stopped')`,
			`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('x1', 'external', '2026-11-17T04:00:00.000Z', 'done')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T03:18:01.000Z', 'd1', 'normal', 100, 1, '-sS', '192.168.18.20', 'ok: 1 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T01:00:01.000Z', 's1', 'sweep', 100, 64, '-sn', '192.168.18.0/26', 'ok: 3 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T01:02:01.000Z', 's1', 'sweep', 100, 64, '-sn', '192.168.18.64/26', 'ok: 2 hosts up')`,
		} {
			if _, err := tx.ExecContext(e.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Jobs(e.ctx(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "d1" || got[1].ID != "s1" {
		t.Fatalf("jobs: %+v, want d1 then s1 (external left out)", got)
	}
	if d := got[0]; d.Reason != "scan_now" || d.Status != "failed" || d.Error != "nmap stopped" || len(d.Probes) != 1 || d.Probes[0] != (sa.JobProbe{Targets: "192.168.18.20", Result: "ok: 1 hosts up"}) {
		t.Errorf("device job: %+v", d)
	}
	// every batch of a sweep, in order (#940 review r1 M3)
	if s := got[1]; s.Targets != 254 || s.NewDevices != 2 || len(s.Probes) != 2 || s.Probes[1].Targets != "192.168.18.64/26" || s.Probes[1].Result != "ok: 2 hosts up" {
		t.Errorf("sweep: %+v", s)
	}
}

// kien G7b/c: the device page's Last checks reads the runs that reached one address: its identifications (whatever started them)
// and the SNMP reads whose compact target list names it, a range included; never a sweep, another address, or an external run.
func TestJobsAt_TheRunsThatReachedOneAddress(t *testing.T) {
	e := newEnv(t, fakeOpts{})
	if err := e.db.Write(e.ctx(), func(tx dbTx) error {
		for _, q := range []string{
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('s1', 'sweep', NULL, '2026-11-17T05:00:00.000Z', '2026-11-17T05:05:00.000Z', 'done', 254)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('d1', 'device', 'check_now', '2026-11-17T03:18:00.000Z', '2026-11-17T03:19:00.000Z', 'done', 1)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('d2', 'device', 'discovered', '2026-11-16T03:18:00.000Z', '2026-11-16T03:19:00.000Z', 'done', 1)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('d3', 'device', 'check_now', '2026-11-17T04:00:00.000Z', '2026-11-17T04:01:00.000Z', 'done', 1)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('n1', 'snmp', 'window', '2026-11-17T02:00:00.000Z', '2026-11-17T02:01:00.000Z', 'done', 4)`,
			`INSERT INTO sa_job (id, kind, reason, started_at, finished_at, status, targets) VALUES ('n2', 'snmp', 'snmp_read', '2026-11-17T06:00:00.000Z', '2026-11-17T06:01:00.000Z', 'done', 1)`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T05:00:01.000Z', 's1', 'sweep', 100, 64, '-sn', '192.168.18.0/24', 'ok: 9 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T03:18:01.000Z', 'd1', 'normal', 100, 1, '-sS', '192.168.18.20', 'ok: 1 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-16T03:18:01.000Z', 'd2', 'normal', 100, 1, '-sS', '192.168.18.20', 'ok: 0 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T04:00:01.000Z', 'd3', 'normal', 100, 1, '-sS', '192.168.18.200', 'ok: 1 hosts up')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T02:00:01.000Z', 'n1', 'snmp', 10, 4, 'GET', '192.168.18.1,192.168.18.18-192.168.18.21', 'ok: 3 of 4 answered')`,
			`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-17T06:00:01.000Z', 'n2', 'snmp', 10, 1, 'GET', '192.168.18.2', 'ok: 1 of 1 answered')`,
		} {
			if _, err := tx.ExecContext(e.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.JobsAt(e.ctx(), netip.MustParseAddr("192.168.18.20"), 50)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, j := range got {
		ids = append(ids, j.ID)
	}
	if !slices.Equal(ids, []string{"d1", "n1", "d2"}) {
		t.Fatalf("jobs at 192.168.18.20: %v, want d1, n1 (inside its range), d2; no sweep, no other address", ids)
	}
	if got[0].Probes[0].Result != "ok: 1 hosts up" || got[1].Probes[0].Result != "ok: 3 of 4 answered" {
		t.Errorf("probes: %+v", got)
	}
	if got, _ := e.svc.JobsAt(e.ctx(), netip.MustParseAddr("192.168.18.20"), 1); len(got) != 2 || got[0].ID != "d1" || got[1].ID != "n1" {
		t.Errorf("limit is per kind: %+v", got)
	}
}
