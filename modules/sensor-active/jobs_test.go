package sensoractive_test

import (
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
