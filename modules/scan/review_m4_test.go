package scan

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/jobs"
)

type jobsJob = jobs.Job

// core/run records a run a restart left live as stopped; the module's recover job then closes its open probe rows. A shutdown
// leaves the live run as it is, for the next start to record.
func TestReview_M4_RecoverJobAndShutdown(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		if err := seedRun(r.ctx(), tx, "run-old", "running", "2026-11-10T09:00:00.000Z", "a-web01"); err != nil {
			return err
		}
		_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request) VALUES ('pr-old', '2026-11-10T09:00:00.000Z', 'run-old', '192.168.10.12', 'WEB01', 't.yaml', 'GET / HTTP/1.1')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	js := Jobs(r.svc)
	i := slices.IndexFunc(js, func(j jobsJob) bool { return j.Name == "recover" })
	if i < 0 {
		t.Fatal("no recover job")
	}
	if err := js[i].Run(r.ctx()); err != nil || r.count(`SELECT count(*) FROM scan_probe WHERE id = 'pr-old' AND result IS NULL`) != 1 {
		t.Fatalf("the job closed the probes of a run still recorded as live: %v", err)
	}
	if err := r.runs.Recover(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := r.run("run-old"); got.Status != "stopped" || got.StopReason == nil || *got.StopReason != "Vedette restarted" {
		t.Fatalf("after the restart: %+v", got)
	}
	if err := js[i].Run(r.ctx()); err != nil || r.count(`SELECT count(*) FROM scan_probe WHERE id = 'pr-old' AND result = 'stopped'`) != 1 {
		t.Fatalf("recover: %v", err)
	}

	started := r.eng.blockRuns()
	v := r.start("a-web01")
	<-started
	r.runs.Close()
	if got := r.run(v.ID); got.Status != "running" {
		t.Fatalf("after a shutdown: %+v", got)
	}
	if err := r.runs.Recover(r.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := r.run(v.ID); got.Status != "stopped" || got.StopReason == nil || *got.StopReason != "Vedette restarted" {
		t.Fatalf("after the next start: %+v", got)
	}
	if err := js[i].Run(r.ctx()); err != nil || r.count(`SELECT count(*) FROM scan_probe WHERE result IS NULL`) != 0 {
		t.Fatalf("recover after the shutdown: %v", err)
	}
}
