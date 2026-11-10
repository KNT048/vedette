package scan

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/jobs"
)

type jobsJob = jobs.Job

// M4: the module's job closes a run a restart left live, and Close stops the live run and waits for it.
func TestReview_M4_RecoverJobAndClose(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_run (id, trigger, started_at, started_by, status, picked, target_ids, total)
VALUES ('run-old', 'manual', '2026-11-10T09:00:00.000Z', 'x', 'running', '[]', '["a-web01"]', 1)`)
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
	if err := js[i].Run(r.ctx()); err != nil || r.run("run-old").Status != "stopped" {
		t.Fatalf("recover: %v %+v", err, r.run("run-old"))
	}
	started := r.eng.blockRuns()
	v := r.start("a-web01")
	<-started
	r.svc.Close()
	got := r.run(v.ID)
	if got.Status != "stopped" || got.StopReason == nil || *got.StopReason != "Vedette was shut down during this scan." || r.svc.liveRun() != "" {
		t.Fatalf("after Close: %+v", got)
	}
}
