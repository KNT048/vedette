package core

import "github.com/knt048/vedette/core/selfcheck"

func init() {
	selfcheck.Register(selfcheck.Invariant{
		Name:  "core.job_run_ends_after_start",
		Query: `SELECT count(*) FROM core_job_run WHERE finished_at < started_at`,
	})
}
