package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// KeepRuns is how many runs core_job_run keeps per job.
const KeepRuns = 200

// History is the Recorder that writes core_job_run.
type History struct {
	db *store.DB
}

// NewHistory returns a Recorder backed by the database.
func NewHistory(db *store.DB) *History { return &History{db: db} }

// Record inserts the run and prunes that job's older rows beyond KeepRuns, in one transaction.
func (h *History) Record(ctx context.Context, r Run) error {
	var msg *string
	if r.Error != "" {
		msg = &r.Error
	}
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		err := q.InsertJobRun(ctx, coredb.InsertJobRunParams{
			ID: store.NewID("jr"), Module: r.Module, Job: r.Job, StartedAt: store.FormatTS(r.StartedAt),
			FinishedAt: store.FormatTS(r.FinishedAt), Status: string(r.Status), Error: msg,
		})
		if err != nil {
			return fmt.Errorf("jobs: insert run: %w", err)
		}
		err = q.PruneJobRuns(ctx, coredb.PruneJobRunsParams{Module: r.Module, Job: r.Job, Module_2: r.Module, Job_2: r.Job, Limit: KeepRuns})
		if err != nil {
			return fmt.Errorf("jobs: prune runs: %w", err)
		}
		return nil
	})
}

// Recent returns up to limit runs of one job, newest first.
func (h *History) Recent(ctx context.Context, module, job string, limit int) ([]Run, error) {
	rows, err := coredb.New(h.db.Reader()).ListJobRuns(ctx, coredb.ListJobRunsParams{Module: module, Job: job, Limit: int64(limit)})
	if err != nil {
		return nil, fmt.Errorf("jobs: read runs: %w", err)
	}
	out := make([]Run, 0, len(rows))
	for _, row := range rows {
		started, err1 := time.Parse(time.RFC3339Nano, row.StartedAt)
		finished, err2 := time.Parse(time.RFC3339Nano, row.FinishedAt)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("jobs: run %s has a malformed timestamp", row.ID)
		}
		r := Run{Module: row.Module, Job: row.Job, StartedAt: started, FinishedAt: finished, Status: Status(row.Status)}
		if row.Error != nil {
			r.Error = *row.Error
		}
		out = append(out, r)
	}
	return out, nil
}
