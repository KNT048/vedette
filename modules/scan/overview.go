package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/progress"
)

// EngineView is the scan module as Settings › Scanning shows its nuclei card (#850, core INV-40): the newest run that ended, the run
// going on now with its progress, and why no scan can start (nil when one can).
type EngineView struct {
	Last        *RunHead
	Running     *RunHead
	BlockReason *string
}

// RunHead is a run without its per-device rows.
type RunHead struct {
	ID, Trigger, Status, StartedAt string
	EndedAt                        *string
	Total, Done, Matched           int
	Progress                       *progress.View // the running run's current device; nil otherwise
}

// Engine reads EngineView: two indexed rows of core_run and the configuration view, nothing per device.
func (s *Service) Engine(ctx context.Context) (EngineView, error) {
	cv, err := s.Config(ctx)
	if err != nil {
		return EngineView{}, err
	}
	v := EngineView{BlockReason: cv.BlockReason}
	if v.Last, err = s.runHead(ctx, `r.status NOT IN ('queued', 'running', 'stopping')`); err != nil {
		return EngineView{}, err
	}
	if v.Running, err = s.runHead(ctx, `r.status IN ('queued', 'running', 'stopping')`); err != nil {
		return EngineView{}, err
	}
	if v.Running != nil {
		v.Running.Progress = s.progressOf(v.Running.ID)
	}
	return v, nil
}

func (s *Service) runHead(ctx context.Context, where string) (*RunHead, error) {
	row := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.module = ? AND r.kind = ? AND `+where+ // where is one of two constants of Engine
		` ORDER BY r.queued_at DESC, r.rowid DESC LIMIT 1`, ModuleID, runKindName)
	v, err := scanRunHead(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no such run
	}
	if err != nil {
		return nil, fmt.Errorf("scan: reading the newest run: %w", err)
	}
	h := &RunHead{ID: v.ID, Trigger: v.Trigger, Status: v.Status, StartedAt: v.StartedAt, EndedAt: v.EndedAt, Total: v.Total, Done: v.Done}
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run_item WHERE run_id = ? AND subject_kind = 'device' AND outcome = 'matched'`, v.ID).Scan(&h.Matched); err != nil {
		return nil, fmt.Errorf("scan: reading the newest run: %w", err)
	}
	return h, nil
}
