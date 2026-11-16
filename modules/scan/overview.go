package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/progress"
)

// EngineView is the scan module as Settings › Scanning shows its nuclei card (#850, core INV-40): the newest run that ended, the run
// going on now with its progress, the next scheduled run and why no scan can start (nil when one can).
type EngineView struct {
	Last        *RunHead
	Running     *RunHead
	NextRun     *string
	BlockReason *string
}

// RunHead is a run without its per-device rows.
type RunHead struct {
	ID, Trigger, Status, StartedAt string
	EndedAt                        *string
	Total, Done, Matched           int
	Progress                       *progress.View // the running run's current device; nil otherwise
}

// Engine reads EngineView: two indexed rows of scan_run and the configuration view, nothing per device.
func (s *Service) Engine(ctx context.Context) (EngineView, error) {
	cv, err := s.Config(ctx)
	if err != nil {
		return EngineView{}, err
	}
	v := EngineView{NextRun: cv.NextRun, BlockReason: cv.BlockReason}
	if v.Last, err = s.runHead(ctx, `status NOT IN ('running', 'stopping')`); err != nil {
		return EngineView{}, err
	}
	if v.Running, err = s.runHead(ctx, `status IN ('running', 'stopping')`); err != nil {
		return EngineView{}, err
	}
	if v.Running != nil {
		v.Running.Progress = s.progressOf(v.Running.ID)
	}
	return v, nil
}

func (s *Service) runHead(ctx context.Context, where string) (*RunHead, error) {
	var h RunHead
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT id, trigger, status, started_at, ended_at, total, done, matched FROM scan_run WHERE `+where+ // where is one of two constants of Engine
		` ORDER BY started_at DESC, rowid DESC LIMIT 1`).Scan(&h.ID, &h.Trigger, &h.Status, &h.StartedAt, &h.EndedAt, &h.Total, &h.Done, &h.Matched)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no such run
	}
	if err != nil {
		return nil, fmt.Errorf("scan: reading the newest run: %w", err)
	}
	return &h, nil
}
