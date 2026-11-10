package ai

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// Stubs: the tests of slice 3 are written first and run against these, so they fail on behaviour and not on the compiler. The
// implementation replaces this file in the commits that follow.

// ChainPruner is core's part of a retention prune (issue #194: chainhead.Prune).
type ChainPruner interface {
	Prune(ctx context.Context, tx *sql.Tx, chain, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error
}

// ErrNoPruner means the box has no ChainPruner: the retention prune is off.
var ErrNoPruner = errors.New("ai: the retention prune needs core's chain pruner")

var errNotImplemented = errors.New("ai: not implemented yet")

// ExportActivity is the ai_activity source of GET /core/logs/export.
func (s *Service) ExportActivity(context.Context, time.Time, time.Time, io.Writer) error {
	return errNotImplemented
}

// PruneActivity removes the activity rows older than the retention.
func (s *Service) PruneActivity(context.Context) (int, error) { return 0, errNotImplemented }

// Jobs are the scheduled jobs of the module.
func (s *Service) Jobs() []jobs.Job { return nil }
