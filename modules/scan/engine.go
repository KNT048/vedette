package scan

import (
	"context"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// Engine is the scanner seam (D-125): the worker in the scan container that runs the pinned nuclei binary, reached
// over the sensor protocol (S5). Tests pass a fake. Without an Engine, or without a template pack, the scanner is
// unavailable and nothing is ever sent (INV-2).
type Engine interface {
	// Ready returns nil when a job can be sent now: the worker has a fresh heartbeat with nuclei and the template
	// pack present. Otherwise it says why, for the log; the user sees msgScannerDown.
	Ready(ctx context.Context) error
	// Run runs one job, already checked by core (nucleiargv.Build), and returns what nuclei printed. Cancelling ctx
	// stops the run (Stop now, the device timeout): the engine kills the process group and returns soon after.
	Run(ctx context.Context, j nucleiargv.Job) (Output, error)
}
