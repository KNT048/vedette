package scan

import (
	"context"
	"errors"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// Engine is the scanner seam (D-125): the worker in the scan container that runs the pinned nuclei binary, reached
// over the sensor protocol (S5: cmd/vedette wires the Dispatcher of sensor-active). Tests pass a fake. Without an
// Engine, or without a template pack, the scanner is unavailable and nothing is ever sent (INV-2).
type Engine interface {
	// Ready returns nil when a job can be sent now: the worker has a fresh heartbeat with nuclei and the template
	// pack present. Otherwise it says why, for the log; the user sees msgScannerDown.
	Ready(ctx context.Context) error
	// Run runs one job, already checked by core (nucleiargv.Build), and returns one result per line nuclei printed,
	// parsed fail closed against the job's templates and targets (nucleiout.Parse): a line that is not what the job
	// asked for makes the whole run an error, and output over the cap is an error too (INV-10). No line is an empty
	// result, which only means "no match reported", never "not vulnerable" (D-133 (5)); with -ms nuclei prints a non-match
	// or error line per template and target, so an empty output is unusual. Outcome.HostErrors says which targets
	// nuclei gave up on (timeouts counted from its error log, D-165): how core sees a device that died after it had
	// answered some templates (INV-6). Cancelling ctx stops the run
	// (Stop now, the device timeout): the engine stops nuclei and returns soon after. An error that wraps
	// ErrEngineDown says the scanner itself cannot run jobs now (the worker gone, another template pack): the run stops
	// with that message instead of trying every device.
	Run(ctx context.Context, j Job) (nucleiout.Outcome, error)
}

// Job is one nuclei run as core planned it: the argv job (template paths of the pack index, checked by
// nucleiargv.Build), the same templates by id in the same order, and the pack they come from. The worker's copy of the
// index maps the ids to its paths and refuses a job planned for another pack (D-133 (4)).
type Job struct {
	nucleiargv.Job
	IDs                     []string
	PackVersion, PackSHA256 string
}

// ErrEngineDown is wrapped by an Engine.Run error that means the scanner cannot run any job now.
var ErrEngineDown = errors.New("scan: the scanner cannot run jobs now")
