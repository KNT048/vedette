package sensoractive

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/knt048/vedette/core/exec"
)

// Output is what a finished nmap run hands back: the XML it printed on stdout (D-113).
type Output struct {
	XML       []byte
	Truncated bool // the run printed more than the cap; XML is incomplete and must be discarded (INV-7)
}

// Prober runs one nmap command that sensoractive has already checked against the scope, the window and the
// settings (INV-1..INV-3), and whose probe row is already written (INV-9). argv is the whole nmapargv.Build
// line; ctx carries the deadline (the window's end or maxRun) and cancelling it kills the run. A non-zero exit
// is an error that errors.As finds an *exec.ExitError in. The local implementation runs nmap through core/exec;
// SP-3 adds one that hands the job to a worker in the scan container.
type Prober interface {
	Probe(ctx context.Context, argv []string) (Output, error)
}

type localProber struct{ runner *exec.Runner }

// NewLocalProber returns the Prober that starts the OS package's nmap at path through core/exec, whose
// allowlist re-validates the argv (SYS-2). A nil log discards.
func NewLocalProber(log *slog.Logger, path string) (Prober, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r, err := exec.NewRunner(log, NmapBinary(path))
	if err != nil {
		return nil, fmt.Errorf("sensoractive: %w", err)
	}
	return localProber{runner: r}, nil
}

func (p localProber) Probe(ctx context.Context, argv []string) (Output, error) {
	res, err := p.runner.Run(ctx, nmapName, argv, nil)
	return Output{XML: res.Stdout, Truncated: res.Truncated}, err
}
