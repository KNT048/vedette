package scan

import "context"

// Engine is the scanner seam (D-125): the worker in the scan container that runs the pinned nuclei binary, reached
// over the sensor protocol. Tests pass a fake. A dev-only local runner may implement it later; production wires the
// remote one (S5). Without an Engine the scanner is unavailable and nothing is ever sent (INV-2).
type Engine interface {
	// Ready returns nil when a job can be sent now: the worker has a fresh heartbeat with nuclei and the template
	// pack present. Otherwise it says why, for the log; the user sees msgScannerDown.
	Ready(ctx context.Context) error
}
