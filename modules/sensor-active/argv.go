package sensoractive

import (
	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// MaxBatch is the most addresses one nmap run gets, so its XML stays small (D-84 (7)).
const MaxBatch = nmapargv.MaxBatch

// maxOutput caps what one nmap run may print; more means the run is discarded (INV-7).
const maxOutput = nmapargv.MaxOutput

// ValidateNmapArgs re-checks a whole nmap argv; the rules live in the leaf package nmapargv, which the sensor
// binary links too.
func ValidateNmapArgs(args []string) error { return nmapargv.Validate(args) }

// NmapBinary is the allowlist entry for nmap: an absolute path to the OS package's binary, the validator
// above, and the output cap. Register it with core/exec.NewRunner.
func NmapBinary(path string) exec.Binary {
	return exec.Binary{Name: nmapName, Path: path, Validate: ValidateNmapArgs, MaxOutput: maxOutput}
}

const nmapName = "nmap"
