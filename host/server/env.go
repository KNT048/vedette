package server

import (
	"errors"
	"log/slog"

	vexec "github.com/knt048/vedette/core/exec"
)

// debianFrontend completes the clean environment of SYS-1 for child processes: core/exec fixes
// PATH and LANG=C and inherits nothing; the host adds DEBIAN_FRONTEND so apt never prompts.
const debianFrontend = "DEBIAN_FRONTEND=noninteractive"

// NewCommandRunner builds the one exec.Runner commands use for child processes. Every binary it
// gets runs with exactly PATH, LANG=C and DEBIAN_FRONTEND=noninteractive, no shell, from "/".
// A binary that sets its own Env is rejected: the environment is not the command's to choose.
func NewCommandRunner(log *slog.Logger, bins ...vexec.Binary) (*vexec.Runner, error) {
	for i := range bins {
		if len(bins[i].Env) != 0 {
			return nil, errors.New("host: binaries must not set their own Env")
		}
		bins[i].Env = []string{debianFrontend}
	}
	return vexec.NewRunner(log, bins...)
}
