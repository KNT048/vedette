package nucleiout

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// Host errors (INV-6, D-165). With -ms (matcher status) stdout has a line per template and target, but a device that
// answered some templates and then died leaves lines that look like answers. The signal that says it stopped is nuclei's own error log (-elog, written to stderr): one JSON object per failed request,
// {"template","type","input","address","error","kind"} (pkg/output JSONLogRequest, v3.11.1). The worker counts, per
// target of the job, the lines whose kind is "network-temporary-error" (a timeout: what a device that went quiet
// produces; "connection refused" is a permanent error and means the device is alive) and reports them.

// Limits of the error log the worker reads.
const (
	MaxErrorLog     = 1 << 20 // bytes of stderr read; the rest is ignored (an undercount is the safe side)
	maxErrorLogLine = 8 << 10 // a longer line is not an error-log line
	kindTimeout     = "network-temporary-error"
)

// HostError is what the worker saw for one target of a nuclei job.
type HostError struct {
	Target      string // host:port, one of the job's targets
	Errors      int    // lines of kind network-temporary-error for it
	Unreachable bool   // Errors reached the job's max host errors: nuclei itself stops sending to such a target (-mhe)
}

// Outcome is what a nuclei run gave core: the lines of stdout and the host errors of the worker.
type Outcome struct {
	Results    []Result
	HostErrors []HostError
}

type errLine struct {
	Input   string `json:"input"`
	Address string `json:"address"`
	Kind    string `json:"kind"`
}

// ParseHostErrors counts the timeouts per target in nuclei's error log. The input is untrusted and mixed with anything else
// nuclei writes to stderr, so it never fails: a line that is not one JSON object of the shape above, an ambiguous one, a
// long one, and a line for a target the job did not name are skipped, and only the first MaxErrorLog bytes are read. It
// returns one entry, in the job's order, for each target with at least one timeout; targets are host:port.
func ParseHostErrors(stderr []byte, targets []string, maxHostErrors int) []HostError {
	if len(stderr) > MaxErrorLog {
		stderr = stderr[:MaxErrorLog]
	}
	counts := make([]int, len(targets))
	for _, raw := range bytes.Split(stderr, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || len(raw) > maxErrorLogLine || raw[0] != '{' || jsonstrict.Ambiguous(raw) != "" {
			continue
		}
		var l errLine
		if json.Unmarshal(raw, &l) != nil || l.Kind != kindTimeout {
			continue
		}
		i := slices.Index(targets, l.Address)
		if i < 0 {
			i = slices.Index(targets, hostOf(l.Input))
		}
		if i >= 0 && counts[i] < 1<<20 {
			counts[i]++
		}
	}
	var out []HostError
	for i, n := range counts {
		if n > 0 {
			out = append(out, HostError{Target: targets[i], Errors: n, Unreachable: maxHostErrors > 0 && n >= maxHostErrors})
		}
	}
	return out
}
