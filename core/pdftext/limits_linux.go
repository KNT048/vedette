//go:build linux

package pdftext

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	growthAS = 512 << 20 // address space the child may add to what the Go runtime has reserved at start
)

// limitCPUText is the seconds of CPU; soft = hard, so the kernel sends SIGKILL at the limit. A string only so that the test child can be
// built with `-ldflags -X` to a short one (pdftexttest.BuildChild); the release build keeps 60.
var limitCPUText = "60"

// setLimits lowers the child's own limits (soft = hard, so they cannot be raised again): address space, CPU time, no core file
// (a core dump would write the untrusted file's memory to disk). RLIMIT_FSIZE is left alone: it would kill the child with SIGXFSZ
// when stdout is a file, and the child opens no file anyway. A limit the unit already set lower (LimitCPU=, LimitAS=) is kept: the
// child takes the lower of the two, as an unprivileged process cannot raise a hard limit.
//
// It also makes the child the first pick of the OOM killer (oom_score_adj 1000): if the box or the container's cgroup runs out of
// memory while a PDF is read, the kernel kills the child, not core. Raising one's own score needs no privilege. ponytail: no nice;
// on Linux setpriority acts on one thread and the Go runtime runs several, the CPU limit bounds the child anyway.
//
// The address-space limit is the size at start plus growthAS, not a bare 512 MiB: a Go process has about 1.2 GB of address space
// reserved before it runs a line (arena index, spans, stacks; measured with a hello world), so 512 MiB in absolute terms would make the first
// allocation fail. What the limit bounds is what the file can make the process add, which is what matters.
func setLimits() error {
	base, err := addressSpace()
	if err != nil {
		return err
	}
	cpu, err := strconv.ParseUint(limitCPUText, 10, 64)
	if err != nil || cpu == 0 {
		return fmt.Errorf("pdftext: bad CPU limit %q", limitCPUText)
	}
	for _, l := range []struct {
		res int
		n   uint64
	}{{syscall.RLIMIT_AS, base + growthAS}, {syscall.RLIMIT_CPU, cpu}, {syscall.RLIMIT_CORE, 0}} {
		var cur syscall.Rlimit
		if err := syscall.Getrlimit(l.res, &cur); err != nil {
			return err
		}
		n := min(l.n, cur.Max)
		if err := syscall.Setrlimit(l.res, &syscall.Rlimit{Cur: n, Max: n}); err != nil {
			return err
		}
	}
	return os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0)
}

// addressSpace is the current virtual size in bytes: the first field of /proc/self/statm is in pages.
func addressSpace() (uint64, error) {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	f, _, _ := strings.Cut(string(b), " ")
	pages, err := strconv.ParseUint(f, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("pdftext: /proc/self/statm: %w", err)
	}
	return pages * uint64(os.Getpagesize()), nil //nolint:gosec // the page size is positive
}
