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
	limitCPU = 60        // seconds of CPU; the kernel sends SIGXCPU at the soft limit and SIGKILL at the hard one
)

// setLimits lowers the child's own limits (soft = hard, so they cannot be raised again): address space, CPU time, no core file
// (a core dump would write the untrusted file's memory to disk). RLIMIT_FSIZE is left alone: it would kill the child with SIGXFSZ
// when stdout is a file, and the child opens no file anyway.
//
// The address-space limit is the size at start plus growthAS, not a bare 512 MiB: a Go process has about 1.2 GB of address space
// reserved before it runs a line (arena index, spans, stacks; measured with a hello world), so 512 MiB in absolute terms would make the first
// allocation fail. What the limit bounds is what the file can make the process add, which is what matters.
func setLimits() error {
	base, err := addressSpace()
	if err != nil {
		return err
	}
	for _, l := range []struct {
		res int
		n   uint64
	}{{syscall.RLIMIT_AS, base + growthAS}, {syscall.RLIMIT_CPU, limitCPU}, {syscall.RLIMIT_CORE, 0}} {
		if err := syscall.Setrlimit(l.res, &syscall.Rlimit{Cur: l.n, Max: l.n}); err != nil {
			return err
		}
	}
	return nil
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
