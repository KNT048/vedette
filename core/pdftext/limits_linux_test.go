//go:build linux

package pdftext

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// limitsHelper is set in the re-executed test binary: it lowers RLIMIT_CPU first (a unit with LimitCPU=30), runs setLimits and prints
// what the kernel then says. setLimits cannot be undone, so it runs in a process of its own. This is the package's only TestMain
// (Linux only): another TestMain in package pdftext would not build on Linux; merge it into this one.
const limitsHelper = "VEDETTE_PDFTEXT_LIMITS_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(limitsHelper) == "1" {
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 30, Max: 30}); err != nil { // a runner already below 30 s
			os.Stdout.WriteString("lowering RLIMIT_CPU: " + err.Error())
			os.Exit(3)
		}
		if err := setLimits(); err != nil {
			os.Stdout.WriteString("setLimits: " + err.Error())
			os.Exit(4)
		}
		var cpu syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_CPU, &cpu)
		score, _ := os.ReadFile("/proc/self/oom_score_adj")
		os.Stdout.WriteString("cpu=" + strconv.FormatUint(cpu.Max, 10) + " oom=" + strings.TrimSpace(string(score)))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// L3, L4 (#339 review): the child keeps a lower limit the unit set (it cannot raise a hard limit, and refusing every PDF would be
// silent), and makes itself the OOM killer's first pick, so a PDF that eats the cgroup's memory takes down the child, not core.
func TestSetLimitsKeepsALowerUnitLimitAndRaisesTheOOMScore(t *testing.T) {
	t.Parallel()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), limitsHelper+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v %q", err, out)
	}
	if got := string(out); got != "cpu=30 oom=1000" {
		t.Fatalf("after setLimits: %q, want cpu=30 oom=1000", got)
	}
}
