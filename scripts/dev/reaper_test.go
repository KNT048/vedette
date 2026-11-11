package dev

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Throwaway trees only: every reaper run is limited by VEDETTE_REAPER_ONLY to the test's own
// temp dir, so a real orphan on the developer's machine is never touched.

const (
	fakeVite = "#!/bin/sh\nsleep 300 &\nwait\n"
	fakePnpm = "#!/bin/sh\n\"$(dirname \"$0\")/node_modules/.bin/vite\"\n"
)

func pidsMatching(t *testing.T, pattern string) []int {
	t.Helper()
	out, _ := exec.Command("pgrep", "-f", pattern).Output()
	var pids []int
	for _, f := range strings.Fields(string(out)) {
		if p, err := strconv.Atoi(f); err == nil && p != os.Getpid() {
			pids = append(pids, p)
		}
	}
	return pids
}

func ppidOf(pid int) int {
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return -1
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func alive(pid int) bool { return exec.Command("kill", "-0", strconv.Itoa(pid)).Run() == nil }

// tree starts `pnpm dev` (sh wrapper) -> fake vite -> sleep in a fresh dir. orphan=true detaches
// the wrapper so its parent exits and it is reparented to init.
func tree(t *testing.T, orphan bool) (dir string, pids []int) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", ".bin", "vite"), []byte(fakeVite), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm"), []byte(fakePnpm), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range pidsMatching(t, dir) {
			_ = exec.Command("kill", "-KILL", strconv.Itoa(p)).Run()
		}
	})
	script := `"` + dir + `/pnpm" dev </dev/null >/dev/null 2>&1 &`
	if orphan {
		if err := exec.Command("sh", "-c", script).Run(); err != nil {
			t.Fatal(err)
		}
	} else {
		c := exec.Command("sh", "-c", `exec "`+dir+`/pnpm" dev </dev/null >/dev/null 2>&1`)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pids = pidsMatching(t, dir)
		if len(pids) >= 2 { // wrapper + vite; sleep's argv does not contain dir
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(pids) < 2 {
		t.Fatalf("tree did not start: %v", pids)
	}
	return dir, pids
}

func reap(t *testing.T, dir string) string {
	t.Helper()
	script, _ := filepath.Abs("orphan-reaper.sh")
	c := exec.Command("bash", script)
	c.Env = append(os.Environ(),
		"VEDETTE_REAPER_ONLY="+dir, "VEDETTE_REAPER_SERVER_MIN=0", "VEDETTE_REAPER_ISSUES=0",
		"VEDETTE_REAPER_NOTIFY=0", "VEDETTE_REAPER_LOG="+filepath.Join(t.TempDir(), "log"))
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("reaper: %v\n%s", err, out)
	}
	logb, _ := os.ReadFile(c.Env[len(c.Env)-1][len("VEDETTE_REAPER_LOG="):])
	return string(logb)
}

func waitDead(pids []int) []int {
	deadline := time.Now().Add(10 * time.Second)
	var left []int
	for time.Now().Before(deadline) {
		left = left[:0]
		for _, p := range pids {
			if alive(p) {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return left
}

func TestReapsOrphanedPnpmTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS and Linux only")
	}
	dir, pids := tree(t, true)
	// the wrapper is the one whose parent is not another tree member
	root := pids[0]
	for _, p := range pids {
		if ppidOf(p) == 1 || !contains(pids, ppidOf(p)) {
			root = p
		}
	}
	if ppidOf(root) != 1 {
		t.Skipf("orphan was not reparented to pid 1 (ppid %d): subreaper environment", ppidOf(root))
	}
	log := reap(t, dir)
	if left := waitDead(append(pids, childrenOf(pids)...)); left != nil {
		t.Fatalf("still alive after reaper: %v\nlog: %s", left, log)
	}
	if !strings.Contains(log, "stopped") || !strings.Contains(log, "orphaned dev server") {
		t.Fatalf("log line missing: %q", log)
	}
}

func TestLeavesLiveTreeAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS and Linux only")
	}
	dir, pids := tree(t, false) // root's parent is this test process: alive, not init
	reap(t, dir)
	time.Sleep(500 * time.Millisecond)
	for _, p := range pids {
		if !alive(p) {
			t.Fatalf("live tree member %d was killed", p)
		}
	}
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func childrenOf(pids []int) []int {
	var out []int
	for _, p := range pids {
		b, _ := exec.Command("pgrep", "-P", strconv.Itoa(p)).Output()
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
