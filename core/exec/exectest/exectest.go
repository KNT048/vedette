// Package exectest helps tests that run fake programs (a fake nmap, apt, systemctl…) through core/exec.
package exectest

import (
	"os"
	"syscall"
	"testing"
)

// WriteScript writes an executable file for a test. It holds syscall.ForkLock while the file is open for
// writing: a process that a parallel test forks in that moment would otherwise inherit the write descriptor
// until it execs, and running the script right away would fail with ETXTBSY ("text file busy") on Linux
// (golang/go#22315). os/exec takes the read side of the same lock around fork.
func WriteScript(t testing.TB, path, body string) {
	t.Helper()
	syscall.ForkLock.Lock()
	err := os.WriteFile(path, []byte(body), 0o700) //nolint:gosec // a fake program must be executable
	syscall.ForkLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}
