package honeypot_test

// The log folder belongs to the honeypot container, which faces attackers and may be compromised (D-89): whatever it puts at
// the log name must never block, redirect or overload core.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// releaseFIFO opens the write end so a reader blocked in open(2) wakes up, then closes it (the reader sees EOF).
func releaseFIFO(t *testing.T, path string) {
	t.Helper()
	w, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // test FIFO
	if err == nil {
		_ = w.Close()
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// A FIFO at the log name must not block Poll in open(2): it is opened without waiting, found not to be a regular file,
// skipped and counted.
func TestTailFIFOAtTheLogNameDoesNotBlockPoll(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	mkfifo(t, e.logPath())
	done := make(chan error, 1)
	go func() { done <- e.svc.Poll(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a FIFO is skipped, not an error that fills the log every second: %v", err)
		}
	case <-time.After(5 * time.Second):
		releaseFIFO(t, e.logPath())
		t.Log(<-done)
		t.Fatal("Poll blocked in open(2) on a FIFO planted at the log name")
	}
	if n := e.svc.Stats().NotRegular; n != 1 {
		t.Fatalf("NotRegular = %d, want 1", n)
	}
}

// Poll runs inside the run loop: a Poll that cannot be stuck means the module can still be switched off, which takes the
// container and the decoy IPs down (SYS-5).
func TestTailFIFOAtTheLogNameDoesNotBlockSwitchOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.PollEvery = 10 * time.Millisecond })
	e.setup()
	ctx, cancel := context.WithCancel(e.ctx())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	waitFor(t, "container started", e.host.isRunning)
	mkfifo(t, e.logPath())
	<-time.After(300 * time.Millisecond) // several polls meet the FIFO
	e.gate.set(true)                     // the owner switches the module off; the scheduler cancels the job
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if e.host.isRunning() || e.host.ipCount() != 0 {
			t.Fatalf("module off but running=%v ips=%d", e.host.isRunning(), e.host.ipCount())
		}
	case <-time.After(5 * time.Second):
		releaseFIFO(t, e.logPath())
		t.Log(<-done)
		t.Fatal("Run did not return after the module was switched off: stuck in Poll")
	}
}

// A symlink at the log name is never followed, whether it leaves the folder or not: core would read a file the container
// chose.
func TestTailRefusesASymlinkAtTheLogName(t *testing.T) {
	t.Parallel()
	for name, target := range map[string]func(e *env) string{
		"outside the folder": func(e *env) string { return filepath.Join(e.dir, "outside-the-folder.jsonl") },
		"inside the folder":  func(e *env) string { return filepath.Join(e.dir, "log", "other.jsonl") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.setup()
			dst := target(e)
			if err := os.MkdirAll(filepath.Dir(e.logPath()), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, []byte(sshNew("192.168.10.157", 4242, t0).json()+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dst, e.logPath()); err != nil {
				t.Fatal(err)
			}
			err := e.svc.Poll(e.ctx())
			if n := e.hitCount(); n != 0 || err == nil {
				t.Fatalf("core followed a symlink planted in the log folder to %s: %d hit(s), err=%v", dst, n, err)
			}
		})
	}
}

// More than 64 MiB unread (core was down while the container wrote a flood): the reader jumps to the end, counts the
// bytes it skipped and goes on with what comes next; the half-written last line is skipped too.
func TestTailJumpsToTheEndWhenFarBehind(t *testing.T) {
	t.Parallel()
	for name, ending := range map[string]string{"at a line end": "\n", "inside a line": `{"logtype":4000,"src_ho`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.setup()
			e.appendLog(sshNew("192.168.10.157", 1, t0).json())
			e.poll()
			if e.hitCount() != 1 {
				t.Fatal("setup")
			}
			f, err := os.OpenFile(e.logPath(), os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString("\n" + sshNew("192.168.10.158", 2, t0).json() + "\n"); err != nil { // never read: jumped over
				t.Fatal(err)
			}
			st, _ := f.Stat()
			if err := f.Truncate(st.Size() + 70<<20); err != nil { // a sparse 70 MiB of the flood
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte(ending), st.Size()+70<<20); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			e.poll()
			if n := e.svc.Stats().SkippedBytes; n < 64<<20 {
				t.Fatalf("SkippedBytes = %d", n)
			}
			if e.hitCount() != 1 {
				t.Fatalf("%d hits: what was unread must not be read", e.hitCount())
			}
			// The empty line ends the half-written one (garbage, skipped); the next line is read.
			e.appendLog("", sshNew("192.168.10.159", 3, t0).json())
			e.poll()
			if e.hitCount() != 2 {
				t.Fatalf("%d hits after the first line past the jump, want 2", e.hitCount())
			}
		})
	}
}
