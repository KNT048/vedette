//go:build linux

package exec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	vexec "github.com/knt048/vedette/core/exec"
)

// ttyView is what the helper's "tty" mode prints: what nmap 7.95's tty_init asks before it lets --stats-every print anything.
type ttyView struct {
	StdinTTY   bool `json:"stdin_tty"`  // isatty(0)
	Ctty       bool `json:"ctty"`       // open("/dev/tty", O_RDONLY|O_NONBLOCK) succeeds
	Foreground bool `json:"foreground"` // tcgetpgrp(that fd) == getpgrp()
}

// ttyHelper prints a ttyView. With "flood" it first writes 1 MiB to its terminal: far more than a pseudo-terminal buffers, so it
// returns only if the Runner reads the other end.
func ttyHelper(args []string) {
	var v ttyView
	_, err := unix.IoctlGetTermios(0, unix.TCGETS)
	v.StdinTTY = err == nil
	if fd, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NONBLOCK, 0); err == nil {
		v.Ctty = true
		pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		v.Foreground = err == nil && pg == unix.Getpgrp()
		_ = unix.Close(fd)
	}
	if len(args) > 0 && args[0] == "flood" {
		w, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
		if err != nil {
			os.Exit(4)
		}
		line := bytes.Repeat([]byte("x"), 1023)
		line = append(line, '\n')
		for range 1024 {
			if _, err := w.Write(line); err != nil {
				os.Exit(5)
			}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(v)
}

// canOpenPTY skips a test where this machine (a container without devpts, say) has no pseudo-terminals at all.
func canOpenPTY(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	_ = f.Close()
}

func runTTY(t *testing.T, r *vexec.Runner, args ...string) ttyView {
	t.Helper()
	res, err := r.Run(deadline(t, 30*time.Second), "helper", helperArgs("tty", args...), nil)
	if err != nil {
		t.Fatalf("run: %v (stderr %q)", err, res.Stderr)
	}
	var v ttyView
	if err := json.Unmarshal(res.Stdout, &v); err != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, err)
	}
	return v
}

// #830 FAIL 1: nmap in the scan container printed no progress, because core/exec started it without a controlling terminal. A TTY
// binary gets one, as its stdin, with its process group in the foreground; its stdout is still the captured pipe.
func TestTTYBinaryHasAControllingTerminal(t *testing.T) {
	t.Parallel()
	canOpenPTY(t)
	b := testBinary(t, nil, 0)
	b.TTY = true
	if v := runTTY(t, newRunner(t, b)); !v.StdinTTY || !v.Ctty || !v.Foreground {
		t.Fatalf("TTY binary sees %+v, want a terminal on stdin that is its controlling one, in the foreground", v)
	}
	plain := testBinary(t, nil, 0)
	// Without TTY the child is in a process group of its own: even where the test itself runs on a terminal, that group is never
	// the terminal's foreground one, so nmap would stay quiet (what the N100 showed).
	if v := runTTY(t, newRunner(t, plain)); v.StdinTTY || v.Foreground {
		t.Fatalf("plain binary sees %+v, want no terminal", v)
	}
}

// What the child writes to its terminal is read and dropped: a child that writes far more than the terminal buffers still ends.
func TestTTYOutputNeverBlocksTheChild(t *testing.T) {
	t.Parallel()
	canOpenPTY(t)
	b := testBinary(t, nil, 0)
	b.TTY = true
	if v := runTTY(t, newRunner(t, b), "flood"); !v.Ctty {
		t.Fatalf("view = %+v", v)
	}
}

// A TTY binary reads its terminal: a stdin is refused before anything starts, not silently dropped.
func TestTTYBinaryTakesNoStdin(t *testing.T) {
	t.Parallel()
	b := testBinary(t, nil, 0)
	b.TTY = true
	_, err := newRunner(t, b).Run(deadline(t, 30*time.Second), "helper", helperArgs("tty"), strings.NewReader("x"))
	if !errors.Is(err, vexec.ErrBadArgs) {
		t.Fatalf("err = %v, want ErrBadArgs", err)
	}
}

// recordWarns counts the warnings a Runner logs.
type recordWarns struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordWarns) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }
func (h *recordWarns) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.msgs = append(h.msgs, r.Message)
	h.mu.Unlock()
	return nil
}
func (h *recordWarns) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordWarns) WithGroup(string) slog.Handler      { return h }

// Where no terminal can be opened the program still runs, as it did before #830 (no live progress), and the Runner says so once.
func TestTTYFallsBackWithoutATerminal(t *testing.T) {
	t.Parallel()
	b := testBinary(t, nil, 0)
	b.TTY = true
	h := &recordWarns{}
	r, err := vexec.NewRunner(slog.New(h), b)
	if err != nil {
		t.Fatal(err)
	}
	vexec.SetPTMX(r, "/nonexistent/ptmx")
	for range 2 {
		if v := runTTY(t, r); v.StdinTTY || v.Foreground {
			t.Fatalf("view = %+v, want no terminal", v)
		}
	}
	if len(h.msgs) != 1 {
		t.Fatalf("warnings = %q, want exactly one", h.msgs)
	}
}
