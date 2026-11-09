package exec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
)

// The test binary doubles as the helper process: `<test-binary> __helper__ <mode> [args...]`.
// The Runner clears the environment, so the mode travels in argv.
const helperArg = "__helper__"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		helper(os.Args[2], os.Args[3:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string, args []string) {
	switch mode {
	case "echo": // argv as a JSON array
		_ = json.NewEncoder(os.Stdout).Encode(args)
	case "env":
		_ = json.NewEncoder(os.Stdout).Encode(os.Environ())
	case "cwd":
		wd, _ := os.Getwd()
		_, _ = fmt.Fprint(os.Stdout, wd)
	case "cat": // stdin to stdout
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "exit":
		code, _ := strconv.Atoi(args[0])
		_, _ = fmt.Fprint(os.Stderr, "some stderr")
		os.Exit(code)
	case "flood": // N bytes on stdout and N on stderr
		n, _ := strconv.Atoi(args[0])
		chunk := bytes.Repeat([]byte("x"), 1000)
		for _, w := range []*os.File{os.Stdout, os.Stderr} {
			for left := n; left > 0; left -= len(chunk) {
				_, _ = w.Write(chunk[:min(left, len(chunk))])
			}
		}
	case "block":
		blockForever()
	case "fork": // start a blocked grandchild, print its pid, then block too
		p, err := os.StartProcess(os.Args[0], []string{os.Args[0], helperArg, "block"}, &os.ProcAttr{}) //nolint:gosec // test helper re-executing the test binary itself
		if err != nil {
			os.Exit(3)
		}
		fmt.Println(p.Pid)
		blockForever()
	case "spawn": // start a blocked grandchild, print its pid, and exit normally; "inherit" shares our stdout
		files := []*os.File(nil)
		if len(args) > 0 && args[0] == "inherit" {
			files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
		}
		p, err := os.StartProcess(os.Args[0], []string{os.Args[0], helperArg, "block"}, &os.ProcAttr{Files: files}) //nolint:gosec // test helper re-executing the test binary itself
		if err != nil {
			os.Exit(3)
		}
		fmt.Println(p.Pid)
	default:
		os.Exit(99)
	}
}

// blockForever waits on a signal channel: a registered handler keeps the runtime's
// "all goroutines are asleep" deadlock detector from ending the process early.
func blockForever() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	<-c
}

func testBinary(t *testing.T, validate func([]string) error, maxOutput int64) vexec.Binary {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if validate == nil {
		validate = func(args []string) error {
			if len(args) < 1 {
				return errors.New("missing mode")
			}
			return nil
		}
	}
	return vexec.Binary{Name: "helper", Path: self, Validate: validate, MaxOutput: maxOutput}
}

// helperArgs prefixes the helper switch; the runner passes args straight to the binary.
func helperArgs(mode string, args ...string) []string {
	return append([]string{helperArg, mode}, args...)
}

func newRunner(t *testing.T, bins ...vexec.Binary) *vexec.Runner {
	t.Helper()
	r, err := vexec.NewRunner(slog.New(slog.DiscardHandler), bins...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func deadline(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestNewRunner(t *testing.T) {
	t.Parallel()
	ok := func(string) vexec.Binary { return testBinary(t, nil, 0) }
	tests := []struct {
		name string
		bins []vexec.Binary
		ok   bool
	}{
		{"none", nil, true},
		{"one", []vexec.Binary{ok("")}, true},
		{"duplicate", []vexec.Binary{ok(""), ok("")}, false},
		{"relative path", []vexec.Binary{{Name: "x", Path: "bin/x", Validate: func([]string) error { return nil }}}, false},
		{"empty path", []vexec.Binary{{Name: "x", Validate: func([]string) error { return nil }}}, false},
		{"nil validator", []vexec.Binary{{Name: "x", Path: "/bin/x"}}, false},
		{"bad name", []vexec.Binary{{Name: "X Y", Path: "/bin/x", Validate: func([]string) error { return nil }}}, false},
		{"empty name", []vexec.Binary{{Path: "/bin/x", Validate: func([]string) error { return nil }}}, false},
		{"negative max output", []vexec.Binary{{Name: "x", Path: "/bin/x", Validate: func([]string) error { return nil }, MaxOutput: -1}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := vexec.NewRunner(slog.New(slog.DiscardHandler), tc.bins...)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestRunRefusals(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, func(args []string) error {
		if len(args) > 3 {
			return errors.New("too many args")
		}
		return nil
	}, 0))

	t.Run("unknown name", func(t *testing.T) {
		t.Parallel()
		_, err := r.Run(deadline(t, 10*time.Second), "nmap", nil, nil)
		if !errors.Is(err, vexec.ErrNotAllowed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("name is not a path", func(t *testing.T) {
		t.Parallel()
		self, _ := os.Executable()
		_, err := r.Run(deadline(t, 10*time.Second), self, helperArgs("echo"), nil)
		if !errors.Is(err, vexec.ErrNotAllowed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no deadline", func(t *testing.T) {
		t.Parallel()
		_, err := r.Run(t.Context(), "helper", helperArgs("echo"), nil)
		if !errors.Is(err, vexec.ErrNoDeadline) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("validator rejects", func(t *testing.T) {
		t.Parallel()
		_, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("echo", "a", "b", "c"), nil)
		if !errors.Is(err, vexec.ErrBadArgs) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("NUL in an argument", func(t *testing.T) {
		t.Parallel()
		_, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("echo", "a\x00b"), nil)
		if !errors.Is(err, vexec.ErrBadArgs) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing binary file", func(t *testing.T) {
		t.Parallel()
		missing := newRunner(t, vexec.Binary{Name: "ghost", Path: "/nonexistent/ghost", Validate: func([]string) error { return nil }})
		_, err := missing.Run(deadline(t, 10*time.Second), "ghost", nil, nil)
		if err == nil {
			t.Fatal("expected a start error")
		}
		var ee *vexec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("start failure reported as exit error: %v", err)
		}
	})
}

func TestRunNoShell(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	nasty := []string{
		"$(id); rm -rf /",
		"`id`",
		"a && b || c | d > e < f & g",
		"; touch /tmp/pwned",
		"*",
		"~",
		"$HOME ${PATH}",
		"with 'single' and \"double\" quotes",
		"line1\nline2",
		"--flag=$(whoami)",
		"",
		"  spaces  ",
	}
	res, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("echo", nasty...), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(res.Stdout, &got); err != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, err)
	}
	if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", nasty) {
		t.Fatalf("argv changed in transit:\n got %q\nwant %q", got, nasty)
	}
	if res.ExitCode != 0 || res.Truncated {
		t.Fatalf("res = %+v", res)
	}
}

func TestRunEnvironmentAndDir(t *testing.T) {
	t.Setenv("VEDETTE_SECRET_FOR_TEST", "must-not-leak")
	r := newRunner(t, testBinary(t, nil, 0))

	res, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("env"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	if err := json.Unmarshal(res.Stdout, &env); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"PATH=/usr/sbin:/usr/bin:/sbin:/bin": true, "LANG=C": true}
	for _, e := range env {
		if !want[e] {
			// The Go runtime may add nothing else; anything extra is a leak from the parent.
			t.Errorf("unexpected environment entry %q", e)
		}
		delete(want, e)
	}
	if len(want) != 0 {
		t.Errorf("missing environment entries %v (got %v)", want, env)
	}

	res, err = r.Run(deadline(t, 10*time.Second), "helper", helperArgs("cwd"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "/" {
		t.Fatalf("cwd = %q, want /", res.Stdout)
	}
}

func TestRunStdin(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	res, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("cat"), strings.NewReader("hello stdin"))
	if err != nil || string(res.Stdout) != "hello stdin" {
		t.Fatalf("res = %q, err = %v", res.Stdout, err)
	}
}

func TestRunExitCode(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	for _, code := range []int{1, 2, 42, 255} {
		res, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("exit", strconv.Itoa(code)), nil)
		var ee *vexec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("code %d: err = %v, want *ExitError", code, err)
		}
		if ee.ExitCode != code || res.ExitCode != code || ee.Name != "helper" {
			t.Errorf("code %d: ExitError %+v, Result.ExitCode %d", code, ee, res.ExitCode)
		}
		if string(res.Stderr) != "some stderr" {
			t.Errorf("stderr = %q", res.Stderr)
		}
		if strings.Contains(err.Error(), "some stderr") {
			t.Errorf("ExitError leaks output: %v", err)
		}
	}
}

func TestRunOutputBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		max       int64
		n         int
		wantLen   int
		truncated bool
	}{
		{"under the limit", 5000, 3000, 3000, false},
		{"exactly the limit", 3000, 3000, 3000, false},
		{"one byte over", 3000, 3001, 3000, true},
		{"far over (child must not block)", 1000, 2_000_000, 1000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRunner(t, testBinary(t, nil, tc.max))
			res, err := r.Run(deadline(t, 30*time.Second), "helper", helperArgs("flood", strconv.Itoa(tc.n)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Stdout) != tc.wantLen || len(res.Stderr) != tc.wantLen || res.Truncated != tc.truncated {
				t.Fatalf("stdout %d, stderr %d, truncated %v; want %d, %v", len(res.Stdout), len(res.Stderr), res.Truncated, tc.wantLen, tc.truncated)
			}
		})
	}
	t.Run("default limit is 4 MiB", func(t *testing.T) {
		t.Parallel()
		r := newRunner(t, testBinary(t, nil, 0))
		res, err := r.Run(deadline(t, 30*time.Second), "helper", helperArgs("flood", strconv.Itoa(5<<20)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(res.Stdout)) != vexec.DefaultMaxOutput || !res.Truncated {
			t.Fatalf("stdout %d, truncated %v", len(res.Stdout), res.Truncated)
		}
	})
}

func TestRunTimeoutKillsProcess(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	res, err := r.Run(deadline(t, 300*time.Millisecond), "helper", helperArgs("block"), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if res.Duration > 10*time.Second {
		t.Fatalf("took %v: process was not killed at the deadline", res.Duration)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = %d for a killed process", res.ExitCode)
	}
}

func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	res, err := r.Run(deadline(t, time.Second), "helper", helperArgs("fork"), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	waitGone(t, res.Stdout)
}

// waitGone fails unless the pid printed by the helper is gone soon. A killed grandchild is
// reparented and reaped asynchronously, so poll.
func waitGone(t *testing.T, out []byte) {
	t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("grandchild pid from %q: %v", out, err)
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	limit := time.After(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		select {
		case <-tick.C:
		case <-limit:
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild %d survived", pid)
		}
	}
}

// The child exits normally but leaves a grandchild behind: it must not outlive the command.
func TestRunKillsGrandchildAfterNormalExit(t *testing.T) {
	t.Parallel()
	r := newRunner(t, testBinary(t, nil, 0))
	t.Run("grandchild without stdio", func(t *testing.T) {
		t.Parallel()
		res, err := r.Run(deadline(t, 30*time.Second), "helper", helperArgs("spawn"), nil)
		if err != nil {
			t.Fatal(err)
		}
		waitGone(t, res.Stdout)
	})
	t.Run("grandchild holding the output pipe", func(t *testing.T) {
		t.Parallel()
		res, err := r.Run(deadline(t, 30*time.Second), "helper", helperArgs("spawn", "inherit"), nil)
		if err != nil { // the child exited 0; the held pipe only delays Run (WaitDelay)
			t.Fatal(err)
		}
		waitGone(t, res.Stdout)
	})
}

func TestRunLogsNoArgvOrOutput(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, err := vexec.NewRunner(log, testBinary(t, nil, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("echo", "TOPSECRET-ARG"), nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "TOPSECRET") {
		t.Fatalf("log contains argv or output: %s", out)
	}
	for _, want := range []string{`"binary":"helper"`, `"exit_code":0`, `"duration"`, `"level":"DEBUG"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s: %s", want, out)
		}
	}
}

func TestNewRunnerRejectsNilLogger(t *testing.T) {
	t.Parallel()
	if _, err := vexec.NewRunner(nil, testBinary(t, nil, 0)); err == nil {
		t.Fatal("nil logger accepted")
	}
}

func TestRunExtraEnv(t *testing.T) {
	t.Setenv("VEDETTE_SECRET_FOR_TEST", "must-not-leak")
	b := testBinary(t, nil, 0)
	b.Env = []string{"DEBIAN_FRONTEND=noninteractive"}
	r := newRunner(t, b)
	res, err := r.Run(deadline(t, 10*time.Second), "helper", helperArgs("env"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	if err := json.Unmarshal(res.Stdout, &env); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"PATH=/usr/sbin:/usr/bin:/sbin:/bin": true, "LANG=C": true, "DEBIAN_FRONTEND=noninteractive": true}
	for _, e := range env {
		if !want[e] {
			t.Errorf("unexpected environment entry %q", e)
		}
		delete(want, e)
	}
	if len(want) != 0 {
		t.Errorf("missing environment entries %v", want)
	}
}

func TestNewRunnerRejectsBadEnv(t *testing.T) {
	t.Parallel()
	for _, env := range [][]string{
		{"PATH=/evil"}, {"LANG=en_US"}, {"lower=x"}, {"NOEQUALS"}, {"DEBIAN_FRONTEND=a\x00b"}, {"DEBIAN_FRONTEND=a", "DEBIAN_FRONTEND=b"}, {"=x"},
		{"LD_PRELOAD=/tmp/evil.so"}, {"LD_LIBRARY_PATH=/tmp"}, {"LC_ALL=C"}, {"LC_MESSAGES=C"}, {"PYTHONPATH=/tmp"}, {"FOO=bar"}, {"BASH_ENV=/tmp/x"},
	} {
		b := testBinary(t, nil, 0)
		b.Env = env
		if _, err := vexec.NewRunner(slog.New(slog.DiscardHandler), b); err == nil {
			t.Errorf("Env %q was accepted", env)
		}
	}
}
