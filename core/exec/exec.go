// Package exec is the only place Vedette starts external processes (SYS-1, core PRE-4/POST-4).
// A Runner holds an allowlist of binaries; each call names one, passes an argv array that the
// binary's validator accepted, and must carry a deadline. There is no shell anywhere.
//
// OS assumption: Unix (process groups). Other platforms get ErrUnsupportedOS from Run.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// DefaultMaxOutput is the per-stream capture limit when Binary.MaxOutput is 0.
const DefaultMaxOutput int64 = 4 << 20

const waitDelay = 2 * time.Second

var (
	// ErrNotAllowed means the binary name is not on the allowlist.
	ErrNotAllowed = errors.New("exec: binary not allowed")
	// ErrNoDeadline means the context has no deadline; every run must be bounded.
	ErrNoDeadline = errors.New("exec: context has no deadline")
	// ErrBadArgs means the argv was rejected (NUL byte or the binary's validator).
	ErrBadArgs = errors.New("exec: arguments rejected")
	// ErrUnsupportedOS is returned on platforms without process groups.
	ErrUnsupportedOS = errors.New("exec: unsupported operating system")
)

// Binary describes one allowlisted program.
type Binary struct {
	Name      string                    // key used by callers
	Path      string                    // absolute path; PATH is never searched
	Validate  func(args []string) error // must accept the whole argv before the process starts
	MaxOutput int64                     // per-stream capture limit in bytes; 0 = DefaultMaxOutput
	// Env adds KEY=value entries after the fixed PATH and LANG. Only keys on the allowlist
	// (DEBIAN_FRONTEND) are accepted; the parent environment is never inherited.
	Env []string
}

// Result is what a finished process produced.
type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
	Truncated      bool // stdout or stderr hit MaxOutput; the rest was discarded
	Duration       time.Duration
}

// ExitError is returned (together with the Result) when the process exits non-zero.
// It carries no output: stderr may hold secrets, read it from Result.
type ExitError struct {
	Name     string
	ExitCode int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exec: %s exited with code %d", e.Name, e.ExitCode)
}

// Runner runs allowlisted binaries.
type Runner struct {
	log  *slog.Logger
	bins map[string]Binary
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// NewRunner validates the allowlist. Names must be unique, paths absolute, Validate non-nil.
func NewRunner(log *slog.Logger, bins ...Binary) (*Runner, error) {
	if log == nil {
		return nil, errors.New("exec: nil logger")
	}
	r := &Runner{log: log, bins: make(map[string]Binary, len(bins))}
	for _, b := range bins {
		switch {
		case !nameRE.MatchString(b.Name):
			return nil, fmt.Errorf("exec: binary name %q must match %s", b.Name, nameRE)
		case !filepath.IsAbs(b.Path) || strings.ContainsRune(b.Path, 0):
			return nil, fmt.Errorf("exec: binary %q: path %q must be absolute", b.Name, b.Path)
		case b.Validate == nil:
			return nil, fmt.Errorf("exec: binary %q: Validate is required", b.Name)
		case b.MaxOutput < 0:
			return nil, fmt.Errorf("exec: binary %q: negative MaxOutput", b.Name)
		}
		if err := checkEnv(b.Env); err != nil {
			return nil, fmt.Errorf("exec: binary %q: %w", b.Name, err)
		}
		if _, dup := r.bins[b.Name]; dup {
			return nil, fmt.Errorf("exec: binary %q listed twice", b.Name)
		}
		if b.MaxOutput == 0 {
			b.MaxOutput = DefaultMaxOutput
		}
		r.bins[b.Name] = b
	}
	return r, nil
}

// allowedEnv is the whole list of keys a binary may add to the fixed environment: only what
// vedette-host needs. Everything else (LD_*, LC_*, PATH, LANG, PYTHON*, ...) is refused by name,
// so a typo or a hostile caller cannot reshape how the child loads code or localises output.
var allowedEnv = map[string]bool{"DEBIAN_FRONTEND": true}

// checkEnv accepts KEY=value entries whose key is on allowedEnv, once each, without NUL.
func checkEnv(env []string) error {
	seen := make(map[string]bool, len(env))
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		switch {
		case !ok || !allowedEnv[k]:
			return fmt.Errorf("env key %q is not allowed", k)
		case strings.ContainsRune(v, 0):
			return fmt.Errorf("env value of %s contains NUL", k)
		case seen[k]:
			return fmt.Errorf("env key %s listed twice", k)
		}
		seen[k] = true
	}
	return nil
}

// capped keeps the first max bytes and silently drops the rest, so the child never blocks on a full pipe.
type capped struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - int64(c.buf.Len()); int64(n) > room {
		c.truncated = true
		p = p[:room]
	}
	c.buf.Write(p)
	return n, nil
}

// Run starts the allowlisted binary name with args. ctx must have a deadline; when it expires the
// whole process group is killed. A non-zero exit returns the Result and an *ExitError.
func (r *Runner) Run(ctx context.Context, name string, args []string, stdin io.Reader) (Result, error) {
	bin, ok := r.bins[name]
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrNotAllowed, name)
	}
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, fmt.Errorf("%w (binary %s)", ErrNoDeadline, name)
	}
	for i, a := range args {
		if strings.ContainsRune(a, 0) {
			return Result{}, fmt.Errorf("%w: argument %d contains NUL", ErrBadArgs, i)
		}
	}
	if err := bin.Validate(args); err != nil {
		return Result{}, fmt.Errorf("%w: %s: %w", ErrBadArgs, name, err)
	}

	cmd := osexec.CommandContext(ctx, bin.Path, args...) //nolint:gosec // path from the allowlist, argv validated, no shell
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, bin.Env...)
	cmd.Dir = "/"
	cmd.Stdin = stdin
	stdout, stderr := &capped{max: bin.MaxOutput}, &capped{max: bin.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = waitDelay
	if err := isolate(cmd); err != nil {
		return Result{}, err
	}

	// Keep this goroutine on one OS thread while the child runs: on Linux the child's
	// Pdeathsig fires when the thread that forked it exits, not when the process does.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	start := time.Now()
	runErr := cmd.Run()
	reapGroup(cmd) // whatever the child left behind dies with the command, however it ended
	// A grandchild that kept the output pipes open only delays Run; the child itself succeeded.
	if errors.Is(runErr, osexec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		runErr = nil
	}
	res := Result{
		Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(),
		ExitCode: -1, Truncated: stdout.truncated || stderr.truncated, Duration: time.Since(start),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	r.log.DebugContext(ctx, "exec finished", "binary", name, "exit_code", res.ExitCode, "duration", res.Duration)

	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("exec: %s: %w", name, ctxErr)
	}
	var exitErr *osexec.ExitError
	switch {
	case runErr == nil:
		return res, nil
	case errors.As(runErr, &exitErr):
		return res, &ExitError{Name: name, ExitCode: res.ExitCode}
	default:
		return res, fmt.Errorf("exec: %s: %w", name, runErr)
	}
}
