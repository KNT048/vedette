package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/peer"
)

// Function-level tests of parked runs (D-316 slice 1, review r1): no socket, no real-clock waits.

func parksCmd(timeout time.Duration) Command {
	return Define(Spec[struct{}]{
		Name: "t.parks", Write: true, Parks: true, Timeout: timeout,
		Run: func(context.Context, *RunContext, struct{}) (any, error) {
			return Parked{Deadline: time.Now().Add(time.Hour)}, nil
		},
	})
}

var plainCmd = Define(Spec[struct{}]{
	Name: "t.plain", Write: true, Timeout: time.Second,
	Run: func(context.Context, *RunContext, struct{}) (any, error) { return nil, nil },
})

// newParkServer opens a server (no Listen) on the state under dir.
func newParkServer(t *testing.T, dir string, resume func(api.Run) bool) *Server {
	t.Helper()
	reg, err := NewRegistry(parksCmd(time.Second), plainCmd)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		SocketPath: filepath.Join(dir, "run", "h.sock"), StateDir: filepath.Join(dir, "state"), AuditPath: filepath.Join(dir, "log", "audit.jsonl"),
		Registry: reg, Resume: resume, OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler),
		PeerCheck: func(net.Conn) (peer.Info, error) { return peer.Info{}, errors.New("no peers in this test") },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startWrite records a running write run of cmd holding the lock, as submit does.
func startWrite(t *testing.T, s *Server, cmd Command) *liveRun {
	t.Helper()
	runID, _ := newID("rn_")
	auditID, _ := newID("au_")
	now := s.now()
	lr := &liveRun{
		sr:  storedRun{Run: api.Run{RunID: runID, Command: cmd.name, Status: api.StatusRunning, StartedAt: now.UTC(), Actor: "admin", AuditID: auditID}, Write: true},
		sub: submission{actor: "admin", command: cmd.name, write: true}, ev: newEventLog(s.now), started: now,
	}
	s.mu.Lock()
	s.active, s.live[runID] = runID, lr.ev
	s.mu.Unlock()
	if err := s.runs.put(lr.sr); err != nil {
		t.Fatal(err)
	}
	return lr
}

func auditResults(t *testing.T, s *Server, runID string) (out []string) {
	t.Helper()
	page, err := s.audit.page(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Records {
		if r.RunID != nil && *r.RunID == runID {
			out = append(out, r.Result)
		}
	}
	return out
}

// Review r1 M1: a park that cannot be stored is undone, so a restart never finds a plain running
// run whose work goes on outside the process; the run then ends command_failed and frees the lock.
func TestEnterParked_ARunThatCannotBeStoredIsNotParked(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	dir := shortTemp(t)
	s := newParkServer(t, dir, nil)
	defer func() { _ = s.Shutdown(context.Background()) }()
	cmd, _ := s.reg.Lookup("t.parks")
	lr := startWrite(t, s, cmd)
	runs := filepath.Join(dir, "state", "runs")
	if err := os.Chmod(runs, 0o500); err != nil { //nolint:gosec // a directory: read-only so the run file cannot be written
		t.Fatal(err)
	}
	called := false
	err := s.enterParked(lr, cmd, Parked{Deadline: time.Now().Add(time.Hour), Result: "staged"}, &RunContext{parked: []func(){func() { called = true }}})
	if cerr := os.Chmod(runs, 0o700); cerr != nil { //nolint:gosec // a directory: the host's own 0700
		t.Fatal(cerr)
	}
	if err == nil || errors.Is(err, errParkDraining) {
		t.Fatalf("enterParked = %v, want a failure to park", err)
	}
	if called || s.parked != nil || lr.sr.Run.ParkedDeadline != nil || lr.sr.Run.Result != nil {
		t.Fatalf("a park that was not stored left state: OnParked %v, parked %v, run %+v", called, s.parked != nil, lr.sr.Run)
	}
	if got := auditResults(t, s, lr.sr.Run.RunID); len(got) != 0 {
		t.Fatalf("audit lines of a run that did not park: %v", got)
	}
	if st, _, rerr := s.outcome(context.Background(), nil, err, false); st != api.StatusFailed || rerr == nil || rerr.Code != api.CodeCommandFailed {
		t.Fatalf("outcome = %s %+v", st, rerr)
	}
}

// Review r1 M2: only a run of a command declared Parks (Awaits) is resumed; a stored deadline beyond
// the park window is clamped.
func TestResume_KeepsOnlyRunsOfCommandsThatParkOrAwaitAndClampsTheDeadline(t *testing.T) {
	t.Parallel()
	start := time.Now().UTC().Add(-time.Minute)
	far, revert := start.Add(10*time.Hour), start.Add(time.Minute)
	for name, c := range map[string]struct {
		run  api.Run
		keep bool
	}{
		"parked, command not declared Parks":    {api.Run{Command: "t.plain", Status: api.StatusRunning, ParkedDeadline: &far}, false},
		"parked, command unknown":               {api.Run{Command: "t.gone", Status: api.StatusRunning, ParkedDeadline: &far}, false},
		"awaiting, command not declared Awaits": {api.Run{Command: "t.parks", Status: api.StatusAwaitingConfirm, RevertAt: &revert}, false},
		"parked, deadline beyond the window":    {api.Run{Command: "t.parks", Status: api.StatusRunning, ParkedDeadline: &far}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := shortTemp(t)
			runs := filepath.Join(dir, "state", "runs")
			if err := os.MkdirAll(runs, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, "state"), 0o700); err != nil { //nolint:gosec // a directory: the host's own 0700
				t.Fatal(err)
			}
			r := c.run
			r.RunID, r.StartedAt, r.Actor, r.AuditID = "rn_00000000000000aa", start, "admin", "au_00000000000000aa"
			if err := writeJSONAtomic(filepath.Join(runs, r.RunID+".json"), storedRun{Run: r, Write: true}); err != nil {
				t.Fatal(err)
			}
			asked := 0
			s := newParkServer(t, dir, func(api.Run) bool { asked++; return true })
			defer func() { _ = s.Shutdown(context.Background()) }()
			got, _ := s.runs.get(r.RunID)
			if !c.keep {
				if asked != 0 || s.active != "" || s.parked != nil || s.waiting != nil || got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeHostRestarted {
					t.Fatalf("Resume asked %d, lock %q, run %+v", asked, s.active, got)
				}
				return
			}
			if s.parked == nil || s.active != r.RunID || got.ParkedDeadline == nil || !got.ParkedDeadline.Equal(start.Add(maxParkWindow)) {
				t.Fatalf("lock %q, run %+v: want it kept with parked_deadline clamped to started_at + %v", s.active, got, maxParkWindow)
			}
		})
	}
}

// Review r1 L5: once parked, the command's goroutine is done, so Spec.Timeout no longer applies.
func TestExecute_SpecTimeoutNoLongerAppliesOnceParked(t *testing.T) {
	t.Parallel()
	dir := shortTemp(t)
	synctest.Test(t, func(t *testing.T) {
		s := newParkServer(t, dir, nil)
		cmd, _ := s.reg.Lookup("t.parks") // Spec.Timeout 1 s
		lr := startWrite(t, s, cmd)
		s.wg.Add(1)
		s.execute(lr, cmd, struct{}{})
		tm := time.NewTimer(30 * time.Minute) // the bubble's clock: far past the timeout, well before the deadline
		<-tm.C
		synctest.Wait()
		got, _ := s.runs.get(lr.sr.Run.RunID)
		if s.parked != lr || s.active != lr.sr.Run.RunID || got.Status != api.StatusRunning || got.ParkedDeadline == nil {
			t.Fatalf("after the timeout: parked %v, lock %q, run %+v", s.parked == lr, s.active, got)
		}
		if err := s.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
