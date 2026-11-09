// Round-2 review contract tests of the host (D-87).
package host_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// raceNotifier is the server's Notifier; once armed, the first time the host asks "is a write
// running?" and the answer is no, a write request is sent and accepted before the answer is
// returned: exactly a request that arrives between the check and the gate.
type raceNotifier struct {
	inner  ops.Notifier
	armed  atomic.Bool
	once   sync.Once
	inject func()
}

func (r *raceNotifier) Note(c, code string, d map[string]any) error { return r.inner.Note(c, code, d) }

func (r *raceNotifier) AwaitingConfirm() bool { return r.inner.AwaitingConfirm() }

func (r *raceNotifier) WriteActive() bool {
	v := r.inner.WriteActive()
	if !v && r.armed.Load() {
		r.once.Do(r.inject)
	}
	return v
}

// A write request that arrives just after a scheduled reboot looked for running writes must not be
// accepted and then killed by the reboot: the gate goes up before the host looks, so the request is
// either seen as running (the reboot waits) or refused by the gate.
func TestContract_ScheduledRebootRaisesTheGateBeforeLookingForRunningWrites(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	// apt-get update blocks on a FIFO, so the os.check that wins the race is still running when
	// systemctl reboot is called.
	fifo := filepath.Join(e.m.Rec, "hold")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := os.OpenFile(filepath.Join(e.m.Rules, "apt-get"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(rf, "update|%s|0||\n", fifo)
	_ = rf.Close()
	e.rules()

	var runID atomic.Value
	var refusal atomic.Value
	rn := &raceNotifier{inner: e.h.Server}
	rn.inject = func() {
		r, err := e.h.Client.Run(context.Background(), "os.check", struct{}{}, e.id(), "admin@example.com")
		if err != nil {
			refusal.Store(err.Error()) // the gate refusing it is the other way to be safe
			return
		}
		runID.Store(r.RunID)
	}
	e.o.Start(context.Background(), rn)
	defer e.o.Close()

	at := e.clock.Now().Add(2 * time.Hour)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "at", At: at.Format(time.RFC3339)})
	e.clock.Advance(2 * time.Hour)
	rn.armed.Store(true)
	e.timers.active()[0].fire()
	eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })

	id, _ := runID.Load().(string)
	if id == "" {
		// The request was made in the window and the gate refused it: the reboot is safe.
		msg, _ := refusal.Load().(string)
		if !strings.Contains(msg, "rebooting") {
			t.Fatalf("the request in the window was neither accepted nor refused by the reboot gate: %q", msg)
		}
		return
	}
	// What was on disk when the fake systemctl got "reboot".
	running := false
	dec := json.NewDecoder(bytes.NewReader([]byte(e.m.RunsAtReboot())))
	for {
		var sr struct {
			Run api.Run `json:"run"`
		}
		if err := dec.Decode(&sr); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("decode runs at reboot: %v", err)
			}
			break
		}
		if sr.Run.RunID == id && sr.Run.Status == api.StatusRunning {
			running = true
		}
	}
	// Release the fake apt-get and let the run end before the harness stops.
	if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { //nolint:gosec // a FIFO this test made
		_ = w.Close()
	}
	waitDone(t, e.h.Client, id)
	if running {
		t.Errorf("systemctl reboot was issued while write run %s (os.check, accepted after the WriteActive check and before the gate) was running", id)
	}
}
