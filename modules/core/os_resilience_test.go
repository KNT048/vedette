package core_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

// Tests of how the OS endpoints behave when the host is slow, loses an answer or refuses, and of what they
// promise about the audit rows, the snapshot directories and the host's request budget. The host is the real
// in-process one; hookHost lets a test replace single calls.

// hookHost passes every call to the real host except where a test set a hook, and counts some of them.
type hookHost struct {
	hostBase
	onStateOS      func(ctx context.Context) (api.OSState, error)
	onListRuns     func(ctx context.Context, limit int) ([]api.Run, error)
	onOSInstall    func(ctx context.Context, scope, snapshot, requestID, actor string) (api.Run, error)
	onRebootCancel func(ctx context.Context, requestID, actor string) (api.Run, error)
	onBackupCreate func(ctx context.Context, args api.BackupCreateArgs, requestID, actor string) (api.Run, error)
	onDownload     func(ctx context.Context, id string) (io.ReadCloser, int64, error)

	stateCalls, runsCalls, backupCalls atomic.Int64
}

// hostBase is the real host, set once the environment exists.
type hostBase struct {
	real atomic.Pointer[hostclient.Client]
}

func (b *hostBase) h() *hostclient.Client { return b.real.Load() }

func (h *hookHost) StateOS(ctx context.Context) (api.OSState, error) {
	h.stateCalls.Add(1)
	if h.onStateOS != nil {
		return h.onStateOS(ctx)
	}
	return h.h().StateOS(ctx)
}

func (h *hookHost) ListRuns(ctx context.Context, limit int) ([]api.Run, error) {
	h.runsCalls.Add(1)
	if h.onListRuns != nil {
		return h.onListRuns(ctx, limit)
	}
	return h.h().ListRuns(ctx, limit)
}

func (h *hookHost) OSInstall(ctx context.Context, scope, snapshot, requestID, actor string) (api.Run, error) {
	if h.onOSInstall != nil {
		return h.onOSInstall(ctx, scope, snapshot, requestID, actor)
	}
	return h.h().OSInstall(ctx, scope, snapshot, requestID, actor)
}

func (h *hookHost) OSRebootCancel(ctx context.Context, requestID, actor string) (api.Run, error) {
	if h.onRebootCancel != nil {
		return h.onRebootCancel(ctx, requestID, actor)
	}
	return h.h().OSRebootCancel(ctx, requestID, actor)
}

func (h *hookHost) BackupCreate(ctx context.Context, args api.BackupCreateArgs, requestID, actor string) (api.Run, error) {
	h.backupCalls.Add(1)
	if h.onBackupCreate != nil {
		return h.onBackupCreate(ctx, args, requestID, actor)
	}
	return h.h().BackupCreate(ctx, args, requestID, actor)
}

func (h *hookHost) DownloadBackup(ctx context.Context, id string) (io.ReadCloser, int64, error) {
	if h.onDownload != nil {
		return h.onDownload(ctx, id)
	}
	return h.h().DownloadBackup(ctx, id)
}

func (h *hookHost) OSCheck(ctx context.Context, requestID, actor string) (api.Run, error) {
	return h.h().OSCheck(ctx, requestID, actor)
}

func (h *hookHost) OSAutoSecuritySet(ctx context.Context, enabled bool, requestID, actor string) (api.Run, error) {
	return h.h().OSAutoSecuritySet(ctx, enabled, requestID, actor)
}

func (h *hookHost) OSReboot(ctx context.Context, args api.OSRebootArgs, requestID, actor string) (api.Run, error) {
	return h.h().OSReboot(ctx, args, requestID, actor)
}

func (h *hookHost) GetRun(ctx context.Context, runID string) (api.Run, error) {
	return h.h().GetRun(ctx, runID)
}

func (h *hookHost) Events(ctx context.Context, runID string, after uint64) *hostclient.Stream {
	return h.h().Events(ctx, runID, after)
}

// newHookEnv is an environment whose core talks to a hookHost.
func newHookEnv(t *testing.T) (*osEnv, *hookHost) {
	t.Helper()
	hh := &hookHost{}
	e := newOSEnv(t, osOpts{host: hh})
	hh.real.Store(e.hh.Client)
	return e, hh
}

// fakeState is a host state that needs no check.
func fakeState(auto bool) api.OSState {
	return api.OSState{OS: api.OSDetails{Distro: "ubuntu", Name: "Ubuntu 24.04.3 LTS", Release: "24.04", Kernel: "6.8.0", SupportEnd: "2029-04-25", BootedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), LastCheck: time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC)}, AutoSecurity: auto}
}

// pause lets other goroutines get as far as they can before the test goes on (a settle time, not a condition).
func pause(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-t.Context().Done():
	case <-time.After(d):
	}
}

func waitCount(t *testing.T, c *atomic.Int64, want int64, what string) {
	t.Helper()
	eventuallyOS(t, what, func() bool { return c.Load() >= want })
}

// ---- restart ----

// Core restarts while an install runs and the run ends in the host before core is back: nothing asks for the
// run, yet the end is audited once (POST-6) and the snapshot with the key goes at once.
func TestOSRestartAfterTheRunEndedAuditsAndRemovesTheSnapshot(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	e.gate.on.Store(true) // core's follower never learns the run ended
	wantOK(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 202)
	eventuallyOS(t, "the host run to end", func() bool {
		runs, err := e.hh.Client.ListRuns(t.Context(), 10)
		return err == nil && slices.ContainsFunc(runs, func(r api.Run) bool { return r.Command == api.CmdOSInstall && r.Status.Terminal() })
	})
	e.handler.Close() // the crash: the follower stops without finishing
	if len(e.snapshotDirs()) != 1 {
		t.Fatalf("setup: snapshot dirs = %v", e.snapshotDirs())
	}
	e.newHandlers(t, e.hh.Client, 0) // back within the hour, so the age sweep leaves the directory alone
	eventuallyOS(t, "the end of the run to be audited at start-up", func() bool { return countOf(e.actions(), "os.install_done") == 1 })
	eventuallyOS(t, "the snapshot directory with the key to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
	done := e.viewer.get("/core/updates/os/run")
	wantOK(t, done, 200)
	if done.str("status") != "done" {
		t.Fatalf("run after restart = %s", done.Raw)
	}
	// A second restart changes nothing: the row is written once.
	e.newHandlers(t, e.hh.Client, 0)
	wantOK(t, e.viewer.get("/core/updates/os/run"), 200)
	pause(t, 200*time.Millisecond)
	if n := countOf(e.actions(), "os.install_done"); n != 1 {
		t.Errorf("os.install_done audited %d times after two restarts, want 1", n)
	}
}

// ---- slow host ----

// A hung host call must not stall the other requests: the rebuild of the run after a restart runs outside runMu,
// and a request that waits for it leaves at its own deadline.
func TestOSRunReadLeavesAtItsDeadlineWhileTheHostIsSlow(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hh.onListRuns = func(ctx context.Context, _ int) ([]api.Run, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("released")
	}
	go func() { _, _ = e.handler.CoreGetCoreUpdatesOsRun(context.Background()) }()
	waitCount(t, &hh.runsCalls, 1, "the first read to reach the host")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.handler.CoreGetCoreUpdatesOsRun(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the second read ended with %v, want its own deadline", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a second GET /core/updates/os/run with a 200 ms deadline was still waiting after 3 s")
	}
	if n := hh.runsCalls.Load(); n != 1 {
		t.Errorf("%d ListRuns calls for two readers, want them to share one", n)
	}
}

// Concurrent readers of the run share one rebuild.
func TestOSRunReadsShareOneRebuildFromTheHost(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	release := make(chan struct{})
	hh.onListRuns = func(ctx context.Context, _ int) ([]api.Run, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, nil
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.handler.CoreGetCoreUpdatesOsRun(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	waitCount(t, &hh.runsCalls, 1, "a read to reach the host")
	pause(t, 100*time.Millisecond)
	close(release)
	wg.Wait()
	if n := hh.runsCalls.Load(); n != 1 {
		t.Errorf("%d ListRuns calls for 8 readers, want 1", n)
	}
}

// ---- state cache ----

// Viewers share one read of the host (it allows 60 requests a minute for all of core): concurrent reads are one
// call, later ones come from the copy for 10 seconds, and every change drops it.
func TestOSStateReadsAreCoalescedCachedAndDroppedByAChange(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	var auto atomic.Bool
	auto.Store(true)
	release := make(chan struct{})
	var first atomic.Bool
	hh.onStateOS = func(ctx context.Context) (api.OSState, error) {
		if first.CompareAndSwap(false, true) { // only the very first read is slow: the others must join it
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return fakeState(auto.Load()), nil
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.handler.CoreGetCoreUpdatesOs(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	waitCount(t, &hh.stateCalls, 1, "a read to reach the host")
	pause(t, 100*time.Millisecond)
	close(release)
	wg.Wait()
	if n := hh.stateCalls.Load(); n != 1 {
		t.Fatalf("10 concurrent reads made %d host calls, want 1", n)
	}
	for range 61 {
		wantOK(t, e.viewer.get("/core/updates/os"), 200)
	}
	if n := hh.stateCalls.Load(); n != 1 {
		t.Errorf("61 viewer reads within the TTL made %d host calls in all, want 1", n)
	}
	// The box changes behind core's back: the copy is still served until it expires...
	auto.Store(false)
	if getVal(e.viewer.get("/core/updates/os"), "auto_security") != true {
		t.Error("the copy was not used within its lifetime")
	}
	e.clock.Advance(11 * time.Second)
	if getVal(e.viewer.get("/core/updates/os"), "auto_security") != false || hh.stateCalls.Load() != 2 {
		t.Errorf("after 11 s the host was not asked again (calls %d)", hh.stateCalls.Load())
	}
	// ...and a change by core drops it at once.
	auto.Store(true)
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "always", "days": []int{7}, "from": "02:00", "to": "05:00"}}), 200)
	if getVal(e.viewer.get("/core/updates/os"), "auto_security") != true {
		t.Error("a change did not drop the copy of the host's state")
	}
}

// ---- first check ----

// A box that never ran os.check has no state to read: a change to the settings or a reboot is answered from
// core's own settings with an empty host part, once, not 409 after the change was committed.
func TestOSSettingsAndRebootOnABoxThatNeverCheckedAnswerOnce(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.setZone("UTC")
	win := map[string]any{"mode": "window", "days": []int{1, 2, 3, 4, 5, 6, 7}, "from": "01:00", "to": "03:00"}
	r := e.admin.patch("/core/updates/os/settings", map[string]any{"window": win})
	wantOK(t, r, 200)
	if r.str("window", "mode") != "window" || len(getArr(r, "pending")) != 0 {
		t.Errorf("answer = %s", r.Raw)
	}
	if n := countOf(e.actions(), "os.settings"); n != 1 || slices.Contains(e.actions(), "os.settings_failed") {
		t.Errorf("settings rows: %v", e.actions())
	}
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 200)
	if n := countOf(e.actions(), "os.reboot_schedule"); n != 1 {
		t.Errorf("reboot rows: %v", e.actions())
	}
	wantOK(t, e.admin.request("DELETE", "/core/updates/os/reboot", nil), 200)
	wantStatus(t, e.viewer.get("/core/updates/os"), 409, "no_check_yet") // reading still needs the check
}

// ---- settings and the scheduled reboot ----

// A new window that no longer holds the scheduled reboot cancels it BEFORE it is saved; when the cancel fails
// (the host's write lock is taken) nothing is saved and the answer says why.
func TestOSSettingsWindowIsNotSavedWhenTheOutOfWindowRebootCannotBeCancelled(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.setZone("UTC")
	e.checked()
	every := []int{1, 2, 3, 4, 5, 6, 7}
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": every, "from": "02:00", "to": "05:00"}}), 200)
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 200)
	hh.onRebootCancel = func(context.Context, string, string) (api.Run, error) {
		return api.Run{}, &hostclient.Error{Status: 409, Code: api.CodeBusy, Message: "busy"}
	}
	r := e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{6}, "from": "10:00", "to": "11:00"}})
	wantStatus(t, r, 409, "busy")
	st := e.viewer.get("/core/updates/os")
	if st.str("window", "from") != "02:00" || st.JSON["reboot_scheduled_at"] == nil {
		t.Errorf("after the refused change the state is %s, want the old window and the reboot still scheduled", st.Raw)
	}
	if !slices.Contains(e.actions(), "os.settings_failed") {
		t.Errorf("no failure row: %v", e.actions())
	}
	// With the cancel working the same change goes through and the schedule is gone.
	hh.onRebootCancel = nil
	r = e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": []int{6}, "from": "10:00", "to": "11:00"}})
	wantOK(t, r, 200)
	if r.JSON["reboot_scheduled_at"] != nil || r.str("window", "from") != "10:00" {
		t.Errorf("answer = %s", r.Raw)
	}
}

// A network change that waits for confirmation holds the host's write lock: the host answers pending_confirm
// (or its second line of defence, net_pending_confirm) and core says so in one plain 409, with the host's run
// id kept out of the answer (host-api section 4, D-100).
func TestOSRebootWhileANetworkChangeAwaitsConfirmationAnswersPendingConfirm(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.setZone("UTC")
	e.checked()
	every := []int{1, 2, 3, 4, 5, 6, 7}
	wantOK(t, e.admin.patch("/core/updates/os/settings", map[string]any{"window": map[string]any{"mode": "window", "days": every, "from": "02:00", "to": "05:00"}}), 200)
	wantOK(t, e.admin.post("/core/updates/os/reboot", map[string]any{"when": "window"}), 200)
	for _, code := range []string{api.CodePendingConfirm, api.CodeNetPendingConfirm} {
		hh.onRebootCancel = func(context.Context, string, string) (api.Run, error) {
			return api.Run{}, &hostclient.Error{Status: 409, Code: code, Message: "waiting", RunID: "rn_0123456789abcdef"}
		}
		r := e.admin.request("DELETE", "/core/updates/os/reboot", nil)
		wantStatus(t, r, 409, "pending_confirm")
		if strings.Contains(r.Raw, "rn_0123456789abcdef") {
			t.Errorf("the host's run id leaked into %s", r.Raw)
		}
	}
}

// ---- update checks off ----

func TestOSCheckWithUpdateChecksOffMakesNoHostCall(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.setting("core_privacy", `{"update_check":false}`)
	wantStatus(t, e.oper.post("/core/updates/os/check", nil), 409, "check_off")
	if n := hh.stateCalls.Load() + hh.runsCalls.Load() + hh.backupCalls.Load(); n != 0 {
		t.Errorf("check_off made %d host call(s)", n)
	}
}

// ---- snapshot failures ----

// A snapshot that cannot be written is never a 500.
func TestSnapshotFailureAnswers(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	for _, c := range []struct {
		name, failed string
		call         func(e *osEnv) reply
	}{
		{"install", "os.install_failed", func(e *osEnv) reply {
			e.checked()
			return e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"})
		}},
		{"backup", "data.backup_failed", func(e *osEnv) reply { return e.admin.get("/core/data/backup") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newOSEnv(t, osOpts{})
			dir := filepath.Join(e.m.CoreData, "snapshots")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a directory: stands in for EROFS or a full disk
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory
			wantStatus(t, c.call(e), 502, "snapshot_failed")
			if slices.ContainsFunc(e.m.Calls("apt-get"), func(a []string) bool { return slices.Contains(a, "install") }) {
				t.Error("apt install ran without a snapshot")
			}
			if !slices.Contains(e.actions(), c.failed) {
				t.Errorf("no failure row: %v", e.actions())
			}
		})
	}
}

// ---- backup download ----

// The download looks at busy() first: no snapshot is written and no backup.create is sent while an install runs.
func TestBackupDownloadDuringAnInstallIs409BeforeAnySnapshot(t *testing.T) {
	t.Parallel()
	e := newOSEnv(t, osOpts{})
	e.checked()
	e.gate.on.Store(true)
	t.Cleanup(func() { close(e.gate.gate) })
	wantOK(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 202)
	if getVal(e.viewer.get("/core/updates/os"), "busy") != true {
		t.Fatal("setup: core does not see the run as busy")
	}
	manual := func() (n int) {
		bl, err := e.hh.Client.StateBackups(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bl.Backups {
			if b.Kind == "manual" {
				n++
			}
		}
		return n
	}
	wantStatus(t, e.admin.get("/core/data/backup"), 409, "busy")
	if manual() != 0 {
		t.Error("a manual backup was made while an install runs")
	}
	if len(e.snapshotDirs()) != 1 { // the install's own
		t.Errorf("snapshot dirs = %v, want only the install's", e.snapshotDirs())
	}
	if slices.Contains(e.actions(), "data.backup") {
		t.Error("a refused download wrote an intent row")
	}
}

// One download at a time (a second concurrent one is 409 busy) and one a minute (429 with Retry-After): each is
// a full snapshot and a manual backup on the box.
func TestBackupDownloadsAreOneAtATimeAndOnePerMinute(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hh.onBackupCreate = func(ctx context.Context, args api.BackupCreateArgs, id, actor string) (api.Run, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return hh.h().BackupCreate(ctx, args, id, actor)
	}
	first := make(chan reply, 1)
	go func() { first <- e.admin.get("/core/data/backup") }()
	<-entered
	wantStatus(t, e.admin.get("/core/data/backup"), 409, "busy")
	close(release)
	if r := <-first; r.Code != 200 {
		t.Fatalf("first download = %d %s", r.Code, r.Raw)
	}
	if n := hh.backupCalls.Load(); n != 1 {
		t.Errorf("%d backup.create calls, want 1", n)
	}
	r := e.admin.get("/core/data/backup")
	wantStatus(t, r, 429, "rate_limited")
	ra, err := strconv.Atoi(r.Header.Get("Retry-After"))
	if err != nil || ra < 1 || ra > 60 {
		t.Errorf("Retry-After = %q", r.Header.Get("Retry-After"))
	}
	if n := hh.backupCalls.Load(); n != 1 {
		t.Errorf("a rate-limited download reached the host (%d calls)", n)
	}
	if len(e.snapshotDirs()) != 0 {
		t.Errorf("snapshot dirs = %v", e.snapshotDirs())
	}
	e.clock.Advance(61 * time.Second)
	if r := e.admin.get("/core/data/backup"); r.Code != 200 {
		t.Errorf("download a minute later = %d %s", r.Code, r.Raw)
	}
}

// The backup exists on the box but cannot be handed over: its own audit row, and a clear code.
func TestBackupDownloadFailureAfterTheBackupIsAudited(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	hh.onDownload = func(context.Context, string) (io.ReadCloser, int64, error) {
		return nil, 0, &hostclient.Error{Status: 500, Code: "internal", Message: "disk"}
	}
	wantStatus(t, e.admin.get("/core/data/backup"), 502, "host_error")
	got := e.actions()
	if i := slices.Index(got, "data.backup"); i < 0 || !slices.Contains(got[i:], "data.backup_failed") {
		t.Errorf("audit rows: %v", got)
	}
}

// A backup whose size the host does not tell is refused before the 200 goes out.
func TestBackupDownloadOfUnknownSizeIsRefused(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	var closed atomic.Bool
	hh.onDownload = func(ctx context.Context, id string) (io.ReadCloser, int64, error) {
		body, _, err := hh.h().DownloadBackup(ctx, id)
		if err != nil {
			return nil, 0, err
		}
		return &closeSpy{ReadCloser: body, closed: &closed}, -1, nil
	}
	wantStatus(t, e.admin.get("/core/data/backup"), 502, "host_error")
	if !closed.Load() {
		t.Error("the body of the refused download was not closed")
	}
	if !slices.Contains(e.actions(), "data.backup_failed") {
		t.Errorf("audit rows: %v", e.actions())
	}
}

type closeSpy struct {
	io.ReadCloser
	closed *atomic.Bool
}

func (c *closeSpy) Close() error { c.closed.Store(true); return c.ReadCloser.Close() }

// ---- a lost answer ----

var errLost = fmt.Errorf("%w: read unix: connection reset by peer", hostclient.ErrUnreachable)

// The host took os.install but its answer never arrived: core asks it by request id and follows the run; the
// snapshot stays until the run is over and then goes.
func TestOSLostAnswerOfInstallThatTheHostTookFollowsTheRun(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.checked()
	hh.onOSInstall = func(ctx context.Context, scope, snap, id, actor string) (api.Run, error) {
		if _, err := hh.h().OSInstall(ctx, scope, snap, id, actor); err != nil {
			return api.Run{}, err
		}
		return api.Run{}, errLost
	}
	r := e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"})
	wantOK(t, r, 202)
	done := e.waitRunDone(e.viewer)
	if getVal(done, "result", "installed") != float64(2) {
		t.Errorf("run = %s", done.Raw)
	}
	eventuallyOS(t, "the snapshot directory to be removed", func() bool { return len(e.snapshotDirs()) == 0 })
	eventuallyOS(t, "the end to be audited", func() bool { return countOf(e.actions(), "os.install_done") == 1 })
}

// The host never saw the command: the failure is reported and the snapshot goes at once.
func TestOSLostAnswerOfInstallThatTheHostNeverSawFailsAndCleansUp(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.checked()
	hh.onOSInstall = func(context.Context, string, string, string, string) (api.Run, error) { return api.Run{}, errLost }
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 503, "host_unreachable")
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot directories left: %v", d)
	}
	if !slices.Contains(e.actions(), "os.install_failed") {
		t.Errorf("audit rows: %v", e.actions())
	}
}

// The host cannot even be asked whether it took the command: it may be reading the snapshot, so it stays (the
// start-up sweep removes it later).
func TestOSLostAnswerThatCannotBeCheckedKeepsTheSnapshot(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	e.checked()
	var lost atomic.Bool
	hh.onOSInstall = func(context.Context, string, string, string, string) (api.Run, error) {
		lost.Store(true)
		return api.Run{}, errLost
	}
	hh.onListRuns = func(ctx context.Context, limit int) ([]api.Run, error) {
		if lost.Load() {
			return nil, errLost
		}
		return hh.h().ListRuns(ctx, limit)
	}
	wantStatus(t, e.admin.post("/core/updates/os/install", map[string]any{"scope": "all"}), 503, "host_unreachable")
	if d := e.snapshotDirs(); len(d) != 1 {
		t.Errorf("snapshot directories = %v, want the one the host may be reading", d)
	}
}

// A lost answer to backup.create: the backup exists, the download goes on.
func TestOSLostAnswerOfBackupCreateThatTheHostTookStillDownloads(t *testing.T) {
	t.Parallel()
	e, hh := newHookEnv(t)
	hh.onBackupCreate = func(ctx context.Context, args api.BackupCreateArgs, id, actor string) (api.Run, error) {
		if _, err := hh.h().BackupCreate(ctx, args, id, actor); err != nil {
			return api.Run{}, err
		}
		return api.Run{}, errLost
	}
	r := e.admin.get("/core/data/backup")
	if r.Code != 200 || !strings.HasPrefix(r.Raw, "\x1f\x8b") {
		t.Fatalf("download = %d %.60q", r.Code, r.Raw)
	}
	if d := e.snapshotDirs(); len(d) != 0 {
		t.Errorf("snapshot directories left: %v", d)
	}
}
