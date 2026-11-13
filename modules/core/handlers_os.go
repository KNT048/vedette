package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/internal/release"
)

// OSHandlers implements the operating system part of Settings → Updates (S-CORE-7: /core/updates/os*) and the
// backup download (S-CORE-1: /core/data/backup) on top of vedette-host. Embed it in the composite handler beside
// the other core handlers; its operations are disjoint from theirs. Every host call is made with a fresh
// idempotency key and an actor label, after a core_audit row for the intent (and one more when it fails);
// nothing here runs a command itself (SYS-1).
type OSHandlers struct {
	gate  *PurgeGate // shut while a purge runs: act refuses (N4)
	db    *store.DB
	auth  *auth.Service
	audit *audit.Log
	host  Host // nil: not an appliance
	snaps *snapshotter
	// installed is OSConfig.Installed (nil: none).
	installed func()
	// pkgDir is <core_data>/host-packages: the system helper package a software run downloads for the host
	// (host.self_update, D-316); empty without a host.
	pkgDir string
	zone   func(context.Context) (string, error)
	log    *slog.Logger
	now    func() time.Time
	// loadTimeout bounds one shared read of the host (loadTimeout, shorter in tests).
	loadTimeout time.Duration

	ctx    context.Context //nolint:containedctx // the lifetime of the run followers, not of a request
	cancel context.CancelFunc
	wg     sync.WaitGroup

	installMu sync.Mutex // one install at a time through this process, from the busy check to the host's answer
	runMu     sync.Mutex // guards run, loaded, loading and the fields of the run state; never held across a host call
	run       *osRunState
	loaded    bool
	loading   *flight[*osRunState]

	state stateCache

	urun updRun // the run side of the software update (updates_run.go)

	restoreMu     sync.Mutex  // one settle of a restore run at a time (restore.go)
	restoreSynced atomic.Bool // this process has asked the host for the latest restore once
	rrMu          sync.Mutex  // guards rrRuns and rrAt
	rrRuns        []api.Run   // the host's recent runs as restoreRuns last read them; nil = none
	rrAt          time.Time
	started       time.Time // wall clock at start: snapshots older than this are an earlier process's (removeBefore)

	dlMu   sync.Mutex // one backup download at a time: held from the busy check until backup.create ends
	lastDL time.Time  // when the last download started its snapshot; guarded by dlMu

	upd updCheck // the check side of the software update (updates_check.go)
}

// stateTTL is how long GET /core/updates/os may answer from one read of the host: the host allows 60 requests a
// minute for all of core, and a page that refreshes must not spend them. Every change (a check, an install and
// its end, settings, a reboot) drops the copy.
const stateTTL = 10 * time.Second

// downloadGap is the least time between two backup downloads; every one makes a full snapshot and a manual
// backup on the box (the host keeps the latest 10 manual ones).
const downloadGap = time.Minute

// stateCache is the last answer of the host's state/os, shared by concurrent readers.
type stateCache struct {
	mu     sync.Mutex
	st     api.OSState
	at     time.Time
	valid  bool
	flight *flight[api.OSState]
}

// OSConfig wires OSHandlers. DB, Auth, Audit, Log and Zone are required; Host may be nil (an install without
// vedette-host); DataDir and KeyPath are required with a Host.
type OSConfig struct {
	DB    *store.DB
	Auth  *auth.Service
	Audit *audit.Log
	Log   *slog.Logger
	Host  Host
	// DataDir is core_data: the directory of the database file, where snapshots/ lives (host-api 6.11).
	DataDir string
	// KeyPath is the master key file that goes into a snapshot for a pre-update backup.
	KeyPath string
	// Zone returns the IANA name of the organization time zone (APIHandlers.OrgTimeZone).
	Zone  func(context.Context) (string, error)
	Clock func() time.Time // nil: time.Now
	// Gate is shut while a factory reset runs: every host write then answers 409 busy (N4). The same gate as HandlersConfig.Gate; nil = never shut.
	Gate *PurgeGate
	// UpdateRetry is the software update follower's wait between two tries; 0 = followRetry (tests shorten it).
	UpdateRetry time.Duration

	// Software update check (updates_check.go, D-341). Version is the running release (main.version); ReleaseBase
	// is where the signed release documents are downloaded from ("" = DefaultReleaseBase; tests: a local server);
	// HTTPClient nil = a client with timeouts that follows redirects only to the GitHub hosts of PRIVACY.md flow 6;
	// Trust nil = release.Embedded.
	Version     string
	ReleaseBase string
	HTTPClient  *http.Client
	Trust       func() (release.Trust, error)
	// Wake runs the core/software-update job now (core/jobs Scheduler.Wake): a box that never checked checks
	// firstCheckAfter after its process started, not at the next tick (D-398). nil: no early run (tests).
	Wake func()
	// Installed is called once after an OS update run that succeeded has been audited: the box's packages changed, so its
	// package list is read again now (wiring: the inventory/box job, D-470) instead of at the next hourly run. nil: nothing.
	Installed func()
}

// NewOSHandlers returns the handlers and sweeps the snapshot directories an earlier run left behind.
func NewOSHandlers(c OSConfig) (*OSHandlers, error) {
	if c.DB == nil || c.Auth == nil || c.Audit == nil || c.Log == nil || c.Zone == nil {
		return nil, errors.New("core: OSConfig needs DB, Auth, Audit, Log and Zone")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	h := &OSHandlers{gate: c.Gate, db: c.DB, auth: c.Auth, audit: c.Audit, host: c.Host, zone: c.Zone, log: c.Log, now: c.Clock, loadTimeout: loadTimeout, started: time.Now(), installed: c.Installed}
	if err := h.upd.init(c, c.Clock()); err != nil {
		return nil, err
	}
	if c.Host != nil {
		if c.DataDir == "" || c.KeyPath == "" {
			return nil, errors.New("core: OSConfig with a Host needs DataDir and KeyPath")
		}
		h.snaps = newSnapshotter(c.DB, c.DataDir, c.KeyPath, c.Clock)
		if n, err := h.snaps.sweep(); err != nil {
			c.Log.Warn("core: sweeping old snapshots failed", "error", err)
		} else if n > 0 {
			c.Log.Info("core: removed old snapshots", "count", n)
		}
		h.pkgDir = filepath.Join(c.DataDir, hostPackagesDir)
		h.sweepHostPackages()
	}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.urun.retry = c.UpdateRetry
	if c.Host != nil {
		if m, err := h.loadRunMeta(h.ctx); err == nil && (m.Snapshot != "" || !m.Audited) {
			h.wg.Add(1)
			go h.resume()
		}
		h.resumeUpdate()
	}
	return h, nil
}

// Close stops the followers of install runs and waits for them. The run itself goes on in the host.
func (h *OSHandlers) Close() {
	h.cancel()
	h.upd.wakeMu.Lock()
	if h.upd.wakeT != nil {
		h.upd.wakeT.Stop()
	}
	h.upd.wakeMu.Unlock()
	h.wg.Wait()
}

func (h *OSHandlers) needHost() error {
	if h.host == nil {
		return notAppliance()
	}
	return nil
}

// alive is needHost plus one cheap read of the host, for the operations that would otherwise write their audit
// row before finding out there is no helper: an absent socket (409 not_appliance) or a host that does not
// answer (503) then leaves no row, because nothing was attempted.
func (h *OSHandlers) alive(ctx context.Context) error {
	if err := h.needHost(); err != nil {
		return err
	}
	if _, err := h.host.StateOS(ctx); errors.Is(err, client.ErrUnreachable) || errors.Is(err, client.ErrDenied) {
		return hostErr(ctx, h.log, err)
	}
	return nil
}

// record writes the core_audit row of an intent; with admin it first re-checks, in the same transaction, that
// the caller is still an administrator with a live session (INV-7).
func (h *OSHandlers) record(ctx context.Context, c caller, admin bool, action, target, detail string) error {
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		if admin {
			if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
				return err
			}
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: action, Target: target, Detail: cutAtRune(detail, auditMaxDetail)})
	})
}

// act records the intent, runs fn (a host call and the wait for it) and, when fn fails, records that too.
func (h *OSHandlers) act(ctx context.Context, c caller, admin bool, action, target, detail string, fn func(requestID, actor string) error) error {
	leave, ok := h.gate.Enter() // held for the whole call (L1): a purge cannot start while this host work runs
	if !ok {                    // a purge is running (N4): no audit row, nothing started
		return errPurging()
	}
	defer leave()
	if err := h.record(ctx, c, admin, action, target, detail); err != nil {
		return err
	}
	id, err := newRequestID()
	if err != nil {
		return err
	}
	if err := fn(id, actorLabel(c.Email, c.ID)); err != nil {
		code := "error"
		if ae, ok := apierr.As(err); ok {
			code = ae.Code
		}
		fctx := context.WithoutCancel(ctx) // the failure of a cancelled request is still worth its row
		if rerr := h.record(fctx, c, false, action+"_failed", target, code); rerr != nil {
			h.log.ErrorContext(ctx, "core: could not audit a failed host call", "action", action, "error", rerr)
		}
		return err
	}
	return nil
}

// ---- settings ----

// osSettings is core_setting os.settings.
type osSettings struct {
	Window maintWindow `json:"window"`
	// AutoSecurity is the switch as last applied through vedette-host (nil: never set from here); the page
	// shows what the host reads back, this is the record of what core asked for.
	AutoSecurity *bool  `json:"auto_security,omitempty"`
	AppliedAt    string `json:"applied_at,omitempty"`
}

func (h *OSHandlers) settings(ctx context.Context) (osSettings, error) {
	s := osSettings{Window: defaultWindow()}
	if err := h.loadJSON(ctx, keyOSSettings, &s); err != nil {
		return osSettings{}, err
	}
	return s, nil
}

// keyPrivacy is the core_setting key of the Privacy settings and privacySetting the part of its JSON that
// the OS code reads. The writer of Privacy (GET and PATCH /core/privacy) must use both, or the switch of
// update checks has no effect; a test pins the shape.
const keyPrivacy = "core_privacy"

type privacySetting struct {
	// UpdateCheck is the switch of update checks (PRIVACY.md flow 6); nil, an absent row included, means on.
	UpdateCheck *bool `json:"update_check,omitempty"`
	// Telemetry is the switch of the anonymous signal (PRIVACY.md flow 2); nil means on. D-82: nothing is sent whatever it says.
	Telemetry *bool `json:"telemetry,omitempty"`
}

// updateCheckOn reads the switch of update checks from the Privacy setting.
func (h *OSHandlers) updateCheckOn(ctx context.Context) (bool, error) {
	var p privacySetting
	if err := h.loadJSON(ctx, keyPrivacy, &p); err != nil {
		return false, err
	}
	return p.UpdateCheck == nil || *p.UpdateCheck, nil
}

func (h *OSHandlers) location(ctx context.Context) (*time.Location, error) {
	name, err := h.zone(ctx)
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("core: organization time zone %q: %w", name, err)
	}
	return loc, nil
}

// hostState reads state/os, from the copy younger than stateTTL when there is one, else from the host; callers
// that arrive during a read share it. It is the read for GET /core/updates/os.
func (h *OSHandlers) hostState(ctx context.Context) (api.OSState, error) {
	c := &h.state
	c.mu.Lock()
	if age := h.now().Sub(c.at); c.valid && age >= 0 && age < stateTTL {
		st := c.st
		c.mu.Unlock()
		return st, nil
	}
	f := c.flight
	if f == nil {
		f = newFlight[api.OSState]()
		c.flight = f
		h.wg.Add(1)
		go h.fetchState(f) //nolint:contextcheck // the read is shared: it runs on the handlers' lifetime, each waiter leaves at its own deadline
	}
	c.mu.Unlock()
	st, err := f.wait(ctx)
	if err != nil {
		return api.OSState{}, h.failure(ctx, err)
	}
	return st, nil
}

func (h *OSHandlers) fetchState(f *flight[api.OSState]) {
	defer h.wg.Done()
	ctx, cancel := context.WithTimeout(h.ctx, h.loadTimeout)
	defer cancel()
	st, err := h.host.StateOS(ctx)
	err = h.timedOut(ctx, err)
	c := &h.state
	c.mu.Lock()
	if c.flight == f { // not dropped by a change meanwhile
		if err == nil {
			c.st, c.at, c.valid = st, h.now(), true
		}
		c.flight = nil
	}
	f.val, f.err = st, err
	c.mu.Unlock()
	close(f.done)
}

// invalidateState drops the copy and lets no read that started before now fill it.
func (h *OSHandlers) invalidateState() {
	h.state.mu.Lock()
	h.state.valid, h.state.flight = false, nil
	h.state.mu.Unlock()
}

// isNoCheck reports whether err is the host's "no check yet", raw or already mapped to the API error.
func isNoCheck(err error) bool {
	var he *client.Error
	if errors.As(err, &he) {
		return he.Code == api.CodeNoCheckYet
	}
	ae, ok := apierr.As(err)
	return ok && ae.Code == CodeNoCheckYet
}

// stateNow reads the host's view and adds what core owns. A box that has never checked answers like stateAfter:
// core's settings with an empty host part (os null), not 409 no_check_yet (D-407: every open of the page logged it).
func (h *OSHandlers) stateNow(ctx context.Context) (osStateView, error) {
	hs, err := h.hostState(ctx)
	if isNoCheck(err) {
		hs, err = api.OSState{}, nil
	}
	if err != nil {
		return osStateView{}, err
	}
	return h.compose(ctx, hs)
}

// stateAfter is the answer of an operation that changed something: a fresh read of the host. On a box that has
// never checked, the host has no state to give: the answer is core's own settings with an empty host part
// (os null, no packages), not an error after the change was made.
func (h *OSHandlers) stateAfter(ctx context.Context) (osStateView, error) {
	h.invalidateState()
	hs, err := h.hostState(ctx)
	if isNoCheck(err) {
		hs, err = api.OSState{}, nil
	}
	if err != nil {
		return osStateView{}, err
	}
	return h.compose(ctx, hs)
}

func (h *OSHandlers) compose(ctx context.Context, hs api.OSState) (osStateView, error) {
	s, err := h.settings(ctx)
	if err != nil {
		return osStateView{}, err
	}
	return stateView(hs, s.Window, h.busy(ctx)), nil
}

// ---- GET /core/updates/os ----

// CoreGetCoreUpdatesOs implements GET /core/updates/os (viewer).
func (h *OSHandlers) CoreGetCoreUpdatesOs(ctx context.Context) (*oas.CoreGetCoreUpdatesOsOK, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	v, err := h.stateNow(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreGetCoreUpdatesOsOK](v)
}

// ---- POST /core/updates/os/check ----

// CorePostCoreUpdatesOsCheck implements POST /core/updates/os/check (operator): apt update and a new list of
// pending packages. 409 check_off when update checks are off under Privacy: the box then makes no request.
func (h *OSHandlers) CorePostCoreUpdatesOsCheck(ctx context.Context) (*oas.CorePostCoreUpdatesOsCheckOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	on, err := h.updateCheckOn(ctx) // before any host call: with checks off the box makes no request at all
	if err != nil {
		return nil, err
	}
	if !on {
		return nil, apierr.New(409, CodeCheckOff, "Update checks are off under Privacy. Turn them on to look for operating system updates.")
	}
	if err := h.alive(ctx); err != nil {
		return nil, err
	}
	if h.busy(ctx) {
		return nil, apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish, then check again.")
	}
	err = h.act(ctx, c, false, "os.check", "operating system", "", func(id, actor string) error {
		run, err := h.host.OSCheck(ctx, id, actor)
		if err != nil {
			return hostErr(ctx, h.log, err)
		}
		_, err = waitRun(ctx, h.log, h.host, run, 6*time.Minute)
		return err
	})
	if err != nil {
		return nil, err
	}
	v, err := h.stateAfter(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreUpdatesOsCheckOK](v)
}

// ---- POST /core/updates/os/install and GET /core/updates/os/run ----

// CorePostCoreUpdatesOsInstall implements POST /core/updates/os/install (admin, 202): core writes a snapshot
// of its data (with the key: the host keeps the pre_os_update backup on the box), names it in os.install, and
// follows the run. The snapshot is deleted when the run ends.
func (h *OSHandlers) CorePostCoreUpdatesOsInstall(ctx context.Context, req *oas.CorePostCoreUpdatesOsInstallReq) (*oas.CorePostCoreUpdatesOsInstallAccepted, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	scope := string(req.Scope)
	if scope != "security" && scope != "all" {
		return nil, apierr.New(400, CodeInvalidScope, "Choose security updates or all updates.")
	}
	h.installMu.Lock()
	defer h.installMu.Unlock()
	if h.busy(ctx) {
		return nil, apierr.New(409, codeBusy, "Another update run is already in progress. Wait for it to finish; only one run can go at a time.")
	}
	hs, err := h.host.StateOS(ctx)
	if err != nil {
		return nil, hostErr(ctx, h.log, err)
	}
	n := len(hs.Pending)
	if scope == "security" {
		n = hs.SecurityCount
	}
	if n == 0 {
		msg := "There are no updates waiting. Click \"Check now\" to look again."
		if scope == "security" {
			msg = "There are no security updates waiting. Click \"Check now\" to look again."
		}
		return nil, apierr.New(409, CodeNothingToDo, msg)
	}

	var snap snapshot
	var run api.Run
	keepSnap := false
	err = h.act(ctx, c, true, "os.install", scope, fmt.Sprintf("%d packages waiting", n), func(id, actor string) error {
		var err error
		if snap, err = h.snaps.create(ctx, true); err != nil {
			return h.snapshotFailure(ctx, err)
		}
		if run, err = h.host.OSInstall(ctx, scope, snap.ID, id, actor); err != nil {
			var found, known bool
			if run, found, known = h.recoverRun(ctx, err, api.CmdOSInstall, id); found {
				return nil // the host took it; only its answer was lost
			}
			keepSnap = !known // the host may be running it and reading the snapshot: the start-up sweep removes it later
			return notTaken(ctx, h.log, err, run)
		}
		return nil
	})
	if err != nil {
		if !keepSnap {
			snap.remove() // the host did not take the run: nothing will read it
		}
		return nil, err
	}
	h.invalidateState()
	rs := &osRunState{
		meta:    osRunMeta{RunID: run.RunID, Scope: scope, User: c.Email, Snapshot: snap.ID},
		started: run.StartedAt, status: run.Status, lines: []string{},
	}
	wctx := context.WithoutCancel(ctx) // the run is going: its record is written even when the caller left
	if err := h.db.Write(wctx, func(tx *sql.Tx) error { return h.putSetting(wctx, tx, keyOSRun, rs.meta, c.Email) }); err != nil {
		h.log.ErrorContext(ctx, "core: could not store the install run", "run", run.RunID, "error", err) // the run goes on; the host holds the record
	}
	h.runMu.Lock()
	h.run, h.loaded = rs, true
	h.wg.Add(1)
	go h.follow(rs)
	v := rs.view()
	h.runMu.Unlock()
	return asOAS[oas.CorePostCoreUpdatesOsInstallAccepted](v)
}

// CoreGetCoreUpdatesOsRun implements GET /core/updates/os/run (viewer): the latest install run with its output
// so far, null before the first one. It answers from core's copy; the host is asked only to rebuild it after a
// restart.
func (h *OSHandlers) CoreGetCoreUpdatesOsRun(ctx context.Context) (oas.NilCoreGetCoreUpdatesOsRunOK, error) {
	if err := h.needHost(); err != nil {
		return oas.NilCoreGetCoreUpdatesOsRunOK{}, err
	}
	rs, err := h.current(ctx)
	if err != nil {
		return oas.NilCoreGetCoreUpdatesOsRunOK{}, err
	}
	if rs == nil {
		return oas.NilCoreGetCoreUpdatesOsRunOK{Null: true}, nil
	}
	h.runMu.Lock()
	v := rs.view()
	h.runMu.Unlock()
	out, err := asOAS[oas.NilCoreGetCoreUpdatesOsRunOK](v)
	if err != nil {
		return oas.NilCoreGetCoreUpdatesOsRunOK{}, err
	}
	return *out, nil
}

// ---- PATCH /core/updates/os/settings ----

// CorePatchCoreUpdatesOsSettings implements PATCH /core/updates/os/settings (admin): the maintenance window
// (core's own) and the automatic security updates switch (applied through os.auto_security.set and read back by
// the host). A window that no longer holds the scheduled reboot cancels that reboot, as the page says.
func (h *OSHandlers) CorePatchCoreUpdatesOsSettings(ctx context.Context, req *oas.CorePatchCoreUpdatesOsSettingsReq) (*oas.CorePatchCoreUpdatesOsSettingsOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	cur, err := h.settings(ctx)
	if err != nil {
		return nil, err
	}
	next := cur
	detail := ""
	if w, ok := req.Window.Get(); ok {
		nw, verr := maintWindow{Mode: string(w.Mode), Days: w.Days, From: w.From, To: w.To}.normalize(cur.Window)
		if verr != nil {
			return nil, verr
		}
		next.Window = nw
		detail = fmt.Sprintf("window %s", windowText(nw))
	}
	auto, autoSet := req.AutoSecurity.Get()
	if autoSet {
		detail += fmt.Sprintf("; auto security %t", auto)
	}
	loc, err := h.location(ctx)
	if err != nil {
		return nil, err
	}
	// Also the check that the helper answers, before anything is written. A box that has never checked has no
	// schedule to read; any other failure means the schedule is unknown, and a window is not saved over that.
	hs, err := h.host.StateOS(ctx)
	if err != nil && !isNoCheck(err) {
		return nil, hostErr(ctx, h.log, err)
	}
	// The schedule belongs to the old window: if the new one does not hold it, it is cancelled BEFORE the
	// window is saved, and a cancel that fails refuses the whole change.
	cancel := err == nil && hs.RebootScheduledAt != nil && !next.Window.contains(*hs.RebootScheduledAt, loc)
	err = h.act(ctx, c, true, "os.settings", "operating system", detail, func(id, actor string) error {
		if cancel {
			if err := h.cancelReboot(ctx, c, "no longer inside the maintenance window"); err != nil {
				return err
			}
		}
		if autoSet {
			run, err := h.host.OSAutoSecuritySet(ctx, auto, id, actor)
			if err != nil {
				return hostErr(ctx, h.log, err)
			}
			if _, err := waitRun(ctx, h.log, h.host, run, 6*time.Minute); err != nil {
				return err
			}
			next.AutoSecurity, next.AppliedAt = &auto, store.FormatTS(h.now())
		}
		return nil
	})
	h.invalidateState()
	if err != nil {
		return nil, err
	}
	if err := h.db.Write(ctx, func(tx *sql.Tx) error { return h.putSetting(ctx, tx, keyOSSettings, next, c.Email) }); err != nil {
		return nil, err
	}
	v, err := h.stateAfter(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePatchCoreUpdatesOsSettingsOK](v)
}

func windowText(w maintWindow) string {
	if w.Mode == windowAlways {
		return "any time"
	}
	return fmt.Sprintf("days %v %s-%s", w.Days, w.From, w.To)
}

// ---- POST and DELETE /core/updates/os/reboot ----

// CorePostCoreUpdatesOsReboot implements POST /core/updates/os/reboot (admin). now → host "now"; window → the
// next start of the maintenance window; custom → the next HH:MM inside the window; both in the organization
// time zone, sent to the host as one UTC instant (os.reboot "at"). 409 busy while an install runs.
func (h *OSHandlers) CorePostCoreUpdatesOsReboot(ctx context.Context, req *oas.CorePostCoreUpdatesOsRebootReq) (*oas.CorePostCoreUpdatesOsRebootOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if h.busy(ctx) {
		return nil, apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish before rebooting.")
	}
	args, action, target, detail, err := h.rebootPlan(ctx, req)
	if err != nil {
		return nil, err
	}
	before, err := h.stateAfter(ctx) // also what the answer falls back to when the box is already going down
	if err != nil {
		return nil, err
	}
	err = h.act(ctx, c, true, action, target, detail, func(id, actor string) error {
		run, err := h.host.OSReboot(ctx, args, id, actor)
		if err != nil {
			return hostErr(ctx, h.log, err)
		}
		_, err = waitRun(ctx, h.log, h.host, run, 2*time.Minute)
		return err
	})
	if err != nil {
		return nil, err
	}
	v, err := h.stateAfter(ctx)
	if err != nil {
		v = before // the reboot was accepted; the box may already be going down
	}
	return asOAS[oas.CorePostCoreUpdatesOsRebootOK](v)
}

// rebootPlan turns the request into the host's arguments and the audit text.
func (h *OSHandlers) rebootPlan(ctx context.Context, req *oas.CorePostCoreUpdatesOsRebootReq) (args api.OSRebootArgs, action, target, detail string, err error) {
	if req.When == oas.CorePostCoreUpdatesOsRebootReqWhenNow {
		return api.OSRebootArgs{When: "now"}, "os.reboot", "now", "", nil
	}
	s, err := h.settings(ctx)
	if err != nil {
		return args, "", "", "", err
	}
	loc, err := h.location(ctx)
	if err != nil {
		return args, "", "", "", err
	}
	now := h.now()
	var when time.Time
	switch req.When {
	case oas.CorePostCoreUpdatesOsRebootReqWhenWindow:
		if s.Window.Mode != windowOnly {
			return args, "", "", "", apierr.New(400, CodeNoWindow, "There is no maintenance window yet. Set the days and hours first, or pick a time yourself.")
		}
		var ok bool
		if when, ok = s.Window.nextStart(now, loc); !ok {
			return args, "", "", "", apierr.New(400, CodeNoWindow, "No maintenance window starts in the next 7 days. Check the days you chose.")
		}
		target = "next window"
	case oas.CorePostCoreUpdatesOsRebootReqWhenCustom:
		hhmm := req.At.Or("")
		if !hhmmRE.MatchString(hhmm) {
			return args, "", "", "", apierr.New(400, CodeInvalidTime, "Enter the time as hours and minutes, for example 03:30.")
		}
		var ok bool
		if when, ok = s.Window.nextAt(now, hhmm, loc); !ok {
			return args, "", "", "", apierr.New(400, CodeOutsideWindow, hhmm+" is outside the maintenance window. Pick a time inside it, or change the window first.")
		}
		target = hhmm
	default:
		return args, "", "", "", apierr.New(400, CodeInvalidWhen, "Choose: now, next maintenance window, or a time inside the window.")
	}
	at := when.UTC().Format(time.RFC3339)
	return api.OSRebootArgs{When: "at", At: at}, "os.reboot_schedule", target, at, nil
}

// CoreDeleteCoreUpdatesOsReboot implements DELETE /core/updates/os/reboot (admin): cancel the scheduled reboot.
func (h *OSHandlers) CoreDeleteCoreUpdatesOsReboot(ctx context.Context) (*oas.CoreDeleteCoreUpdatesOsRebootOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	hs, err := h.host.StateOS(ctx)
	if err != nil && !isNoCheck(err) { // a box that never checked can still hold a schedule: ask it to cancel
		return nil, hostErr(ctx, h.log, err)
	}
	if err == nil && hs.RebootScheduledAt == nil {
		return nil, apierr.New(409, CodeNothingPlanned, "No reboot is scheduled.")
	}
	err = h.cancelReboot(ctx, c, "")
	h.invalidateState()
	if err != nil {
		return nil, err
	}
	v, err := h.stateAfter(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreDeleteCoreUpdatesOsRebootOK](v)
}

func (h *OSHandlers) cancelReboot(ctx context.Context, c caller, why string) error {
	return h.act(ctx, c, true, "os.reboot_cancel", "operating system", why, func(id, actor string) error {
		run, err := h.host.OSRebootCancel(ctx, id, actor)
		if err != nil {
			return hostErr(ctx, h.log, err)
		}
		_, err = waitRun(ctx, h.log, h.host, run, 2*time.Minute)
		return err
	})
}

// ---- GET /core/data/backup ----

// backupLabel is the label the host keeps with the backup (letters, digits and a few signs only).
const backupLabel = "Downloaded from Settings"

// CoreGetCoreDataBackup implements GET /core/data/backup (admin): a backup of the database WITHOUT the master
// key, streamed from the host's copy. core writes a snapshot without the key (INV-6: a downloadable backup never
// holds one), asks for backup.create {manual, include_secrets: false}, deletes the snapshot when that call ends,
// and copies the host's file to the response as it reads it; nothing is held whole in memory. Every download
// makes a full snapshot and a manual backup on the box (the host keeps the latest 10), so: 409 busy while an
// install runs or another download is being made, 429 within a minute of the last one.
func (h *OSHandlers) CoreGetCoreDataBackup(ctx context.Context) (oas.CoreGetCoreDataBackupOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	if err := h.alive(ctx); err != nil {
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	if h.busy(ctx) {
		return oas.CoreGetCoreDataBackupOK{}, apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish, then download the backup.")
	}
	if !h.dlMu.TryLock() {
		return oas.CoreGetCoreDataBackupOK{}, apierr.New(409, codeBusy, "A backup is already being made. Wait for it to finish.")
	}
	defer h.dlMu.Unlock()
	if wait := downloadGap - h.now().Sub(h.lastDL); !h.lastDL.IsZero() && wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		return oas.CoreGetCoreDataBackupOK{}, apierr.New(429, codeRateLimited, "A backup was made a moment ago. Wait a minute before downloading another.").With("retry_after", secs)
	}
	var backupID string
	err = h.act(ctx, c, true, "data.backup", "backup", "database without secrets", func(id, actor string) error {
		h.lastDL = h.now()
		snap, err := h.snaps.create(ctx, false)
		if err != nil {
			return h.snapshotFailure(ctx, err)
		}
		keepSnap := false
		defer func() {
			if !keepSnap {
				snap.remove()
			}
		}()
		run, err := h.host.BackupCreate(ctx, api.BackupCreateArgs{Kind: "manual", IncludeSecrets: false, Label: backupLabel, Snapshot: snap.ID}, id, actor)
		if err != nil {
			var found, known bool
			if run, found, known = h.recoverRun(ctx, err, api.CmdBackupCreate, id); !found {
				keepSnap = !known // the host may be reading it: the start-up sweep removes it later
				return notTaken(ctx, h.log, err, run)
			}
		}
		run, err = waitRun(ctx, h.log, h.host, run, 16*time.Minute)
		if err != nil {
			return err
		}
		res := api.BackupResult{}
		if err := json.Unmarshal(run.Result, &res); err != nil || res.BackupID == "" {
			h.log.ErrorContext(ctx, "core: backup run without a usable result", "run", run.RunID)
			return apierr.New(502, CodeHostError, "The operating system helper could not do this. The details are in the box log.")
		}
		backupID = res.BackupID
		return nil
	})
	if err != nil {
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	// From here the backup exists on the box: a failure to hand it over is its own audit row.
	failed := func(code string, err error) (oas.CoreGetCoreDataBackupOK, error) {
		if rerr := h.record(context.WithoutCancel(ctx), c, false, "data.backup_failed", "backup", code); rerr != nil {
			h.log.ErrorContext(ctx, "core: could not audit a failed download", "error", rerr)
		}
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	body, size, err := h.host.DownloadBackup(ctx, backupID)
	if err != nil {
		herr := hostErr(ctx, h.log, err)
		code := "error"
		if ae, ok := apierr.As(herr); ok {
			code = ae.Code
		}
		return failed(code, herr)
	}
	if size < 0 { // the 200 and its headers would go out before anybody could tell a cut file from a whole one
		_ = body.Close()
		h.log.ErrorContext(ctx, "core: the host sent a backup of unknown size", "backup", backupID)
		return failed(CodeHostError, apierr.New(502, CodeHostError, "The operating system helper could not do this. The details are in the box log."))
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", `attachment; filename="vedette-backup-`+h.now().UTC().Format("2006-01-02")+`.tar.gz"`)
		hd.Set("Content-Length", strconv.FormatInt(size, 10))
	}
	return oas.CoreGetCoreDataBackupOK{Data: body}, nil // the encoder closes body when the copy ends
}

// recoverRun is for a write command whose answer may have been lost (the call went out and nothing came back:
// a timeout, a reset connection, the caller leaving). The host remembers the run by request id (host-api 4, 11):
// found is true with the run when it took the command. A run it refused is not one to follow: found is false and
// the run is returned for notTaken to answer its code. known is false when the host could not be asked, so the
// command may be running and its snapshot must stay.
func (h *OSHandlers) recoverRun(ctx context.Context, err error, command, requestID string) (run api.Run, found, known bool) {
	var he *client.Error
	if errors.As(err, &he) || errors.Is(err, client.ErrDenied) || errors.Is(err, fs.ErrNotExist) {
		return api.Run{}, false, true // an answer, or no socket at all: the command was not taken
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	runs, lerr := h.host.ListRuns(lctx, listRunsWindow)
	if lerr != nil {
		return api.Run{}, false, false
	}
	for _, r := range runs {
		if r.RequestID == requestID && r.Command == command {
			return r, r.Status != api.StatusRefused, true
		}
	}
	return api.Run{}, false, true
}

// notTaken is the answer to a write command the host did not take after its answer was lost: the code of the
// refusal it recorded under the key (recoverRun), else the call's own error.
func notTaken(ctx context.Context, log *slog.Logger, err error, run api.Run) error {
	if run.Status == api.StatusRefused && run.Error != nil {
		return mapHostCode(ctx, log, run.Error.Code, run.Error.Message, 0)
	}
	return hostErr(ctx, log, err)
}

// refusedElsewhere: a refused run that is not the run core recorded for its command (mine). The host records a
// refusal as a run (host-api 4): one refused by its check never started, so it is not the OS run after a restart
// nor a restore to settle. A run core recorded was accepted (202) and may still be refused while it runs
// (host/server: schema_newer, low_disk, dpkg_locked, ...): that one is the run and is settled like any end.
func refusedElsewhere(r api.Run, mine string) bool {
	return r.Status == api.StatusRefused && r.RunID != mine
}

// snapshotFailure is the answer for a snapshot that could not be written: 409 low_disk when the disk is full
// or too small for a copy, else 502 snapshot_failed; never a 500.
func (h *OSHandlers) snapshotFailure(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, errLowDisk), errors.Is(err, syscall.ENOSPC), strings.Contains(err.Error(), "disk is full"):
		return mapHostCode(ctx, h.log, api.CodeLowDisk, "", 0)
	}
	h.log.ErrorContext(ctx, "core: could not write a snapshot of the data", "error", err)
	return apierr.New(502, CodeSnapshotFailed, "Vedette could not write a copy of its data to the box's data folder. Check that the folder is writable and the disk is healthy, then try again.")
}
