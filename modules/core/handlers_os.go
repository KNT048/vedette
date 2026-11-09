package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
)

// OSHandlers implements the operating system part of Settings → Updates (S-CORE-7: /core/updates/os*) and the
// backup download (S-CORE-1: /core/data/backup) on top of vedette-host. Embed it in the composite handler beside
// the other core handlers; its operations are disjoint from theirs. Every host call is made with a fresh
// idempotency key and an actor label, after a core_audit row for the intent (and one more when it fails);
// nothing here runs a command itself (SYS-1).
type OSHandlers struct {
	db    *store.DB
	auth  *auth.Service
	audit *audit.Log
	host  Host // nil: not an appliance
	snaps *snapshotter
	zone  func(context.Context) (string, error)
	log   *slog.Logger
	now   func() time.Time

	ctx    context.Context //nolint:containedctx // the lifetime of the run followers, not of a request
	cancel context.CancelFunc
	wg     sync.WaitGroup

	installMu sync.Mutex // one install at a time through this process, from the busy check to the host's answer
	runMu     sync.Mutex // guards run, loaded and the fields of the run state
	run       *osRunState
	loaded    bool
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
}

// NewOSHandlers returns the handlers and sweeps the snapshot directories an earlier run left behind.
func NewOSHandlers(c OSConfig) (*OSHandlers, error) {
	if c.DB == nil || c.Auth == nil || c.Audit == nil || c.Log == nil || c.Zone == nil {
		return nil, errors.New("core: OSConfig needs DB, Auth, Audit, Log and Zone")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	h := &OSHandlers{db: c.DB, auth: c.Auth, audit: c.Audit, host: c.Host, zone: c.Zone, log: c.Log, now: c.Clock}
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
	}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	return h, nil
}

// Close stops the followers of install runs and waits for them. The run itself goes on in the host.
func (h *OSHandlers) Close() {
	h.cancel()
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

// updateCheckOn reads the Privacy switch of update checks (core_setting core_privacy, field update_check; on
// when nothing was ever stored: PRIVACY.md flow 6 is on by default).
func (h *OSHandlers) updateCheckOn(ctx context.Context) (bool, error) {
	var p struct {
		UpdateCheck *bool `json:"update_check"`
	}
	if err := h.loadJSON(ctx, "core_privacy", &p); err != nil {
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

// stateNow reads the host's view and adds what core owns.
func (h *OSHandlers) stateNow(ctx context.Context) (osStateView, error) {
	hs, err := h.host.StateOS(ctx)
	if err != nil {
		return osStateView{}, hostErr(ctx, h.log, err)
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
	if err := h.alive(ctx); err != nil {
		return nil, err
	}
	on, err := h.updateCheckOn(ctx)
	if err != nil {
		return nil, err
	}
	if !on {
		return nil, apierr.New(409, CodeCheckOff, "Update checks are off under Privacy. Turn them on to look for operating system updates.")
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
	v, err := h.stateNow(ctx)
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
	err = h.act(ctx, c, true, "os.install", scope, fmt.Sprintf("%d packages waiting", n), func(id, actor string) error {
		var err error
		if snap, err = h.snaps.create(ctx, true); err != nil {
			return fmt.Errorf("core: write snapshot: %w", err)
		}
		if run, err = h.host.OSInstall(ctx, scope, snap.ID, id, actor); err != nil {
			return hostErr(ctx, h.log, err)
		}
		return nil
	})
	if err != nil {
		snap.remove() // the host did not take the run: nothing will read it
		return nil, err
	}
	rs := &osRunState{
		meta:    osRunMeta{RunID: run.RunID, Scope: scope, User: c.Email, Snapshot: snap.ID},
		started: run.StartedAt, status: run.Status, lines: []string{},
	}
	if err := h.db.Write(ctx, func(tx *sql.Tx) error { return h.putSetting(ctx, tx, keyOSRun, rs.meta, c.Email) }); err != nil {
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
	if err := h.alive(ctx); err != nil {
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
	err = h.act(ctx, c, true, "os.settings", "operating system", detail, func(id, actor string) error {
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
	if err != nil {
		return nil, err
	}
	if err := h.db.Write(ctx, func(tx *sql.Tx) error { return h.putSetting(ctx, tx, keyOSSettings, next, c.Email) }); err != nil {
		return nil, err
	}
	// The schedule belongs to the old window: if the new one does not hold it, drop it.
	if hs, err := h.host.StateOS(ctx); err == nil && hs.RebootScheduledAt != nil && !next.Window.contains(*hs.RebootScheduledAt, loc) {
		if cerr := h.cancelReboot(ctx, c, "no longer inside the maintenance window"); cerr != nil {
			h.log.WarnContext(ctx, "core: could not cancel a reboot outside the new window", "error", cerr)
		}
	}
	v, err := h.stateNow(ctx)
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
	before, err := h.stateNow(ctx) // also what the answer falls back to when the box is already going down
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
	v, err := h.stateNow(ctx)
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
	if err != nil {
		return nil, hostErr(ctx, h.log, err)
	}
	if hs.RebootScheduledAt == nil {
		return nil, apierr.New(409, CodeNothingPlanned, "No reboot is scheduled.")
	}
	if err := h.cancelReboot(ctx, c, ""); err != nil {
		return nil, err
	}
	v, err := h.stateNow(ctx)
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
// and copies the host's file to the response as it reads it; nothing is held whole in memory.
func (h *OSHandlers) CoreGetCoreDataBackup(ctx context.Context) (oas.CoreGetCoreDataBackupOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	if err := h.alive(ctx); err != nil {
		return oas.CoreGetCoreDataBackupOK{}, err
	}
	var backupID string
	err = h.act(ctx, c, true, "data.backup", "backup", "database without secrets", func(id, actor string) error {
		snap, err := h.snaps.create(ctx, false)
		if err != nil {
			return fmt.Errorf("core: write snapshot: %w", err)
		}
		defer snap.remove()
		run, err := h.host.BackupCreate(ctx, api.BackupCreateArgs{Kind: "manual", IncludeSecrets: false, Label: backupLabel, Snapshot: snap.ID}, id, actor)
		if err != nil {
			return hostErr(ctx, h.log, err)
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
	body, size, err := h.host.DownloadBackup(ctx, backupID)
	if err != nil {
		return oas.CoreGetCoreDataBackupOK{}, hostErr(ctx, h.log, err)
	}
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", `attachment; filename="vedette-backup-`+h.now().UTC().Format("2006-01-02")+`.tar.gz"`)
		if size >= 0 {
			hd.Set("Content-Length", strconv.FormatInt(size, 10))
		}
	}
	return oas.CoreGetCoreDataBackupOK{Data: body}, nil // the encoder closes body when the copy ends
}
