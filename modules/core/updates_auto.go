package core

import (
	"context"
	"database/sql"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// The automatic side of the software update (S-CORE-2; update-manifest.md §6, §12; D-53, D-388): a job of core checks for
// releases every 6 hours ± 30 minutes through the same check as POST /core/updates/check, and in automatic mode starts
// the run of the release on offer as user "system", only inside the maintenance window (os.settings) and never while
// another run is busy. Nothing here when update checks are off under Privacy: no request and no install (PRIVACY flow 6).

const (
	// UpdateTickEvery is how often the job looks (cmd/vedette registers it as core/software-update). A check is made
	// only when it is due; an install may start at any tick inside the window, so a short window is not missed.
	UpdateTickEvery   = 10 * time.Minute
	updateCheckEvery  = 6 * time.Hour    // update-manifest §12
	updateCheckJitter = 30 * time.Minute // ± around updateCheckEvery
	// autoFresh is how old the last good check may be when the automatic mode installs: one regular interval and a tick.
	// A check that fails (an index held back to hide a revocation, §13) leaves last_check old, so nothing installs.
	autoFresh = updateCheckEvery + updateCheckJitter + UpdateTickEvery
	// autoMinLeft: a run does not start when less of the window is left (pulls and core's switch take a while).
	autoMinLeft = 30 * time.Minute
	userSystem  = "system" // the audit user and host actor of what the box does by itself (UpdateRun.user)
)

// systemCaller is the caller of the periodic check and of the automatic install: no session, no admin check.
var systemCaller = caller{Principal: server.Principal{Email: userSystem}}

// system reports whether c is systemCaller; a signed-in caller always has an id.
func (c caller) system() bool { return c.ID == "" && c.Email == userSystem }

// checkInterval is the wait until the next periodic check: 6 hours ± 30 minutes, drawn at every check.
func checkInterval() time.Duration {
	return updateCheckEvery - updateCheckJitter + rand.N(2*updateCheckJitter+1) //nolint:gosec // spreads the boxes' checks over an hour; not a secret
}

// errAutoSkip: the automatic mode leaves the offer alone this time (logged once where it is decided).
var errAutoSkip = errors.New("core: the automatic mode does not install now")

// UpdateTick is the job: a check when one is due (6 hours ± 30 minutes after the last one this process made, or after the
// stored last_check when it has made none, never before UpdateTickEvery after the process started), then the automatic
// install unless that check failed. Off under Privacy, or before first-run setup (no install id: the administrator has not
// seen Privacy yet): nothing.
func (h *OSHandlers) UpdateTick(ctx context.Context) error {
	on, err := h.updateCheckOn(ctx)
	if err != nil || !on {
		return err
	}
	if _, set, err := h.cohort(ctx); err != nil || !set {
		return err
	}
	due, err := h.checkDue(ctx)
	if err != nil {
		return err
	}
	if due {
		if err := h.check(ctx, systemCaller); err != nil { // logged and audited (update.check, user system) like a check from the page
			return err
		}
	}
	return h.autoInstall(ctx, "")
}

func (h *OSHandlers) checkDue(ctx context.Context) (bool, error) {
	h.upd.checkMu.Lock()
	defer h.upd.checkMu.Unlock()
	if h.upd.next.IsZero() {
		s, err := h.updSettings(ctx)
		if err != nil {
			return false, err
		}
		// Never at the first tick of a process: a core that restarts (its own update switch does) adds no check, and
		// a box never checked checks one tick after it starts.
		h.upd.next = later(s.LastCheck.Add(checkInterval()), h.upd.started.Add(UpdateTickEvery))
	}
	return !h.now().Before(h.upd.next), nil
}

// autoInstall starts the run of the release on offer when the mode is automatic, update checks are on, this box has a
// vedette-host (a container-only install never updates itself, update-manifest §7), now is inside the maintenance window
// with at least autoMinLeft of it left (os.settings, the organization time zone; "always" = any time) and no reboot is
// scheduled in the next updateRunMax. The release rules are read again under urun.mu (autoPlan). It goes through
// beginUpdate and planApply as systemCaller, so the run, its audit rows and its history entry name "system" (by, when
// not empty, is the person whose Check now led to it: in the audit detail). A busy box (a software, OS or restore run, a
// purge) or nothing to install is not an error: the next tick looks again.
func (h *OSHandlers) autoInstall(ctx context.Context, by string) error {
	if h.host == nil {
		return nil
	}
	s, err := h.updSettings(ctx)
	if err != nil || s.Mode != "auto" {
		return err
	}
	on, err := h.updateCheckOn(ctx)
	if err != nil || !on {
		return err
	}
	in, err := h.inWindow(ctx)
	if err != nil || !in {
		return err
	}
	if st, err := h.hostState(ctx); err != nil {
		return err
	} else if at := st.RebootScheduledAt; at != nil && at.Before(h.now().Add(updateRunMax)) {
		h.skipOnce(ctx, "auto-reboot", "a reboot is scheduled", "reboot_at", *at)
		return nil
	}
	err = h.beginUpdate(ctx, systemCaller, func(ctx context.Context) (*updateRunRec, string, func(*sql.Tx) error, error) {
		rel, err := h.autoPlan(ctx)
		if err != nil {
			return nil, "", nil, err
		}
		rec, detail, err := h.planApply(ctx, systemCaller, rel)
		detail = "automatic: " + detail
		if by != "" {
			detail += "; after a check by " + by
		}
		return rec, detail, nil, err
	})
	if err == nil {
		h.log.InfoContext(ctx, "core: the automatic mode started the software update")
		h.upd.warned.Delete("auto-stale")
		h.upd.warned.Delete("auto-reboot")
		return nil
	}
	ae, ok := apierr.As(err)
	switch {
	case errors.Is(err, errAutoSkip), errors.Is(err, errNoUpdate), ok && ae.Code == codeBusy:
		return nil
	case ok && ae.Code == CodeNotAppliance: // a host, but core does not run from a pinned container (a development box)
		h.skipOnce(ctx, "auto-not-appliance", "Vedette does not run from a pinned container")
		return nil
	}
	return err
}

// autoPlan is the release the automatic mode installs now, read under urun.mu: the mode is still automatic, the last good
// check is at most autoFresh old and its index is not past expires_at (revocations are known, §6, §13), something is
// offered (verified again, revoked releases dropped), and no run to that release was made yet (D-388: one that failed or
// was reverted is left to an administrator; one that ended done while this build still runs the older version would
// otherwise repeat).
func (h *OSHandlers) autoPlan(ctx context.Context) (*verifiedRelease, error) {
	s, err := h.updSettings(ctx)
	if err != nil {
		return nil, err
	}
	if s.Mode != "auto" {
		return nil, errAutoSkip
	}
	r, err := h.releaseNow(ctx)
	if err != nil {
		h.skipOnce(ctx, "auto-state", "the stored update information could not be read", "error", err)
		return nil, errAutoSkip
	}
	if r.offer == nil {
		return nil, errNoUpdate
	}
	if age := h.now().Sub(s.LastCheck); age > autoFresh || age < 0 || r.idx.Expired(h.now()) {
		h.skipOnce(ctx, "auto-stale", "the last good update check is too old or its index has expired", "last_check", s.LastCheck)
		return nil, errAutoSkip
	}
	v := r.offer.M.Version
	last, err := h.loadUpdateRun(ctx)
	if err != nil {
		return nil, err
	}
	if last != nil && last.Action == actionUpdate && last.To == v {
		h.skipOnce(ctx, "auto-tried "+v, "an update to this release was already made, so the automatic mode leaves it to an administrator", "version", v, "status", last.Status)
		return nil, errAutoSkip
	}
	return r.offer, nil
}

// skipOnce logs, once per kind, why the automatic mode did not install.
func (h *OSHandlers) skipOnce(ctx context.Context, kind, why string, args ...any) {
	if h.upd.firstWarn(kind) {
		h.log.WarnContext(ctx, "core: the automatic software update waits: "+why, args...)
	}
}

// inWindow reports whether now is inside the maintenance window of os.settings (S-CORE-7, organization time zone) with at
// least autoMinLeft of it left.
func (h *OSHandlers) inWindow(ctx context.Context) (bool, error) {
	st, err := h.settings(ctx)
	if err != nil {
		return false, err
	}
	loc, err := h.location(ctx)
	if err != nil {
		return false, err
	}
	now := h.now()
	return st.Window.contains(now, loc) && st.Window.contains(now.Add(autoMinLeft), loc), nil
}
