package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
)

// The box has one time zone (INV-43): the organization's (Settings › General, the first-run setup) is the zone of every page, mail,
// log export, schedule and maintenance window, and the operating system is set to the same zone through the system helper
// (os.timezone.set), so the system journal, the apt timers and a shell on the box read the same clock. Core aligns the operating
// system after every change of the zone and at its own start; it changes it only when it differs, and audits only a change.

// The states of the operating system side (GET /core/general os_time_zone.state).
const (
	osZoneInSync     = "in_sync"     // the operating system uses the box's zone
	osZonePending    = "pending"     // not yet: the helper is busy, restarting or not answering; the box tries again by itself
	osZoneFailed     = "failed"      // the helper could not set it (the zone is unknown to the operating system, timedatectl failed)
	osZoneNotManaged = "not_managed" // no helper that can set it: a container-only install, or a helper older than os.timezone.set
)

// osZoneSync is how the operating system side stands (GET and PUT /core/general os_time_zone).
type osZoneSync struct {
	State   string  `json:"state"`
	Zone    *string `json:"zone"`    // what the operating system uses now; nil when it could not be read
	Message *string `json:"message"` // why it is not in sync; nil when it is
}

func zoneSyncOf(state, osZone, msg string) osZoneSync {
	s := osZoneSync{State: state}
	if osZone != "" {
		s.Zone = &osZone
	}
	if msg != "" {
		s.Message = &msg
	}
	return s
}

// The pace of the alignment loop: retries of a helper that is busy or not answering back off from zoneRetryFirst to zoneRetryMax;
// once aligned (or refused for good) the loop looks again every zoneRecheck (someone may have changed the zone on the box by hand) or
// when woken (the first-run setup is done).
const (
	zoneRetryFirst = 30 * time.Second
	zoneRetryMax   = 10 * time.Minute
	zoneRecheck    = time.Hour
	zoneRunLimit   = 2 * time.Minute // one os.timezone.set run (the host gives it one minute)
	zoneSaveLimit  = 20 * time.Second
)

// zoneAligner is the operating system side of OSHandlers.
type zoneAligner struct {
	mu     sync.Mutex // one alignment at a time
	lastMu sync.Mutex // guards last and logged
	last   *osZoneSync
	logged string // the state and message last logged: a state is logged once, not at every look
	wake   chan struct{}
}

// WakeZoneAlignment asks the alignment loop to look now (after the first-run setup or a restore set the zone). It never blocks.
func (h *OSHandlers) WakeZoneAlignment() {
	select {
	case h.tz.wake <- struct{}{}:
	default:
	}
}

// boxZone is the organization's zone under its current IANA name ("" when it cannot be read).
func (h *OSHandlers) boxZone(ctx context.Context) (string, error) {
	name, err := h.zone(ctx)
	if err != nil {
		return "", err
	}
	return orgtime.CanonicalZone(name), nil
}

// alignZone makes the operating system use the box's zone when it does not, and returns how it stands. actor is the person whose
// save asked for it, or userSystem. Only a change is audited (core.os_time_zone); a state is logged once.
func (h *OSHandlers) alignZone(ctx context.Context, actor string) osZoneSync {
	h.tz.mu.Lock()
	defer h.tz.mu.Unlock()
	s := h.alignZoneOnce(ctx, actor)
	h.tz.lastMu.Lock()
	h.tz.last = &s
	key := s.State
	if s.Message != nil {
		key += " " + *s.Message
	}
	logIt := key != h.tz.logged
	h.tz.logged = key
	h.tz.lastMu.Unlock()
	if logIt && s.State != osZoneInSync {
		h.log.WarnContext(ctx, "core: the operating system time zone is not the box's", "state", s.State, "message", deref(s.Message))
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (h *OSHandlers) alignZoneOnce(ctx context.Context, actor string) osZoneSync {
	if h.host == nil {
		return zoneSyncOf(osZoneNotManaged, "", "This install has no system helper, so the operating system keeps its own time zone. Vedette writes every time in the zone above.")
	}
	want, err := h.boxZone(ctx)
	if err != nil {
		h.log.WarnContext(ctx, "core: reading the box's time zone failed", "error", err)
		return zoneSyncOf(osZonePending, "", "The box's time zone could not be read. Vedette tries again.")
	}
	st, err := h.host.StateTime(ctx)
	if err != nil {
		return h.zoneHostErr(ctx, err, "")
	}
	if st.Timezone == want {
		return zoneSyncOf(osZoneInSync, st.Timezone, "")
	}
	rid, err := newRequestID()
	if err != nil {
		return zoneSyncOf(osZonePending, st.Timezone, "Vedette could not ask the system helper. It tries again.")
	}
	run, err := h.host.OSTimezoneSet(ctx, want, rid, actor)
	if err != nil {
		return h.zoneHostErr(ctx, err, st.Timezone)
	}
	run, err = waitRun(ctx, h.log, h.host, run, zoneRunLimit)
	if err != nil {
		if run.Error != nil {
			h.log.WarnContext(ctx, "core: os.timezone.set failed", "code", run.Error.Code, "message", run.Error.Message)
			return zoneSyncOf(osZoneFailed, st.Timezone, zoneRunMessage(run.Error.Code, run.Error.Message, want))
		}
		return zoneSyncOf(osZonePending, st.Timezone, "The system helper did not finish setting the time zone. Vedette tries again.")
	}
	res, _ := client.ResultOf[api.OSTimezoneResult](run)
	if res.Changed {
		from := st.Timezone
		if from == "" {
			from = "an unknown zone"
		}
		detail := fmt.Sprintf("from %s to %s", from, want)
		wctx := context.WithoutCancel(ctx)
		err := h.db.Write(wctx, func(tx *sql.Tx) error {
			return h.audit.Append(wctx, tx, audit.Entry{User: actor, Action: "core.os_time_zone", Target: want, Detail: detail})
		})
		if err != nil {
			h.log.ErrorContext(ctx, "core: auditing the operating system time zone change failed", "error", err)
		}
		h.log.InfoContext(ctx, "core: the operating system time zone now follows the box's", "from", st.Timezone, "to", want)
	}
	return zoneSyncOf(osZoneInSync, want, "")
}

// zoneHostErr is the state for a host call that did not get a run: no helper or an older one is not_managed, a refusal of the zone
// is failed, anything a retry can fix is pending.
func (h *OSHandlers) zoneHostErr(ctx context.Context, err error, osZone string) osZoneSync {
	var he *client.Error
	switch {
	case errors.Is(err, client.ErrUnreachable) && errors.Is(err, fs.ErrNotExist):
		return zoneSyncOf(osZoneNotManaged, osZone, "This install has no system helper, so the operating system keeps its own time zone. Vedette writes every time in the zone above.")
	case errors.As(err, &he) && he.Code == api.CodeUnknownCommand:
		return zoneSyncOf(osZoneNotManaged, osZone, "The system helper on this box is older than this version of Vedette and cannot set the time zone. It sets it once the helper is updated (Settings › Updates).")
	case errors.As(err, &he) && he.Code == api.CodeZoneUnknown:
		return zoneSyncOf(osZoneFailed, osZone, "The operating system does not know this time zone. Choose another name for it from the list.")
	case errors.As(err, &he) && (he.Code == api.CodeInvalidArgs || he.Code == api.CodeNotAppliance):
		return zoneSyncOf(osZoneFailed, osZone, "The system helper refused this time zone. Choose another one from the list.")
	}
	if ctx.Err() == nil {
		h.log.InfoContext(ctx, "core: the system helper did not take the time zone now", "error", err)
	}
	return zoneSyncOf(osZonePending, osZone, "The system helper is busy or not answering. Vedette sets the operating system's time zone as soon as it can.")
}

// zoneRunMessage is the sentence for a run of os.timezone.set that failed.
func zoneRunMessage(code, hostMsg, zone string) string {
	switch code {
	case api.CodeTimezoneNotSet:
		return "The operating system refused the time zone " + zone + ": " + cutAtRune(strings.TrimPrefix(hostMsg, "timedatectl could not set the time zone: "), 200)
	case api.CodeEffectNotVerified:
		return "The operating system did not take the time zone " + zone + ". Check the box (timedatectl status)."
	}
	return "The system helper could not set the time zone. The details are in the box log."
}

// zoneSync is how the operating system side stands for GET /core/general: the last alignment, or (before the first one has run) a
// read of the helper that changes nothing.
func (h *OSHandlers) zoneSync(ctx context.Context) osZoneSync {
	h.tz.lastMu.Lock()
	last := h.tz.last
	h.tz.lastMu.Unlock()
	if last != nil {
		return *last
	}
	if h.host == nil {
		return zoneSyncOf(osZoneNotManaged, "", "This install has no system helper, so the operating system keeps its own time zone. Vedette writes every time in the zone above.")
	}
	want, err := h.boxZone(ctx)
	if err != nil {
		return zoneSyncOf(osZonePending, "", "")
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := h.host.StateTime(rctx)
	if err != nil {
		return h.zoneHostErr(ctx, err, "")
	}
	if st.Timezone == want {
		return zoneSyncOf(osZoneInSync, st.Timezone, "")
	}
	return zoneSyncOf(osZonePending, st.Timezone, "The operating system still uses another time zone. Vedette sets it in a moment.")
}

// zoneLoop aligns the operating system's zone at start once first-run setup is done (before it the zone is only the default, which
// nobody chose), then again when woken, retrying a helper that is busy or away with a growing pause.
func (h *OSHandlers) zoneLoop() {
	defer h.wg.Done()
	retry := zoneRetryFirst
	for {
		wait := zoneRecheck
		done, err := h.setup.setupDone(h.ctx)
		switch {
		case h.ctx.Err() != nil:
			return
		case err != nil:
			wait = retry
		case done:
			if s := h.alignZone(h.ctx, userSystem); s.State == osZonePending {
				wait = retry
				retry = min(retry*2, zoneRetryMax)
			} else {
				retry = zoneRetryFirst
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-h.ctx.Done():
			t.Stop()
			return
		case <-h.tz.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// zoneSaved aligns the operating system right after a person saved the zone (PUT /core/general), within zoneSaveLimit; a helper that
// is busy leaves it to the loop.
func (h *OSHandlers) zoneSaved(ctx context.Context, actor string) osZoneSync {
	ctx, cancel := context.WithTimeout(ctx, zoneSaveLimit)
	defer cancel()
	s := h.alignZone(ctx, actor)
	if s.State == osZonePending {
		h.WakeZoneAlignment()
	}
	return s
}
