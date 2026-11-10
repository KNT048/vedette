package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"regexp"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
)

// Host is what core needs of vedette-host (docs/specs/host-api.md). *client.Client implements it; tests run the
// real client against an in-process host. A nil Host is an install without the helper ("container only",
// D-55): every OS endpoint then answers 409 not_appliance.
type Host interface {
	StateOS(ctx context.Context) (api.OSState, error)
	OSCheck(ctx context.Context, requestID, actor string) (api.Run, error)
	OSInstall(ctx context.Context, scope, snapshot, requestID, actor string) (api.Run, error)
	OSAutoSecuritySet(ctx context.Context, enabled bool, requestID, actor string) (api.Run, error)
	OSReboot(ctx context.Context, args api.OSRebootArgs, requestID, actor string) (api.Run, error)
	OSRebootCancel(ctx context.Context, requestID, actor string) (api.Run, error)
	BackupCreate(ctx context.Context, args api.BackupCreateArgs, requestID, actor string) (api.Run, error)
	DownloadBackup(ctx context.Context, backupID string) (io.ReadCloser, int64, error)
	GetRun(ctx context.Context, runID string) (api.Run, error)
	ListRuns(ctx context.Context, limit int) ([]api.Run, error)
	Events(ctx context.Context, runID string, after uint64) *client.Stream
}

var _ Host = (*client.Client)(nil)

// Error codes that come from the host (host-api section 11) or from not having one. Where they sit in the
// API: 409 for what the state of the box refuses, 502 for a helper that failed or answered wrongly, 503 when it
// cannot be reached.
const (
	CodeNotAppliance      = "not_appliance"
	CodeHostUnreachable   = "host_unreachable"
	CodeHostError         = "host_error"
	CodeNoCheckYet        = "no_check_yet"
	CodeDpkgLocked        = "dpkg_locked"
	CodeDpkgInconsistent  = "dpkg_inconsistent"
	CodeLowDisk           = "low_disk"
	CodeRebooting         = "rebooting"
	CodeRebootLimit       = "reboot_limit_reached"
	CodeSnapshotRejected  = "snapshot_rejected"
	CodeSnapshotFailed    = "snapshot_failed"
	CodeAptFailed         = "apt_failed"
	CodeHealthCheckFailed = "health_check_failed"
	CodeEffectNotVerified = "effect_not_verified"
	codeBusy              = "busy"
	codePendingConfirm    = "pending_confirm"
	codeRateLimited       = "rate_limited"
)

func notAppliance() *apierr.Error {
	return apierr.New(409, CodeNotAppliance, "This install has no operating system helper (container-only install), so Vedette cannot update or back up the operating system from here.")
}

// hostErr turns an error of the host client into the API error the caller sees. No branch is a 500 for a
// helper that is absent, busy or unhappy; what the helper says that is not for the user (internal codes, file
// paths) is logged and replaced by a plain sentence.
func hostErr(ctx context.Context, log *slog.Logger, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, client.ErrUnreachable):
		if errors.Is(err, fs.ErrNotExist) { // no socket file: not an appliance (or its host service was never installed)
			return notAppliance()
		}
		log.WarnContext(ctx, "vedette-host is not answering", "error", err)
		return apierr.New(503, CodeHostUnreachable, "The operating system helper (vedette-host) is not answering. Try again in a minute; if it keeps happening, check that the vedette-host service is running.")
	case errors.Is(err, client.ErrDenied):
		log.ErrorContext(ctx, "vedette-host refused this process", "error", err)
		return apierr.New(503, CodeHostUnreachable, "The operating system helper (vedette-host) did not accept this request. Check its logs on the box.")
	}
	var he *client.Error
	if errors.As(err, &he) {
		return mapHostCode(ctx, log, he.Code, he.Message, he.RetryAfterS)
	}
	log.ErrorContext(ctx, "vedette-host call failed", "error", err)
	return apierr.New(502, CodeHostError, "The operating system helper gave an answer Vedette could not use. Try again; the details are in the box log.")
}

// mapHostCode is the table of host-api section 11 to API_CONVENTIONS section 3.3. Both the refusals of a call
// and the error of a finished run go through it.
func mapHostCode(ctx context.Context, log *slog.Logger, code, hostMsg string, retryAfter int) *apierr.Error {
	switch code {
	case api.CodeBusy, api.CodeInstallInProgress:
		return apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish, then try again.")
	case api.CodePendingConfirm, api.CodeNetPendingConfirm:
		return apierr.New(409, codePendingConfirm, "A network change is waiting for confirmation. Confirm or cancel it in Settings, Box network, then try again.")
	case api.CodeNotAppliance:
		return apierr.New(409, CodeNotAppliance, "This operating system release is not one Vedette updates (see the supported list in the documentation).")
	case api.CodeNoCheckYet:
		return apierr.New(409, CodeNoCheckYet, "The box has not looked for operating system updates yet. Click Check now.")
	case api.CodeDpkgLocked:
		e := apierr.New(409, CodeDpkgLocked, "Another package manager is running on the box (for example automatic updates). Try again in a minute.")
		if retryAfter > 0 {
			e = e.With("retry_after", retryAfter)
		}
		return e
	case api.CodeDpkgInconsistent:
		return apierr.New(409, CodeDpkgInconsistent, "The package database on the box is in a broken state. Run dpkg --audit on the box and repair it before updating.")
	case api.CodeLowDisk:
		return apierr.New(409, CodeLowDisk, "There is not enough free disk space for this. Free some space on the box and try again.")
	case api.CodeRebooting:
		return apierr.New(409, CodeRebooting, "The box is rebooting. Wait for it to come back, then try again.")
	case api.CodeRebootLimit:
		return apierr.New(409, CodeRebootLimit, "The box has already rebooted three times in 24 hours. Wait before rebooting again.")
	case api.CodeAtInPast, api.CodeAtTooFar:
		return apierr.New(400, CodeInvalidTime, "The reboot time must be between a minute and a week from now.")
	case api.CodeSnapshotRequired, api.CodeSnapshotInvalid, api.CodeDBUnreadable, "key_unreadable":
		log.ErrorContext(ctx, "vedette-host rejected the snapshot of the data", "code", code, "message", hostMsg)
		return apierr.New(502, CodeSnapshotRejected, "The helper could not take over a copy of the box's data. Check the box clock and the permissions of the data folder, then try again.")
	case api.CodeAptFailed, api.CodeStaleCheck:
		return apierr.New(502, CodeAptFailed, "The package manager failed. See the update output for the reason.")
	case api.CodeHealthCheckFailed:
		return apierr.New(502, CodeHealthCheckFailed, "The updates were installed but a health check failed afterwards. Check the services on the box.")
	case api.CodeEffectNotVerified:
		return apierr.New(502, CodeEffectNotVerified, "The change was made but could not be confirmed on the box. Check the setting again.")
	case api.CodeRateLimited:
		e := apierr.New(429, codeRateLimited, "Too many requests to the operating system helper. Try again shortly.")
		if retryAfter > 0 {
			e = e.With("retry_after", retryAfter)
		}
		return e
	case api.CodeShuttingDown:
		return apierr.New(503, CodeHostUnreachable, "The operating system helper is restarting. Try again in a minute.")
	}
	if e := mapNetCode(code); e != nil { // the network commands (S-CORE-8, D-99, D-100)
		return e
	}
	log.ErrorContext(ctx, "vedette-host refused or failed a call", "code", code, "message", hostMsg)
	return apierr.New(502, CodeHostError, "The operating system helper could not do this. The details are in the box log.")
}

var actorRE = regexp.MustCompile(`^[a-zA-Z0-9_.@:-]{1,64}$`)

// actorLabel is the label core puts on a host call for the host's audit line: the e-mail of the user when it
// has the host's alphabet, else the user id.
func actorLabel(email, id string) string {
	if actorRE.MatchString(email) {
		return email
	}
	if l := "user:" + id; actorRE.MatchString(l) {
		return l
	}
	return "user"
}

// newRequestID returns a UUID v4: the idempotency key of one host call.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("core: request id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// runWaiter is what following a run needs of the host (Host and NetHost both have it).
type runWaiter interface {
	GetRun(ctx context.Context, runID string) (api.Run, error)
	Events(ctx context.Context, runID string, after uint64) *client.Stream
}

// waitRun follows a run to its end (the stream carries only a few events for the short commands) and returns
// the finished run; a run that did not end well is the API error its code maps to.
func waitRun(ctx context.Context, log *slog.Logger, h runWaiter, run api.Run, limit time.Duration) (api.Run, error) {
	return waitRunTo(ctx, log, h, run, limit, false)
}

// waitRunTo is waitRun that may also stop at awaiting_confirm (a net.apply that changed the management address
// waits there for net.confirm, D-100): the run is then returned as it is, with no error.
func waitRunTo(ctx context.Context, log *slog.Logger, h runWaiter, run api.Run, limit time.Duration, stopAtAwaiting bool) (api.Run, error) {
	done := func(r api.Run) bool {
		return r.Status.Terminal() || (stopAtAwaiting && r.Status == api.StatusAwaitingConfirm)
	}
	if !done(run) {
		parent := ctx
		ctx, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		fail := func(err error) error {
			if parent.Err() == nil && ctx.Err() != nil { // our own time limit, not the caller leaving
				return apierr.New(502, CodeHostError, "The operating system helper took too long. Check the box and try again.")
			}
			return hostErr(parent, log, err)
		}
		// The stream ending (or showing awaiting_confirm) does not prove the stored run has caught up: on a loaded box the
		// stream can end first, and GetRun then still reads "running". Look again until the stored run is done or the
		// time limit ends, opening the stream again so a run that is still going is followed, not polled blindly.
		for {
			st := h.Events(ctx, run.RunID, 0)
			for {
				ev, err := st.Next()
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					st.Close()
					return api.Run{}, fail(err)
				}
				if stopAtAwaiting && ev.Kind == api.KindState && ev.Status == api.StatusAwaitingConfirm {
					break
				}
			}
			st.Close()
			var err error
			if run, err = h.GetRun(ctx, run.RunID); err != nil {
				return api.Run{}, fail(err)
			}
			if done(run) {
				break
			}
			select {
			case <-ctx.Done():
				return api.Run{}, fail(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if run.Status == api.StatusSucceeded || (stopAtAwaiting && run.Status == api.StatusAwaitingConfirm) {
		return run, nil
	}
	if run.Error != nil {
		return run, mapHostCode(ctx, log, run.Error.Code, run.Error.Message, 0)
	}
	return run, mapHostCode(ctx, log, api.CodeCommandFailed, "run ended "+string(run.Status), 0)
}
