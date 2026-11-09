package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The confirm window of a management change (D-100, spec 6.5): what is on disk while it lasts, how
// the host finds it again after a crash or a reboot, and the timer that ends it.
//
// net/pending.json in the state directory is the host's note of an unconfirmed change:
// {run_id, revert_at, boot_id, old_sha, new_sha}. The new configuration lives only in the /run
// overlay until net.confirm moves it to /etc, so a reboot (which empties /run) is a revert by
// construction. The host never trusts the note to keep a configuration: a note that is not exactly
// what the host writes (or sits behind a link, or is not 0600 and the host's own) is read as
// "revert", never as "confirm".

const (
	pendingName   = "pending.json"
	maxPendingLen = 4 << 10

	netplanEtcDir = "etc/netplan"
	netplanRunDir = "run/netplan"

	netStepTimeout   = 30 * time.Second  // one tidy-up step after the run's own context is gone
	netRevertTimeout = 180 * time.Second // a whole revert (three tries of apply about 30 s apart, effect check)
)

type netPending struct {
	RunID string `json:"run_id"`
	// StartedAt is the wall time the run started: after a restart the monotonic clock is gone, and
	// this is what the 660 s bound of a re-armed timer is measured from.
	StartedAt time.Time `json:"started_at"`
	RevertAt  time.Time `json:"revert_at"`
	BootID    string    `json:"boot_id"`
	OldSHA    string    `json:"old_sha"` // sha256 of /etc/netplan/90-vedette.yaml before the change; "" when there was none
	NewSHA    string    `json:"new_sha"` // sha256 of the new file
	// RebootAt is set when a revert could not be applied and the host scheduled a reboot (D-100 (8)).
	RebootAt *time.Time `json:"reboot_at,omitempty"`
}

type pendState int

const (
	pendNone pendState = iota
	pendOK
	pendBad // there is an entry, and it is not a note the host wrote
)

var (
	runIDRE = regexp.MustCompile(`^rn_[0-9a-f]{16}$`)
	shaRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (p netPending) valid() bool {
	return runIDRE.MatchString(p.RunID) && !p.StartedAt.IsZero() && !p.RevertAt.IsZero() && bootIDRE.MatchString(p.BootID) &&
		(p.OldSHA == "" || shaRE.MatchString(p.OldSHA)) && shaRE.MatchString(p.NewSHA)
}

func (o *Ops) pendingDir() string { return o.stateFile("net") }

// loadPending reads net/pending.json through an os.Root on its directory: a link, a directory, a
// FIFO, a file that is not 0600 and owned by the host's owner, an unknown field, trailing data or
// a value out of shape is pendBad.
func (o *Ops) loadPending() (netPending, pendState) {
	r, err := os.OpenRoot(o.pendingDir())
	if err != nil {
		return netPending{}, pendBad
	}
	defer func() { _ = r.Close() }()
	if st, err := r.Lstat(pendingName); err == nil {
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(sys.Uid) != o.cfg.OwnerUID || st.Mode().Perm()&0o077 != 0 {
			return netPending{}, pendBad
		}
	}
	b, st := readNoFollow(r, pendingName, maxPendingLen)
	switch st {
	case fileAbsent:
		return netPending{}, pendNone
	case fileBroken:
		return netPending{}, pendBad
	}
	var p netPending
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || !p.valid() {
		return netPending{}, pendBad
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return netPending{}, pendBad
	}
	return p, pendOK
}

func (o *Ops) savePending(p netPending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(o.pendingDir())
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return writeAtomicIn(r, pendingName, b, 0o600)
}

// deletePending removes the note (a link or a file at that name; never what a link points to).
func (o *Ops) deletePending() error {
	r, err := os.OpenRoot(o.pendingDir())
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := r.Remove(pendingName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// --- the timer ----------------------------------------------------------------------------------

// armNetTimer ends the confirm window by itself at `at`. Deps.AfterFunc is the seam.
func (o *Ops) armNetTimer(runID string, at time.Time) {
	d := max(at.Sub(o.d.Now()), 0)
	stop := o.d.AfterFunc(d, func() {
		o.revertWaiting(runID, api.CodeNotConfirmed, "The change was not confirmed in time, so the previous network configuration was restored.")
	})
	o.netMu.Lock()
	if o.netStop != nil {
		o.netStop()
	}
	o.netStop = stop
	o.netMu.Unlock()
}

func (o *Ops) stopNetTimer() {
	o.netMu.Lock()
	defer o.netMu.Unlock()
	if o.netStop != nil {
		o.netStop()
		o.netStop = nil
	}
}

// claim takes the right to end the awaiting run (server.Claim): the confirm-against-timer race is
// decided here, before any effect.
func (o *Ops) claim(runID string) (*server.Claimed, error) {
	o.mu.Lock()
	n := o.notifier
	o.mu.Unlock()
	if n == nil {
		return nil, server.ErrShuttingDown
	}
	return n.Claim(runID)
}

// revertWaiting is the revert of an awaiting run that nobody asked for (the timer, or start-up):
// Claim first, then the effects, then Finish. The loser of a race does nothing.
func (o *Ops) revertWaiting(runID, code, msg string) {
	c, err := o.claim(runID)
	if err != nil {
		o.log.Info("a network revert found nothing to end", "run_id", runID)
		return
	}
	o.stopNetTimer()
	ctx, cancel := context.WithTimeout(context.Background(), netRevertTimeout)
	defer cancel()
	o.finishReverted(ctx, c, code, msg)
}

// finishReverted puts the previous configuration back and ends the claimed run: reverted with
// code when that worked, failed revert_failed when it did not. It always finishes the claim.
func (o *Ops) finishReverted(ctx context.Context, c *server.Claimed, code, msg string) (reverted bool) {
	done := false
	defer func() { //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
		if !done {
			_ = c.Finish(api.StatusFailed, &api.RunError{Code: api.CodeRevertFailed, Message: "The revert stopped unexpectedly."})
		}
	}()
	err := o.undoOverlay(ctx, nil)
	done = true
	if err != nil {
		o.log.ErrorContext(ctx, "the network revert failed; the file on disk is the old configuration, a reboot restores it", "error", err.Error())
		_ = c.Finish(api.StatusFailed, &api.RunError{Code: api.CodeRevertFailed, Message: "Restoring the previous network configuration failed. The saved configuration is the old one: restarting the box restores it."}) //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
		return false
	}
	_ = c.Finish(api.StatusReverted, &api.RunError{Code: code, Message: msg}) //nolint:contextcheck // Finish takes no context: it must finish even when the caller's is cancelled
	return true
}

// --- start-up and restart -------------------------------------------------------------------------

// Resume is the server's Options.Resume: it keeps a net.apply run that was awaiting confirmation
// when the host stopped, as long as there is a note about it (Start then ends it or re-arms its
// timer). It only reads. Without a note nothing can be reverted from here, and the run fails as
// host_restarted; an overlay left behind is cleaned by Start.
func (o *Ops) Resume(run api.Run) bool {
	if run.Command != api.CmdNetApply {
		return false
	}
	if _, st := o.loadPending(); st == pendNone {
		return false
	}
	o.netMu.Lock()
	o.resumed = run.RunID
	o.netMu.Unlock()
	return true
}

// recoverNet runs once in Start, before the server listens. A resumed run is ended or its timer
// re-armed; a note or an overlay with no run behind it is cleaned up.
func (o *Ops) recoverNet(ctx context.Context) {
	o.netMu.Lock()
	id := o.resumed
	o.resumed = ""
	o.netMu.Unlock()
	p, st := o.loadPending()
	_, overlay := o.readNoFollowIn(netplanRunDir, netplanName, maxNetplan)
	switch {
	case id != "":
		o.recoverResumed(id, p, st, overlay != fileAbsent) //nolint:contextcheck // start-up has no request: a revert has a context of its own
	case st != pendNone || overlay != fileAbsent:
		o.recoverOrphan(ctx, p, st, overlay != fileAbsent)
	}
}

func (o *Ops) recoverResumed(id string, p netPending, st pendState, overlay bool) {
	boot := o.bootID()
	if st == pendOK && p.RunID == id && o.confirmReachedEtc(p) {
		// The host died inside net.confirm after /etc was written: the confirm is done (review of 3-4, L-1).
		c, err := o.claim(id)
		if err != nil {
			return
		}
		_ = o.removeIn(netplanRunDir, netplanName)
		_ = o.deletePending()
		o.note(api.CmdNetApply, "confirm_completed_at_start", map[string]any{"run_id": id})
		_ = c.Finish(api.StatusSucceeded, nil)
		return
	}
	switch {
	case st != pendOK || p.RunID != id:
		o.log.Error("net/pending.json is not the note the host wrote; the change is reverted", "run_id", id)
		o.revertWaiting(id, api.CodePendingInvalid, "The note about the unconfirmed change could not be trusted, so the previous network configuration was restored.")
	case p.BootID != boot && (overlay || boot == ""):
		// A different boot id does not prove a reboot: an overlay still in /run means the box has not
		// restarted (tmpfs), and an unreadable boot id says nothing. Either way the box may still be
		// running the unconfirmed configuration, so this is a full revert, never a silent clean-up.
		code := api.CodeNotConfirmed
		if boot != "" {
			code = api.CodePendingInvalid
		}
		o.log.Error("the note's boot id differs but the box did not demonstrably reboot; the change is reverted", "run_id", id)
		o.revertWaiting(id, code, "The box did not demonstrably restart, so the previous network configuration was restored.")
	case p.BootID != boot:
		// The box restarted inside the window: /run is empty, the old file on disk is what is running.
		c, err := o.claim(id)
		if err != nil {
			return
		}
		_ = o.removeIn(netplanRunDir, netplanName)
		_ = o.deletePending()
		_ = c.Finish(api.StatusReverted, &api.RunError{Code: api.CodeRevertedByReboot, Message: "The box restarted before the change was confirmed, so it came back on the previous network configuration."})
	default:
		// Monotonic time is gone after a restart: the 660 s bound is measured from the note's wall-clock start.
		left := min(p.RevertAt.Sub(o.d.Now()), p.StartedAt.Add(maxAwaitWindow).Sub(o.d.Now()))
		if left <= 0 {
			o.revertWaiting(id, api.CodeNotConfirmed, "The change was not confirmed in time, so the previous network configuration was restored.")
			return
		}
		o.armNetTimer(id, o.d.Now().Add(left))
	}
}

// maxAwaitWindow is the longest a stored revert_at may lie ahead (the server's own bound, spec 18).
const maxAwaitWindow = 660 * time.Second

// recoverOrphan handles a note or an overlay that no awaiting run owns (a crash while the change
// was starting or being confirmed). A change whose new file already reached /etc is finished (the
// overlay is dropped); anything else is reverted.
func (o *Ops) recoverOrphan(ctx context.Context, p netPending, st pendState, overlay bool) {
	rctx, cancel := context.WithTimeout(ctx, netRevertTimeout)
	defer cancel()
	etc, es := o.readNoFollowIn(netplanEtcDir, netplanName, maxNetplan)
	switch {
	case st == pendOK && es == fileOK && shaHex(etc) == p.NewSHA:
		_ = o.removeIn(netplanRunDir, netplanName)
		_ = o.deletePending()
		o.note(api.CmdNetApply, "confirm_completed_at_start", map[string]any{"run_id": p.RunID})
	case st == pendOK && !overlay && o.bootID() != "" && p.BootID != o.bootID():
		_ = o.deletePending() // the box restarted: nothing of the change is left to undo
		o.note(api.CmdNetApply, "pending_dropped_at_start", map[string]any{"run_id": p.RunID})
	default:
		o.log.WarnContext(ctx, "an unconfirmed network change has no run; reverting it")
		err := o.undoOverlay(rctx, nil)
		o.note(api.CmdNetApply, "reverted_at_start", map[string]any{"ok": err == nil})
		if err != nil {
			o.log.ErrorContext(ctx, "the revert at start failed; a reboot restores the saved configuration", "error", err.Error())
		}
	}
}

// confirmReachedEtc reports whether /etc/netplan/90-vedette.yaml is already the file of the note.
func (o *Ops) confirmReachedEtc(p netPending) bool {
	etc, es := o.readNoFollowIn(netplanEtcDir, netplanName, maxNetplan)
	return es == fileOK && shaHex(etc) == p.NewSHA
}
