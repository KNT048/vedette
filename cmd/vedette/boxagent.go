package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

// The osquery agent on the box itself (vedette-host box_agent.check, spec 6.19). Vedette's Linux install command can be run on the box
// like on any server; what it writes to /etc/osquery is not part of Vedette's package, so a reinstall or a data purge leaves it pinning the
// CA of the earlier install, and that agent then fails every few seconds against a box that no longer trusts it. At every start core
// gives the host the CA agents pin now; an agent on the box that pins another one and reports to this machine is stopped and its Vedette
// settings removed (the box reads its own packages without it). Running the install command on the box enrols it again.

// boxAgentHost is what the check needs of vedette-host.
type boxAgentHost interface {
	BoxAgentCheck(ctx context.Context, ca, requestID, actor string) (api.Run, error)
	GetRun(ctx context.Context, runID string) (api.Run, error)
}

const (
	boxAgentActor = "system"
	boxAgentWait  = 3 * time.Minute // a run longer than the command's own 2 minute bound has ended badly
	boxAgentRetry = 2 * time.Minute // the CA can be busy at the very first start (the leaf is being issued) and the host busy at a restart
	boxAgentTries = 5               // then the next start tries again
	boxAgentPoll  = 2 * time.Second // how often a run is looked at
)

// startBoxAgentCheck runs the check in the background once the services are built; it never delays or fails the start.
func startBoxAgentCheck(ctx context.Context, d deps) {
	if d.HostSocket == "" || d.TrustAnchor == nil {
		return // a container-only install has no host, and loopback serves no TLS: no agent can pin anything
	}
	go checkBoxAgent(ctx, d.Log, hostclient.New(d.HostSocket), d.TrustAnchor, func(ctx context.Context) {
		auditBoxAgentRemoved(ctx, d)
	}, func(ctx context.Context) bool { return sleepCtx(ctx, boxAgentRetry) })
}

// checkBoxAgent asks the host once the anchor can be read and the host takes the call, at most boxAgentTries times.
func checkBoxAgent(ctx context.Context, log *slog.Logger, h boxAgentHost, anchor func() ([]byte, error), removed func(context.Context), wait func(context.Context) bool) {
	for try := 1; ; try++ {
		state, again, err := boxAgentOnce(ctx, h, anchor)
		switch {
		case err == nil && state == api.BoxAgentRemoved:
			log.WarnContext(ctx, "the osquery agent on this box pinned the certificate authority of an earlier install (a reinstall or a data purge made a new one): it was stopped and its Vedette settings removed; to have it report again, run the install command from Devices › Setup › Agents on the box (the box reads its own packages without it)")
			removed(ctx)
			return
		case err == nil:
			log.DebugContext(ctx, "the osquery agent on this box was checked", "state", state)
			return
		case !again || try >= boxAgentTries:
			log.WarnContext(ctx, "the osquery agent on this box could not be checked against the box's certificate; the next start tries again", "error", err.Error())
			return
		}
		if !wait(ctx) {
			return
		}
	}
}

// boxAgentOnce is one call; again says whether a later try can do better (an anchor not ready, a busy or restarting host).
func boxAgentOnce(ctx context.Context, h boxAgentHost, anchor func() ([]byte, error)) (state string, again bool, err error) {
	ca, err := anchor()
	if err != nil {
		return "", true, err
	}
	if api.ParseAnchor(ca) == nil {
		return "", false, errors.New("the certificate agents pin is not PEM certificates")
	}
	id, err := newUUID()
	if err != nil {
		return "", false, err
	}
	run, err := h.BoxAgentCheck(ctx, string(ca), id, boxAgentActor)
	if err != nil {
		var he *hostclient.Error
		if errors.As(err, &he) && he.Code == api.CodeUnknownCommand {
			return api.BoxAgentNone, false, nil // a host older than the check: nothing to do until it is updated
		}
		return "", ctx.Err() == nil, err
	}
	end := time.Now().Add(boxAgentWait)
	for i := 0; !run.Status.Terminal(); i++ {
		if time.Now().After(end) {
			return "", true, errors.New("box_agent.check did not end in time")
		}
		if i > 0 && !sleepCtx(ctx, boxAgentPoll) { // the first look is at once: the check usually ends within milliseconds
			return "", false, ctx.Err()
		}
		if run, err = h.GetRun(ctx, run.RunID); err != nil {
			return "", ctx.Err() == nil, err
		}
	}
	if run.Status != api.StatusSucceeded {
		msg := string(run.Status)
		if run.Error != nil {
			msg = run.Error.Code + ": " + run.Error.Message
		}
		return "", false, errors.New("box_agent.check: " + msg)
	}
	res, err := hostclient.ResultOf[api.BoxAgentCheckResult](run)
	return res.State, false, err
}

// auditBoxAgentRemoved writes the audit row: the box stopped something a person had set up.
func auditBoxAgentRemoved(ctx context.Context, d deps) {
	if d.DB == nil || d.Audit == nil {
		return
	}
	err := d.DB.Write(ctx, func(tx *sql.Tx) error {
		return d.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "core.box_agent_removed", Target: "osqueryd",
			Detail: "pinned the certificate authority of an earlier install; stopped, disabled, Vedette settings removed"})
	})
	if err != nil {
		d.Log.ErrorContext(ctx, "auditing the removal of the box's own osquery agent failed", "error", err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
