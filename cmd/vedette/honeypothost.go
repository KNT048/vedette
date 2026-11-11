package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/honeypot"
)

// honeypotHost is honeypot.Host over vedette-host (D-161): decoy_ip.add/remove (host-api 6.6) and container.start/stop
// of the `honeypot` service (6.8, 6.9). Core never touches the OS itself (FORBID-3); this adapter only turns the module's
// five idempotent calls into host runs and waits for each run to end.
//
// Idempotency: the host's own answers already are (a decoy that is there is refused with duplicate_decoy, removing a
// missing one succeeds, start of a running container and stop of a stopped one succeed); the adapter reads
// duplicate_decoy as "already there". One request id covers the retries of one call after a busy host, so a call that the
// host did accept is never run twice.
type honeypotHost struct {
	api hostAPI
	log *slog.Logger
	// poll is the gap between looks at a run; busyFor bounds the wait for a host that is busy with another write or
	// rate-limits core; runFor bounds the wait for one accepted run. The module's loop asks again every 15 s, so a
	// call that gives up is retried, not lost.
	poll, busyFor, runFor time.Duration
}

// hostAPI is the part of *hostclient.Client the adapter uses; tests wrap the real client to make the host busy.
type hostAPI interface {
	Run(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error)
	GetRun(ctx context.Context, runID string) (api.Run, error)
	StateContainers(ctx context.Context) (api.ContainersState, error)
	StateNet(ctx context.Context) (api.NetState, error)
}

var _ hostAPI = (*hostclient.Client)(nil)

// hostActor is the audit label of every host call of the module: the run loop and the teardown act for the system
// (D-189), not for a user.
const hostActor = "system"

// newHoneypotHost is the Host of the honeypot: the adapter when core has a host socket, else notAnAppliance (dev and a
// bare box, D-55: nothing can listen and the module says so).
func newHoneypotHost(d *deps) honeypot.Host {
	if d.HostSocket == "" {
		return notAnAppliance{}
	}
	return &honeypotHost{api: hostclient.New(d.HostSocket), log: d.Log, poll: 100 * time.Millisecond, busyFor: 90 * time.Second, runFor: 5 * time.Minute}
}

// Status reads the container state of `honeypot`. A host that cannot be reached, a box without a host socket file, and a
// box where the container is not installed are Available=false with a reason; any other failure of the host is an error.
func (h *honeypotHost) Status(ctx context.Context) (honeypot.HostStatus, error) {
	st, err := h.api.StateContainers(ctx)
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return honeypot.HostStatus{}, ctx.Err()
	case errors.Is(err, hostclient.ErrUnreachable) && errors.Is(err, fs.ErrNotExist):
		return honeypot.HostStatus{Reason: notApplianceReason}, nil
	case errors.Is(err, hostclient.ErrUnreachable), errors.Is(err, hostclient.ErrDenied):
		h.log.WarnContext(ctx, "honeypot: vedette-host is not answering", "error", err)
		return honeypot.HostStatus{Reason: "vedette-host is not answering"}, nil
	default:
		return honeypot.HostStatus{}, fmt.Errorf("honeypot: host state: %w", err)
	}
	for _, s := range st.Services {
		if s.Service != api.ServiceHoneypot {
			continue
		}
		if !s.Installed {
			break
		}
		return honeypot.HostStatus{Available: true, Running: s.UnitState == api.UnitActive}, nil
	}
	return honeypot.HostStatus{Reason: "the honeypot container is not installed on this box"}, nil
}

func (h *honeypotHost) AddDecoyIP(ctx context.Context, ip netip.Addr) error {
	// The module asks for every wanted address at every Apply and the host takes 10 writes a minute (6.6): an address
	// the host already holds costs no write. A failed read only costs the write (duplicate_decoy is success too).
	if ns, err := h.api.StateNet(ctx); err == nil {
		for _, d := range ns.Decoys {
			if a, err := netip.ParseAddr(d.IP); err == nil && a == ip {
				return nil
			}
		}
	}
	// No OUI: the host gives the decoy a locally administered MAC derived from its own key (6.6).
	err := h.do(ctx, api.CmdDecoyAdd, api.DecoyAddArgs{IP: ip.String()}, api.CodeDuplicateDecoy)
	if err != nil {
		return fmt.Errorf("honeypot: decoy address %s: %w", ip, err)
	}
	return nil
}

func (h *honeypotHost) RemoveDecoyIP(ctx context.Context, ip netip.Addr) error {
	// An address the host does not hold answers removed=false: that is success.
	if err := h.do(ctx, api.CmdDecoyRemove, api.DecoyRemoveArgs{IP: ip.String()}, ""); err != nil {
		return fmt.Errorf("honeypot: remove decoy address %s: %w", ip, err)
	}
	return nil
}

// StartContainer is container.start of the current image (no version); restart makes a container that runs read the new
// configuration, otherwise a running one is left alone.
func (h *honeypotHost) StartContainer(ctx context.Context, restart bool) error {
	return h.do(ctx, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot, Restart: restart}, "")
}

// StopContainer persists the stop (the unit loses its [Install] section): it is only asked when the module is off or no
// trap is on, and a reboot must not bring the traps back.
func (h *honeypotHost) StopContainer(ctx context.Context) error {
	return h.do(ctx, api.CmdContainerStop, api.ContainerStopArgs{Service: api.ServiceHoneypot, Persist: true}, "")
}

// do sends one command, waits for its run and maps a refusal to a plain error. ok is a refusal code that counts as success.
func (h *honeypotHost) do(ctx context.Context, command string, args any, ok string) error {
	run, err := h.call(ctx, command, args)
	var he *hostclient.Error
	switch {
	case errors.As(err, &he):
		if ok != "" && he.Code == ok {
			return nil
		}
		return h.refusal(ctx, command, he.Code, he.Message)
	case err != nil:
		return err
	case run.Status == api.StatusSucceeded:
		return nil
	case run.Error != nil:
		if ok != "" && run.Error.Code == ok {
			return nil
		}
		return h.refusal(ctx, command, run.Error.Code, run.Error.Message)
	}
	return h.refusal(ctx, command, api.CodeCommandFailed, "run ended "+string(run.Status))
}

var (
	errHostBusy    = errors.New("the host is busy with another operation; will try again")
	errHostTooLong = errors.New("the host did not finish in time; will try again")
)

// call sends the command (under one request id; a busy or rate-limiting host is waited for up to busyFor) and follows
// the accepted run to its end (up to runFor). A host Error (a refusal before any run) is returned as is.
func (h *honeypotHost) call(ctx context.Context, command string, args any) (api.Run, error) {
	id, err := newUUID()
	if err != nil {
		return api.Run{}, err
	}
	busyUntil := time.Now().Add(h.busyFor)
	var run api.Run
	for {
		run, err = h.api.Run(ctx, command, args, id, hostActor)
		var he *hostclient.Error
		if !errors.As(err, &he) || (he.Code != api.CodeBusy && he.Code != api.CodeRateLimited) {
			break
		}
		wait := h.poll
		if he.Code == api.CodeRateLimited && he.RetryAfterS > 0 {
			wait = time.Duration(he.RetryAfterS) * time.Second
		}
		if !time.Now().Add(wait).Before(busyUntil) {
			return api.Run{}, errHostBusy
		}
		select {
		case <-ctx.Done():
			return api.Run{}, ctx.Err()
		case <-time.After(wait):
		}
	}
	if err != nil {
		return api.Run{}, err
	}
	wctx, cancel := context.WithTimeout(ctx, h.runFor)
	defer cancel()
	for !run.Status.Terminal() {
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return api.Run{}, ctx.Err()
			}
			return api.Run{}, errHostTooLong
		case <-time.After(h.poll):
		}
		if run, err = h.api.GetRun(wctx, run.RunID); err != nil {
			if ctx.Err() == nil && wctx.Err() != nil {
				return api.Run{}, errHostTooLong
			}
			return api.Run{}, err
		}
	}
	return run, nil
}

// refusal logs what the host said (its text is not for the user) and returns a plain sentence with the code: the module
// shows the text beside the address it could not place.
func (h *honeypotHost) refusal(ctx context.Context, command, code, hostMsg string) error {
	h.log.WarnContext(ctx, "honeypot: vedette-host refused or failed a command", "command", command, "code", code, "message", hostMsg)
	what := "the host could not do it"
	switch code {
	case api.CodeIPNotInMgmtSubnet:
		what = "the address is outside the network the box is on"
	case api.CodeIPIsGateway, api.CodeIPIsHost, api.CodeIPIsNetwork, api.CodeIPIsBroadcast:
		what = "the address belongs to the gateway, the box or the network itself"
	case api.CodeIPInUse:
		what = "another device already answers on this address"
	case api.CodeLimitReached:
		what = "the host holds the most decoy addresses it allows"
	case api.CodeUnitUnknown, api.CodeNotPulled:
		what = "the honeypot container is not installed on this box"
	case api.CodeUnitUnsafe:
		what = "the honeypot container's unit is missing or not one the host trusts"
	case api.CodeNotAppliance:
		what = notApplianceReason
	case api.CodeShuttingDown:
		what = "the host is restarting; will try again"
	}
	return fmt.Errorf("%s (%s)", what, code)
}

// newUUID returns a UUID v4: the idempotency key of one host call (host-api 5).
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("honeypot: request id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
