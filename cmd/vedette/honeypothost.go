package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/honeypot"
)

// honeypotHost is honeypot.Host over vedette-host (D-161): decoy_ip.add/remove (host-api 6.6) and container.start/stop
// of the `honeypot` service (6.8, 6.9). Core never touches the OS itself (FORBID-3); this adapter only turns the module's
// five idempotent calls into host runs and waits for each run to end.
//
// The host is shared with the rest of core (OS updates, the network page): it allows 60 requests and 10 writes a minute
// for all of core and one write at a time, so the adapter is frugal. A run is followed over its event stream (as core's
// waitRunTo does), never polled fast; a busy or rate-limiting host is not waited for (the module asks again at its next
// Apply, a minute later); the decoys and the container state are read once and remembered for a few seconds, and a
// container that runs is not started again.
//
// Outcomes: a refusal of the host (a 4xx answer, a run that ended failed or refused) wraps honeypot.ErrRefused: the host
// definitely did not take it. Anything else (busy, a lost answer, a timeout, a 429 on a read) is an unknown outcome: the
// host may have done it, so the module keeps what it handed over on record and the teardown removes it (SYS-5).
//
// Idempotency: the host's own answers already are (a decoy that is there is refused with duplicate_decoy, removing a
// missing one succeeds, start of a running container and stop of a stopped one succeed); the adapter reads
// duplicate_decoy as "already there". One request id covers one call, so an answer lost on the way is never run twice.
type honeypotHost struct {
	api hostAPI
	log *slog.Logger
	// who names the service in logs and errors; empty = "honeypot". The sensor and scan followers (modulecontainer.go) reuse this adapter's
	// host calls, each with its own instance, so their warnings carry their own name and are rate-limited apart.
	who string
	// poll is the gap between looks at a run that is still going after its event stream ended (at least a second on a
	// real host); runFor bounds the wait for one accepted run.
	poll, runFor time.Duration

	mu     sync.Mutex
	status stateAt // the container state the last Status read
	// stopped: a persisted container.stop succeeded in this process and nothing was started since; with a fresh Status
	// that saw the container not running, the next stop costs no write (it starts false, so the first Apply still stops).
	stopped   bool
	decoyAt   time.Time
	decoys    map[netip.Addr]bool
	macs      map[netip.Addr]string // the MAC of each decoy of the last state/net read, lower case
	lastWarns map[string]time.Time
}

type stateAt struct {
	at      time.Time
	running bool
	down    bool // the unit is inactive or failed: only then may a stop be skipped (an `other`/`unknown` unit may be coming up)
}

// hostAPI is the part of *hostclient.Client the adapter uses; tests wrap the real client to break it.
type hostAPI interface {
	Run(ctx context.Context, command string, args any, requestID, actor string) (api.Run, error)
	GetRun(ctx context.Context, runID string) (api.Run, error)
	Events(ctx context.Context, runID string, after uint64) *hostclient.Stream
	StateContainers(ctx context.Context) (api.ContainersState, error)
	StateNet(ctx context.Context) (api.NetState, error)
}

var _ hostAPI = (*hostclient.Client)(nil)

const (
	// hostActor is the audit label of every host call of the module: the run loop and the teardown act for the system
	// (D-189), not for a user.
	hostActor = "system"
	// stateTTL is how long the container state and the decoy list stay valid: one Apply (an address can take 4 s to
	// probe) reads each once; the next Apply, a minute later, reads again.
	stateTTL = 20 * time.Second
	// hostWarnEvery rate-limits the adapter's own warnings, as the module does for its own (ingest.go warnEvery).
	hostWarnEvery = time.Minute
)

// newHoneypotHost is the Host of the honeypot: the adapter when core has a host socket, else notAnAppliance (dev and a
// bare box, D-55: nothing can listen and the module says so).
func newHoneypotHost(d *deps) honeypot.Host {
	if d.HostSocket == "" {
		return notAnAppliance{}
	}
	return &honeypotHost{api: hostclient.New(d.HostSocket), log: d.Log, poll: 2 * time.Second, runFor: 5 * time.Minute}
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
		if h.warnDue("answering") {
			h.log.WarnContext(ctx, "honeypot: vedette-host is not answering", "error", err)
		}
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
		running := s.UnitState == api.UnitActive
		h.mu.Lock()
		h.status = stateAt{at: time.Now(), running: running, down: s.UnitState == api.UnitInactive || s.UnitState == api.UnitFailed}
		h.mu.Unlock()
		return honeypot.HostStatus{Available: true, Running: running}, nil
	}
	h.setRunning(false)
	return honeypot.HostStatus{Reason: "the honeypot container is not installed on this box"}, nil
}

func (h *honeypotHost) setRunning(running bool) {
	h.mu.Lock()
	h.status = stateAt{at: time.Now(), running: running}
	h.mu.Unlock()
}

func (h *honeypotHost) AddDecoyIP(ctx context.Context, ip netip.Addr) error {
	// The module asks for every wanted address at every Apply and the host takes 10 writes a minute (6.6): an address
	// the host already holds costs no write. A failed read only costs the write (duplicate_decoy is success too).
	if h.holds(ctx, ip) {
		return nil
	}
	// No OUI: the host gives the decoy a locally administered MAC derived from its own key (6.6).
	err := h.do(ctx, api.CmdDecoyAdd, api.DecoyAddArgs{IP: ip.String()}, api.CodeDuplicateDecoy)
	if err != nil {
		h.forgetDecoys()
		return fmt.Errorf("honeypot: decoy address %s: %w", ip, err)
	}
	h.noteDecoy(ip, true)
	return nil
}

func (h *honeypotHost) RemoveDecoyIP(ctx context.Context, ip netip.Addr) error {
	// An address the host does not hold answers removed=false: that is success.
	if err := h.do(ctx, api.CmdDecoyRemove, api.DecoyRemoveArgs{IP: ip.String()}, ""); err != nil {
		h.forgetDecoys()
		return fmt.Errorf("honeypot: remove decoy address %s: %w", ip, err)
	}
	h.noteDecoy(ip, false)
	return nil
}

// holds reports whether the host lists ip among its decoys (GET /v1/state/net, read once per stateTTL).
func (h *honeypotHost) holds(ctx context.Context, ip netip.Addr) bool {
	h.mu.Lock()
	if h.decoys != nil && time.Since(h.decoyAt) < stateTTL {
		defer h.mu.Unlock()
		return h.decoys[ip]
	}
	h.mu.Unlock()
	ns, err := h.api.StateNet(ctx)
	if err != nil {
		return false
	}
	set := map[netip.Addr]bool{}
	macs := map[netip.Addr]string{}
	for _, d := range ns.Decoys {
		if a, err := netip.ParseAddr(d.IP); err == nil {
			set[a] = true
			macs[a] = strings.ToLower(d.MAC)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.decoys, h.macs, h.decoyAt = set, macs, time.Now()
	return set[ip]
}

// DecoyMACs is the MAC the host gave each decoy address (the optional honeypot.macReporter), from the same state/net read
// as holds; a decoy added since that read has none until the next one (at most stateTTL later).
func (h *honeypotHost) DecoyMACs(ctx context.Context) map[netip.Addr]string {
	h.holds(ctx, netip.Addr{}) // refresh when older than stateTTL
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.macs)
}

func (h *honeypotHost) noteDecoy(ip netip.Addr, held bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.decoys != nil {
		h.decoys[ip] = held
	}
}

func (h *honeypotHost) forgetDecoys() {
	h.mu.Lock()
	h.decoys = nil
	h.mu.Unlock()
}

// StartContainer is container.start of the current image (no version); restart makes a container that runs read the new
// configuration. Without restart, a container the last Status saw running is left alone: no write is spent on it.
func (h *honeypotHost) StartContainer(ctx context.Context, restart bool) error {
	h.mu.Lock()
	skip := !restart && h.status.running && time.Since(h.status.at) < stateTTL
	if !skip {
		h.stopped = false
	}
	h.mu.Unlock()
	if skip {
		return nil
	}
	if err := h.do(ctx, api.CmdContainerStart, api.ContainerStartArgs{Service: api.ServiceHoneypot, Restart: restart}, ""); err != nil {
		h.setStale()
		return err
	}
	h.setRunning(true)
	return nil
}

// StopContainer persists the stop (the unit loses its [Install] section): it is only asked when the module is off or no
// trap is on, and a reboot must not bring the traps back.
// A stop already done in this process, with a fresh Status that saw the container not running, costs no write: a module
// on with no trap, or with every address refused, asks for the stop at every Apply.
func (h *honeypotHost) StopContainer(ctx context.Context) error {
	h.mu.Lock()
	skip := h.stopped && h.status.down && time.Since(h.status.at) < stateTTL
	h.mu.Unlock()
	if skip {
		return nil
	}
	if err := h.do(ctx, api.CmdContainerStop, api.ContainerStopArgs{Service: api.ServiceHoneypot, Persist: true}, ""); err != nil {
		h.mu.Lock()
		h.stopped = false
		h.mu.Unlock()
		h.setStale()
		return err
	}
	h.mu.Lock()
	h.status = stateAt{at: time.Now(), down: true}
	h.stopped = true
	h.mu.Unlock()
	return nil
}

func (h *honeypotHost) name() string {
	if h.who == "" {
		return "honeypot"
	}
	return h.who
}

func (h *honeypotHost) setStale() {
	h.mu.Lock()
	h.status = stateAt{}
	h.mu.Unlock()
}

// do sends one command, waits for its run and maps the outcome. ok is a refusal code that counts as success.
func (h *honeypotHost) do(ctx context.Context, command string, args any, ok string) error {
	run, err := h.call(ctx, command, args)
	var he *hostclient.Error
	switch {
	case errors.As(err, &he):
		if ok != "" && he.Code == ok {
			return nil
		}
		return h.outcome(ctx, command, he.Code, he.Message)
	case err != nil:
		return err // unknown outcome
	case run.Status == api.StatusSucceeded:
		return nil
	case run.Error != nil:
		if ok != "" && run.Error.Code == ok {
			return nil
		}
		return h.outcome(ctx, command, run.Error.Code, run.Error.Message)
	}
	if h.warnDue(command + " ended") {
		h.log.WarnContext(ctx, "container host: a host run ended without a result", "service", h.name(), "command", command, "status", string(run.Status))
	}
	return fmt.Errorf("%s: %s ended %s with no result; outcome unknown, will check again at the next apply", h.name(), command, run.Status)
}

// outcome sorts a code of the host. A run that was cut off (the host restarted or is stopping, a timeout, a failure of
// the host itself) may have done its work, so it is an unknown outcome, never a refusal: a refusal drops the address from
// the record and a decoy the host re-creates at start would then outlive the teardown (SYS-5). A host busy with a network
// change or an install is errHostBusy. Everything else is the host saying no.
func (h *honeypotHost) outcome(ctx context.Context, command, code, hostMsg string) error {
	switch code {
	case api.CodeHostRestarted, api.CodeShuttingDown, api.CodeTimeout, api.CodeCommandFailed, api.CodeInternal:
		if h.warnDue(command + " " + code) {
			h.log.WarnContext(ctx, "container host: a host run was cut off; outcome unknown", "service", h.name(), "command", command, "code", code, "message", hostMsg)
		}
		return fmt.Errorf("%s: %s was cut off (%s); outcome unknown, will check again at the next apply", h.name(), command, code)
	case api.CodePendingConfirm, api.CodeNetPendingConfirm, api.CodeInstallInProgress:
		return errHostBusy
	}
	return h.refusal(ctx, command, code, hostMsg)
}

var (
	errHostBusy    = errors.New("the host is busy with another operation or rate-limiting core; will try again at the next apply")
	errHostTooLong = errors.New("the host did not finish in time; outcome unknown, will check again at the next apply")
)

// call sends the command and follows the accepted run to its end (up to runFor). A busy or rate-limiting host is
// errHostBusy at once. A refusal before any run (a 4xx) is returned as a *hostclient.Error; every other error is an
// unknown outcome.
func (h *honeypotHost) call(ctx context.Context, command string, args any) (api.Run, error) {
	id, err := newUUID()
	if err != nil {
		return api.Run{}, err
	}
	run, err := h.api.Run(ctx, command, args, id, hostActor)
	var he *hostclient.Error
	if errors.As(err, &he) {
		switch {
		case he.Code == api.CodeBusy || he.Code == api.CodeRateLimited:
			return api.Run{}, errHostBusy
		case he.Status >= http.StatusInternalServerError:
			return api.Run{}, fmt.Errorf("the host failed to answer (%s), outcome unknown: %v", he.Code, err) //nolint:errorlint // %v: this is not a refusal, the caller must not find the *hostclient.Error in it
		}
		return api.Run{}, err // a refusal
	}
	if err != nil {
		if ctx.Err() != nil {
			return api.Run{}, ctx.Err()
		}
		return api.Run{}, fmt.Errorf("the host could not be asked, outcome unknown: %v", err) //nolint:errorlint // %v, as above
	}
	return h.follow(ctx, run)
}

// follow reads the events of the run until its stream ends, then looks at the stored run (the stream can end first, as
// core's waitRunTo notes); a run still going is looked at again after poll. It costs the host two reads per run.
func (h *honeypotHost) follow(ctx context.Context, run api.Run) (api.Run, error) {
	wctx, cancel := context.WithTimeout(ctx, h.runFor)
	defer cancel()
	unknown := func(err error) (api.Run, error) {
		switch {
		case ctx.Err() != nil:
			return api.Run{}, ctx.Err()
		case wctx.Err() != nil:
			return api.Run{}, errHostTooLong
		}
		return api.Run{}, fmt.Errorf("the host's answer was lost, outcome unknown: %v", err) //nolint:errorlint // %v, as above; a 429 on a read lands here too
	}
	for !run.Status.Terminal() {
		st := h.api.Events(wctx, run.RunID, 0)
		for {
			if _, err := st.Next(); err != nil {
				st.Close()
				if errors.Is(err, io.EOF) {
					break
				}
				return unknown(err)
			}
		}
		var err error
		if run, err = h.api.GetRun(wctx, run.RunID); err != nil {
			return unknown(err)
		}
		if run.Status.Terminal() {
			break
		}
		select {
		case <-wctx.Done():
			return unknown(wctx.Err())
		case <-time.After(h.poll):
		}
	}
	return run, nil
}

// refusedError is a refusal of the host: the module's ErrRefused, with a plain sentence for the user. hostFault: the
// refusal is not about the address (the host could not set it up), so it is also the module's ErrHostFailed (#475).
type refusedError struct {
	what, code string
	hostFault  bool
}

func (e refusedError) Error() string { return e.what + " (" + e.code + ")" }

// UserReason is the plain sentence without the code: what the module shows beside the address (honeypot.userReason).
func (e refusedError) UserReason() string { return e.what }
func (e refusedError) Is(target error) bool {
	return target == honeypot.ErrRefused || e.hostFault && target == honeypot.ErrHostFailed
}

// refusal logs what the host said (its text is not for the user) and returns a plain sentence with the code: the module
// shows the text beside the address it could not place.
func (h *honeypotHost) refusal(ctx context.Context, command, code, hostMsg string) error {
	if h.warnDue(command + " " + code) {
		h.log.WarnContext(ctx, "container host: vedette-host refused or failed a command", "service", h.name(), "command", command, "code", code, "message", hostMsg)
	}
	what := "the host could not do it"
	switch code {
	case api.CodeIPNotInMgmtSubnet:
		what = "the address is outside the network the box is on"
	case api.CodeIPIsGateway, api.CodeIPIsHost, api.CodeIPIsNetwork, api.CodeIPIsBroadcast:
		what = "the address belongs to the gateway, the box or the network itself"
	case api.CodeIPInUse:
		what = "another device already answers on this address"
	case api.CodeMACInUse:
		what = "the MAC address this address would get is already another decoy's"
	case api.CodeLimitReached:
		what = "the host holds the most decoy addresses it allows"
	case api.CodeUnitUnknown, api.CodeNotPulled:
		what = "the " + h.name() + " container is not installed on this box"
	case api.CodeUnitUnsafe:
		what = "the " + h.name() + " container's unit is missing or not one the host trusts"
	case api.CodeNotAppliance:
		what = notApplianceReason
	}
	return refusedError{what: what, code: code, hostFault: !slices.Contains(addressRefusals, code)}
}

// addressRefusals are the codes of decoy_ip.add that are about the address itself; the module shows them as a conflict.
// Any other code (decoy_failed, a namespace or state of the host that is not usable, a failed ARP probe, an unknown code)
// is the host failing, and no conflict (#475).
var addressRefusals = []string{api.CodeIPNotInMgmtSubnet, api.CodeIPIsGateway, api.CodeIPIsHost, api.CodeIPIsNetwork,
	api.CodeIPIsBroadcast, api.CodeIPInUse, api.CodeMACInUse, api.CodeLimitReached}

// warnDue says whether a warning for key may be logged now: at most once per hostWarnEvery for a key: a loop that fails the same way every minute must not fill the log.
func (h *honeypotHost) warnDue(key string) bool {
	h.mu.Lock()
	if h.lastWarns == nil {
		h.lastWarns = map[string]time.Time{}
	}
	last, seen := h.lastWarns[key]
	due := !seen || time.Since(last) >= hostWarnEvery
	if due {
		h.lastWarns[key] = time.Now()
	}
	h.mu.Unlock()
	return due
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
