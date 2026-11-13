package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
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
	decoys    map[netip.Addr]heldDecoy // what the last state/net read listed; nil = read again
	parent    string                   // the management card of that read: the decoys' macvlan links hang off it
	lastWarns map[string]time.Time
	// infoAt and setPorts: whether the host lists decoy_ip.set_ports (GET /v1/info, read once per infoTTL): only then does
	// core send ports (host-api 6.6 compatibility, D-466).
	infoAt   time.Time
	setPorts bool
	infoRead bool // an answer of GET /v1/info was read once in this process
}

// heldDecoy is one decoy as state/net lists it: its MAC (lower case) and allow-list (nil = none).
type heldDecoy struct {
	mac   string
	ports *[]api.DecoyPort
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
	Info(ctx context.Context) (api.Info, error)
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
	// infoTTL is how long the host's command list stays valid: it changes only when vedette-host is updated.
	infoTTL = 5 * time.Minute
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

// AddDecoyIP makes the host hold ip as spec says, sending only what differs from state/net (the module asks for every
// wanted address at every Apply and the host takes 10 writes a minute, 6.6): an address that is not there is added with the
// vendor's OUI and its ports; one whose MAC does not carry the wanted prefix is removed and added again (the host refuses a
// second add of the same address, duplicate_decoy); one whose ports differ gets decoy_ip.set_ports. Ports go only to a host
// that lists decoy_ip.set_ports (KeepsPorts); an older host refuses the field, and its addresses answer every service.
// A failed state/net read only costs a write (duplicate_decoy is success too).
func (h *honeypotHost) AddDecoyIP(ctx context.Context, ip netip.Addr, spec honeypot.DecoySpec) error {
	keeps, known := h.keepsPorts(ctx)
	var want *[]api.DecoyPort
	if keeps {
		p := apiPorts(spec.Ports)
		want = &p
	}
	cur, held := h.held(ctx, ip)
	if held && !macHasPrefix(cur.mac, spec.OUI) {
		if err := h.RemoveDecoyIP(ctx, ip); err != nil {
			return err
		}
		held = false
	}
	if held {
		if !known || !keeps || samePorts(cur.ports, want) { // ports unknown: leave the address as it is until they are
			return nil
		}
		err := h.do(ctx, api.CmdDecoySetPorts, api.DecoySetPortsArgs{IP: ip.String(), Ports: *want}, "")
		var re refusedError
		if errors.As(err, &re) && re.code == api.CodeNotADecoy { // gone since the read: add it
			h.forgetDecoys()
		} else if err != nil {
			h.forgetDecoys()
			return fmt.Errorf("honeypot: ports of decoy address %s: %w", ip, err)
		} else {
			h.noteDecoy(ip, &heldDecoy{mac: cur.mac, ports: want})
			return nil
		}
	}
	if !known {
		// Never add an address without its ports because the host's command list could not be read yet: it would
		// answer every running service until the next Apply (B2 review). Unknown outcome, asked again next Apply.
		return fmt.Errorf("honeypot: decoy address %s: %w", ip, errNoCommandList)
	}
	err := h.do(ctx, api.CmdDecoyAdd, api.DecoyAddArgs{IP: ip.String(), OUI: spec.OUI, Ports: want}, api.CodeDuplicateDecoy)
	if err != nil {
		h.forgetDecoys()
		return fmt.Errorf("honeypot: decoy address %s: %w", ip, err)
	}
	h.forgetDecoys() // the next look (DecoyLinks at the end of this Apply) reads the MAC the host gave it
	return nil
}

// KeepsPorts says whether the host keeps each decoy address to its own ports (it lists decoy_ip.set_ports, host-api 6.6);
// the module tells the owner when it does not. A host whose info was never read is taken not to here (only the note);
// AddDecoyIP adds nothing until it is read.
func (h *honeypotHost) KeepsPorts(ctx context.Context) bool {
	keeps, _ := h.keepsPorts(ctx)
	return keeps
}

// errNoCommandList: the host's command list (GET /v1/info) has not been read yet, so whether it takes ports is unknown.
var errNoCommandList = errors.New("the host's command list could not be read yet; will try again at the next apply")

// keepsPorts is KeepsPorts with known: false while GET /v1/info was never read (a later failure keeps the last answer).
func (h *honeypotHost) keepsPorts(ctx context.Context) (keeps, known bool) {
	h.mu.Lock()
	if !h.infoAt.IsZero() && time.Since(h.infoAt) < infoTTL {
		defer h.mu.Unlock()
		return h.setPorts, true
	}
	h.mu.Unlock()
	info, err := h.api.Info(ctx)
	if err != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.setPorts, h.infoRead // the last answer stands until one is read
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.setPorts, h.infoAt, h.infoRead = slices.Contains(info.Commands, api.CmdDecoySetPorts), time.Now(), true
	return h.setPorts, true
}

// apiPorts is the allow-list of a spec in the host's order (protocol, then port), never nil: an empty list closes every port.
func apiPorts(l []honeypot.Port) []api.DecoyPort {
	out := make([]api.DecoyPort, 0, len(l))
	for _, p := range l {
		if dp := (api.DecoyPort{Proto: p.Proto, Port: p.Port}); !slices.Contains(out, dp) {
			out = append(out, dp)
		}
	}
	slices.SortFunc(out, func(a, b api.DecoyPort) int {
		if a.Proto != b.Proto {
			return strings.Compare(a.Proto, b.Proto)
		}
		return a.Port - b.Port
	})
	return out
}

// samePorts compares an allow-list the host holds with the wanted one (both sorted; nil = no allow-list).
func samePorts(have, want *[]api.DecoyPort) bool {
	if have == nil || want == nil {
		return have == want
	}
	return slices.Equal(apiPorts(toSpecPorts(*have)), *want)
}

func toSpecPorts(l []api.DecoyPort) []honeypot.Port {
	out := make([]honeypot.Port, len(l))
	for i, p := range l {
		out[i] = honeypot.Port{Proto: p.Proto, Port: p.Port}
	}
	return out
}

// macHasPrefix says whether the MAC the host gave a decoy is what the wanted OUI asks for: the vendor's six hex digits, or
// with no OUI a locally administered MAC (the host's default). An unknown MAC is taken to match: no write on a guess.
func macHasPrefix(mac, ouiHex string) bool {
	hexOnly := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	if len(hexOnly) != 12 {
		return true
	}
	if ouiHex != "" {
		return hexOnly[:6] == strings.ToLower(ouiHex)
	}
	b, err := strconv.ParseUint(hexOnly[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

func (h *honeypotHost) RemoveDecoyIP(ctx context.Context, ip netip.Addr) error {
	// An address the host does not hold answers removed=false: that is success.
	if err := h.do(ctx, api.CmdDecoyRemove, api.DecoyRemoveArgs{IP: ip.String()}, ""); err != nil {
		h.forgetDecoys()
		return fmt.Errorf("honeypot: remove decoy address %s: %w", ip, err)
	}
	h.noteDecoy(ip, nil)
	return nil
}

// held is what the host lists for ip among its decoys (GET /v1/state/net, read once per stateTTL); ok is false when it
// does not list it or the read failed.
func (h *honeypotHost) held(ctx context.Context, ip netip.Addr) (heldDecoy, bool) {
	h.refresh(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	d, ok := h.decoys[ip]
	return d, ok
}

// refresh reads state/net when the last read is older than stateTTL or was dropped.
func (h *honeypotHost) refresh(ctx context.Context) {
	h.mu.Lock()
	fresh := h.decoys != nil && time.Since(h.decoyAt) < stateTTL
	h.mu.Unlock()
	if fresh {
		return
	}
	ns, err := h.api.StateNet(ctx)
	if err != nil {
		return
	}
	set := map[netip.Addr]heldDecoy{}
	for _, d := range ns.Decoys {
		if a, err := netip.ParseAddr(d.IP); err == nil {
			set[a] = heldDecoy{mac: strings.ToLower(d.MAC), ports: d.Ports}
		}
	}
	parent := ""
	if ns.Config.Mgmt != nil {
		parent = ns.Config.Mgmt.Iface
	}
	for _, c := range ns.Interfaces {
		if parent == "" && c.Role == api.NetRoleManagement {
			parent = c.Name
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.decoys, h.parent, h.decoyAt = set, parent, time.Now()
}

// DecoyLinks is how the host holds each decoy address (the optional honeypot.linkReporter), from the same state/net read
// as held: its MAC, its macvlan link (host-api 6.6 names it vdh + the eight hex digits of the address) and the management
// card it hangs off; a decoy added since that read is missing until the next one (at most stateTTL later).
func (h *honeypotHost) DecoyLinks(ctx context.Context) map[netip.Addr]honeypot.DecoyLink {
	h.refresh(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[netip.Addr]honeypot.DecoyLink, len(h.decoys))
	for ip, d := range h.decoys {
		b := ip.As4()
		out[ip] = honeypot.DecoyLink{MAC: d.mac, Link: fmt.Sprintf("vdh%02x%02x%02x%02x", b[0], b[1], b[2], b[3]), Parent: h.parent}
	}
	return out
}

// noteDecoy updates the last read after a write the host confirmed: d nil = the address is gone.
func (h *honeypotHost) noteDecoy(ip netip.Addr, d *heldDecoy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.decoys == nil {
		return
	}
	if d == nil {
		delete(h.decoys, ip)
		return
	}
	h.decoys[ip] = *d
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
