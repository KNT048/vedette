package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// container.start (the current image: no version yet) and container.stop (spec 6.8, 6.9, D-105,
// D-123), and the journal of the unit changes they make.
//
// A unit change is: journal it (containers/transition.json), write the unit (D-105 (2): units.go),
// systemctl daemon-reload, then restart or stop, then look at the effect: the container reports
// the right image digest and "healthy" (Podman 4.9 has no Notify=healthy, so the host asks again and
// again for up to 120 s), or systemctl is-active prints "inactive". A start that does not get
// healthy puts the old unit back and restarts it (reverted, unit_failed). A host that dies in
// the middle finds the journal at Start and puts the old unit back unless the new one is healthy.

const (
	maxInspectOutput = 1 << 20
	reloadLimit      = 30 * time.Second
	restartLimit     = 60 * time.Second
	stopLimit        = 60 * time.Second
	probeLimit       = 20 * time.Second
	// stopVerifyWait bounds the look for "inactive" after a stop.
	stopVerifyWait = 20 * time.Second
	// revertLimit bounds putting the old unit back; it runs on a context that outlives the run's own
	// (a run that timed out must still undo what it did).
	revertLimit = 90 * time.Second
	// recoverLimit bounds recoverTransition at Start (a term of the TimeoutStartSec sum, D-121 (6), D-123).
	recoverLimit      = 60 * time.Second
	recoverHealthWait = 30 * time.Second
)

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]{1,32})?(\+[0-9A-Za-z.-]{1,32})?$`)

// serviceArg checks a service name against the closed list.
func serviceArg(s string) error {
	if !slices.Contains(api.Services, s) {
		return server.Invalid("service", "must be one of core, sensor, honeypot, scan, greenbone")
	}
	return nil
}

func (o *Ops) cmdContainerStart() server.Command {
	return server.Define(server.Spec[api.ContainerStartArgs]{
		// Spec 10 says 3 minutes; a start that waits up to 120 s for health, then puts the old unit back,
		// cannot fit in it (D-123 (6)).
		Name: api.CmdContainerStart, Write: true, Timeout: 5 * time.Minute,
		Validate: func(a *api.ContainerStartArgs) error {
			if err := serviceArg(a.Service); err != nil {
				return err
			}
			if a.Version != "" && (len(a.Version) > 64 || !semverRE.MatchString(a.Version)) {
				return server.Invalid("version", "must be a semantic version")
			}
			switch {
			case a.Snapshot != "" && !hexIDRE.MatchString(a.Snapshot):
				return server.Invalid("snapshot", "must be 32 lowercase hex characters")
			case a.Snapshot != "" && a.Service != api.ServiceCore:
				return server.Invalid("snapshot", "only core takes a snapshot")
			case a.Service == api.ServiceCore && a.Version != "" && a.Snapshot == "":
				return server.Invalid("snapshot", "core needs a snapshot when the version changes")
			}
			return nil
		},
		Check: o.checkContainerStart,
		Run:   o.runContainerStart,
	})
}

func (o *Ops) cmdContainerStop() server.Command {
	return server.Define(server.Spec[api.ContainerStopArgs]{
		Name: api.CmdContainerStop, Write: true, Timeout: 2 * time.Minute,
		Validate: func(a *api.ContainerStopArgs) error { return serviceArg(a.Service) },
		Check:    o.checkContainerStop,
		Run:      o.runContainerStop,
	})
}

// fillFor is the unit fill-in for a digest, with the host.conf ids.
func (o *Ops) fillFor(digest string, install bool) unitFill {
	return unitFill{
		Digest: digest, Install: install, CoreUID: o.cfg.CoreUID, CoreGID: o.cfg.CoreGID,
		SensorUID: o.cfg.SensorUID, SensorGID: o.cfg.SensorGID,
	}
}

// renderFor builds the unit of a service, mapping a missing host.conf value to its refusal.
func (o *Ops) renderFor(service, digest string, install bool) ([]byte, error) {
	b, err := renderUnit(service, o.fillFor(digest, install))
	switch {
	case errors.Is(err, errNoTemplate):
		return nil, refuse412(api.CodeUnitUnknown, "That service has no unit the host can write yet.")
	case err != nil:
		return nil, refuse412(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid this unit needs.")
	}
	return b, nil
}

const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// checkCommon is what both commands settle before a run: the appliance, a service with a template,
// and the ids it needs.
func (o *Ops) checkCommon(service string) error {
	if _, err := o.platform(); err != nil {
		return err
	}
	_, err := o.renderFor(service, zeroDigest, true)
	return err
}

// currentUnit reads and parses the unit of a service. A missing unit is not_pulled (no image has
// been installed); a link, an odd file or one this host's templates do not describe is unit_unsafe.
func (o *Ops) currentUnit(service string) (text []byte, digest string, err error) {
	text, st := o.readUnit(service)
	switch st {
	case fileAbsent:
		return nil, "", refuse412(api.CodeNotPulled, "There is no installed image for that service yet.")
	case fileBroken:
		return nil, "", refuse412(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
	}
	digest, _, perr := parseUnit(service, text)
	if perr != nil {
		return nil, "", refuse412(api.CodeUnitUnsafe, "The unit of that service is not one this host wrote.")
	}
	return text, digest, nil
}

func (o *Ops) checkContainerStart(_ context.Context, a api.ContainerStartArgs) error {
	if a.Version != "" {
		return refuse412(api.CodeNotPulled, "Switching to another version needs container.pull, which is not available yet.")
	}
	if err := o.checkCommon(a.Service); err != nil {
		return err
	}
	if _, _, err := o.unitDirChain(); err != nil {
		return refuse412(api.CodeUnitUnsafe, "The Quadlet directory is not safe to write as root.")
	}
	_, _, err := o.currentUnit(a.Service)
	return err
}

func (o *Ops) checkContainerStop(_ context.Context, a api.ContainerStopArgs) error {
	if a.Service == api.ServiceCore {
		return refuse412(api.CodeCannotStopCore, "Stopping core would stop the caller. Restart it with container.start, or reboot the box.")
	}
	if err := o.checkCommon(a.Service); err != nil {
		return err
	}
	if a.Persist {
		if _, _, err := o.unitDirChain(); err != nil {
			return refuse412(api.CodeUnitUnsafe, "The Quadlet directory is not safe to write as root.")
		}
		// A service with no unit has nothing to rewrite; a unit that is there must be one the host wrote.
		if text, st := o.readUnit(a.Service); st == fileBroken {
			return refuse412(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
		} else if st == fileOK {
			if _, _, err := parseUnit(a.Service, text); err != nil {
				return refuse412(api.CodeUnitUnsafe, "The unit of that service is not one this host wrote.")
			}
		}
	}
	return nil
}

// ---- systemctl and podman ---------------------------------------------------------------------

// sctl runs one systemctl call under its own time limit and says whether it exited 0.
func (o *Ops) sctl(ctx context.Context, limit time.Duration, args ...string) (ok bool) {
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	_, code, err := o.exec(cctx, binSystemctl, args...)
	return err == nil && code == 0
}

// ClassifyActive turns the output of "systemctl is-active" into one of api.Unit*. The words are
// read, the exit code is not (the code of is-active is 0 for active and 3 for everything else, and a
// program that lied about it would still have to print the word). Exported for fuzzing.
func ClassifyActive(out []byte) string {
	if len(out) > 32 {
		return api.UnitUnknown
	}
	switch strings.TrimSpace(string(out)) {
	case "active":
		return api.UnitActive
	case "inactive":
		return api.UnitInactive
	case "failed":
		return api.UnitFailed
	case "activating", "deactivating", "reloading", "maintenance", "refreshing":
		return api.UnitOther
	}
	return api.UnitUnknown
}

// unitActive asks systemd what state the service's unit is in.
func (o *Ops) unitActive(ctx context.Context, service string) string {
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	defer cancel()
	res, _, err := o.exec(cctx, binSystemctl, "is-active", unitOf(service))
	if err != nil || res.Truncated {
		return api.UnitUnknown
	}
	return ClassifyActive(res.Stdout)
}

// inspectInfo is what the host believes of a container after "podman container inspect".
type inspectInfo struct {
	Digest  string // the image digest the container was made from
	Running bool
	Health  string // api.Health*
}

type inspectHealth struct {
	Status string `json:"Status"`
}

// inspectDoc is the part of Podman's inspect output the host reads. Podman 4.9 and 5.x differ in
// places (the health block is "Health" in some, "Healthcheck" in others), so both are read.
type inspectDoc struct {
	Name        string `json:"Name"`
	ImageDigest string `json:"ImageDigest"`
	State       struct {
		Running     bool           `json:"Running"`
		Health      *inspectHealth `json:"Health"`
		Healthcheck *inspectHealth `json:"Healthcheck"`
	} `json:"State"`
}

var errInspect = errors.New("ops: podman inspect output is not usable")

// ParseInspect reads the output of "podman container inspect vedette-<service>": a JSON array of
// exactly one container named for the service, with an image digest of the form sha256:<64 hex>.
// The health word must be one Podman uses, else it is "unknown". Exported for fuzzing.
func ParseInspect(out []byte, service string) (digest string, running bool, health string, err error) {
	i, err := parseInspect(out, service)
	return i.Digest, i.Running, i.Health, err
}

func parseInspect(out []byte, service string) (inspectInfo, error) {
	if len(out) == 0 || len(out) > maxInspectOutput {
		return inspectInfo{}, errInspect
	}
	var docs []inspectDoc
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&docs); err != nil {
		return inspectInfo{}, errInspect
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return inspectInfo{}, errInspect
	}
	if len(docs) != 1 || docs[0].Name != containerName(service) || !digestRE.MatchString(docs[0].ImageDigest) {
		return inspectInfo{}, errInspect
	}
	d := docs[0]
	h := d.State.Health
	if h == nil {
		h = d.State.Healthcheck
	}
	health := api.HealthNone
	if h != nil {
		switch h.Status {
		case "healthy":
			health = api.HealthHealthy
		case "unhealthy":
			health = api.HealthUnhealthy
		case "starting":
			health = api.HealthStarting
		case "":
			health = api.HealthNone
		default:
			health = api.HealthUnknown
		}
	}
	return inspectInfo{Digest: d.ImageDigest, Running: d.State.Running, Health: health}, nil
}

// inspect asks Podman about the service's container. A container that does not exist (non-zero exit)
// or output the host cannot read is an error: neither counts as healthy.
func (o *Ops) inspect(ctx context.Context, service string) (inspectInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	defer cancel()
	res, code, err := o.exec(cctx, binPodman, "container", "inspect", containerName(service))
	switch {
	case err != nil:
		return inspectInfo{}, err
	case code != 0:
		return inspectInfo{}, errors.New("ops: no such container")
	case res.Truncated:
		return inspectInfo{}, errInspect
	}
	return parseInspect(res.Stdout, service)
}

// waitHealthy looks for the service's container to report digest and "healthy", every HealthPoll
// for up to total (counted in sleeps, and capped by the wall clock so a hung podman cannot stretch it).
func (o *Ops) waitHealthy(ctx context.Context, rc *server.RunContext, service, digest string, total time.Duration) bool {
	end := time.Now().Add(total + probeLimit)
	var waited time.Duration
	last := ""
	for {
		info, err := o.inspect(ctx, service)
		seen := "no container yet"
		if err == nil {
			seen = fmt.Sprintf("health %s, running %t, image matches %t", info.Health, info.Running, info.Digest == digest)
			if info.Digest == digest && info.Running && info.Health == api.HealthHealthy {
				return true
			}
		}
		if rc != nil && seen != last {
			rc.Log(containerName(service) + ": " + seen)
			last = seen
		}
		if waited >= total || time.Now().After(end) || ctx.Err() != nil {
			return false
		}
		if !o.d.Sleep(ctx, o.d.HealthPoll) {
			return false
		}
		waited += o.d.HealthPoll
	}
}

// runningHealthy is one look: the unit is active and the container runs this digest and is healthy.
func (o *Ops) runningHealthy(ctx context.Context, service, digest string) bool {
	if o.unitActive(ctx, service) != api.UnitActive {
		return false
	}
	info, err := o.inspect(ctx, service)
	return err == nil && info.Digest == digest && info.Running && info.Health == api.HealthHealthy
}

// ---- the journal --------------------------------------------------------------------------------

// transition is containers/transition.json: written before a unit changes, removed when the change
// is over (healthy, stopped, or put back).
type transition struct {
	Service string    `json:"service"`
	Op      string    `json:"op"` // "start" | "stop"
	Digest  string    `json:"digest"`
	PrevSHA string    `json:"prev_sha256"` // sha256 of the unit text before the change
	NewSHA  string    `json:"new_sha256"`  // sha256 of the text the change writes
	At      time.Time `json:"at"`
	RunID   string    `json:"run_id"`
}

const (
	opStart = "start"
	opStop  = "stop"
)

func (o *Ops) transitionPath() string { return o.stateFile("containers", "transition.json") }

func (o *Ops) saveTransition(t transition) error { return writeJSONAtomic(o.transitionPath(), t) }

func (o *Ops) clearTransition() { _ = removeIfThere(o.transitionPath()) }

// loadTransition reads the journal strictly: no unknown field, no trailing data, every value valid.
func (o *Ops) loadTransition() (transition, fileState) {
	r, err := openRootOf(o.stateFile("containers"))
	if err != nil {
		return transition{}, fileAbsent
	}
	defer func() { _ = r.Close() }()
	b, st := readNoFollow(r, "transition.json", 4<<10)
	if st != fileOK {
		return transition{}, st
	}
	var t transition
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&t) != nil {
		return transition{}, fileBroken
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return transition{}, fileBroken
	}
	if _, ok := services[t.Service]; !ok || (t.Op != opStart && t.Op != opStop) || !digestRE.MatchString(t.Digest) ||
		!shaRE.MatchString(t.PrevSHA) || !shaRE.MatchString(t.NewSHA) || (t.RunID != "" && !runIDRE.MatchString(t.RunID)) {
		return transition{}, fileBroken
	}
	return t, fileOK
}

// ---- container.start ----------------------------------------------------------------------------

func (o *Ops) runContainerStart(ctx context.Context, rc *server.RunContext, a api.ContainerStartArgs) (any, error) {
	svc := a.Service
	old, digest, err := o.currentUnit(svc)
	if err != nil {
		return nil, err
	}
	want, err := o.renderFor(svc, digest, true)
	if err != nil {
		return nil, err
	}
	res := api.ContainerStartResult{Service: svc, Digest: digest, Healthy: true}
	// Already running this image and healthy, and no restart asked: nothing to restart. If only the
	// [Install] section was missing (the service was stopped with persist), put it back and reload; the
	// running container is not touched.
	if !a.Restart && o.runningHealthy(ctx, svc, digest) {
		if !bytes.Equal(old, want) {
			if err := o.writeUnit(svc, want, true); err != nil {
				return nil, unitWriteFailure(err)
			}
			if !o.sctl(ctx, reloadLimit, "daemon-reload") {
				return nil, fail(api.CodeUnitUnwritable, "systemd would not reload the unit.")
			}
			rc.Log("unit written with [Install]; the running container was left alone")
		}
		return res, nil
	}
	tr := transition{Service: svc, Op: opStart, Digest: digest, PrevSHA: sha256Hex(old), NewSHA: sha256Hex(want), At: o.d.Now().UTC(), RunID: rc.RunID}
	if err := o.saveTransition(tr); err != nil {
		return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	if err := o.writeUnit(svc, want, true); err != nil {
		o.clearTransition()
		return nil, unitWriteFailure(err)
	}
	res.Restarted = true
	rc.Log("unit written, reloading systemd and restarting " + unitOf(svc))
	ok := o.sctl(ctx, reloadLimit, "daemon-reload") && o.sctl(ctx, restartLimit, "restart", unitOf(svc))
	if ok && o.waitHealthy(ctx, rc, svc, digest, o.d.HealthWait) {
		o.clearTransition()
		return res, nil
	}
	rc.Log("the service did not become healthy; putting the previous unit back")
	res.Healthy = false
	if err := o.revertUnit(ctx, svc, old); err != nil {
		// The journal stays: the next start of the host tries again.
		return nil, &server.Failure{Code: api.CodeUnitFailed, Message: "The new unit did not become healthy and the previous one could not be put back.", Result: res}
	}
	o.clearTransition()
	return nil, &server.Reverted{Code: api.CodeUnitFailed, Message: "The service did not become healthy; the previous unit was put back and restarted.", Result: res}
}

func unitWriteFailure(err error) error {
	if errors.Is(err, errUnitUnsafe) {
		return fail(api.CodeUnitUnsafe, "The Quadlet directory or the unit is not safe to write as root.")
	}
	return fail(api.CodeUnitUnwritable, "The unit could not be written.")
}

// revertUnit writes the old unit text back (without touching .prev), reloads and restarts. It runs on
// a context that outlives the run's, so a run that timed out still puts things back.
func (o *Ops) revertUnit(ctx context.Context, service string, old []byte) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revertLimit)
	defer cancel()
	if err := o.writeUnit(service, old, false); err != nil {
		return err
	}
	if !o.sctl(rctx, reloadLimit, "daemon-reload") || !o.sctl(rctx, restartLimit, "restart", unitOf(service)) {
		return errors.New("ops: systemd would not reload or restart the previous unit")
	}
	return nil
}

// ---- container.stop -----------------------------------------------------------------------------

func (o *Ops) runContainerStop(ctx context.Context, rc *server.RunContext, a api.ContainerStopArgs) (any, error) {
	svc := a.Service
	res := api.ContainerStopResult{Service: svc, Persist: a.Persist}
	state := o.unitActive(ctx, svc)
	if a.Persist {
		changed, err := o.dropInstall(ctx, rc, svc)
		if err != nil {
			return nil, err
		}
		res.Changed = changed
	}
	if state != api.UnitInactive {
		rc.Log("stopping " + unitOf(svc))
		o.sctl(ctx, stopLimit, "stop", unitOf(svc)) // the effect check below decides, not the exit code
		res.Changed = true
	}
	if !o.waitInactive(ctx, svc) {
		return nil, &server.Failure{Code: api.CodeStopNotVerified, Message: "systemctl did not report the service inactive after the stop.", Result: res}
	}
	return res, nil
}

// dropInstall rewrites the unit without [Install] (persist), journaling the change, and reloads.
// It reports whether it changed anything. A service with no unit has nothing to rewrite.
func (o *Ops) dropInstall(ctx context.Context, rc *server.RunContext, svc string) (bool, error) {
	text, st := o.readUnit(svc)
	switch st {
	case fileAbsent:
		return false, nil
	case fileBroken:
		return false, fail(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
	}
	digest, install, err := parseUnit(svc, text)
	if err != nil {
		return false, fail(api.CodeUnitUnsafe, "The unit of that service is not one this host wrote.")
	}
	if !install {
		return false, nil
	}
	want, err := renderUnit(svc, o.fillFor(digest, false))
	if err != nil {
		return false, fail(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid this unit needs.")
	}
	tr := transition{Service: svc, Op: opStop, Digest: digest, PrevSHA: sha256Hex(text), NewSHA: sha256Hex(want), At: o.d.Now().UTC(), RunID: rc.RunID}
	if err := o.saveTransition(tr); err != nil {
		return false, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	if err := o.writeUnit(svc, want, true); err != nil {
		o.clearTransition()
		return false, unitWriteFailure(err)
	}
	if !o.sctl(ctx, reloadLimit, "daemon-reload") {
		if err := o.writeUnit(svc, text, false); err == nil {
			o.clearTransition()
		}
		return false, fail(api.CodeUnitUnwritable, "systemd would not reload the unit.")
	}
	o.clearTransition()
	rc.Log("unit rewritten without [Install]")
	return true, nil
}

// waitInactive looks, by the output of is-active, for the unit to be inactive: every HealthPoll for
// up to stopVerifyWait.
func (o *Ops) waitInactive(ctx context.Context, svc string) bool {
	for waited := time.Duration(0); ; waited += o.d.HealthPoll {
		if o.unitActive(ctx, svc) == api.UnitInactive {
			return true
		}
		if waited >= stopVerifyWait || !o.d.Sleep(ctx, o.d.HealthPoll) {
			return false
		}
	}
}

// ---- recovery at Start --------------------------------------------------------------------------

// recoverTransition puts back a unit change the host died in the middle of (D-105 (7)), the way
// recoverRestore does for a restore. A start whose new unit is healthy is simply finished; one that
// is not gets the previous unit back and a restart. A stop gets the previous unit text back and
// nothing else (the service is left as it is). The whole step is bounded by recoverLimit.
func (o *Ops) recoverTransition(ctx context.Context) {
	t, st := o.loadTransition()
	switch st {
	case fileAbsent:
		return
	case fileBroken:
		o.log.WarnContext(ctx, "the unit journal is unreadable; removing it")
		o.clearTransition()
		o.note(api.CmdContainerStart, "transition_invalid", nil)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, recoverLimit)
	defer cancel()
	detail := map[string]any{"service": t.Service, "op": t.Op, "run_id": t.RunID}
	if t.Op == opStart {
		cur, cs := o.readUnit(t.Service)
		if cs == fileOK && sha256Hex(cur) == t.NewSHA && o.waitHealthy(rctx, nil, t.Service, t.Digest, recoverHealthWait) {
			o.clearTransition()
			detail["action"] = "completed"
			o.note(api.CmdContainerStart, "transition_interrupted", detail)
			return
		}
	}
	if err := o.putBackUnit(rctx, t); err != nil {
		o.log.ErrorContext(ctx, "could not put back an interrupted unit change", "service", t.Service, "error", err.Error())
		detail["action"] = "failed"
		o.note(api.CmdContainerStart, "transition_recovery_failed", detail)
		return // the journal stays for the next start
	}
	o.clearTransition()
	detail["action"] = "reverted"
	o.note(api.CmdContainerStart, "transition_interrupted", detail)
}

// putBackUnit restores the unit text from before the change (when it is not there already), reloads
// systemd and, for a start, restarts the unit.
func (o *Ops) putBackUnit(ctx context.Context, t transition) error {
	cur, cs := o.readUnit(t.Service)
	if cs == fileBroken {
		return errUnitUnsafe
	}
	if cs != fileOK || sha256Hex(cur) != t.PrevSHA {
		prev, ps := o.readPrev(t.Service)
		if ps != fileOK || sha256Hex(prev) != t.PrevSHA {
			return errors.New("ops: the previous unit is not kept or does not match the journal")
		}
		if err := o.writeUnit(t.Service, prev, false); err != nil {
			return err
		}
	}
	if !o.sctl(ctx, reloadLimit, "daemon-reload") {
		return errors.New("ops: systemd would not reload")
	}
	if t.Op == opStart && !o.sctl(ctx, restartLimit, "restart", unitOf(t.Service)) {
		return errors.New("ops: systemd would not restart the previous unit")
	}
	return nil
}
