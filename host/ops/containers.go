package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// container.start (the current image; with a version and container.rollback: update.go), container.stop
// (spec 6.8, 6.9, D-105, D-123, D-138), and the journal of the unit changes they make.
//
// A unit change is: journal it (containers/transition-<service>.json, phase "pending"), write the unit
// (D-105 (2): units.go), systemctl daemon-reload, then restart or stop, then look at the effect: the
// container reports the right image digest and "healthy" (Podman 4.9 has no Notify=healthy, so the host
// asks again and again for up to 120 s), or systemctl is-active says the unit is stopped. When the effect
// is seen the journal gets the phase "verified" (fsynced) and is removed. A start that does not get
// healthy puts the old unit back and restores the state the service had (restart if it was active, stop
// if not): reverted, unit_failed.
//
// A host that died in the middle finds the journals at Start. Before it is READY the host only puts the
// unit bytes back and reloads systemd: the container units are After=vedette-host.service, so a
// synchronous restart now would wait for the host's own start job. The restore of the state (restart or
// stop, then the health look) is AfterReady, under the write lock (D-123 amendment H1).

const (
	maxInspectOutput = 1 << 20
	reloadLimit      = 30 * time.Second
	stopLimit        = 60 * time.Second
	probeLimit       = 20 * time.Second
	// stopVerifyWait bounds the look for a stopped unit after a stop (counted in HealthPoll sleeps, and
	// capped by the wall clock).
	stopVerifyWait = 20 * time.Second
	// fileSlack covers the file work (journal, unit, .prev) of one step.
	fileSlack = 30 * time.Second
	// recoverLimit bounds recoverTransitions at Start, a term of the TimeoutStartSec sum (D-121 (6),
	// D-123): at most one daemon-reload plus the file work for the four units.
	recoverLimit = reloadLimit + fileSlack
	// afterReadyLimit bounds the restore of the state after READY: per unit a reload, a restart (the
	// unit's start timeout) and the health wait.
	afterReadyLimit = 15 * time.Minute
	// afterReadyRetry and afterReadyGiveUp pace the wait for the write lock.
	afterReadyRetry  = 2 * time.Second
	afterReadyGiveUp = 10 * time.Minute
	// afterReadyMaxBackoff caps the wait between two tries to put core's database back.
	afterReadyMaxBackoff = 5 * time.Minute
)

// revertLimitFor bounds putting an old unit back: the write, a reload, and a restart or a stop.
func revertLimitFor(service string) time.Duration {
	return fileSlack + reloadLimit + max(restartLimitFor(service), stopLimit)
}

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]{1,32})?(\+[0-9A-Za-z.-]{1,32})?$`)

// unitServices are the services that have a unit template, in the order the host recovers them.
var unitServices = []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan}

// serviceArg checks a service name against the closed list.
func serviceArg(s string) error {
	if !slices.Contains(api.Services, s) {
		return server.Invalid("service", "must be one of core, sensor, honeypot, scan, greenbone")
	}
	return nil
}

func rcLog(rc *server.RunContext, line string) {
	if rc != nil {
		rc.Log(line)
	}
}

func rcID(rc *server.RunContext) string {
	if rc != nil {
		return rc.RunID
	}
	return ""
}

func (o *Ops) cmdContainerStart() server.Command {
	return server.Define(server.Spec[api.ContainerStartArgs]{
		// One number covers the command (D-123 L6, D-138): a core start with a version makes a backup (up to
		// backupLimit), waits for a restart of up to its TimeoutStartSec and the health, then may restore the
		// backup and start the old release again.
		Name: api.CmdContainerStart, Write: true, Timeout: startTimeout,
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

func (o *Ops) cmdContainerRollback() server.Command {
	return server.Define(server.Spec[api.ContainerRollbackArgs]{
		// Spec 6.10: 3 minutes, core 30 (as backup.restore); one number for the command (D-138).
		Name: api.CmdContainerRollback, Write: true, Timeout: rollbackTimeout,
		Validate: func(a *api.ContainerRollbackArgs) error { return serviceArg(a.Service) },
		Check:    o.checkContainerRollback,
		Run:      o.runContainerRollback,
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
		SensorUID: o.cfg.SensorUID, SensorGID: o.cfg.SensorGID, DataDir: o.cfg.CoreData,
	}
}

// renderFor builds the unit of a service (with [Install]: a stopped-with-persist service is the only one
// without it, and dropInstall renders that itself), mapping a missing host.conf value to its refusal.
// For core the daemon also vets core_data first (coreDataUsable): its unit binds that directory.
func (o *Ops) renderFor(service, digest string) ([]byte, error) {
	if service == api.ServiceCore {
		if err := o.coreDataUsable(); err != nil {
			return nil, err
		}
	}
	return o.renderUnitFor(service, digest)
}

// renderUnitFor is renderFor without the look at core_data's directory (the bootstrap, which makes or vets it next).
func (o *Ops) renderUnitFor(service, digest string) ([]byte, error) {
	b, err := renderUnit(service, o.fillFor(digest, true))
	switch {
	case errors.Is(err, errNoTemplate):
		return nil, refuse412(api.CodeUnitUnknown, "That service has no unit the host can write yet.")
	case err != nil && service == api.ServiceCore && o.cfg.CoreData == "":
		return nil, refuse412(api.CodeHostConfIncomplete, "host.conf does not give core_data, which core's unit binds.")
	case err != nil && service == api.ServiceCore && !validCoreData(o.cfg.CoreData):
		return nil, refuse412(api.CodeHostConfIncomplete, "core_data in host.conf is not a plain absolute path that a unit can carry.")
	case err != nil:
		return nil, refuse412(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid this unit needs.")
	}
	return b, nil
}

// coreDataUsable is what the daemon asks before it renders core's unit: the value is one the unit can carry and
// not a place of the host's own, and the directory is core's (checkChain: a real directory, owned by core or root,
// under root-owned directories that nobody else can write).
func (o *Ops) coreDataUsable() error {
	if o.cfg.CoreData == "" || !validCoreData(o.cfg.CoreData) {
		_, err := o.renderUnitFor(api.ServiceCore, zeroDigest)
		return err
	}
	if o.coreDataForbidden(o.cfg.CoreData) {
		return refuse412(api.CodeCoreDataInvalid, "core_data names a place the host keeps for itself (its state, the units, the audit log or a system directory).")
	}
	if _, _, err := o.checkChain(o.cfg.CoreData); err != nil {
		o.log.Warn("core's data directory is not safe to bind into core's unit", "error", err.Error())
		return refuse412(api.CodeCoreDataInvalid, "core_data is not a real directory owned by core under root-owned directories that nobody else can write.")
	}
	return nil
}

const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// checkCommon is what both commands settle before a run: the appliance, a service with a template,
// the ids it needs, and no journal of an earlier change waiting to be recovered (D-123, M3).
func (o *Ops) checkCommon(service string) error {
	if _, err := o.platform(); err != nil {
		return err
	}
	if _, err := o.renderFor(service, zeroDigest); err != nil {
		return err
	}
	if t, st, _ := o.loadJournal(service); st != jAbsent {
		return refuse412(api.CodeTransitionPending, transitionPendingText(t, st == jOK))
	}
	return nil
}

// currentUnit reads the unit of a service. A missing unit is not_pulled (no image has been
// installed); a link, an odd file or one that is not byte for byte what this host would write is
// unit_unsafe (D-123 L2).
func (o *Ops) currentUnit(service string) (text []byte, digest string, err error) {
	text, st := o.readUnit(service)
	switch st {
	case fileAbsent:
		return nil, "", refuse412(api.CodeNotPulled, "There is no installed image for that service yet.")
	case fileBroken:
		return nil, "", refuse412(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
	}
	digest, _, perr := o.ourUnit(service, text)
	if perr != nil {
		return nil, "", refuse412(api.CodeUnitUnsafe, "The unit of that service is not exactly what this host writes.")
	}
	return text, digest, nil
}

// checkContainerStart settles every refusal before a run (D-104 (4), D-138). With a version that is
// the stored index, the record of the pulled version and its image, the version rules and, for core, the
// snapshot and the disk: no write call of podman, no change of any file.
func (o *Ops) checkContainerStart(ctx context.Context, a api.ContainerStartArgs) error {
	if err := o.checkCommon(a.Service); err != nil {
		return err
	}
	if _, _, err := o.unitDirChain(); err != nil {
		return refuse412(api.CodeUnitUnsafe, "The Quadlet directory is not safe to write as root.")
	}
	old, digest, err := o.currentUnit(a.Service)
	if err != nil {
		return err
	}
	if a.Service != api.ServiceHoneypot && o.volumeOwnerChanged(ctx) != "" { // the start writes the credential volume units (D-316 (10))
		return refuse412(api.CodeUnitUnsafe, volumeOwnerText)
	}
	// The ports a restart would add (D-455) are judged here only when the run restarts for sure (restart asked, or another digest);
	// a start without restart of a running, healthy service keeps the unit's template, so Run decides that once it has looked.
	if a.Version == "" {
		if !a.Restart {
			return nil
		}
		return o.portsFreeFor(ctx, a.Service, old, digest)
	}
	plan, err := o.planStartVersion(ctx, a)
	if err != nil {
		return err
	}
	if plan.change || a.Restart {
		if plan.change {
			digest = plan.rec.Digest
		}
		if err := o.portsFreeFor(ctx, a.Service, old, digest); err != nil { // before the backup: a refusal here changes nothing
			return err
		}
	}
	if plan.change && a.Service == api.ServiceCore {
		return o.backupPreflight(a.Snapshot, true, true) // snapshot_required, snapshot_invalid, low_disk, db_unreadable: as backup.create
	}
	return nil
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
		// A service with no unit has nothing to rewrite; a unit that is there must be exactly ours.
		if text, st := o.readUnit(a.Service); st == fileBroken {
			return refuse412(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
		} else if st == fileOK {
			if _, _, err := o.ourUnit(a.Service, text); err != nil {
				return refuse412(api.CodeUnitUnsafe, "The unit of that service is not exactly what this host writes.")
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

// isStopped says whether a unit state means no process runs: inactive, and failed (a unit that failed
// has nothing running, and "systemctl stop" would only reset it; D-123 M2).
func isStopped(state string) bool { return state == api.UnitInactive || state == api.UnitFailed }

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
	// Started names this run of the container: its ID and StartedAt, each only when it has the expected shape; "" when
	// neither does. It changes whenever the container is made or started again (conntrack.go).
	Started string
}

type inspectHealth struct {
	Status string `json:"Status"`
}

// inspectDoc is the part of Podman's inspect output the host reads. Podman 4.9 and 5.x differ in
// places (the health block is "Health" in some, "Healthcheck" in others), so both are read.
type inspectDoc struct {
	Name        string `json:"Name"`
	ID          string `json:"Id"`
	ImageDigest string `json:"ImageDigest"`
	// Image is the ID of the image the container was made from: for scan, whose image is built on the box and has no registry digest,
	// it is the "digest" the host compares (D-147).
	Image string `json:"Image"`
	State struct {
		Running     bool           `json:"Running"`
		StartedAt   string         `json:"StartedAt"`
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
	if len(docs) != 1 || docs[0].Name != containerName(service) {
		return inspectInfo{}, errInspect
	}
	d := docs[0]
	if services[service].byID {
		d.ImageDigest = "sha256:" + d.Image
		if !imageIDRE.MatchString(d.Image) {
			return inspectInfo{}, errInspect
		}
	}
	if !digestRE.MatchString(d.ImageDigest) {
		return inspectInfo{}, errInspect
	}
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
	return inspectInfo{Digest: d.ImageDigest, Running: d.State.Running, Health: health, Started: runIdentity(d.ID, d.State.StartedAt)}, nil
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
			if service == api.ServiceCore && info.Digest == digest && info.Running {
				o.coreLooked(ctx, info) // the host just (re)started core: stale syslog flows go as soon as the new run is seen, not after the 30 to 60 s health wait or the next watch tick (D-268); one run clears once
			}
			if info.Digest == digest && info.Running && info.Health == api.HealthHealthy {
				return true
			}
		}
		if seen != last {
			rcLog(rc, containerName(service)+": "+seen)
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

// waitStopped looks, by the output of is-active, for the unit to be stopped (inactive or failed): every
// HealthPoll for up to stopVerifyWait, counted in sleeps and capped by the wall clock.
func (o *Ops) waitStopped(ctx context.Context, svc string) bool {
	end := time.Now().Add(stopVerifyWait + probeLimit)
	for waited := time.Duration(0); ; waited += o.d.HealthPoll {
		if isStopped(o.unitActive(ctx, svc)) {
			return true
		}
		if waited >= stopVerifyWait || time.Now().After(end) || !o.d.Sleep(ctx, o.d.HealthPoll) {
			return false
		}
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

// transition is containers/transition-<service>.json: one per service, written before the bytes of a
// unit change and removed when the change is over. Phase is "pending" while the change may be half
// done, "restored" once Start put the old bytes back and the state is still to be restored after READY,
// and "verified" once the effect was seen (the journal is then only waiting to be deleted).
type transition struct {
	Service   string    `json:"service"`
	Op        string    `json:"op"`    // "start" | "stop" | "rollback"
	Phase     string    `json:"phase"` // "pending" | "restored" | "verified"
	Digest    string    `json:"digest"`
	PrevSHA   string    `json:"prev_sha256"` // sha256 of the unit text before the change
	NewSHA    string    `json:"new_sha256"`  // sha256 of the text the change writes
	WasActive bool      `json:"was_active"`  // the unit was active before the change (is-active)
	At        time.Time `json:"at"`
	RunID     string    `json:"run_id"`
	// A start with a version and a rollback also say (D-138): the version moved to, the digest moved
	// from, the pre_update backup that belongs to the change, how core's database goes back when the
	// change is undone ("backup": restore BackupID; "aside": the files moved aside come back), and
	// whether the change took effect (Applied: the versions are then recorded, once, even after a crash).
	Version    string `json:"version,omitempty"`
	FromDigest string `json:"from_digest,omitempty"`
	BackupID   string `json:"backup_id,omitempty"`
	DBRevert   string `json:"db_revert,omitempty"`
	Applied    bool   `json:"applied,omitempty"`
	// Aside is exactly the names a rollback moved (or is about to move) to <name>.rollback in core's data
	// directory, journaled before the moves; only these are put back or dropped.
	Aside []string `json:"aside,omitempty"`
	// Unrecoverable says the host gave up putting core's data back (errUnrecoverable): the journal stays so
	// that commands for core keep refusing, but nothing retries and core is left as it is (D-138 N1).
	Unrecoverable bool `json:"unrecoverable,omitempty"`
	// Recover is the progress of vedette-host -recover-core-data (D-317), written before its first rename so that
	// a rerun finishes the job instead of guessing from the files. Nothing else reads or writes it.
	Recover *recoverState `json:"recover,omitempty"`
}

const (
	opStart    = "start"
	opStop     = "stop"
	opRollback = "rollback"

	dbBackup = "backup"
	dbAside  = "aside"

	phasePending  = "pending"
	phaseRestored = "restored"
	phaseVerified = "verified"
)

func (t transition) command() string {
	switch t.Op {
	case opStop:
		return api.CmdContainerStop
	case opRollback:
		return api.CmdContainerRollback
	}
	return api.CmdContainerStart
}

func journalName(service string) string { return "transition-" + service + ".json" }

// jstate is what loadJournal found.
type jstate int

const (
	jAbsent     jstate = iota
	jOK                // a valid journal
	jInvalid           // it does not parse or has a wrong type, value or kind of file: quarantine it
	jUnreadable        // an I/O error: say so, touch nothing
)

func (o *Ops) saveJournal(t transition) error {
	if f := o.d.JournalFault; f != nil {
		if err := f(t.Service, t.Phase); err != nil {
			return err
		}
	}
	return writeJSONAtomic(o.stateFile("containers", journalName(t.Service)), t)
}

// removeJournal deletes the journal and makes the removal durable: the directory is fsynced.
func (o *Ops) removeJournal(service string) {
	_ = removeIfThere(o.stateFile("containers", journalName(service)))
	syncDir(o.stateFile("containers"))
}

// finishJournal records that the effect was seen (phase verified, fsynced) and then deletes the
// journal: a crash between the two leaves a verified journal that Start only deletes, never reverts.
func (o *Ops) finishJournal(t transition) {
	t.Phase = phaseVerified
	_ = o.saveJournal(t)
	o.removeJournal(t.Service)
}

// finishApplied is finishJournal for a change that took effect and has consequences beyond the unit:
// the verified phase says "applied" first (durable), then the versions are recorded and the database
// files moved aside are dropped (both idempotent: Start repeats them from a verified journal), and
// only then is the journal deleted.
//
// If the verified journal cannot be written, the host tries to delete the (pending) journal instead
// (N3): with no journal a later start has nothing to undo, so the switch that worked stays and is settled
// normally. Only when the journal can be neither updated nor removed is nothing settled and the error
// returned: the pending journal would make the next start put the old release back, and settling versions
// against that would contradict it; the run fails.
func (o *Ops) finishApplied(t transition) error {
	t.Phase, t.Applied = phaseVerified, true
	if err := o.saveJournal(t); err != nil {
		o.removeJournal(t.Service)
		if _, st, _ := o.loadJournal(t.Service); st != jAbsent {
			o.log.Error("could not record that a change took effect, nor remove its journal; the versions are not updated", "service", t.Service, "error", err.Error())
			return err
		}
		o.log.Warn("could not write the verified journal; removed it instead, the change stands", "service", t.Service, "error", err.Error())
		o.settleVerified(t)
		return nil
	}
	o.settleVerified(t)
	o.removeJournal(t.Service)
	return nil
}

// settleVerified is what a change that took effect leaves to do after its journal says so.
func (o *Ops) settleVerified(t transition) {
	if !t.Applied {
		return
	}
	o.completeTransition(t)
	if t.DBRevert == dbAside {
		if tree, err := o.openCore(); err == nil {
			if err := tree.dropAside(t.Aside); err != nil {
				o.log.Warn("could not drop the files a rollback moved aside; they are left", "error", err.Error())
			}
			tree.close()
		}
	}
}

// loadJournal reads the journal of a service strictly: no unknown field, no trailing data, every
// value valid. A kind of file that is not a regular file, a size over the cap, or content that fails to
// parse or validate is jInvalid; an I/O error is jUnreadable (and returned).
func (o *Ops) loadJournal(service string) (transition, jstate, error) {
	r, err := openRootOf(o.stateFile("containers"))
	if err != nil {
		return transition{}, jUnreadable, err
	}
	defer func() { _ = r.Close() }()
	name := journalName(service)
	lst, err := r.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return transition{}, jAbsent, nil
	}
	if err != nil {
		return transition{}, jUnreadable, err
	}
	if !lst.Mode().IsRegular() || lst.Size() > 4<<10 {
		return transition{}, jInvalid, nil
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return transition{}, jInvalid, nil
		}
		return transition{}, jUnreadable, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return transition{}, jInvalid, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 4<<10+1))
	if err != nil {
		return transition{}, jUnreadable, err
	}
	if len(b) > 4<<10 {
		return transition{}, jInvalid, nil
	}
	var t transition
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&t) != nil {
		return transition{}, jInvalid, nil
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return transition{}, jInvalid, nil
	}
	if t.Service != service || (t.Op != opStart && t.Op != opStop && t.Op != opRollback) || (t.Phase != phasePending && t.Phase != phaseRestored && t.Phase != phaseVerified) ||
		!digestRE.MatchString(t.Digest) || !shaRE.MatchString(t.PrevSHA) || !shaRE.MatchString(t.NewSHA) || (t.RunID != "" && !runIDRE.MatchString(t.RunID)) ||
		(t.Version != "" && (len(t.Version) > 64 || !tagVersionRE.MatchString(t.Version))) || (t.FromDigest != "" && !digestRE.MatchString(t.FromDigest)) ||
		(t.BackupID != "" && !hexIDRE.MatchString(t.BackupID)) || (t.DBRevert != "" && t.DBRevert != dbBackup && t.DBRevert != dbAside) ||
		len(t.Aside) > 8 || slices.ContainsFunc(t.Aside, func(n string) bool { return !isAsideName(n) }) || !t.Recover.valid() {
		return transition{}, jInvalid, nil
	}
	return t, jOK, nil
}

// keepInvalid is how many quarantined journals of a service are kept (D-121 (7)).
const keepInvalid = 3

// quarantineJournal moves a journal that does not parse aside under a timestamped name (keeping the
// newest keepInvalid), so the evidence stays and the service is not blocked.
func (o *Ops) quarantineJournal(service string) {
	r, err := openRootOf(o.stateFile("containers"))
	if err != nil {
		return
	}
	defer func() { _ = r.Close() }()
	name := journalName(service)
	if err := r.Rename(name, fmt.Sprintf("%s.invalid-%019d", name, time.Now().UnixNano())); err != nil {
		_ = r.Remove(name)
	}
	d, err := r.Open(".")
	if err != nil {
		return
	}
	names, _ := d.Readdirnames(-1)
	_ = d.Close()
	var old []string
	for _, n := range names {
		if strings.HasPrefix(n, name+".invalid-") {
			old = append(old, n)
		}
	}
	slices.Sort(old) // fixed-width timestamps: oldest first
	for len(old) > keepInvalid {
		_ = r.Remove(old[0])
		old = old[1:]
	}
	syncDir(o.stateFile("containers"))
}

func (o *Ops) newJournal(rc *server.RunContext, op, service, digest string, prev, next []byte, wasActive bool) transition {
	return transition{
		Service: service, Op: op, Phase: phasePending, Digest: digest, PrevSHA: sha256Hex(prev), NewSHA: sha256Hex(next),
		WasActive: wasActive, At: o.d.Now().UTC(), RunID: rcID(rc),
	}
}

// ---- container.start ----------------------------------------------------------------------------

func (o *Ops) runContainerStart(ctx context.Context, rc *server.RunContext, a api.ContainerStartArgs) (any, error) {
	if a.Version == "" {
		return o.runStartCurrent(ctx, rc, a)
	}
	plan, err := o.planStartVersion(ctx, a) // the same rules as Check, on what is true now
	if err != nil {
		return nil, err
	}
	if plan.change {
		return o.runSwitch(ctx, rc, a, plan)
	}
	// The unit already pins this digest: a restart or nothing, then the version is known to the host.
	res, err := o.runStartCurrent(ctx, rc, a)
	if err != nil {
		return nil, err
	}
	if r, ok := res.(api.ContainerStartResult); ok {
		o.adoptCurrent(plan.rec)
		v := plan.rec.Version
		r.Version, r.IndexExpired = &v, plan.expired
		o.noteExpired(rc, api.CmdContainerStart, plan)
		o.retainImages(ctx, rc, api.CmdContainerStart, a.Service)
		return r, nil
	}
	return res, nil
}

// runStartCurrent is container.start of the image the unit pins now (slice 3-6, D-123).
func (o *Ops) runStartCurrent(ctx context.Context, rc *server.RunContext, a api.ContainerStartArgs) (any, error) {
	svc := a.Service
	old, digest, err := o.currentUnit(svc)
	if err != nil {
		return nil, err
	}
	want, err := o.renderFor(svc, digest)
	if err != nil {
		return nil, err
	}
	res := api.ContainerStartResult{Service: svc, Digest: digest, Healthy: true}
	state := o.unitActive(ctx, svc)
	wasActive := state == api.UnitActive
	// Already running this image and healthy, and no restart asked: nothing to restart. If only the
	// [Install] section was missing (the service was stopped with persist), put it back and reload; the
	// running container is not touched. The change of bytes is journaled like any other.
	if !a.Restart && o.runningHealthy(ctx, svc, digest) {
		if added := addedPorts(old, want); len(added) > 0 {
			// The current template adds host ports, which would only take effect at a later restart with no check and no revert
			// behind it (D-455): the unit keeps its own template (only [Install] may come back), and the next start that
			// restarts the service checks the ports and moves it.
			_, install, err := o.ourUnit(svc, old)
			if err == nil {
				want, err = o.ownTemplate(svc, old, digest, install, true)
			}
			if err != nil {
				return nil, fail(api.CodeUnitUnsafe, "The unit of that service is not exactly what this host writes.")
			}
			o.noteUnitDeferred(ctx, svc, digest, rcID(rc), added)
			rcLog(rc, "the unit stays on its earlier template until the service restarts: the current one publishes new host ports")
		}
		if bytes.Equal(old, want) {
			return res, nil
		}
		tr := o.newJournal(rc, opStart, svc, digest, old, want, true)
		if err := o.saveJournal(tr); err != nil {
			return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
		}
		if err := o.writeUnitForStart(ctx, svc, want); err != nil {
			o.removeJournal(svc)
			return nil, unitWriteFailure(err)
		}
		if !o.sctl(ctx, reloadLimit, "daemon-reload") {
			if o.writeUnit(svc, old, false) == nil {
				o.removeJournal(svc)
			}
			return nil, fail(api.CodeUnitUnwritable, "systemd would not reload the unit.")
		}
		o.finishJournal(tr)
		rcLog(rc, "unit written with [Install]; the running container was left alone")
		return res, nil
	}
	if err := o.portsFreeToStart(ctx, svc, old, want, state); err != nil { // before the journal: nothing changes (D-455)
		return nil, err
	}
	tr := o.newJournal(rc, opStart, svc, digest, old, want, wasActive)
	if err := o.saveJournal(tr); err != nil {
		return nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	if err := o.writeUnitForStart(ctx, svc, want); err != nil {
		o.removeJournal(svc)
		return nil, unitWriteFailure(err)
	}
	res.Restarted = true
	rcLog(rc, "unit written, reloading systemd and restarting "+unitOf(svc))
	ok := o.sctl(ctx, reloadLimit, "daemon-reload") && o.sctl(ctx, restartLimitFor(svc), "restart", unitOf(svc))
	if ok && o.waitHealthy(ctx, rc, svc, digest, o.d.HealthWait) {
		o.finishJournal(tr)
		return res, nil
	}
	rcLog(rc, "the service did not become healthy; putting the previous unit back")
	res.Healthy = false
	if err := o.revertUnit(ctx, svc, old, wasActive); err != nil {
		// The journal stays (pending): the next start of the host puts the bytes back and the state after READY.
		return nil, &server.Failure{Code: api.CodeUnitFailed, Message: "The new unit did not become healthy and the previous one could not be put back.", Result: res}
	}
	o.finishJournal(tr)
	return nil, &server.Reverted{Code: api.CodeUnitFailed, Message: "The service did not become healthy; the previous unit was put back and the service returned to the state it had.", Result: res}
}

func unitWriteFailure(err error) error {
	if errors.Is(err, errVolumeOwner) {
		return fail(api.CodeUnitUnsafe, volumeOwnerText)
	}
	if errors.Is(err, errBadFill) {
		return fail(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid the credential volumes need.")
	}
	if errors.Is(err, errUnitUnsafe) {
		return fail(api.CodeUnitUnsafe, "The Quadlet directory or the unit is not safe to write as root.")
	}
	return fail(api.CodeUnitUnwritable, "The unit could not be written.")
}

// revertUnit writes the old unit text back (without touching .prev), reloads, and returns the service to
// the state it had: restart when it was active, stop when it was not (a service stopped with persist
// must not come up because its enabling failed, SYS-5). It runs on a context that outlives the run's, so
// a run that timed out still puts things back.
func (o *Ops) revertUnit(ctx context.Context, service string, old []byte, wasActive bool) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revertLimitFor(service))
	defer cancel()
	if err := o.writeUnit(service, old, false); err != nil {
		return err
	}
	if !o.sctl(rctx, reloadLimit, "daemon-reload") {
		return errors.New("ops: systemd would not reload the previous unit")
	}
	if wasActive {
		if !o.sctl(rctx, restartLimitFor(service), "restart", unitOf(service)) {
			return errors.New("ops: systemd would not restart the previous unit")
		}
		return nil
	}
	o.sctl(rctx, stopLimit, "stop", unitOf(service)) // the state is read, not the exit code
	if !isStopped(o.unitActive(rctx, service)) {
		return errors.New("ops: the service could not be stopped again")
	}
	return nil
}

// ---- container.stop -----------------------------------------------------------------------------

func (o *Ops) runContainerStop(ctx context.Context, rc *server.RunContext, a api.ContainerStopArgs) (any, error) {
	svc := a.Service
	res := api.ContainerStopResult{Service: svc, Persist: a.Persist}
	state := o.unitActive(ctx, svc)
	var tr *transition
	if a.Persist {
		changed, j, err := o.dropInstall(ctx, rc, svc, state == api.UnitActive)
		if err != nil {
			return nil, err
		}
		res.Changed, tr = changed, j
	}
	if !isStopped(state) {
		rcLog(rc, "stopping "+unitOf(svc))
		o.sctl(ctx, stopLimit, "stop", unitOf(svc)) // the effect check below decides, not the exit code
		res.Changed = true
	}
	ok := o.waitStopped(ctx, svc)
	if tr != nil {
		// The unit change is done whether or not the stop was seen: a failed stop is the caller's to retry,
		// and a journal left pending would only block that retry.
		o.finishJournal(*tr)
	}
	if !ok {
		return nil, &server.Failure{Code: api.CodeStopNotVerified, Message: "systemctl did not report the service stopped after the stop.", Result: res}
	}
	return res, nil
}

// dropInstall rewrites the unit without [Install] (persist), journaling the change, and reloads. It
// reports whether it changed anything and returns the journal, still pending: the caller finishes it
// once the stop was looked at. A service with no unit has nothing to rewrite.
func (o *Ops) dropInstall(ctx context.Context, rc *server.RunContext, svc string, wasActive bool) (bool, *transition, error) {
	text, st := o.readUnit(svc)
	switch st {
	case fileAbsent:
		return false, nil, nil
	case fileBroken:
		return false, nil, fail(api.CodeUnitUnsafe, "The unit of that service is not a regular file the host can trust.")
	}
	digest, install, err := o.ourUnit(svc, text)
	if err != nil {
		return false, nil, fail(api.CodeUnitUnsafe, "The unit of that service is not exactly what this host writes.")
	}
	if !install {
		return false, nil, nil
	}
	want, err := o.ownTemplate(svc, text, digest, true, false) // the same template without [Install]: a stop never adds a port (D-455)
	if err != nil {
		return false, nil, fail(api.CodeHostConfIncomplete, "host.conf does not give the uid and gid this unit needs.")
	}
	tr := o.newJournal(rc, opStop, svc, digest, text, want, wasActive)
	if err := o.saveJournal(tr); err != nil {
		return false, nil, fail(api.CodeUnitUnwritable, "The host could not write its journal.")
	}
	if err := o.writeUnit(svc, want, true); err != nil {
		o.removeJournal(svc)
		return false, nil, unitWriteFailure(err)
	}
	if !o.sctl(ctx, reloadLimit, "daemon-reload") {
		if o.writeUnit(svc, text, false) == nil {
			o.removeJournal(svc)
		}
		return false, nil, fail(api.CodeUnitUnwritable, "systemd would not reload the unit.")
	}
	rcLog(rc, "unit rewritten without [Install]")
	return true, &tr, nil
}

// ---- recovery -----------------------------------------------------------------------------------

// recoverTransitions runs at Start, before the host is READY, and only puts unit bytes back and
// reloads systemd (D-123 H1): the container units are After=vedette-host.service, so a synchronous
// restart now would wait for this very start job, and no container can be judged healthy before the
// host is ready. A journal in phase verified is only deleted; one in phase pending gets the bytes it
// recorded back (from .prev, which must match its hash) and becomes "restored"; the service state
// (restart if it was active, stop if not) is restored by AfterReady. A journal that does not parse is
// moved aside; one that cannot be read is left alone and says so. Until a journal is gone, container
// commands for that service are refused (transition_pending). Bounded by recoverLimit. atStart is Start's
// call (not the retries of the loops after READY): only then are the units of an earlier host release moved
// to the current template (migrateUnits, once per start, D-316 (10)), inside the same one reload.
func (o *Ops) recoverTransitions(ctx context.Context, atStart bool) {
	rctx, cancel := context.WithTimeout(ctx, recoverLimit)
	defer cancel()
	o.restorePending = nil
	changed := false
	for _, svc := range unitServices {
		t, st, err := o.loadJournal(svc)
		switch st {
		case jAbsent:
			continue
		case jUnreadable:
			o.log.ErrorContext(ctx, "the unit journal cannot be read; leaving it", "service", svc, "error", err.Error())
			o.note(api.CmdContainerStart, "transition_unreadable", map[string]any{"service": svc})
			continue
		case jInvalid:
			o.log.WarnContext(ctx, "the unit journal is not valid; moving it aside", "service", svc)
			o.quarantineJournal(svc)
			o.note(api.CmdContainerStart, "transition_invalid", map[string]any{"service": svc})
			continue
		case jOK:
		}
		detail := map[string]any{"service": svc, "op": t.Op, "run_id": t.RunID}
		if t.Unrecoverable {
			continue // the host gave up on this one (N1): nothing is retried, commands for the service keep refusing
		}
		switch t.Phase {
		case phaseVerified:
			o.settleVerified(t) // what a change that took effect still had to do, once (D-138)
			o.removeJournal(svc)
			detail["action"] = "completed"
			o.note(t.command(), "transition_interrupted", detail)
		case phaseRestored:
			o.restorePending = append(o.restorePending, svc)
		default: // pending
			wrote, err := o.restoreBytes(t)
			if err != nil {
				o.log.ErrorContext(ctx, "could not put back the unit of an interrupted change", "service", svc, "error", err.Error())
				detail["action"] = "failed"
				o.noteRecoveryFailed(svc, t.command(), detail)
				if svc == api.ServiceCore && t.DBRevert != "" && (errors.Is(err, errUnitUnsafe) || errors.Is(err, errPrevMissing)) {
					// Core's data is half swapped and the unit cannot be put back, and trying again cannot cure
					// that (N4). Any other error (I/O, a full disk) keeps the journal pending and is retried.
					o.markUnrecoverable(t)
				}
				continue // the journal stays; commands for the service are refused
			}
			if !wrote && t.DBRevert == dbBackup {
				t.DBRevert = "" // the new unit never replaced the old one: the new release never ran, the database is as it was
			}
			t.Phase = phaseRestored
			if err := o.saveJournal(t); err != nil {
				detail["action"] = "failed"
				o.noteRecoveryFailed(svc, t.command(), detail)
				continue
			}
			changed = true
			o.restorePending = append(o.restorePending, svc)
			detail["action"] = "bytes_restored"
			o.note(t.command(), "transition_interrupted", detail)
		}
	}
	if atStart && o.migrateUnits(rctx) { // units of an earlier host release, to the current template (D-316 (10)): the same one reload
		changed = true
	}
	if changed && !o.sctl(rctx, reloadLimit, "daemon-reload") {
		o.log.ErrorContext(ctx, "systemd would not reload after the unit bytes were put back or migrated; AfterReady or the next unit command reloads")
	}
}

// errPrevMissing: the old unit text is not kept, or does not match the journal. With errUnitUnsafe it is
// what no retry can cure; any other error of restoreBytes (an I/O error, a full disk) is retried.
var errPrevMissing = errors.New("ops: the previous unit is not kept or does not match the journal")

// restoreBytes puts the unit text from before the change back, unless it is there already, and says
// whether it had to write.
func (o *Ops) restoreBytes(t transition) (wrote bool, err error) {
	cur, cs := o.readUnit(t.Service)
	if cs == fileBroken {
		return false, errUnitUnsafe
	}
	if cs == fileOK && sha256Hex(cur) == t.PrevSHA {
		return false, nil
	}
	prev, ps := o.readPrev(t.Service)
	if ps != fileOK || sha256Hex(prev) != t.PrevSHA {
		return false, errPrevMissing
	}
	return true, o.writeUnit(t.Service, prev, false)
}

// Locker is what AfterReady needs from the server: run a function under the global write lock, the
// way a command does, or say ErrWriteBusy (server.Server implements it).
type Locker interface {
	WithWriteLock(ctx context.Context, fn func(ctx context.Context)) error
}

// AfterReady restores the state of the services whose unit bytes Start put back: restart when the
// service was active before the interrupted change (and look for it to be healthy), stop when it was
// not. It runs once, after the host is READY and listening, on its own goroutine, and takes the write
// lock like a normal run, retrying while a command holds it. Simplest correct form: by now vedette-host
// is active, so a synchronous restart of an After=vedette-host unit no longer waits on the host's own
// start job, and no --no-block is needed. A journal that cannot be completed stays (phase restored) and
// the next start tries again.
func (o *Ops) AfterReady(ctx context.Context, l Locker) {
	o.afterReadySelfUpdate(ctx) // started.json first, then the self-update's settle loop (D-316): nothing waits before READY
	o.mu.Lock()
	o.afterCtx, o.afterL = ctx, l
	o.mu.Unlock()
	// Nothing to do when no journal waits. This reads the disk, not restorePending: that is written under the
	// write lock by the loops, so reading it here would race (D-138 L2). It also covers a run that failed
	// before this was called and so could not start a retry itself (kickRestore).
	if !o.anyJournal() {
		return
	}
	o.restoreLoop(ctx, l, o.recoverAndFinish)
}

// anyJournal says whether any service has a journal that is not given up on.
func (o *Ops) anyJournal() bool {
	for _, svc := range unitServices {
		if t, st, _ := o.loadJournal(svc); st == jOK && !t.Unrecoverable {
			return true
		}
	}
	return false
}

// recoverAndFinish is one try of the loops: put back the bytes of a journal that is still "pending", then
// the state and the database of what waits. It runs under the write lock.
func (o *Ops) recoverAndFinish(ctx context.Context) {
	o.recoverTransitions(ctx, false)
	o.finishRestores(ctx)
}

// afterFailedRevert is what a run does when it could not put the old release back: a failure that no retry
// can cure (errUnrecoverable) is marked at once (a retry would find the quarantined aside copy and skip the
// sidecar cleanup, D-138 L1); anything else starts the retry loop.
func (o *Ops) afterFailedRevert(ctx context.Context, t transition, rerr error) {
	if errors.Is(rerr, errUnrecoverable) {
		o.markUnrecoverable(t)
		return
	}
	o.kickRestore(ctx)
}

// kickRestore starts the retry loop again after a run left core's data to be put back (its revert failed):
// the loop waits for the write lock, so it starts working when the failed run has released it. It does
// nothing before AfterReady was given a Locker (AfterReady then finds the journal itself), or while a loop is already running.
//
// The run's own context is not used (it ends with the run); the loop runs on the one AfterReady was given.
func (o *Ops) kickRestore(_ context.Context) { //nolint:contextcheck // deliberately the process context AfterReady was given, not the ending run's
	o.mu.Lock()
	ctx, l := o.afterCtx, o.afterL
	o.mu.Unlock()
	if l == nil || !o.kicking.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer o.kicking.Store(false)
		o.restoreLoop(ctx, l, o.recoverAndFinish) // the journal is still "pending": put the bytes back, list what waits
	}()
}

// restoreLoop runs body under the write lock until nothing waits for core's database any more. A
// database that has not been put back is retried slowly and never given up on, unless the failure cannot
// be cured by trying again (errUnrecoverable), which marks the journal and stops the loop (D-138 M2, N1).
func (o *Ops) restoreLoop(ctx context.Context, l Locker, body func(context.Context)) {
	give := time.Now().Add(afterReadyGiveUp)
	backoff := afterReadyRetry
	for ctx.Err() == nil {
		err := l.WithWriteLock(ctx, body)
		switch {
		case err == nil:
			if !o.dbRevertPending() {
				return
			}
			// A database that has not been put back is never given up on (D-138 M2): the write gate refuses
			// every write command meanwhile, so try again, slowly, until it works or the host stops.
			o.log.ErrorContext(ctx, "core's database has not been put back yet; trying again", "in", backoff.String())
			if !o.d.Sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, afterReadyMaxBackoff)
		case !errors.Is(err, server.ErrWriteBusy):
			o.log.ErrorContext(ctx, "could not take the write lock to restore units", "error", err.Error())
			return
		default:
			if time.Now().After(give) && !o.dbRevertPending() {
				return
			}
			if !o.d.Sleep(ctx, afterReadyRetry) {
				return
			}
		}
	}
}

// dbRevertPending says whether a journal of core still has a database to put back (its pre_update backup
// or the files moved aside) and can still be retried. Until it is back, the commands that touch core
// (container.* of core, backup.*) are refused with transition_pending (coreFree); the others run.
func (o *Ops) dbRevertPending() bool {
	t, st, _ := o.loadJournal(api.ServiceCore)
	return st == jOK && t.DBRevert != "" && t.Phase != phaseVerified && !t.Unrecoverable
}

// recoveryNoteEvery is how often a failing recovery of one service audits itself: the first failure, then
// at most once an hour (N5), so a retry loop does not flood the chain.
const recoveryNoteEvery = time.Hour

func (o *Ops) noteRecoveryFailed(svc, command string, detail map[string]any) {
	o.noteLimited(svc, command, "transition_recovery_failed", detail)
}

// noteLimited audits key's line the first time and then at most once an hour.
func (o *Ops) noteLimited(key, command, code string, detail map[string]any) {
	o.mu.Lock()
	if o.recNote == nil {
		o.recNote = map[string]time.Time{}
	}
	now := o.d.Now()
	last, seen := o.recNote[key]
	if seen && now.Sub(last) < recoveryNoteEvery && now.Sub(last) >= 0 {
		o.mu.Unlock()
		return
	}
	o.recNote[key] = now
	o.mu.Unlock()
	o.note(command, code, detail)
}

// forgetRecoveryNotes resets the rate limit of a service after a recovery that worked, so that its next
// failure is audited at once.
func (o *Ops) forgetRecoveryNotes(svc string) {
	o.mu.Lock()
	delete(o.recNote, svc)
	delete(o.recNote, "unrecoverable:"+svc)
	o.mu.Unlock()
}

// markUnrecoverable records that the host stopped trying to put core's data back: the journal says so
// (it stays, so commands for core keep refusing, and nothing retries), core is left as it is, and one audit
// line names what is wrong (names only, never paths of core's data or its content). An operator follows
// the RUNBOOK entry core_data_unrecoverable (WP-32).
func (o *Ops) markUnrecoverable(t transition) {
	t.Unrecoverable = true
	if err := o.saveJournal(t); err != nil {
		o.log.Error("could not record that core's data cannot be put back", "error", err.Error())
	}
	o.log.Error("core's data cannot be put back automatically; the host stopped trying and left core as it is (it may be stopped; systemd starts it again at the next boot, on whatever data is there). See RUNBOOK core_data_unrecoverable", "run_id", t.RunID)
	// One line even if the journal cannot be saved (a full state directory) and this runs again: then at most hourly.
	o.noteLimited("unrecoverable:"+t.Service, t.command(), "core_data_unrecoverable", map[string]any{"service": t.Service, "run_id": t.RunID, "db_revert": t.DBRevert, "aside": t.Aside, "backup_id": t.BackupID})
}

// transitionPendingText is what a 412 transition_pending says (N2).
func transitionPendingText(t transition, valid bool) string {
	switch {
	case valid && t.Unrecoverable:
		return "Core's data could not be put back automatically after an interrupted change, and core is left stopped. See the RUNBOOK entry core_data_unrecoverable; the audit log names the files."
	case valid && t.DBRevert != "":
		return "Core's database is being put back after an interrupted or failed change; the host keeps trying. Try again later."
	}
	return "An earlier change of that unit is still being put right (the host does that at its start, or retries by itself). Try again later."
}

// coreFree refuses with transition_pending while core's journal is waiting for recovery: backups and
// restores must not run on a half-swapped core.
func (o *Ops) coreFree() error {
	if t, st, _ := o.loadJournal(api.ServiceCore); st != jAbsent {
		return refuse412(api.CodeTransitionPending, transitionPendingText(t, st == jOK))
	}
	return nil
}

// finishRestores is the body of AfterReady, under the write lock.
func (o *Ops) finishRestores(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, afterReadyLimit)
	defer cancel()
	if len(o.restorePending) == 0 {
		return
	}
	o.sctl(rctx, reloadLimit, "daemon-reload") // idempotent: Start may not have managed it
	for _, svc := range o.restorePending {
		t, st, _ := o.loadJournal(svc)
		if st != jOK || t.Phase != phaseRestored {
			continue
		}
		detail := map[string]any{"service": svc, "op": t.Op, "run_id": t.RunID, "was_active": t.WasActive}
		text, fs := o.readUnit(svc)
		digest, _, err := parseUnit(svc, text)
		if fs != fileOK || err != nil {
			detail["action"] = "failed"
			o.noteRecoveryFailed(svc, t.command(), detail)
			continue
		}
		if t.Unrecoverable {
			continue // given up on; nothing retries, core stays as it is
		}
		if t.DBRevert != "" && svc == api.ServiceCore {
			// The change moved core's database (a restore from the pre_update backup, or the files moved
			// aside for a rollback): stop core and put it back before the old release starts (D-138).
			if err := o.revertDatabase(rctx, t); err != nil {
				o.log.ErrorContext(ctx, "could not put core's database back after an interrupted change", "error", err.Error())
				detail["action"] = "failed"
				o.noteRecoveryFailed(svc, t.command(), detail)
				if errors.Is(err, errUnrecoverable) {
					o.markUnrecoverable(t) // no retry can cure it: stop, leave core stopped, say so (N1)
				}
				continue
			}
			t.DBRevert = ""
			_ = o.saveJournal(t)
		}
		var ok bool
		if t.WasActive {
			ok = o.runningHealthy(rctx, svc, digest)
			if !ok {
				ok = o.sctl(rctx, restartLimitFor(svc), "restart", unitOf(svc)) && o.waitHealthy(rctx, nil, svc, digest, o.d.HealthWait)
			}
		} else {
			if !isStopped(o.unitActive(rctx, svc)) {
				o.sctl(rctx, stopLimit, "stop", unitOf(svc))
			}
			ok = o.waitStopped(rctx, svc)
		}
		if !ok {
			detail["action"] = "failed"
			o.noteRecoveryFailed(svc, t.command(), detail)
			continue
		}
		o.finishJournal(t)
		o.forgetRecoveryNotes(svc)
		detail["action"] = "reverted"
		o.note(t.command(), "transition_interrupted", detail)
	}
	// What is still waiting for its database stays on the list, so that AfterReady's next try finds it.
	var left []string
	for _, svc := range o.restorePending {
		if t, st, _ := o.loadJournal(svc); st == jOK && t.DBRevert != "" && t.Phase == phaseRestored && !t.Unrecoverable {
			left = append(left, svc)
		}
	}
	o.restorePending = left
}
