package api

import "regexp"

// container.start, container.stop and GET /v1/state/containers (docs/specs/host-api.md sections 5,
// 6.8 and 6.9, D-104, D-105, D-123).

// Commands of the container part (slice 3-6 start and stop, slice 3-7 pull, slice 3-8a start with a
// version and rollback).
const (
	CmdContainerStart    = "container.start"
	CmdContainerStop     = "container.stop"
	CmdContainerPull     = "container.pull"
	CmdContainerRollback = "container.rollback"
)

// The services (spec section 6): the closed set a service argument may name.
const (
	ServiceCore      = "core"
	ServiceSensor    = "sensor"
	ServiceHoneypot  = "honeypot"
	ServiceScan      = "scan"
	ServiceGreenbone = "greenbone"
)

// Services lists every service in the order the state endpoint reports them.
var Services = []string{ServiceCore, ServiceSensor, ServiceHoneypot, ServiceScan, ServiceGreenbone}

// Codes of the container commands: refusals (HTTP 412) and the codes a run can end with.
const (
	// CodeNotPulled: there is no installed image to start (a unit with a pinned digest), or a
	// version was named but switching versions arrives with container.pull (slice 3-7).
	CodeNotPulled = "not_pulled"
	// CodeCannotStopCore: container.stop would kill the caller (spec 6.9).
	CodeCannotStopCore = "cannot_stop_core"
	// CodeUnitFailed ends a run as reverted: the new unit did not become healthy and the previous one
	// was put back; as failed when the previous one could not be put back either.
	CodeUnitFailed = "unit_failed"
	// CodeUnitUnsafe: the Quadlet directory, one of its parents, or the unit file is not what a root
	// write may touch (a link, another owner, open to group or others).
	CodeUnitUnsafe = "unit_unsafe"
	// CodeUnitUnwritable: the unit could not be written, or systemd would not reload or restart it.
	CodeUnitUnwritable = "unit_unwritable"
	// CodeStopNotVerified: systemctl is-active did not say inactive after the stop.
	CodeStopNotVerified = "stop_not_verified"
	// CodeTransitionPending: an earlier change of that unit left a journal that has not been recovered
	// yet (the host recovers at its next start); container commands for the service wait.
	CodeTransitionPending = "transition_pending"
	// CodeHostConfIncomplete: the unit needs a uid or gid that host.conf did not give the host.
	CodeHostConfIncomplete = "host_conf_incomplete"
	// CodePortInUse (412, container.start and container.rollback): the unit the command would write publishes a host port that the
	// unit on disk does not, and another program listens on it, so the service would not start; nothing was changed (D-455).
	CodePortInUse = "port_in_use"

	// Refusals of container.pull (spec 6.7, D-104, D-130): what the host's own verification found.
	CodeSignatureInvalid    = "signature_invalid"      // a document or a cosign signature does not verify, or does not parse
	CodeKeyRevoked          = "key_revoked"            // the signing key is revoked by the stored index
	CodeReleaseRevoked      = "release_revoked"        // the release version or an image digest is revoked
	CodeDigestNotInManifest = "digest_not_in_manifest" // the manifest has no image for that service
	CodeRegistryNotAllowed  = "registry_not_allowed"   // an image ref is not the fixed registry ref
	CodeSequenceRegress     = "sequence_regress"       // the index is older than the stored one
	CodePlatformMismatch    = "platform_mismatch"      // no image for linux/<GOARCH>
	CodeManifestMismatch    = "manifest_mismatch"      // version differs from the args, or the hash differs from the index
	CodeBundleUnsupported   = "bundle_unsupported"     // source=bundle on a host older than D-452 (this host no longer sends it)
	CodeNoTrustedKeys       = "no_trusted_keys"        // this build embeds no release keys: it refuses everything (D-130)
	CodeReleaseStateInvalid = "release_state_invalid"  // the stored index is damaged: the host will not guess (D-130)
	CodePullFailed          = "pull_failed"            // run ended failed: podman could not pull or tag
	// CodeScanBuildFailed ends a container.pull of scan as failed: the signed base image was pulled and verified, but the image with
	// nmap that the host builds on the box from it was not (no package mirror, a build error, or nmap below the floor). The previous
	// localhost/vedette-scan-nmap image, if any, is untouched and the previous unit keeps running (D-147).
	CodeScanBuildFailed = "scan_build_failed"

	// Codes of container.pull with source=bundle (spec 6.7, D-452). The bundle is <core_data>/bundles/<bundle_id>.tar.
	// CodeBundleNotFound (412): core has not written that bundle (or core_data is not set or not safe to read).
	CodeBundleNotFound = "bundle_not_found"
	// CodeBundleInvalid: the file or the tar is not what the bundle contract allows (a link, not core's, over 8 GiB, a name
	// outside the closed list, a link or device entry, a member over its cap, a duplicate, a missing document or image, an
	// image archive that is not a complete OCI layout). 412 when Check finds it, a failed run when the run does.
	CodeBundleInvalid = "bundle_invalid"
	// CodeArchiveDigestMismatch ends a bundle pull as failed: the image archive is not the image the signed manifest names
	// (its index.json names another digest, or a blob does not hash to its name).
	CodeArchiveDigestMismatch = "archive_digest_mismatch"

	// Refusals of container.start with a version and of container.rollback (spec 6.8, 6.10, D-104, D-138).
	CodeDowngradeNotAllowed   = "downgrade_not_allowed"   // the version is lower than the running one: going back is container.rollback
	CodeUpgradePathRequired   = "upgrade_path_required"   // the running version is below the target's min_upgrade_from
	CodeNoPrevious            = "no_previous"             // nothing to roll back to (or its image is gone)
	CodePreviousRevoked       = "previous_revoked"        // the previous version, its image digest or its signing key is revoked
	CodeRollbackNotAllowed    = "rollback_not_allowed"    // the previous version is below the running release's rollback.min_version
	CodeRollbackBackupMissing = "rollback_backup_missing" // rollback.safe=false and the pre_update backup of the transition is gone
	CodeRollbackIsUpgrade     = "rollback_is_upgrade"     // core: the previous version is higher than the running one: use container.start with a version and a snapshot
	CodeCoreDataInvalid       = "core_data_invalid"       // an entry of core's data directory that a rollback would move is not a regular file
	CodeCurrentVersionUnknown = "current_version_unknown" // the running version is not recorded (bootstrap 3-8b writes it), so a switch cannot be judged
	// CodeRollbackRevertFailed ends a rollback as failed: it did not work and putting the running release back failed too.
	CodeRollbackRevertFailed = "rollback_revert_failed"
	// CodeEffectNotVerified (api/ops.go) ends a pull whose podman image inspect did not show the digest.
)

// ContainerStartArgs are the args of container.start. Version is semver and names an image that
// container.pull verified on this host (without it: the current image). Snapshot is the id of a
// snapshot core wrote: core must send one with a version (the host makes the pre_update backup from
// it when the digest changes), and no other service may.
type ContainerStartArgs struct {
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
	Restart  bool   `json:"restart,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
}

// ContainerStopArgs are the args of container.stop. Persist rewrites the unit without its
// [Install] section so the service stays down after a reboot.
type ContainerStopArgs struct {
	Service string `json:"service"`
	Persist bool   `json:"persist"`
}

// ContainerStartResult is the result of container.start. Version is null for a start without a
// version; Restarted is false when the service already ran the right image and was healthy.
// PreviousDigest is the digest the service ran before a switch. BackupID is the pre_update backup
// core's switch made. IndexExpired says the index the version was checked against is past its
// expires_at: the caller shows it (D-130).
type ContainerStartResult struct {
	Service        string  `json:"service"`
	Version        *string `json:"version"`
	Digest         string  `json:"digest"`
	PreviousDigest *string `json:"previous_digest"`
	Healthy        bool    `json:"healthy"`
	Restarted      bool    `json:"restarted"`
	BackupID       *string `json:"backup_id,omitempty"`
	IndexExpired   bool    `json:"index_expired,omitempty"`
}

// ContainerRollbackArgs are the args of container.rollback: only the service. The target is always the
// stored previous version.
type ContainerRollbackArgs struct {
	Service string `json:"service"`
}

// ContainerRollbackResult is the result of container.rollback. RestoredBackupID is the pre_update
// backup that was restored (core, when the release it left says rollback.safe=false).
type ContainerRollbackResult struct {
	Digest           string  `json:"digest"`
	FromDigest       string  `json:"from_digest"`
	RestoredBackupID *string `json:"restored_backup_id,omitempty"`
}

// ContainerPullArgs are the args of container.pull (spec 6.7). Index and Manifest are the signed
// documents, base64, with their minisign signatures (each at most 256 KiB decoded); the host
// verifies them itself and never takes an image reference, a digest or a path from here. With
// source=bundle the four documents are not sent: the host reads them from the bundle core wrote at
// <core_data>/bundles/<bundle_id>.tar (D-452).
type ContainerPullArgs struct {
	Service     string `json:"service"`
	Version     string `json:"version"`
	Source      string `json:"source"` // "registry" | "bundle"
	BundleID    string `json:"bundle_id,omitempty"`
	Index       string `json:"index,omitempty"`
	IndexSig    string `json:"index_sig,omitempty"`
	Manifest    string `json:"manifest,omitempty"`
	ManifestSig string `json:"manifest_sig,omitempty"`
}

// Sources of container.pull.
const (
	PullSourceRegistry = "registry"
	PullSourceBundle   = "bundle"
)

// ContainerPullResult is the result of container.pull: the verified digest, the size the manifest
// declares, and the checks that passed.
type ContainerPullResult struct {
	Digest   string   `json:"digest"`
	Size     int64    `json:"size"`
	Verified []string `json:"verified"` // ["minisign","cosign"]
	// IndexExpired says the index this pull was verified with is past its expires_at. An old index only
	// warns (D-104); the caller shows it (D-130).
	IndexExpired bool `json:"index_expired"`
}

// ContainerStopResult is the result of container.stop. Changed is false when the service was
// already stopped and the unit already in the asked state.
type ContainerStopResult struct {
	Service string `json:"service"`
	Persist bool   `json:"persist"`
	Changed bool   `json:"changed"`
}

// Unit states (systemctl is-active) and health (podman) as the state endpoint reports them.
const (
	UnitActive   = "active"
	UnitInactive = "inactive"
	UnitFailed   = "failed"
	UnitOther    = "other"
	UnitUnknown  = "unknown"

	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthStarting  = "starting"
	HealthNone      = "none" // no container, or one without a health check
	HealthUnknown   = "unknown"
)

// ContainerVersion is a version and digest pair. Version is null until container.pull records it.
type ContainerVersion struct {
	Version *string `json:"version"`
	Digest  string  `json:"digest"`
}

// ContainerState is one service in GET /v1/state/containers. Installed says a unit with a pinned
// digest exists; ConfiguredDigest is the digest in that unit and Digest the one the running
// container reports (null when no container exists), so a unit that was changed but not restarted
// shows. Version and Previous come from the versions the host recorded (null when it knows none);
// LatestPulled is the version container.pull verified last.
type ContainerState struct {
	Service          string            `json:"service"`
	Installed        bool              `json:"installed"`
	Version          *string           `json:"version"`
	Digest           *string           `json:"digest"`
	ConfiguredDigest *string           `json:"configured_digest"`
	Previous         *ContainerVersion `json:"previous"`
	LatestPulled     *ContainerVersion `json:"latest_pulled"`
	Enabled          bool              `json:"enabled"`
	UnitState        string            `json:"unit_state"`
	Health           string            `json:"health"`
}

// ContainersState is the body of GET /v1/state/containers.
type ContainersState struct {
	Services []ContainerState `json:"services"`
}

// portsInUseRE is the head of the port_in_use message (host/ops/hostports.go portsFree): "Port 8765/tcp (python3, pid 4242) is in
// use by another program on this machine." or "Ports 8765/tcp (python3, pid 4242), 6514/tcp are in use ...".
var portsInUseRE = regexp.MustCompile(`^(Ports?) ([0-9]{1,5}/(?:tcp|udp)[ -~]{0,480}?) (?:is|are) in use by another program on this machine\.`)

// PortsInUse reads the ports, and the program holding each when the host found it in /proc (name from comm, printable ASCII,
// at most 15 characters, and pid), out of a port_in_use message, for core to show (D-412). list is printable ASCII, plural
// is true for more than one port, ok is false for a message of another shape.
func PortsInUse(msg string) (list string, plural, ok bool) {
	m := portsInUseRE.FindStringSubmatch(msg)
	if m == nil {
		return "", false, false
	}
	return m[2], m[1] == "Ports", true
}
