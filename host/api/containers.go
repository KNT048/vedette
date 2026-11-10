package api

// container.start, container.stop and GET /v1/state/containers (docs/specs/host-api.md sections 5,
// 6.8 and 6.9, D-104, D-105, D-123).

// Commands of the container part (slice 3-6; container.pull and container.rollback come later).
const (
	CmdContainerStart = "container.start"
	CmdContainerStop  = "container.stop"
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
	// CodeHostConfIncomplete: the unit needs a uid or gid that host.conf did not give the host.
	CodeHostConfIncomplete = "host_conf_incomplete"
)

// ContainerStartArgs are the args of container.start. Version is semver and names a pulled image:
// until container.pull exists (slice 3-7) a start with a version is refused with not_pulled.
// Snapshot is the id of a snapshot core wrote; it only matters when the digest changes, which a
// start without a version never does, so it is accepted for core and refused for the others.
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

// ContainerStartResult is the result of container.start. Version is null until container.pull
// records versions; Restarted is false when the service already ran the right image and was healthy.
type ContainerStartResult struct {
	Service        string  `json:"service"`
	Version        *string `json:"version"`
	Digest         string  `json:"digest"`
	PreviousDigest *string `json:"previous_digest"`
	Healthy        bool    `json:"healthy"`
	Restarted      bool    `json:"restarted"`
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
// shows. Previous and LatestPulled are null until container.pull and container.rollback exist.
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
