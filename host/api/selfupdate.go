package api

// host.self_update (docs/specs/host-api.md section 6.14, D-316): the host upgrades its own .deb to the
// vedette-host package of a signed release that core downloaded into core_data.

// CmdHostSelfUpdate is the command name.
const CmdHostSelfUpdate = "host.self_update"

// Refusal and failure codes of host.self_update (spec 6.14). The signature and index codes are the
// ones of container.pull (containers.go); transition_pending, low_disk, dpkg_locked, dpkg_inconsistent,
// db_unreadable, checksum_mismatch and downgrade_not_allowed are shared with other commands.
const (
	CodeHostVersionUnknown      = "host_version_unknown"     // the running binary has no SemVer version (a dev build)
	CodeNoHostPackage           = "no_host_package"          // the manifest has no host part, or its file entry is out of range
	CodeTestVersionRefused      = "test_version_refused"     // a -test. host version, a build that does not trust the test keys, on a host that is not itself a test build
	CodeCurrentPackageMissing   = "current_package_missing"  // versions.json, the binary and dpkg do not agree, or the kept .deb of the running version is gone
	CodePackageMissing          = "package_missing"          // core's file host-packages/<package>.deb is not there
	CodePackageInvalid          = "package_invalid"          // core's file is not a plain file of core, or its size is not the manifest's
	CodePackageMismatch         = "package_mismatch"         // dpkg-deb names another package, version or architecture
	CodeDependenciesUnavailable = "dependencies_unavailable" // apt cannot install it without removing or upgrading something else
	CodeApplierFailed           = "applier_failed"           // the copy of the binary or the start of the transient unit failed
	CodePackageChanged          = "package_changed"          // the applier found a staged or kept .deb that is not the one the journal names
	CodeSelfUpdateUnhealthy     = "self_update_unhealthy"    // the new host did not prove itself healthy; the previous one is back
	CodeInstallFailed           = "install_failed"           // apt or dpkg failed; the previous one is back
	CodeRollbackFailed          = "rollback_failed"          // putting the previous one back failed too: RUNBOOK
	CodeSelfUpdateInterrupted   = "self_update_interrupted"  // the applier died twice, or would outlive the deadline: RUNBOOK
)

// HostSelfUpdateArgs are the args of host.self_update. Index, IndexSig, Manifest and ManifestSig are
// standard padded base64 as for container.pull; Package is the 32-hex id of the file core wrote at
// <core_data>/host-packages/<package>.deb. No path, URL or hash is taken from the request.
type HostSelfUpdateArgs struct {
	Version     string `json:"version"`
	Index       string `json:"index"`
	IndexSig    string `json:"index_sig"`
	Manifest    string `json:"manifest"`
	ManifestSig string `json:"manifest_sig"`
	Package     string `json:"package"`
}

// HostSelfUpdateResult is the result of host.self_update. Changed is false when the release's host
// version is the running one (nothing was touched). RolledBackTo is set when the previous version was
// put back.
type HostSelfUpdateResult struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Changed      bool   `json:"changed"`
	SHA256       string `json:"sha256"`
	RolledBackTo string `json:"rolled_back_to,omitempty"`
}

// HostVersionRef names one version of the host package.
type HostVersionRef struct {
	Version string `json:"version"`
}

// HostUpdate is a self-update the journal says is under way.
type HostUpdate struct {
	RunID string `json:"run_id"`
	Phase string `json:"phase"`
	To    string `json:"to"`
}

// HostState is the body of GET /v1/state/host. A field whose file is damaged is null (and logged).
type HostState struct {
	Version      string          `json:"version"`
	Previous     *HostVersionRef `json:"previous"`
	PackagesKept []string        `json:"packages_kept"`
	Update       *HostUpdate     `json:"update"`
}
