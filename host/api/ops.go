package api

import "time"

// Arguments and results of the system commands (docs/specs/host-api.md section 6), shared by
// host/ops (which runs them) and host/client (which core calls them with).

// Command names (spec section 6).
const (
	CmdOSCheck           = "os.check"
	CmdOSInstall         = "os.install"
	CmdOSAutoSecuritySet = "os.auto_security.set"
	CmdOSReboot          = "os.reboot"
	CmdOSRebootCancel    = "os.reboot.cancel"
	CmdBackupCreate      = "backup.create"
	CmdBackupRestore     = "backup.restore"
	CmdLogsExport        = "logs.export"
)

// Refusal and failure codes of the system commands (spec sections 6 and 11).
const (
	CodeNotAppliance        = "not_appliance"
	CodeDpkgLocked          = "dpkg_locked"
	CodeDpkgInconsistent    = "dpkg_inconsistent"
	CodeLowDisk             = "low_disk"
	CodeStaleCheck          = "stale_check"
	CodeAptFailed           = "apt_failed"
	CodeHealthCheckFailed   = "health_check_failed"
	CodeInstallInProgress   = "install_in_progress"
	CodeNetPendingConfirm   = "net_pending_confirm"
	CodeAtInPast            = "at_in_past"
	CodeAtTooFar            = "at_too_far"
	CodeRebootLimit         = "reboot_limit_reached"
	CodeDBUnreadable        = "db_unreadable"
	CodeBackupUnknown       = "backup_unknown"
	CodeChecksumMismatch    = "checksum_mismatch"
	CodeSchemaNewer         = "schema_newer"
	CodeSecretsMissing      = "secrets_missing"
	CodeContainsSecrets     = "contains_secrets"
	CodeRestoreFailed       = "restore_failed"
	CodeRestoreHealthFailed = "restore_health_failed"
	CodeRangeTooLarge       = "range_too_large"
	CodeUnitUnknown         = "unit_unknown"
	CodeOutputTooLarge      = "output_too_large"
	CodeNoCheckYet          = "no_check_yet"
	CodeExportUnknown       = "export_unknown"
	CodeEffectNotVerified   = "effect_not_verified"
	CodeSnapshotRequired    = "snapshot_required"
	CodeSnapshotInvalid     = "snapshot_invalid"
	CodeRebooting           = "rebooting"
)

// OSInstallArgs are the args of os.install.
type OSInstallArgs struct {
	Scope string `json:"scope"` // "security" | "all"
	// Snapshot is the id (32 hex) of the snapshot core wrote to <core_data>/snapshots/<id>/ just
	// before the call; the host copies it into the pre_os_update backup (spec 6.11, D-87).
	Snapshot string `json:"snapshot"`
}

// OSAutoSecurityArgs are the args of os.auto_security.set.
type OSAutoSecurityArgs struct {
	Enabled bool `json:"enabled"`
}

// OSRebootArgs are the args of os.reboot. At is RFC 3339 UTC, required (and only allowed) for When "at".
type OSRebootArgs struct {
	When string `json:"when"` // "now" | "at"
	At   string `json:"at,omitempty"`
}

// BackupCreateArgs are the args of backup.create.
type BackupCreateArgs struct {
	Kind           string `json:"kind"` // manual | pre_update | pre_os_update | pre_restore
	IncludeSecrets bool   `json:"include_secrets"`
	Label          string `json:"label,omitempty"`
	// Snapshot is the id (32 hex) of the snapshot core wrote to <core_data>/snapshots/<id>/ just
	// before the call (spec 6.11, D-87): the host never opens core's database, it copies this one.
	Snapshot string `json:"snapshot"`
}

// BackupRestoreArgs are the args of backup.restore.
type BackupRestoreArgs struct {
	BackupID string `json:"backup_id"`
	// Snapshot is a snapshot of the state core has right now (spec 6.11): the host keeps it as the
	// pre_restore backup, the way back if the restore does not work.
	Snapshot string `json:"snapshot"`
}

// LogsExportArgs are the args of logs.export. Since and Until are RFC 3339.
type LogsExportArgs struct {
	Units []string `json:"units"`
	Since string   `json:"since"`
	Until string   `json:"until"`
}

// OSPackage is one pending upgrade. CVEs is empty: the host does not know them (core adds them).
type OSPackage struct {
	Name     string   `json:"name"`
	Current  string   `json:"current"`
	New      string   `json:"new"`
	Security bool     `json:"security"`
	Origin   string   `json:"origin"`
	CVEs     []string `json:"cves"`
}

// OSDetails is the os part of OSState (fields of the GUI's OsInfo that the host knows).
type OSDetails struct {
	Distro      string    `json:"distro"`
	Name        string    `json:"name"`
	Release     string    `json:"release"`
	Kernel      string    `json:"kernel"`
	SupportEnd  string    `json:"support_end"`
	ExtendedEnd *string   `json:"extended_end"`
	BootedAt    time.Time `json:"booted_at"`
	LastCheck   time.Time `json:"last_check"`
	Mirrors     []string  `json:"mirrors"`
}

// OSState is the result of os.check and the body of GET /v1/state/os: what the host knows of the
// operating system. Core adds what only it knows (maintenance window, release_upgrade guidance, busy).
type OSState struct {
	OS                OSDetails   `json:"os"`
	Pending           []OSPackage `json:"pending"`
	SecurityCount     int         `json:"security_count"`
	RebootRequired    bool        `json:"reboot_required"`
	RebootReasons     []string    `json:"reboot_reasons"`
	RebootScheduledAt *time.Time  `json:"reboot_scheduled_at"`
	AutoSecurity      bool        `json:"auto_security"`
	LastCheck         time.Time   `json:"last_check"`
}

// Health is one check after an install or a restore.
type Health struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

// OSRunResult is the result of os.install (the GUI's OsRunResult). Backup is "" when there was
// nothing to install and so no backup was needed.
type OSRunResult struct {
	Installed      int      `json:"installed"`
	Security       int      `json:"security"`
	Backup         string   `json:"backup"`
	Health         []Health `json:"health"`
	RebootRequired bool     `json:"reboot_required"`
}

// OSAutoSecurityResult is the result of os.auto_security.set: what was read back.
type OSAutoSecurityResult struct {
	Enabled bool `json:"enabled"`
}

// OSRebootResult is the result of os.reboot. At is set when a reboot was scheduled.
type OSRebootResult struct {
	When string     `json:"when"`
	At   *time.Time `json:"at,omitempty"`
}

// BackupResult is the result of backup.create.
type BackupResult struct {
	BackupID string `json:"backup_id"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// BackupRestoreResult is the result of backup.restore.
type BackupRestoreResult struct {
	RestoredBackupID   string   `json:"restored_backup_id"`
	PreRestoreBackupID string   `json:"pre_restore_backup_id"`
	Version            int      `json:"version"`
	Health             []Health `json:"health"`
}

// Backup is one entry of GET /v1/state/backups.
type Backup struct {
	BackupID        string    `json:"backup_id"`
	Kind            string    `json:"kind"`
	Label           string    `json:"label,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	Version         int       `json:"version"`
	DBSchema        string    `json:"db_schema"`
	IncludesSecrets bool      `json:"includes_secrets"`
	Downloadable    bool      `json:"downloadable"`
}

// BackupList is the body of GET /v1/state/backups.
type BackupList struct {
	Backups []Backup `json:"backups"`
}

// LogsExportResult is the result of logs.export.
type LogsExportResult struct {
	ExportID string `json:"export_id"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Lines    int    `json:"lines"`
}
