// Package api holds the wire types of the vedette-host socket API (docs/specs/host-api.md),
// shared by host/server and host/client so the two cannot drift apart.
package api

import (
	"encoding/json"
	"time"
)

// Proto is the protocol number this build speaks; MinProto is the oldest it still accepts
// (N and N-1, spec section 13). Version 1 is the first, so both are 1.
const (
	Proto    = 1
	MinProto = 1
)

// Header names (spec section 3).
const (
	HeaderRequestID = "X-Request-Id"
	HeaderActor     = "X-Vedette-Actor"
	HeaderProto     = "X-Vedette-Host-Proto"
)

// Status is the state of a Run.
type Status string

// Run statuses (spec section 4).
const (
	StatusQueued          Status = "queued"
	StatusRunning         Status = "running"
	StatusAwaitingConfirm Status = "awaiting_confirm"
	StatusSucceeded       Status = "succeeded"
	StatusFailed          Status = "failed"
	StatusReverted        Status = "reverted"
	StatusRefused         Status = "refused"
)

// Terminal reports whether no further transition happens.
func (s Status) Terminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusReverted, StatusRefused:
		return true
	case StatusQueued, StatusRunning, StatusAwaitingConfirm:
		return false
	}
	return false
}

// Error codes (spec section 11). Command-specific refusal codes (low_disk, ...) live with the commands.
const (
	CodeInvalidArgs      = "invalid_args"
	CodeInvalidRequestID = "invalid_request_id"
	CodeInvalidActor     = "invalid_actor"
	CodePeerNotAllowed   = "peer_not_allowed"
	CodeUnknownCommand   = "unknown_command"
	CodeRunNotFound      = "run_not_found"
	CodeBusy             = "busy"
	// CodePendingConfirm is 409: a run is awaiting confirmation and holds the write lock (spec 4,
	// D-100); the error carries that run's id. CodeNotAwaitingConfirm is 412: the run id of a
	// net.confirm or net.revert is not the run that is waiting (finished, expired or unknown).
	CodePendingConfirm     = "pending_confirm"
	CodeNotAwaitingConfirm = "not_awaiting_confirm"
	CodeRequestIDReuse     = "request_id_reuse"
	CodeRateLimited        = "rate_limited"
	CodeShuttingDown       = "host_shutting_down"
	CodeAuditUnavailable   = "audit_unavailable"
	CodeHostRestarted      = "host_restarted"
	CodeTimeout            = "timeout"
	CodeCommandFailed      = "command_failed"
	CodeInternal           = "internal"
	CodeHostWedged         = "host_wedged"
)

// Detail points at one bad field.
type Detail struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// ErrorBody is the body of every non-2xx response: {"error":{...}}.
type ErrorBody struct {
	Error ErrorInfo `json:"error"`
}

// ErrorInfo is the error object. RunID is set for busy (the run in progress) and for pending_confirm
// (the run that is waiting for confirmation); RetryAfterS for rate_limited.
type ErrorInfo struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Details     []Detail `json:"details,omitempty"`
	RunID       string   `json:"run_id,omitempty"`
	RetryAfterS int      `json:"retry_after_s,omitempty"`
}

// RunError is the error of a failed or refused Run.
type RunError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Run is one command invocation (spec section 4).
type Run struct {
	RunID      string          `json:"run_id"`
	Command    string          `json:"command"`
	Status     Status          `json:"status"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Actor      string          `json:"actor"`
	RequestID  string          `json:"request_id"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      *RunError       `json:"error,omitempty"`
	RevertAt   *time.Time      `json:"revert_at,omitempty"`
	// ParkedDeadline is set while a running run is parked (server.Parked, D-316): the run outlives
	// the host process, and its command's own code ends it (server.SettleParked) by then.
	ParkedDeadline *time.Time `json:"parked_deadline,omitempty"`
	AuditID        string     `json:"audit_id"`
}

// RunList is the body of GET /v1/runs.
type RunList struct {
	Runs []Run `json:"runs"`
}

// CommandRequest is the body of POST /v1/commands/{name}. It carries arguments only:
// no binary, no argv, no path (INV-1).
type CommandRequest struct {
	Args json.RawMessage `json:"args"`
}

// Event kinds.
const (
	KindLog      = "log"
	KindProgress = "progress"
	KindState    = "state"
)

// Event is one SSE event of a run. Truncated is true when older events were dropped.
type Event struct {
	Seq       uint64    `json:"seq"`
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	Line      string    `json:"line,omitempty"`
	Percent   *int      `json:"percent,omitempty"`
	Status    Status    `json:"status,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
}

// OSInfo is the os part of Info.
type OSInfo struct {
	Distro  string `json:"distro"`
	Release string `json:"release"`
	Kernel  string `json:"kernel"`
}

// Info is the body of GET /v1/info.
type Info struct {
	HostVersion string    `json:"host_version"`
	Proto       int       `json:"proto"`
	Commands    []string  `json:"commands"`
	Runner      string    `json:"runner"`
	OS          OSInfo    `json:"os"`
	Arch        string    `json:"arch"`
	BootedAt    time.Time `json:"booted_at"`
	Time        time.Time `json:"time"`
	AuditOK     bool      `json:"audit_ok"`
}

// AuditPeer identifies the caller of a command.
type AuditPeer struct {
	UID  int    `json:"uid"`
	PID  int    `json:"pid"`
	Unit string `json:"unit"`
}

// AuditRecord is one line of audit.jsonl as served by GET /v1/audit. Unknown fields a newer
// host adds are kept out of this view but stay in the chain.
type AuditRecord struct {
	Seq          int64           `json:"seq"`
	ID           string          `json:"id"`
	TS           string          `json:"ts"`
	RequestID    string          `json:"request_id"`
	Actor        string          `json:"actor"`
	Peer         AuditPeer       `json:"peer"`
	Command      string          `json:"command"`
	ArgsDigest   string          `json:"args_digest"`
	ArgsRedacted json.RawMessage `json:"args_redacted"`
	Result       string          `json:"result"`
	Code         *string         `json:"code"`
	RunID        *string         `json:"run_id"`
	PrevHash     string          `json:"prev_hash"`
	Hash         string          `json:"hash"`
}

// AuditPage is the body of GET /v1/audit. Next is the value to pass as `since` for the following page ("" at the end).
type AuditPage struct {
	Records []AuditRecord `json:"records"`
	Next    string        `json:"next,omitempty"`
}
