package notify

import (
	"context"
	"errors"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The wire shapes below carry the JSON names of web/src/features/notify/contract.ts. Times are
// store.FormatTS strings (UTC, milliseconds, Z), which is what the API sends.

// TestResult is the outcome of the last test message of a channel.
type TestResult struct {
	At     string `json:"at"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Approver is a Vedette user who may approve actions from a channel, with the address on that channel.
type Approver struct {
	UserID  string `json:"user_id"`
	Address string `json:"address"`
}

// ApprovalLast4 holds the last 4 characters of the Slack Socket Mode tokens (never the tokens).
type ApprovalLast4 struct {
	AppToken *string `json:"app_token"`
	BotToken *string `json:"bot_token"`
}

// Channel is one channel as the API shows it (INV-1: only secret_last4 and approval_last4).
type Channel struct {
	Type          channel.Type      `json:"type"`
	Configured    bool              `json:"configured"`
	Enabled       bool              `json:"enabled"`
	Fields        map[string]string `json:"fields"`
	SecretLast4   *string           `json:"secret_last4"`
	MinSeverity   Severity          `json:"min_severity"`
	LastTest      *TestResult       `json:"last_test"`
	Approvals     bool              `json:"approvals"`
	Approvers     []Approver        `json:"approvers"`
	ApprovalLast4 ApprovalLast4     `json:"approval_last4"`
}

// ChannelInput is the body of PUT /notify/channels/{type}. An empty secret, AppToken or BotToken keeps the saved one.
type ChannelInput struct {
	Enabled     bool
	Fields      map[string]string
	Secret      string
	MinSeverity Severity
	Approvals   bool
	Approvers   []Approver
	AppToken    string
	BotToken    string
}

// Rules is the quiet-hours and grouping rule pair.
type Rules struct {
	Quiet    Quiet    `json:"quiet"`
	Grouping Grouping `json:"grouping"`
}

// ChannelsView is the answer of GET /notify/channels.
type ChannelsView struct {
	Channels       []Channel `json:"channels"`
	Quiet          Quiet     `json:"quiet"`
	Grouping       Grouping  `json:"grouping"`
	EmailCodeUsers int       `json:"email_code_users"`
}

// SendView is one delivery attempt as the API shows it.
type SendView struct {
	ID      string       `json:"id"`
	Channel channel.Type `json:"channel"`
	To      string       `json:"to"`
	At      string       `json:"at"`
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
}

// HistoryItem is a SendView with what it was about.
type HistoryItem struct {
	SendView
	Kind string `json:"kind"` // incident | vuln | approval
	What string `json:"what"`
	Link string `json:"link"`
}

// HistoryView is the answer of GET /notify/history. Suppressed counts the new vulnerabilities that
// matched no device in the last Days days (INV-2): they were not sent.
type HistoryView struct {
	Items      []HistoryItem `json:"items"`
	Suppressed struct {
		Count int `json:"count"`
		Days  int `json:"days"`
	} `json:"suppressed"`
}

// IncidentKind is what an incident is about (INV-10). There is no vulnerability kind: those are findings.
type IncidentKind string

// The four incident kinds.
const (
	IncidentTrap          IncidentKind = "trap"
	IncidentBadAddress    IncidentKind = "bad_address"
	IncidentLogAnomaly    IncidentKind = "log_anomaly"
	IncidentUnknownDevice IncidentKind = "unknown_device"
)

// Valid reports whether k is one of the four kinds.
func (k IncidentKind) Valid() bool {
	switch k {
	case IncidentTrap, IncidentBadAddress, IncidentLogAnomaly, IncidentUnknownDevice:
		return true
	}
	return false
}

// IncidentStatus is the handling state of an incident.
type IncidentStatus string

// The three incident states; a person can move an incident to any of them (reopening is "new").
const (
	StatusNew          IncidentStatus = "new"
	StatusAcknowledged IncidentStatus = "acknowledged"
	StatusResolved     IncidentStatus = "resolved"
)

// Device names a device of an incident. ID is the inventory asset id.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Incident is one incident as the API shows it.
type Incident struct {
	ID        string         `json:"id"`
	Kind      IncidentKind   `json:"kind"`
	Title     string         `json:"title"`
	Link      string         `json:"link"`
	Devices   []Device       `json:"devices"`
	Severity  Severity       `json:"severity"`
	What      string         `json:"what"`
	Action    string         `json:"action"`
	FirstSeen string         `json:"first_seen"`
	LastSeen  string         `json:"last_seen"`
	Count     int            `json:"count"`
	Status    IncidentStatus `json:"status"`
	HandledBy *string        `json:"handled_by"`
	HandledAt *string        `json:"handled_at"`
	Note      *string        `json:"note"`
	Sends     []SendView     `json:"sends"`
}

// Preview is what one channel received (or would receive) for an incident.
type Preview struct {
	Channel channel.Type `json:"channel"`
	Subject string       `json:"subject,omitempty"`
	Text    string       `json:"text"`
}

// IncidentDetail is the answer of GET and PATCH /notify/incidents/{id}.
type IncidentDetail struct {
	Incident Incident  `json:"incident"`
	Previews []Preview `json:"previews"`
}

// IncidentInput is what a producer (honeypot, logs, inventory) gives OpenIncident (PRE-2).
// Source and Target make the dedupe key with Kind (INV-10): the same thing happening again is one incident.
type IncidentInput struct {
	Kind     IncidentKind
	Source   string // who did it, e.g. the source IP
	Target   string // what it touched, e.g. the trap or the destination
	Title    string // one plain sentence: who did what
	Severity Severity
	What     string
	Action   string
	Link     string // where to see the source, a path inside Vedette: /honeypot/hits/<id>, /logs, /devices/<id>
	Devices  []Device
	At       time.Time // zero = now
}

// ---- what notify needs from the rest of the box (small interfaces, faked in tests) ----

// User is a Vedette user as notify needs to see one (INV-7).
type User struct {
	ID     string
	Email  string
	Role   string // viewer | operator | admin
	Active bool
}

// Users is implemented by the code that owns users (core/auth, Kiên). notify never reads core tables.
type Users interface {
	// Lookup returns the user, or found=false when there is none.
	Lookup(ctx context.Context, id string) (u User, found bool, err error)
	// EmailCodeUsers counts the active users who sign in with a two-step code sent by email (INV-9).
	EmailCodeUsers(ctx context.Context) (int, error)
}

// ModuleGate says whether a module is on (modreg.Registry satisfies it).
type ModuleGate interface{ Enabled(id string) bool }

// Bus is the part of core/events.Bus notify uses. A nil Bus drops events.
type Bus interface {
	Publish(ctx context.Context, e events.Event) error
	Subscribe(name string, fn events.Handler) (unsubscribe func())
	Flush(ctx context.Context, o *events.Outbox)
}

// FindingInfo describes a finding for a notice. The findings module implements FindingDirectory.
type FindingInfo struct {
	CVE      string
	Product  string
	Severity Severity
	Title    string // one plain sentence
	What     string
	Action   string
	Devices  []string // names of the devices the finding matched; empty = it matched none
}

// FindingDirectory looks a finding up by id. Without one, finding events cannot become notices.
type FindingDirectory interface {
	Finding(ctx context.Context, id string) (FindingInfo, bool, error)
}

// DeviceDirectory names a device by inventory id. Without one, device events show the id.
type DeviceDirectory interface {
	DeviceName(ctx context.Context, assetID string) (string, bool, error)
}

// TokenRecorder stores an approval token record (spec approval-tokens.md 4.1: the record in the
// database is the source of truth). The response module implements it; notify mints the token but
// never keeps the record, so without a recorder email approvers get a message that says to open Vedette, not a link.
type TokenRecorder interface {
	// address is where the link was sent (the approver's email): the record carries it (spec 4.1, 4.2).
	RecordToken(ctx context.Context, id TokenID, b Binding, keyID, address string) error
}

// Errors of the service that are not API errors.
var (
	// ErrInvalidNotice means a Notice or IncidentInput broke its precondition (PRE-1, PRE-2).
	ErrInvalidNotice = errors.New("notify: invalid notice")
	// ErrApprovalUnavailable means approval requests cannot be sent: approval links are credentials and need the real box address.
	ErrApprovalUnavailable = errors.New("notify: approval requests are not available: the box address (BaseURL) is not set")
	// ErrModuleOff means the module is off: Publish, OpenIncident and SendApprovalRequest do nothing and queue nothing.
	ErrModuleOff = errors.New("notify: the module is off")
)
