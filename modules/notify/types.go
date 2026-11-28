package notify

import (
	"context"
	"errors"
	"regexp"
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
	// Name is the display name of the approver's account on the channel, as the picker showed it (Zalo personal); "" elsewhere.
	Name string `json:"name,omitempty"`
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
	Signin      string // email: a finished user sign-in whose refresh token becomes the secret
	// SecretKey and RefreshToken (Zalo OA): the app's secret key and the OA refresh token; Secret is then the current access
	// token, optional. Empty keeps the saved one.
	SecretKey    string
	RefreshToken string
	// ZaloLogin (Zalo personal): the session of the saving administrator's finished QR sign-in becomes the channel's secret.
	ZaloLogin bool
}

// Rules are the delivery rules of every channel: quiet hours.
type Rules struct {
	Quiet Quiet `json:"quiet"`
}

// ChannelsView is the answer of GET /notify/channels.
type ChannelsView struct {
	Channels []Channel     `json:"channels"`
	Quiet    Quiet         `json:"quiet"`
	Triggers []TriggerView `json:"triggers"`
	// Vulnerability is the vulnerability trigger: on or off, no minimum (INV-32: a finding alerts only when exploited, always critical)
	Vulnerability  VulnTriggerView `json:"vulnerability_trigger"`
	EmailCodeUsers int             `json:"email_code_users"`
}

// SendView is one delivery attempt as the API shows it.
type SendView struct {
	ID      string       `json:"id"`
	Channel channel.Type `json:"channel"`
	To      string       `json:"to"`
	At      string       `json:"at"`
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	// Delayed: the provider asked to slow down and the message waits in the queue; it is sent again by itself.
	Delayed bool `json:"delayed"`
}

// HistoryItem is a SendView with what it was about.
type HistoryItem struct {
	SendView
	Kind string `json:"kind"` // incident | vuln | approval
	What string `json:"what"`
	Link string `json:"link"`
	// Resent: a person sent this message again from the History (Send again); its words are those of the message it copies.
	Resent bool `json:"resent"`
}

// HistoryView is the answer of GET /notify/history. Suppressed counts the new vulnerabilities that
// matched no device in the last Days days (INV-2): they were not sent. NotSent lists the vulnerability notices of the same days that no
// channel delivered, each with why (waiting for its grouping window or quiet hours, below the channels' minimum, no channel, failed).
type HistoryView struct {
	Items      []HistoryItem  `json:"items"`
	NotSent    []UnsentNotice `json:"not_sent"`
	Suppressed struct {
		Count int `json:"count"`
		Days  int `json:"days"`
	} `json:"suppressed"`
}

// UnsentNotice is a vulnerability notice no channel has delivered: what it says, when it was made, the finding (or the findings list)
// it links to, and why it was not sent.
type UnsentNotice struct {
	ID      string  `json:"id"`
	At      string  `json:"at"`
	What    string  `json:"what"`
	Link    string  `json:"link"`
	NotSent NotSent `json:"not_sent"`
}

// IncidentKind is what an incident is about (INV-10). There is no vulnerability kind: those are findings.
type IncidentKind string

// The incident kinds. The column is an open vocabulary (a shape check only): a new kind is a value here, never a table change.
const (
	IncidentTrap          IncidentKind = "trap"
	IncidentBadAddress    IncidentKind = "bad_address"
	IncidentLogAnomaly    IncidentKind = "log_anomaly"
	IncidentUnknownDevice IncidentKind = "unknown_device"
	// IncidentIntrusion is an IPS or IDS event (ids.alert.detected): one incident per CVE ids or rule and source address while it repeats.
	IncidentIntrusion IncidentKind = "intrusion"
)

// IncidentKinds lists every kind, in the order the API documents them.
var IncidentKinds = []IncidentKind{IncidentTrap, IncidentBadAddress, IncidentLogAnomaly, IncidentUnknownDevice, IncidentIntrusion}

// Valid reports whether k has the shape of a kind (lower case words and digits, at most 40 characters): the vocabulary is open, so a
// producer's new kind needs no change here. "vuln" is taken: a vulnerability is a finding and its notice, never an incident.
func (k IncidentKind) Valid() bool { return kindShape.MatchString(string(k)) && k != "vuln" }

var kindShape = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

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
	ID   string       `json:"id"`
	Kind IncidentKind `json:"kind"`
	// Attempt (bad_address only): the device that logged the connection blocked it, so it was an attempt, not a connection.
	Attempt   bool           `json:"attempt"`
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
	// ResolvedReason is why Vedette closed the incident by itself (INV-22), a plain-English sentence such as "Closed by
	// Vedette: no new activity for 7 days."; nil when a person handled it last or it is open.
	ResolvedReason *string `json:"resolved_reason"`
	// FirstRunSummary: opened in the box's first 36 hours as a low or medium bad-connection or log incident, so it was told in the
	// hourly first-run summary message, not one by one (INV-23).
	FirstRunSummary bool       `json:"first_run_summary"`
	Sends           []SendView `json:"sends"`
	// NotSent says why no channel has the incident (INV-24); nil when any attempt delivered it.
	NotSent *NotSent `json:"not_sent"`
}

// NotSentReason is why an incident or a vulnerability notice reached no channel (INV-24).
type NotSentReason string

// The reasons. queued and quiet_hours are not final: the message still goes out by itself.
const (
	UnsentQueued       NotSentReason = "queued"             // a channel took it; the deliver job sends it within a minute
	UnsentQuietHours   NotSentReason = "quiet_hours"        // held until quiet hours end (INV-5), then sent
	UnsentNoChannel    NotSentReason = "no_channel"         // no channel was set up
	UnsentChannelsOff  NotSentReason = "channels_off"       // channels were set up, none was on
	UnsentChannelOff   NotSentReason = "channel_off"        // the one channel it waited for (quiet hours, rate limit) was turned off before it went
	UnsentChannelGone  NotSentReason = "channel_removed"    // the one channel it waited for was removed before it went
	UnsentBelowMin     NotSentReason = "below_min_severity" // every channel that was on sends only higher severities (INV-4)
	UnsentFailed       NotSentReason = "failed"             // a channel tried and failed (INV-6)
	UnsentDroppedStale NotSentReason = "dropped_stale"      // it waited while the module was off and was too old when it came back on
	UnsentFirstRun     NotSentReason = "first_run_summary"  // held by the first-run window (INV-23), told in the hourly summary
	UnsentLineLeftOut  NotSentReason = "line_left_out"      // a vulnerability notice queued and sent, but its line was past what the message could hold
	UnsentUnknown      NotSentReason = "unknown"            // opened before the reason was kept, and today's channels would take it
	UnsentTriggerOff   NotSentReason = "trigger_off"        // its alert trigger is off, or it is below the trigger's minimum (INV-31)
	// UnsentNotExploited: a finding whose CVE is not exploited in the wild sends no alert (INV-32); it is told in the daily summary
	UnsentNotExploited NotSentReason = "not_exploited"
)

// NotSent is the reason an incident has no message on any channel, in the customer's words (INV-24).
type NotSent struct {
	Reason NotSentReason `json:"reason"`
	Text   string        `json:"text"`
	// Channel is the channel to fix: the one that failed, the one that was turned off or removed, or the one with the lowest minimum severity.
	Channel channel.Type `json:"channel,omitempty"`
	// Until (quiet_hours) is when the held message goes out.
	Until string `json:"until,omitempty"`
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
	// Attempt (bad_address only) says the connection was blocked (logs.bad_address.detected "blocked"). An attempt is a
	// repeat of an open incident of the same source and target, attempt or not; a connection is never a repeat of an attempt, so
	// a blocked attempt never hides the connection that follows it.
	Attempt bool
	// Session (trap only) is the quiet that ends a session: a repeat joins the open incident only when it comes within Session
	// of its last hit and raises it when it is more serious; after a longer quiet the open incident keeps what it had and the
	// repeat opens a new one. Zero = every repeat joins the open incident, as before.
	Session time.Duration
}

// ---- what notify needs from the rest of the box (small interfaces, faked in tests) ----

// User is a Vedette user as notify needs to see one (INV-7).
type User struct {
	ID     string
	Email  string
	Role   string // viewer | operator | admin
	Active bool
}

// Users is implemented by the code that owns users (core/auth). notify never reads core tables.
type Users interface {
	// Lookup returns the user, or found=false when there is none.
	Lookup(ctx context.Context, id string) (u User, found bool, err error)
	// EmailCodeUsers counts the active users who sign in with a two-step code sent by email (INV-9).
	EmailCodeUsers(ctx context.Context) (int, error)
}

// ApproverLinks is implemented by the code that owns users (core/auth, wired in cmd/vedette). It says whether the user has
// linked this address on this channel in My account. An error is not an answer: the approver is skipped.
// Rules for the adapter: an error must not carry the address (it is logged); email addresses are compared case-insensitively;
// chat ids (Telegram, Slack, Zalo) are exact decimal or opaque strings and are compared exactly.
type ApproverLinks interface {
	Linked(ctx context.Context, userID string, ch channel.Type, address string) (bool, error)
}

// LinkCodes makes the token of the confirm link the box sends to an approver's chat ID (Zalo personal; module response
// keeps the token and the proof): only the person, signed in to Vedette as themself, confirms it, so no administrator links anyone.
// name is the Vedette user's name for the message. A refusal is an *apierr.Error (not listed, already linked, a new link too soon,
// Response off): it goes to the administrator as it is. DropChatLink ends the proof of one address when an administrator removes that
// approver or gives them another address, so the old address never counts again without a new proof. DropLinkToken removes one token
// that could not be delivered, and only that token: a newer one, or a proof, stays.
type LinkCodes interface {
	ChatLinkToken(ctx context.Context, userID string, ch channel.Type, address string) (token, name string, err error)
	DropChatLink(ctx context.Context, actor, userID string, ch channel.Type, address string) error
	DropLinkToken(ctx context.Context, userID string, ch channel.Type, address, token string) error
}

// HitRef names a trap hit an incident links to: its id and the time it was seen (the incident's first_seen).
type HitRef struct {
	ID string
	At time.Time
}

// HitConnections is what notify reads from the honeypot at render time: how many connections each hit saw (hp_hits.conn_count;
// later connections of the same source, service and trap IP fold into the hit and raise no event, honeypot INV-17). Hits it does not
// know are left out. ponytail: read at render, not kept; switch to the honeypot.hit.updated event {id, conn_count} when honeypot sends it.
type HitConnections interface {
	HitConnections(ctx context.Context, hits []HitRef) (map[string]int, error)
}

// SessionHit is one hit of a source as a trap session tells it.
type SessionHit struct {
	ID      string
	At      time.Time
	Kind    string // service | token | scan
	Service string
	Label   string // the trap or token as the honeypot names it: "SSH", "File token Payroll", ...
}

// HitSessions reads the honeypot hits of one source address between two times, oldest first, without test hits.
type HitSessions interface {
	SourceHits(ctx context.Context, src string, from, to time.Time) ([]SessionHit, error)
}

// ModuleGate says whether a module is on (modreg.Registry satisfies it).
type ModuleGate interface{ Enabled(id string) bool }

// Bus is the part of core/events.Bus notify uses. A nil Bus drops events.
type Bus interface {
	Publish(ctx context.Context, e events.Event) error
	Subscribe(name string, fn events.Handler) (unsubscribe func())
	Flush(ctx context.Context, o *events.Outbox)
}

// FindingInfo describes a finding for a notice, as findings.View shows it now: the status and its words come from findings (one wording
// source), notify only frames them for the event that is told.
type FindingInfo struct {
	CVE      string
	Product  string
	Severity Severity
	// Open: the finding is open now. A finding that was handled since its event is never announced.
	Open bool
	// Layer is the stored urgency layer of the finding (1 under attack here .. 5 update recommended). Layer 5 never alerts.
	Layer int
	// Exploited is findings' answer to "is it exploited" (Finding.Exploited, the one cutoff findings.ExploitedLayer): only an exploited
	// finding sends an alert (INV-32). notify never decides it from the layer itself.
	Exploited bool
	// Status is the name of the status the finding page shows ("Public exploit available"), Meaning the sentence that says what it asks
	// of a person, Reasons the line of the reasons ("Exploited in the wild: CISA KEV (19 Nov 2026)"; "" when none), all from findings.
	Status, Meaning, Reasons string
	// Verification is the second line under the status on every screen: how Vedette knows the device is affected ("Confirmed by a safe
	// check", "Not confirmed yet: based on a scan banner"; View.VerificationLine of findings); "" when not known.
	Verification string
	// Note is said after the meaning when the device needs it ("The device is not added yet: open the finding to add it or ignore it.").
	Note    string
	Action  string   // what to do first
	Devices []string // names of the devices the finding matched; empty = it matched none
}

// layerUpdate is the urgency layer of a finding with no sign of exploitation (findings.UrgencyUpdate): it never alerts.
const layerUpdate = 5

// FindingDirectory looks a finding up by id. Without one, finding events cannot become notices.
type FindingDirectory interface {
	Finding(ctx context.Context, id string) (FindingInfo, bool, error)
}

// SignalDirectory reads the exploitation news the box holds (feeds_signal) for the History page.
type SignalDirectory interface {
	// UnmatchedExploited counts the CVEs a source reported as exploited (a qualifying signal the box stored at or after since, not one
	// that came with a source's first load) that no device has a finding for.
	UnmatchedExploited(ctx context.Context, since time.Time) (int, error)
}

// DeviceDirectory names a device by inventory id. Without one, device events show the id.
type DeviceDirectory interface {
	DeviceName(ctx context.Context, assetID string) (string, bool, error)
	// DeviceStates is the devices as the Devices page shows them now, for their unknown_device incidents; a device the
	// inventory does not have is absent from the map.
	DeviceStates(ctx context.Context, assetIDs []string) (map[string]DeviceState, error)
}

// DeviceState is a device as the Devices page shows it now.
type DeviceState struct {
	Name       string    // inventory's one naming rule, else the MAC, else the kind; plain text, at most 160 characters
	Address    string    // the IP, else the MAC; "" when neither is known
	Approved   bool      // a person (or an osquery enrolment) approved it
	ApprovedAt time.Time // when; zero when unknown (approved before inventory kept it)
}

// TokenRecorder stores an approval token record (spec approval-tokens.md 4.1: the record in the
// database is the source of truth). The response module implements it; notify mints the token but
// never keeps the record, so without a recorder email approvers get a message that says to open Vedette, not a link.
type TokenRecorder interface {
	// address is where the link was sent (the approver's email): the record carries it (spec 4.1, 4.2).
	RecordToken(ctx context.Context, id TokenID, b Binding, keyID, address string) error
	// RecordReplyCode stores the hash of one Zalo personal reply code (spec approval-tokens.md 7.1) before the message
	// that carries the code is sent; without a recorder no code is sent. The plain code is never stored or logged.
	RecordReplyCode(ctx context.Context, c ReplyCode) error
}

// ReplyCode is one reply code of one approver for one request: CodeHash is the lowercase hex SHA-256 of spec 7.1,
// Address the approver's Zalo user id, Approve false for the "R-" (reject) code. ExpiresAt is never after the request ends
// and at most 30 minutes after the code is made.
type ReplyCode struct {
	RequestID string
	UserID    string
	Address   string
	Approve   bool
	CodeHash  string
	ExpiresAt time.Time
}

// Decision is what a chat listener passes to Decisions after it has checked the platform (Slack team and channel,
// Telegram chat, Zalo session): ExternalID is the sender on the platform, RequestID comes from the button (empty for a
// Zalo personal reply code), Code is the text the approver typed (reply codes only).
type Decision struct {
	Channel    channel.Type
	ExternalID string
	RequestID  string
	Approve    bool
	Code       string
}

// DecisionResult is the answer of the response module: Status says what was recorded (the module response owns the
// values), Message is the short private reply for the person who pressed the button, RequestID the request that was decided
// (a Zalo reply code names its request only through response's record; empty on a refusal).
type DecisionResult struct {
	Status    string
	Message   string
	RequestID string
}

// Decisions is the port of the response module that takes decisions made in chat (PRE-8). notify decides nothing itself. Nothing a
// chat account sends links it to a Vedette user: a Zalo personal approver is linked only by confirming a link while signed in.
type Decisions interface {
	Decide(ctx context.Context, d Decision) (DecisionResult, error)
}

// Errors of the service that are not API errors.
var (
	// ErrInvalidNotice means a Notice or IncidentInput broke its precondition (PRE-1, PRE-2).
	ErrInvalidNotice = errors.New("notify: invalid notice")
	// ErrApprovalUnavailable means approval requests cannot be sent: approval links are credentials and need the real box address.
	ErrApprovalUnavailable = errors.New("notify: approval requests are not available: the box address (BaseURL) is not set")
	// ErrApprovalKeyUnavailable means the approval key (K_approval) does not exist or cannot be opened, so no link can be
	// checked. VerifyApprovalLink never makes a key.
	ErrApprovalKeyUnavailable = errors.New("notify: the approval key is not available")
	// ErrModuleOff means the module is off: Publish, OpenIncident and SendApprovalRequest do nothing and queue nothing.
	ErrModuleOff = errors.New("notify: the module is off")
)
