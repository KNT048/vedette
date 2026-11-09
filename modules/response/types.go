package response

// Wire types. Their JSON names are the names of web/src/features/response/contract.ts: handlers convert them to the
// generated types through their JSON form (the same pattern as modules/notify). Slices and maps are never nil on
// the wire.

// Risk of an action.
type Risk string

// The three risk levels.
const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

func (r Risk) valid() bool { return r == RiskLow || r == RiskMedium || r == RiskHigh }

func maxRisk(items []itemRec) Risk {
	out := RiskLow
	for _, i := range items {
		switch i.Risk {
		case RiskHigh:
			return RiskHigh
		case RiskMedium:
			out = RiskMedium
		}
	}
	return out
}

// Status of a request.
type Status string

// The request statuses.
const (
	StatusPending    Status = "pending"
	StatusApproved   Status = "approved"
	StatusRejected   Status = "rejected"
	StatusExpired    Status = "expired"
	StatusExecuted   Status = "executed"
	StatusFailed     Status = "failed"
	StatusRolledBack Status = "rolled_back"
)

// ItemStatus is the status of one action of a request.
type ItemStatus string

// The item statuses.
const (
	ItemPending    ItemStatus = "pending"
	ItemSkipped    ItemStatus = "skipped"
	ItemExecuted   ItemStatus = "executed"
	ItemFailed     ItemStatus = "failed"
	ItemRolledBack ItemStatus = "rolled_back"
)

// Via is how an approval was given.
type Via string

// The ways to approve. Only app and auto exist in part 1; chat and link approvals are part 13b.
const (
	ViaApp  Via = "app"
	ViaAuto Via = "auto"
)

// RestCall is the exact API call of a step.
type RestCall struct {
	Method string  `json:"method"`
	URL    string  `json:"url"`
	Body   *string `json:"body"`
	// Headers are the headers of the template with the typed values filled in, exactly as they are sent (the sign-in is the connection's and
	// never appears here; a name that INV-14b forbids never reaches this point). Always an object.
	Headers map[string]string `json:"headers"`
}

// RollbackChange is how a change is undone.
type RollbackChange struct {
	Title string    `json:"title"`
	CLI   string    `json:"cli"`
	Rest  *RestCall `json:"rest"`
}

// Change is the exact change of one action.
type Change struct {
	Before   string         `json:"before"`
	After    string         `json:"after"`
	CLI      string         `json:"cli"`
	Rest     *RestCall      `json:"rest"`
	Rollback RollbackChange `json:"rollback"`
	Verify   string         `json:"verify"`
	// What the approver also sees (review of 13b-2): the check that runs right before the change, with the texts that refuse it or
	// that it must contain, and the text the read-back must (after the change) or must not (after the undo) contain.
	Precheck      string `json:"precheck"`
	PrecheckRules string `json:"precheck_rules"`
	VerifyRule    string `json:"verify_rule"`
}

// Verified is the result of the read-back after an action ran.
type Verified struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// RequestItem is one action of a request.
type RequestItem struct {
	ID           string     `json:"id"`
	ActionID     string     `json:"action_id"`
	Title        string     `json:"title"`
	Risk         Risk       `json:"risk"`
	Reversible   bool       `json:"reversible"`
	ConnectorID  *string    `json:"connector_id"`
	Connection   *string    `json:"connection"`
	Tool         string     `json:"tool"`
	Targets      int        `json:"targets"`
	Change       Change     `json:"change"`
	TTLMin       *int       `json:"ttl_min"`
	Status       ItemStatus `json:"status"`
	ExecutedAt   *string    `json:"executed_at"`
	RemoveAt     *string    `json:"remove_at"`
	RolledBackAt *string    `json:"rolled_back_at"`
	Result       *string    `json:"result"`
	Verified     *Verified  `json:"verified"`
	// StateUnknown marks a failed item whose step was sent and whose outcome is not known (a time-out after it left, an answer that does not
	// say "refused", a crash): the change may be in force on the device, so the connection cannot be deleted (ChangesInForce) and a person
	// can undo it to be sure. The sweep reads the device back when the action has a read-back text and settles it either way.
	StateUnknown bool `json:"state_unknown"`
}

// itemRec is the stored form of an item: the wire item plus the checked values it was planned with, which the
// gates read again right before the item runs (never-touch, rate) and which never leave the box.
type itemRec struct {
	RequestItem
	Values map[ParamType]string `json:"values"`
	Acted  []string             `json:"acted"` // the addresses, domains, MACs and ports the item touches (and the subject of the event), read again by the never-touch gate

	// What the request was made against, compared with the catalog and the connection right before the item runs or is undone
	// (INV-9): an admin who edits the action or the connection while the request waits cannot make an approval run something else.
	RunTool      string `json:"run_tool"`
	RollbackTool string `json:"rollback_tool"`
	ConnFP       string `json:"conn_fp"`
	ActionFP     string `json:"action_fp"` // actionFP of the catalog entry when the request was made: its templates and its risk

	// Exec is what is sent to the device: the check before, the run, the rollback and the read-back, rendered when the request was
	// made, so what runs is what the approver saw (INV-22). nil on a device item made by an older version: it cannot run.
	Exec *execRec `json:"exec,omitempty"`

	// RunningAt is set, in its own transaction with a log line, before a step is sent to a device or a webhook (INV-19). An item that
	// stays so after a restart or a timeout is failed by the sweep with "state unknown": a step may have been applied.
	RunningAt string `json:"running_at,omitempty"`

	// ConnIdent is conn.Identity of the connection (id, kind, address) when the request was made: an undo is held to it instead of to ConnFP,
	// so a rotated token or a renewed pin does not strand a change that is in force (D-88 (4)).
	ConnIdent string `json:"conn_ident,omitempty"`

	// UndoUnclear is set when an undo was sent and its outcome is not known (no answer, or a read-back that could not tell): the next try
	// reads the device first and sends the rollback again only when the change is still there.
	UndoUnclear bool `json:"undo_unclear,omitempty"`
}

// Approval is one person's (or a pre-approved rule's) approval.
type Approval struct {
	UserID string   `json:"user_id"`
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Via    Via      `json:"via"`
	At     string   `json:"at"`
	Items  []string `json:"items"`
}

// Evidence of an AI request (part 13b).
type Evidence struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

// SecondCheck is the deterministic second checker of a high-risk AI request (part 13b).
type SecondCheck struct {
	OK    bool   `json:"ok"`
	Notes string `json:"notes"`
}

// AiMeta is what an AI request adds (part 13b); it is always null in this part.
type AiMeta struct {
	Confidence  float64      `json:"confidence"`
	Evidence    []Evidence   `json:"evidence"`
	Why         string       `json:"why"`
	SecondCheck *SecondCheck `json:"second_check"`
	InAppOnly   bool         `json:"in_app_only"`
}

// EmailLink is a preview-build field: the real build always answers an empty list (FORBID-4).
type EmailLink struct {
	Approver  string `json:"approver"`
	Address   string `json:"address"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
	Used      bool   `json:"used"`
}

// ActionRequest is a bundled request: one per rule run or AI proposal.
type ActionRequest struct {
	ID                string        `json:"id"`
	Source            string        `json:"source"` // "rule" or "ai"
	ProposalID        string        `json:"proposal_id"`
	RuleID            *string       `json:"rule_id"`
	RuleName          *string       `json:"rule_name"`
	Trigger           *string       `json:"trigger"`
	TriggerSummary    *string       `json:"trigger_summary"`
	FindingID         *string       `json:"finding_id"`
	CVE               *string       `json:"cve"`
	AssetID           *string       `json:"asset_id"`
	AssetName         string        `json:"asset_name"`
	Title             string        `json:"title"`
	Items             []RequestItem `json:"items"`
	Risk              Risk          `json:"risk"`
	Status            Status        `json:"status"`
	RequestedAt       string        `json:"requested_at"`
	ExpiresAt         string        `json:"expires_at"`
	DecidedAt         *string       `json:"decided_at"`
	RequiresApprovals int           `json:"requires_approvals"`
	TwoBecause        *string       `json:"two_because"`
	Approvals         []Approval    `json:"approvals"`
	SentTo            []string      `json:"sent_to"`
	EmailLinks        []EmailLink   `json:"email_links"`
	Note              *string       `json:"note"`
	PreApproved       bool          `json:"pre_approved"`
	AI                *AiMeta       `json:"ai"`
}

// request is the stored form of ActionRequest.
type request struct {
	ActionRequest
	recs []itemRec // the items with their values
}

func (r request) view() ActionRequest {
	v := r.ActionRequest
	v.Items = make([]RequestItem, len(r.recs))
	for i, it := range r.recs {
		v.Items[i] = it.RequestItem
	}
	if v.Approvals == nil {
		v.Approvals = []Approval{}
	}
	if v.SentTo == nil {
		v.SentTo = []string{}
	}
	v.EmailLinks = []EmailLink{}
	return v
}

// Window is a maintenance window.
type Window struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// AiGates are the gates of the AI requests (part 13b enforces them; the settings keep them).
type AiGates struct {
	Triggers     []string `json:"triggers"`
	BudgetHour   int      `json:"budget_hour"`
	BudgetDay    int      `json:"budget_day"`
	PausedAt     *string  `json:"paused_at"`
	PausedReason *string  `json:"paused_reason"`
}

// Settings is the execution switch and the safety envelope.
type Settings struct {
	Execution         bool     `json:"execution"`
	AcceptedBy        *string  `json:"accepted_by"`
	AcceptedAt        *string  `json:"accepted_at"`
	MaxPerHour        int      `json:"max_per_hour"`
	ExpiryMin         int      `json:"expiry_min"`
	ApprovalChannels  []string `json:"approval_channels"`
	BreakerMaxPerHour int      `json:"breaker_max_per_hour"`
	BreakerTrippedAt  *string  `json:"breaker_tripped_at"`
	BreakerNotified   []string `json:"breaker_notified"`
	// StoppedAt is when the emergency stop was pressed, until an admin resumes (ResetBreaker). It blocks every step that touches a device, an undo
	// included; the execution switch and the breaker do not block an undo.
	StoppedAt      *string  `json:"stopped_at,omitempty"`
	MultiTargetMax int      `json:"multi_target_max"`
	Maintenance    []Window `json:"maintenance"`
	AI             AiGates  `json:"ai"`
}

// ChannelView is an approval channel as the settings show it.
type ChannelView struct {
	Type      string `json:"type"`
	Label     string `json:"label"`
	Ready     bool   `json:"ready"`
	Approvers int    `json:"approvers"`
	Link      bool   `json:"link"`
}

// SettingsView is Settings plus the channels.
type SettingsView struct {
	Settings
	Channels []ChannelView `json:"channels"`
}

// SettingsInput is the body of PUT /response/settings. It has no execution field: the switch has its own endpoint.
type SettingsInput struct {
	MaxPerHour        int      `json:"max_per_hour"`
	ExpiryMin         int      `json:"expiry_min"`
	ApprovalChannels  []string `json:"approval_channels"`
	BreakerMaxPerHour int      `json:"breaker_max_per_hour"`
	MultiTargetMax    int      `json:"multi_target_max"`
	Maintenance       []Window `json:"maintenance"`
	AI                struct {
		Triggers   []string `json:"triggers"`
		BudgetHour int      `json:"budget_hour"`
		BudgetDay  int      `json:"budget_day"`
	} `json:"ai"`
}

// TriggerField is a field a trigger provides.
type TriggerField struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Example string   `json:"example"`
	Choices []string `json:"choices"`
}

// TriggerInfo describes a trigger.
type TriggerInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Fields      []TriggerField `json:"fields"`
	AIAllowed   bool           `json:"ai_allowed"`
}

// Condition is one IF test.
type Condition struct {
	Field     string `json:"field"`
	Op        string `json:"op"`
	Value     string `json:"value"`
	N         *int   `json:"n"`
	WindowMin *int   `json:"window_min"`
}

// RuleAction is one THEN step.
type RuleAction struct {
	ActionID string            `json:"action_id"`
	Params   map[string]string `json:"params"`
	TTLMin   *int              `json:"ttl_min"`
}

// RuleInput is what the client sends for a rule.
type RuleInput struct {
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	Live        bool         `json:"live"`
	Trigger     string       `json:"trigger"`
	Match       string       `json:"match"`
	Conditions  []Condition  `json:"conditions"`
	Actions     []RuleAction `json:"actions"`
	PreApproved bool         `json:"pre_approved"`
	MaxPerHour  int          `json:"max_per_hour"`
	ScheduleMin *int         `json:"schedule_min"`
}

// Rule is a stored rule.
type Rule struct {
	ID string `json:"id"`
	RuleInput
	TemplateID *string `json:"template_id"`
	LastFired  *string `json:"last_fired"`
}

// EventView is an event a trigger watches for.
type EventView struct {
	ID         string            `json:"id"`
	Trigger    string            `json:"trigger"`
	TS         string            `json:"ts"`
	Summary    string            `json:"summary"`
	Fields     map[string]string `json:"fields"`
	DeviceKind *string           `json:"device_kind"`
	HandledBy  []string          `json:"handled_by"`
}

// RunSummary counts what a run did.
type RunSummary struct {
	Matched  int `json:"matched"`
	DryRun   int `json:"dry_run"`
	Requests int `json:"requests"`
	Executed int `json:"executed"`
	Refused  int `json:"refused"`
	Deduped  int `json:"deduped"`
}

// SimStep is one step of a simulation.
type SimStep struct {
	Action string  `json:"action"`
	Risk   Risk    `json:"risk"`
	OK     bool    `json:"ok"`
	Error  *string `json:"error"`
	Change *Change `json:"change"`
}

// SimCondition is one evaluated condition.
type SimCondition struct {
	Text string `json:"text"`
	OK   bool   `json:"ok"`
}

// Simulation is the answer of simulate: what a live run would do. Executed is always 0.
type Simulation struct {
	Event      *EventView     `json:"event"`
	Matched    bool           `json:"matched"`
	Conditions []SimCondition `json:"conditions"`
	Steps      []SimStep      `json:"steps"`
	Notes      []string       `json:"notes"`
	Approvals  int            `json:"approvals"`
	Executed   int            `json:"executed"`
}

// Template is a ready-made rule of the gallery.
type Template struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Trigger     string    `json:"trigger"`
	Risk        Risk      `json:"risk"`
	Approvals   int       `json:"approvals"`
	Rule        RuleInput `json:"rule"`
}

// BlockEntry is one line of the block list.
type BlockEntry struct {
	Value     string  `json:"value"`
	Source    string  `json:"source"`
	Reason    string  `json:"reason"`
	AddedAt   string  `json:"added_at"`
	ExpiresAt *string `json:"expires_at"`
}

// LastFetch is the last time a firewall pulled the block list.
type LastFetch struct {
	At   string `json:"at"`
	From string `json:"from"`
}

// BlocklistView is GET /response/blocklist.
type BlocklistView struct {
	URL        string       `json:"url"`
	TokenLast4 string       `json:"token_last4"`
	Entries    []BlockEntry `json:"entries"`
	LastFetch  *LastFetch   `json:"last_fetch"`
}

// LogEntry is one line of the response log.
type LogEntry struct {
	ID       string `json:"id"`
	TS       string `json:"ts"`
	Kind     string `json:"kind"`
	Actor    string `json:"actor"`
	Detail   string `json:"detail"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Stat is the approval statistics of a source.
type Stat struct {
	Sent             int      `json:"sent"`
	Approved         int      `json:"approved"`
	Rejected         int      `json:"rejected"`
	Expired          int      `json:"expired"`
	Pending          int      `json:"pending"`
	AcceptanceRate   *float64 `json:"acceptance_rate"`
	MedianApproveMin *float64 `json:"median_approve_min"`
}

// RejectedRow is a rejected request in the metrics.
type RejectedRow struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Source string `json:"source"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// Metrics is GET /response/metrics.
type Metrics struct {
	AI          Stat          `json:"ai"`
	Rules       Stat          `json:"rules"`
	Suggestions int           `json:"suggestions"`
	Digested    int           `json:"digested"`
	Rejected    []RejectedRow `json:"rejected"`
}

// Proposal is an AI plan proposal (part 13b writes plans; part 1 reads them).
type Proposal struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	ToolKey     string  `json:"tool_key"`
	Tool        string  `json:"tool"`
	ConnectorID string  `json:"connector_id"`
	Connection  string  `json:"connection"`
	AssetID     string  `json:"asset_id"`
	AssetName   string  `json:"asset_name"`
	Change      Change  `json:"change"`
	State       string  `json:"state"`
	RequestID   *string `json:"request_id"`
}

// PlanStep is one step of a plan.
type PlanStep struct {
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Proposal *Proposal `json:"proposal"`
}

// PlanRead is one read the AI made.
type PlanRead struct {
	Connection string `json:"connection"`
	Tool       string `json:"tool"`
	Summary    string `json:"summary"`
}

// Plan is an AI response plan for a finding.
type Plan struct {
	ID          string     `json:"id"`
	FindingID   string     `json:"finding_id"`
	CVE         string     `json:"cve"`
	AssetID     string     `json:"asset_id"`
	AssetName   string     `json:"asset_name"`
	GeneratedAt string     `json:"generated_at"`
	Model       string     `json:"model"`
	Profile     string     `json:"profile"`
	Path        string     `json:"path"`
	Reads       []PlanRead `json:"reads"`
	Steps       []PlanStep `json:"steps"`
	SentTo      []string   `json:"sent_to"`
}

// PlanList is GET /response/plans.
type PlanList struct {
	Items       []Plan `json:"items"`
	AIAvailable bool   `json:"ai_available"`
	Execution   bool   `json:"execution"`
}

// CatalogAction is an action of the catalog as the API shows it.
type CatalogAction struct {
	ID                string      `json:"id"`
	Builtin           bool        `json:"builtin"`
	Pack              string      `json:"pack"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	ConnectionID      *string     `json:"connection_id"`
	Connection        *string     `json:"connection"`
	ConnectionKind    *string     `json:"connection_kind"`
	Tool              *string     `json:"tool"`
	RollbackTool      *string     `json:"rollback_tool"`
	Run               Tpl         `json:"run"`
	Rollback          Tpl         `json:"rollback"`
	Verify            Tpl         `json:"verify"`
	Precheck          Tpl         `json:"precheck"`
	PrecheckRefuse    []string    `json:"precheck_refuse"`
	PrecheckExpect    string      `json:"precheck_expect"`
	Params            []ParamType `json:"params"`
	Risk              Risk        `json:"risk"`
	Enabled           bool        `json:"enabled"`
	Reversible        bool        `json:"reversible"`
	AIMayPropose      bool        `json:"ai_may_propose"`
	Device            bool        `json:"device"`
	Available         bool        `json:"available"`
	UnavailableReason *string     `json:"unavailable_reason"`
}

// Connection is a connection to a customer device, as the catalog shows it. Part 13b owns the connections
// (ai_connectors); this part reads them through the Connections port.
type Connection struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Kind       string   `json:"kind"`
	WriteTools []string `json:"write_tools"`
	ReadOnly   bool     `json:"read_only"`
}

// Catalog is GET /response/catalog.
type Catalog struct {
	Items       []CatalogAction `json:"items"`
	Connections []Connection    `json:"connections"`
}

// CatalogInput is the body of POST /response/catalog.
type CatalogInput struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	ConnectionID string  `json:"connection_id"`
	Tool         *string `json:"tool"`
	RollbackTool *string `json:"rollback_tool"`
	Run          Tpl     `json:"run"`
	Rollback     Tpl     `json:"rollback"`
	Verify       Tpl     `json:"verify"`
	// Precheck and PrecheckRefuse (D-95) are optional: a read-only template that runs right before the action, and up to 5
	// texts that make it refuse. Both or neither.
	Precheck       Tpl      `json:"precheck"`
	PrecheckRefuse []string `json:"precheck_refuse"`
	PrecheckExpect string   `json:"precheck_expect"`
	Risk           Risk     `json:"risk"`
	Enabled        bool     `json:"enabled"`
	AIMayPropose   bool     `json:"ai_may_propose"`
}

// CatalogUpdate is the body of PUT /response/catalog/{id}: every field optional (a built-in action takes only
// enabled, ai_may_propose and connection_id).
type CatalogUpdate struct {
	Name           *string   `json:"name"`
	Description    *string   `json:"description"`
	ConnectionID   *string   `json:"connection_id"`
	Tool           *string   `json:"tool"`
	RollbackTool   *string   `json:"rollback_tool"`
	Run            *Tpl      `json:"run"`
	Rollback       *Tpl      `json:"rollback"`
	Verify         *Tpl      `json:"verify"`
	Precheck       *Tpl      `json:"precheck"`
	PrecheckRefuse *[]string `json:"precheck_refuse"`
	PrecheckExpect *string   `json:"precheck_expect"`
	Risk           *Risk     `json:"risk"`
	Enabled        *bool     `json:"enabled"`
	AIMayPropose   *bool     `json:"ai_may_propose"`
	// Present records which keys the body carried, so "connection_id": null differs from a missing key.
	Present map[string]bool `json:"-"`
}
