package inventory

import (
	"context"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The three sources a device page shows as equal rows (S-INV-1, S-INV-4): the box's network scan, its SNMP reads and an agent. Each
// row says its state, its colour, when it last read the device, its switch and the one button the page offers; all of it is decided
// here, on the server, from the device, the SNMP of sensor-active and the agent of agent-intake. Passive listening and a person's
// entries are not rows: when one of them is all that feeds the device, Only names it.

// Source rows, in the order the page shows them.
const (
	RowScan  = "scan"
	RowSNMP  = "snmp"
	RowAgent = "agent"
)

// States of a source row. A row says one of them; the page words it.
const (
	StateModuleOff     = "module_off"     // the module behind the source is off
	StateNoAddress     = "no_address"     // the device has no address to send to (scan, SNMP)
	StateOff           = "off"            // a person turned the source off for this device
	StateWaiting       = "waiting"        // on, nothing read yet (scan: the first check is the next window's; SNMP: no read yet; agent: a token was made for the device, no agent reads it yet)
	StateWorking       = "working"        // on and it read the device (scan), it answers (SNMP)
	StateNotApproved   = "not_approved"   // SNMP reads only approved devices
	StateNotSetUp      = "not_set_up"     // SNMP: no settings for this device
	StateNotAnswering  = "not_answering"  // SNMP: the last read got no answer
	StateNone          = "none"           // agent: no agent of this box reads the device
	StateReporting     = "reporting"      // agent: it reports on its rhythm
	StateQuiet         = "quiet"          // agent: silent for more than three of its own rhythm (agent-intake NodeHealth)
	StateNeverReported = "never_reported" // agent: enrolled, never sent its data
	StateReplaced      = "replaced"       // agent: a newer enrolment of the same machine took over
	StateCertChanged   = "cert_changed"   // agent: its agent pins a certificate authority the box no longer has (a reinstall or a data purge made a new one)
	StateUnavailable   = "unavailable"    // the module could not say just now (logged)
	StateBox           = "box"            // the Vedette box itself: it reads its own packages and ports; it is not scanned or read over SNMP
	StateIgnored       = "ignored"        // a person ignored the device: the box does not scan or read it until they stop ignoring it
)

// Dots of a source row: what the state means at a glance.
const (
	DotGreen = "green"
	DotAmber = "amber"
	DotRed   = "red"
	DotGrey  = "grey"
)

// Buttons of a source row.
const (
	ActionTurnOnModule = "turn_on_module" // turn the module on (Settings › Modules, in place)
	ActionScanNow      = "scan_now"       // check the device now instead of waiting for the window
	ActionApprove      = "approve"        // approve the device (SNMP reads approved devices only)
	ActionSetUp        = "set_up"         // set up SNMP for this device
	ActionCheckNow     = "check_now"      // SNMP Check now (POST /inventory/snmp/devices/{id}/check)
	ActionCreateToken  = "create_token"   // no agent and no token made for this device: create an agent token for it
	ActionShowSetup    = "show_setup"     // a token made for this device and no agent yet, or enrolled but never reported: the token and the install command again
	ActionCheck        = "check"          // the agent reported at least once: the troubleshooting steps
	ActionBoxCheck     = "box_check"      // the box's own agent: read its packages and ports now (POST /inventory/box/check)
)

// Agents an agent row names.
const (
	AgentOsquery = "osquery"
	AgentWazuh   = "wazuh"
	AgentBox     = "box" // the Vedette box itself reads its own packages
	AgentNone    = "none"
)

// SourceRow is one row of a device's sources (contract.ts DeviceSourceRow).
type SourceRow struct {
	Source string      `json:"source"`  // RowScan, RowSNMP or RowAgent
	State  string      `json:"state"`   // one of the State constants
	Dot    string      `json:"dot"`     // one of the Dot constants
	LastAt *string     `json:"last_at"` // when it last read the device (SNMP: the last answer; an agent: its last call); nil when never
	Switch *string     `json:"switch"`  // the person's switch for this device, "on" or "off"; nil when the row has none
	Action *string     `json:"action"`  // the one button; nil when none
	Agent  *string     `json:"agent"`   // agent row: AgentOsquery, AgentWazuh, AgentBox or AgentNone; nil on the other rows
	Token  *AgentToken `json:"token"`   // agent row: the token Show setup shows (AgentFact.Token); nil otherwise
	// NextAt is when the source reads the device next by itself: the box's own agent row (its hourly read, BoxEvery after the last one
	// since start); nil otherwise or when not known yet.
	NextAt *string `json:"next_at"`
	// Refused is the agent row of state cert_changed when the box heard the device's agent refuse its certificate: since when, the
	// last time and how often (since the box's start); nil otherwise.
	Refused *Refused `json:"refused"`
}

// Refused is how an agent refused the box's certificate (contract.ts AgentRefused).
type Refused struct {
	Since string `json:"since"`
	Last  string `json:"last"`
	Count int    `json:"count"`
}

// TLSRefusal is what the box heard from one address since its start (Config.TLSRefusals): handshakes that ended because the client
// pins another certificate authority than the box's. Count is 0 when none.
type TLSRefusal struct {
	First, Last time.Time
	Count       int
}

// An agent row says cert_changed from the handshakes alone when they are recent and more than one: osquery retries within seconds
// and refreshes every five minutes, so a stale agent has refused many times within the hour; one odd handshake does not count.
const (
	refusedFresh = 2 * time.Hour
	refusedMin   = 2
)

// AgentToken is an agent enrolment token as the agent row shows it (contract.ts AgentToken): never its secret.
type AgentToken struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Kind         string  `json:"kind"`
	Last4        string  `json:"last4"`
	CreatedAt    string  `json:"created_at"`
	CreatedBy    *string `json:"created_by"`
	LastReceived *string `json:"last_received"`
	Hosts        int     `json:"hosts"`
	ExpiresAt    *string `json:"expires_at"`
	DeviceID     *string `json:"device_id"`
}

// DeviceSourcesView is GET /inventory/devices/{id}/sources (contract.ts DeviceSources).
type DeviceSourcesView struct {
	Rows []SourceRow `json:"rows"` // scan, snmp, agent, in this order
	// Only names what feeds the device when it is neither of the rows: "passive" (only heard on the network) or "manual" (only what a
	// person entered); nil otherwise.
	Only     *string `json:"only"`
	ManualAt *string `json:"manual_at"` // when a person last entered or changed something on the device (Detail.ManualAt)
}

// SNMPFact is what sensor-active says of a device's SNMP (Config.SNMPOf).
type SNMPFact struct {
	State        string    // working, not_answering, waiting, not_set_up
	LastAnswerAt time.Time // zero when it never answered
}

// AgentFact is what agent-intake says of the agent that reads a device (Config.AgentOf).
type AgentFact struct {
	Agent string // AgentOsquery, AgentWazuh, AgentBox or AgentNone
	// State is agent-intake's NodeHealth of the agent: osquery reporting, quiet, never_reported or replaced; Wazuh reporting or quiet;
	// "" for the others. LastSeen is the time it judged by (osquery: the last call; Wazuh: the last pull that delivered the device), so the
	// row never shows a recent time beside quiet.
	State    string
	LastSeen time.Time
	Token    *AgentToken // the token Show setup shows: the one its agent enrolled with, else the newest made for this device; nil when none
}

// DeviceSources is the three source rows of a device. ErrNotFound when it does not exist.
func (s *Service) DeviceSources(ctx context.Context, id string) (DeviceSourcesView, error) {
	d, err := s.Device(ctx, id)
	if err != nil {
		return DeviceSourcesView{}, err
	}
	q := s.db.Reader()
	times, err := sourceTimes(ctx, q, id)
	if err != nil {
		return DeviceSourcesView{}, err
	}
	at, err := manualAt(ctx, q, id)
	if err != nil {
		return DeviceSourcesView{}, err
	}
	if at != nil {
		times[sourceManual] = max(times[sourceManual], *at)
	}
	out := DeviceSourcesView{ManualAt: at, Rows: []SourceRow{s.scanRow(d, times), s.snmpRow(ctx, d), s.agentRow(ctx, d, times)}}
	if times[RowScan] == "" && times[RowSNMP] == "" && times[RowAgent] == "" {
		switch {
		case times["passive"] != "":
			out.Only = ptrTo("passive")
		case times[sourceManual] != "" || d.Origin == "manual":
			out.Only = ptrTo(sourceManual)
		}
	}
	return out, nil
}

func (s *Service) enabled(module string) bool { return s.modules == nil || s.modules.Enabled(module) }

func (s *Service) scanRow(d Device, times map[string]string) SourceRow {
	r := SourceRow{Source: RowScan, Switch: ptrTo(d.ScanSource), LastAt: optional(times[RowScan])}
	switch {
	case d.IsBox: // the switch would be refused (409 box_device)
		r.State, r.Switch = StateBox, nil
	case d.IgnoredAt != nil: // turning it on would be refused (409 device_ignored)
		r.State, r.Switch = StateIgnored, nil
	case !s.enabled("sensor-active"):
		r.State, r.Action = StateModuleOff, ptrTo(ActionTurnOnModule)
	case d.ScanSource == SourceOff:
		r.State = StateOff
	case !hasAddress(d.IP):
		r.State = StateNoAddress
	case r.LastAt == nil:
		r.State, r.Action = StateWaiting, ptrTo(ActionScanNow)
	default:
		r.State = StateWorking
	}
	r.Dot = dotOf(r.State)
	return r
}

func (s *Service) snmpRow(ctx context.Context, d Device) SourceRow {
	r := SourceRow{Source: RowSNMP}
	switch {
	case d.IsBox:
		r.State = StateBox
	case d.IgnoredAt != nil:
		r.State = StateIgnored
	case !s.enabled("sensor-active"):
		r.State, r.Action = StateModuleOff, ptrTo(ActionTurnOnModule)
	case !hasAddress(d.IP):
		r.State = StateNoAddress
	case !d.Approved:
		r.State, r.Action = StateNotApproved, ptrTo(ActionApprove)
	case s.snmpOf == nil:
		r.State = StateUnavailable
	default:
		f, err := s.snmpOf(ctx, d.ID)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: the SNMP of a device could not be read; its source row says so", "device", d.ID, "error", err.Error())
			r.State = StateUnavailable
			break
		}
		if !f.LastAnswerAt.IsZero() {
			r.LastAt = ptrTo(store.FormatTS(f.LastAnswerAt))
		}
		if f.State == StateNotSetUp {
			r.State, r.Action = StateNotSetUp, ptrTo(ActionSetUp)
			break
		}
		r.Switch, r.Action = ptrTo(d.SNMPSource), ptrTo(ActionCheckNow)
		switch {
		case d.SNMPSource == SourceOff:
			r.State = StateOff
		case f.State == StateWorking || f.State == StateNotAnswering:
			r.State = f.State
		default:
			r.State = StateWaiting
		}
	}
	r.Dot = dotOf(r.State)
	return r
}

func (s *Service) agentRow(ctx context.Context, d Device, times map[string]string) SourceRow {
	r := SourceRow{Source: RowAgent, LastAt: optional(times[RowAgent]), Agent: ptrTo(AgentNone)}
	switch {
	case d.IsBox: // it reads its own packages and ports every hour, whatever the Agents module; Check now reads them at once
		r.State, r.Agent = StateReporting, ptrTo(AgentBox)
		if s.box != nil {
			r.Action = ptrTo(ActionBoxCheck)
			if at := s.boxRead.Load(); at > 0 {
				r.NextAt = ptrTo(store.FormatTS(time.UnixMilli(at).Add(BoxEvery)))
			}
		}
	case !s.enabled("agent-intake"):
		r.State, r.Action = StateModuleOff, ptrTo(ActionTurnOnModule)
	case s.agentOf == nil:
		r.State = StateUnavailable
	default:
		f, err := s.agentOf(ctx, d.ID)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: the agent of a device could not be read; its source row says so", "device", d.ID, "error", err.Error())
			r.State = StateUnavailable
			break
		}
		sw, err := s.agentSwitch(ctx, d.ID)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: the agent switch of a device could not be read; its source row says so", "device", d.ID, "error", err.Error())
			r.State = StateUnavailable
			break
		}
		r.Agent, r.Token = ptrTo(f.Agent), f.Token
		if f.Agent == AgentOsquery || f.Agent == AgentWazuh {
			r.LastAt = nil // the agent's own time, the one its state was judged by
			if !f.LastSeen.IsZero() {
				r.LastAt = ptrTo(store.FormatTS(f.LastSeen))
			}
		}
		switch {
		case s.certChanged(ctx, d, f, &r):
			// before every other state: whatever the agent's record says, it cannot reach the box until it is installed again
		case f.Agent == AgentOsquery && f.State == StateNeverReported:
			r.State, r.Action = f.State, ptrTo(ActionShowSetup)
		case f.Agent == AgentOsquery || f.Agent == AgentWazuh:
			r.State, r.Action = cmpOr(f.State, StateReporting), ptrTo(ActionCheck)
		case f.Agent == AgentBox:
			r.State, r.Action = StateReporting, ptrTo(ActionCheck)
		case f.Token != nil:
			r.State, r.Action = StateWaiting, ptrTo(ActionShowSetup)
		default:
			r.State, r.Action = StateNone, ptrTo(ActionCreateToken)
		}
		// The switch is there when an agent reads the device, or when it is off (so a person can turn it on again).
		if f.Agent == AgentOsquery || f.Agent == AgentWazuh || sw == SourceOff {
			r.Switch = ptrTo(sw)
		}
		if sw == SourceOff {
			r.State, r.Refused = StateOff, nil
		}
	}
	r.Dot = dotOf(r.State)
	return r
}

// certChanged says the device's agent pins a certificate authority the box no longer has, and fills the row for it: the box heard the
// device's address refuse its certificate recently (TLSRefusals), or its osquery agent has been silent since before the CA in use
// began (TrustSince: no report can have reached the box under it). The button is the install command again: the token's when one
// exists, else a new token (a purge or a reinstall removed them all).
func (s *Service) certChanged(ctx context.Context, d Device, f AgentFact, r *SourceRow) bool {
	if f.Agent == AgentWazuh || f.Agent == AgentBox || f.State == StateReporting || f.State == StateReplaced {
		return false // a Wazuh agent talks to its own server; an agent that reports reaches the box (a refusal from its address is another client)
	}
	var ref TLSRefusal
	if s.tlsRefusals != nil {
		ref = s.tlsRefusals(d.IP)
	}
	heard := ref.Count >= refusedMin && s.clock().Sub(ref.Last) <= refusedFresh
	before := false
	if !heard && s.trustSince != nil && f.Agent == AgentOsquery && (f.State == StateQuiet || f.State == StateNeverReported) && !f.LastSeen.IsZero() {
		if since := s.trustSince(ctx); !since.IsZero() && f.LastSeen.Before(since) {
			before = true
		}
	}
	if !heard && !before {
		return false
	}
	r.State, r.Action = StateCertChanged, ptrTo(ActionCreateToken)
	if f.Token != nil {
		r.Action = ptrTo(ActionShowSetup)
	}
	if heard {
		r.Refused = &Refused{Since: store.FormatTS(ref.First), Last: store.FormatTS(ref.Last), Count: ref.Count}
	}
	return true
}

// agentSwitch is the device's agent switch, the default resolved (agentState).
func (s *Service) agentSwitch(ctx context.Context, id string) (string, error) {
	var stored string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT coalesce(agent_source, '') FROM inv_asset WHERE id = ?`, id).Scan(&stored); err != nil {
		return "", err
	}
	return agentState(stored), nil
}

// dotOf is the colour of a state: green when the source reads the device as it should, amber when an agent is late or never sent its
// data, red when SNMP gets no answer, grey otherwise (off, not set up, nothing read yet).
func dotOf(state string) string {
	switch state {
	case StateWorking, StateReporting:
		return DotGreen
	case StateQuiet, StateNeverReported:
		return DotAmber
	case StateNotAnswering, StateCertChanged:
		return DotRed
	}
	return DotGrey
}

// hasAddress says whether a device's IP is an address a source can be sent to.
func hasAddress(ip string) bool {
	_, err := netip.ParseAddr(ip)
	return err == nil
}

func ptrTo(s string) *string { return &s }
