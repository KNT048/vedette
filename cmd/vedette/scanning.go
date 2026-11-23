package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/scan"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// Settings › Scanning (#850, core INV-40): the ports core reads every engine through. Core imports no module; this file adapts each
// module's own reads and switches. The memory figures are facts of the box's code, never estimates: the containers' --memory caps of
// host/ops/quadlet.go (sensor 512m, honeypot 256m, scan 1g) and host/ops/zap.go (1g), osquery and Wazuh inside core (0), and the
// measured peak of OpenVAS beside Vedette on a 7 GB test box, about 4.0 GB (modules/exposure/greenbone.go).

const scanContainer = "scan" // nmap discovery, version scans, SNMP and nuclei share the scan container

func mb(n int) *int { return &n }

// scanningHandlers builds core's Settings › Scanning handlers over the module services of d.
func scanningHandlers(d deps) *core.ScanningHandlers {
	e := scanningEngines{d: d}
	h, err := core.NewScanningHandlers(core.ScanningConfig{
		DB: d.DB, Reg: d.Reg, Audit: d.Audit, Log: d.Log,
		Safety:    scanningSafety{inv: d.Inventory},
		Engines:   e.list(),
		Discovery: discoveryRunner{e},
		Estimate: func(ctx context.Context, in core.ScopeCostInput) (core.ScopeCost, error) {
			c := sweepCost(ctx, d, sensoractive.Settings{LANRanges: in.LANRanges, Exclusions: in.Exclusions, Days: in.Days, From: in.From, To: in.To, Rate: in.PacketsPerS})
			return core.ScopeCost{Addresses: c.Addresses, PassSeconds: int(c.Pass / time.Second), WindowSeconds: int(c.Window / time.Second), Windows: c.Windows,
				WeekWindows: c.WeekWindows, FitsWindow: c.Windows <= 1, FitsWeek: c.FitsWeek()}, nil
		},
		History: e.history, // scanninghistory.go
		TimeZone: func(ctx context.Context) string {
			if d.Core == nil {
				return ""
			}
			return orgZone(&d)(ctx)
		},
		MemoryMB: boxMemoryMB,
	})
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	return h
}

// boxMemoryMB is the box's MemTotal in MiB (/proc/meminfo); false when it cannot be read.
func boxMemoryMB() (int, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || kb <= 0 || kb > 1<<40 {
				return 0, false
			}
			return int(kb / 1024), true
		}
	}
	return 0, false
}

// ---- the shared safety block: the inventory is its one store (inventory INV-32) ----

type scanningSafety struct{ inv *inventory.Service }

func (s scanningSafety) view(ctx context.Context, st inventory.Settings) (core.Safety, error) {
	n, err := s.inv.FragileCount(ctx)
	if err != nil {
		return core.Safety{}, err
	}
	return core.Safety{
		LANRanges: st.LANRanges, ConfirmedAt: st.ScopeConfirmedAt, ConfirmedBy: st.ScopeConfirmedBy,
		Days: st.Active.Days, From: st.Active.From, To: st.Active.To, PacketsPerS: st.Active.Rate, RequestsPerS: st.Active.Checks(),
		Exclusions: st.Active.Exclusions, FragileKinds: st.FragileKinds, RegularScanKinds: st.RegularScanKinds, FragileDevices: n,
		Version: st.Version,
	}, nil
}

// changed turns the inventory's *Changed (409 safety_changed, scope_changed) into core's, with the current block; other errors pass.
func (s scanningSafety) changed(ctx context.Context, err error) error {
	var ch *inventory.Changed
	if !errors.As(err, &ch) {
		return err
	}
	cur, verr := s.view(ctx, ch.Current)
	if verr != nil {
		return err
	}
	return &core.SafetyChanged{Code: ch.API.Code, Message: ch.API.Message, Current: cur}
}

func (s scanningSafety) Safety(ctx context.Context) (core.Safety, error) {
	if s.inv == nil {
		return core.Safety{}, errors.New("vedette: scanning: the inventory is not wired")
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return core.Safety{}, err
	}
	return s.view(ctx, st)
}

func (s scanningSafety) SaveSafety(ctx context.Context, actor string, in core.SafetyInput) (core.Safety, []core.Adjustment, error) {
	if s.inv == nil {
		return core.Safety{}, nil, errors.New("vedette: scanning: the inventory is not wired")
	}
	saved, err := s.inv.SaveSafety(ctx, actor, inventory.SafetyInput{
		LANRanges: in.LANRanges, Confirmed: in.Confirmed, Days: in.Days, From: in.From, To: in.To, PacketsPerS: in.PacketsPerS,
		RequestsPerS: in.RequestsPerS, Exclusions: in.Exclusions, FragileKinds: in.FragileKinds, RegularScanKinds: in.RegularScanKinds,
		Version: in.Version,
	})
	if err != nil {
		return core.Safety{}, nil, s.changed(ctx, err)
	}
	v, err := s.view(ctx, saved.Settings)
	if err != nil {
		return core.Safety{}, nil, err
	}
	adj := make([]core.Adjustment, 0, len(saved.Adjusted))
	for _, a := range saved.Adjusted {
		adj = append(adj, core.Adjustment{From: a.From, To: a.To})
	}
	return v, adj, nil
}

func (s scanningSafety) AddRange(ctx context.Context, actor string, in core.RangeAdd) (core.Safety, []core.Adjustment, error) {
	if s.inv == nil {
		return core.Safety{}, nil, errors.New("vedette: scanning: the inventory is not wired")
	}
	saved, err := s.inv.AddRange(ctx, actor, inventory.RangeAdd{Range: in.Range, Shown: in.Shown, ShownConfirmedAt: in.ShownConfirmedAt, Confirmed: in.Confirmed})
	if err != nil {
		return core.Safety{}, nil, s.changed(ctx, err)
	}
	v, err := s.view(ctx, saved.Settings)
	if err != nil {
		return core.Safety{}, nil, err
	}
	adj := make([]core.Adjustment, 0, len(saved.Adjusted))
	for _, a := range saved.Adjusted {
		adj = append(adj, core.Adjustment{From: a.From, To: a.To})
	}
	return v, adj, nil
}

func (s scanningSafety) AddExclusion(ctx context.Context, actor, entry string) (core.Safety, error) {
	if s.inv == nil {
		return core.Safety{}, errors.New("vedette: scanning: the inventory is not wired")
	}
	saved, err := s.inv.AddExclusion(ctx, actor, entry)
	if err != nil {
		return core.Safety{}, s.changed(ctx, err)
	}
	return s.view(ctx, saved.Settings)
}

// ---- the scan module reads the shared window, check rate and exclusions from the inventory (scan INV-16) ----

// scanChecksInv is the inventory's writer of the shared checks (inventory.Service).
type scanChecksInv interface {
	SaveChecks(ctx context.Context, tx *sql.Tx, actor string, in inventory.ChecksInput) error
	Settle(ctx context.Context, tx *sql.Tx, committed bool)
}

// Checks implements scan.SharedChecks.
func (s scanInventory) Checks(ctx context.Context) (scan.Checks, error) {
	if s.inv == nil {
		return scan.Checks{}, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return scan.Checks{}, err
	}
	return scan.Checks{Window: scan.Window{Days: st.Active.Days, From: st.Active.From, To: st.Active.To}, Rate: st.Active.Checks(), Exclusions: st.Active.Exclusions,
		Version: st.Version}, nil
}

// SaveChecks implements scan.SharedChecks.
func (s scanInventory) SaveChecks(ctx context.Context, tx *sql.Tx, user string, c scan.Checks) error {
	w, ok := s.inv.(scanChecksInv)
	if !ok {
		return fmt.Errorf("vedette: scan: the inventory cannot store the shared settings")
	}
	in := inventory.ChecksInput{Days: c.Window.Days, From: c.Window.From, To: c.Window.To, CheckRate: c.Rate, Exclusions: c.Exclusions, Version: c.Version}
	return w.SaveChecks(ctx, tx, user, in)
}

// Settle implements scan.SharedChecks.
func (s scanInventory) Settle(ctx context.Context, tx *sql.Tx, committed bool) {
	if w, ok := s.inv.(scanChecksInv); ok {
		w.Settle(ctx, tx, committed)
	}
}

// ---- the engines ----

// scanningEngines reads the engines through d. sensor-active is found with sensorActiveService, which newHandler's snmpService has built
// with the server's start-up context before any request: a request's ctx passed here only finds it (it keeps the first caller's values).
type scanningEngines struct{ d deps }

func (e scanningEngines) on(id string) bool { return e.d.Reg == nil || e.d.Reg.Enabled(id) }

func (e scanningEngines) available(id string) bool {
	if e.d.Reg == nil {
		return true
	}
	for _, m := range e.d.Reg.List() {
		if m.ID == id {
			return m.Available
		}
	}
	return false
}

const notApplianceText = "This install has no operating system helper (container-only install), so it cannot run this."

func (e scanningEngines) list() []core.ScanEngine {
	scanCost := core.EngineCost{RAMMB: mb(1024), While: core.CostWhileOn, Container: scanContainer}
	discoveryOff := func(ctx context.Context, on bool) error {
		if !on || e.d.Inventory == nil {
			return nil
		}
		st, err := e.d.Inventory.Settings(ctx)
		if err != nil {
			return err
		}
		// Every refusal of SetDiscovery is checked here, before sensor-active is turned on with it (#857): a refused switch
		// changes nothing.
		switch {
		case len(st.LANRanges) == 0:
			return apierr.New(400, "no_ranges", "Active scanning needs at least one network range.")
		case len(st.Active.Days) == 0:
			return apierr.New(400, "no_days", "Choose at least one day for the scan window, or turn active scanning off.")
		case st.ScopeConfirmedAt == nil:
			return apierr.New(400, "scope_not_confirmed", "Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.")
		}
		return nil
	}
	return []core.ScanEngine{
		{ID: "passive", Group: "discover", Module: "sensor-passive", Switch: core.SwitchModule,
			Cost: core.EngineCost{RAMMB: mb(512), While: core.CostWhileOn}, Status: e.passive},
		{ID: "nmap-discovery", Group: "discover", Module: "sensor-active", Switch: core.SwitchOwn, Needs: "sensor-active",
			Affects: []string{"nmap-versions", "snmp"}, Cost: scanCost, Precheck: discoveryOff, Toggle: e.setDiscovery,
			Status: func(ctx context.Context) (core.EngineStatus, error) { return e.active(ctx, "nmap-discovery") }},
		{ID: "nmap-versions", Group: "identify", Module: "sensor-active", Follows: "nmap-discovery", Cost: scanCost,
			Status: func(ctx context.Context) (core.EngineStatus, error) { return e.active(ctx, "nmap-versions") }},
		{ID: "snmp", Group: "identify", Module: "sensor-active", Follows: "nmap-discovery", Cost: scanCost,
			Status: func(ctx context.Context) (core.EngineStatus, error) { return e.active(ctx, "snmp") }},
		{ID: "osquery", Group: "identify", Module: "agent-intake", Switch: core.SwitchModule, Affects: []string{"wazuh"},
			Cost: core.EngineCost{RAMMB: mb(0), While: core.CostWhileOn}, Status: e.osquery},
		{ID: "wazuh", Group: "identify", Module: "agent-intake", Switch: core.SwitchModule, Affects: []string{"osquery"},
			Cost: core.EngineCost{RAMMB: mb(0), While: core.CostWhileOn}, Status: e.wazuh},
		{ID: "nuclei", Group: "vuln", Module: "scan", Preview: true, Switch: core.SwitchModule, Cost: scanCost, Status: e.nuclei},
		{ID: "zap", Group: "vuln", Module: "exposure", Cost: core.EngineCost{RAMMB: mb(1024), While: core.CostWhileRunning}, Status: e.zap},
		{ID: "openvas", Group: "vuln", Module: "exposure", Switch: core.SwitchOwn, Cost: core.EngineCost{RAMMB: mb(4000), While: core.CostWhileOn},
			Precheck: func(_ context.Context, on bool) error {
				if on && !e.on(exposure.ModuleID) {
					return apierr.New(409, "module_off", "The External exposure module is off, so OpenVAS cannot run. An admin can turn it on in Settings, Modules.")
				}
				return nil
			}, Toggle: e.setOpenVAS, Status: e.openvas},
		{ID: "honeypot", Group: "traps", Module: "honeypot", Preview: true, Switch: core.SwitchModule,
			Cost: core.EngineCost{RAMMB: mb(256), While: core.CostWhileOn}, Status: e.honeypot},
	}
}

func parseTS(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func (e scanningEngines) passive(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on("sensor-passive"), State: core.EngineOff}
	if e.d.SensorPassive == nil {
		if s.Enabled {
			s.State = core.EngineUnavailable
		}
		return s, nil
	}
	sensors, err := e.d.SensorPassive.Status(ctx)
	if err != nil {
		return s, err
	}
	var last time.Time
	states := map[string]bool{}
	var capture string
	for _, x := range sensors {
		if x.LastSeen != nil {
			if t, ok := parseTS(*x.LastSeen); ok && t.After(last) {
				last = t
			}
		}
		states[x.Status] = true
		if x.CaptureError != nil && capture == "" {
			capture = *x.CaptureError
		}
	}
	if !last.IsZero() {
		s.Last = &core.LastRun{At: last, Outcome: "ok", Text: "Last report from the passive sensor"}
	}
	if !s.Enabled {
		return s, nil
	}
	switch {
	case capture != "":
		s.State, s.Reason = core.EngineError, "The sensor is online but does not capture ("+strings.ReplaceAll(capture, "_", " ")+"). Settings › Box network says how to fix it."
	case states["online"]:
		s.State = core.EngineReady
	case states["starting"]:
		s.State, s.Reason = core.EngineStarting, "The box is starting the sensor container."
	case states["offline"]:
		s.State, s.Reason = core.EngineError, "The passive sensor has not reported for more than 90 seconds."
	default:
		s.State, s.Reason = core.EngineNeedsSetup, "No passive sensor has reported yet. Start the sensor container (Devices › Scope and sensors says how)."
	}
	return s, nil
}

// active is the card of nmap-discovery, nmap-versions or snmp: one switch (inventory active.enabled behind the sensor-active module).
func (e scanningEngines) active(ctx context.Context, id string) (core.EngineStatus, error) {
	s := core.EngineStatus{State: core.EngineOff}
	if e.d.Inventory == nil {
		return s, nil
	}
	st, err := e.d.Inventory.Settings(ctx)
	if err != nil {
		return s, err
	}
	s.Enabled = e.on("sensor-active") && st.Active.Enabled
	svc, err := sensorActiveService(ctx, e.d)
	if err != nil { // no dispatcher: a build without the scan container's link
		if s.Enabled {
			s.State, s.Reason = core.EngineUnavailable, "Active discovery is not available in this build."
		}
		return s, nil //nolint:nilerr // the card says it
	}
	v, err := svc.Engine(ctx)
	if err != nil {
		return s, err
	}
	kind := map[string]string{"nmap-discovery": sensoractive.KindSweep, "nmap-versions": sensoractive.KindDevice, "snmp": sensoractive.KindSNMP}[id]
	if h, ok := v.Last[kind]; ok {
		s.Last = jobRun(h)
	}
	if !s.Enabled {
		return s, nil
	}
	s.Next = v.NextWindow
	if id == "nmap-discovery" { // the sweep follows its own schedule; the checks of devices and the SNMP reads follow the window
		s.Next = nextStart(ctx, e.d, sensoractive.ScheduleKey)
	}
	switch {
	case st.ScopeConfirmedAt == nil || len(st.LANRanges) == 0:
		s.State, s.Reason = core.EngineNeedsSetup, "Confirm the network ranges Vedette may scan (the safety settings above)."
		return s, nil
	case v.Health.Status != "ok" && e.d.ScanStart.Starting(): // the box is bringing the scan container up (busy host after an update, #889)
		s.State, s.Reason = core.EngineStarting, "The box is starting the scan container."
		return s, nil
	case v.Health.Status != "ok":
		s.State, s.Reason = core.EngineUnavailable, v.Health.Message
		return s, nil
	}
	s.State = core.EngineReady
	switch id {
	case "nmap-discovery":
		s.Reason = v.Health.Warning
		if len(v.Persons) > 0 { // every run a person asked for, queued or going: each says what it waits for
			s.State = core.EngineRunning
			for _, m := range v.Persons {
				s.Running = append(s.Running, manualJob(m))
			}
		} else if c := v.Current; c != nil && c.Kind == sensoractive.KindSweep {
			s.State = core.EngineRunning
			s.Running = append(s.Running, core.RunningJob{Engine: id, ID: orID(c.JobID, "sweep"), Label: "LAN sweep " + strings.Join(st.LANRanges, ", "), StartedAt: c.StartedAt})
		}
	case "nmap-versions":
		if c := v.Current; c != nil && c.Kind == sensoractive.KindDevice {
			s.State = core.EngineRunning
			if len(v.Persons) == 0 { // a run a person started is listed once, under nmap-discovery
				label := "Version scan"
				if len(c.Targets) == 1 {
					label = "Version scan " + c.Targets[0].String()
				}
				s.Running = append(s.Running, core.RunningJob{Engine: id, ID: orID(c.JobID, "device"), Label: label, TargetID: c.Asset, StartedAt: c.StartedAt})
			}
		}
	case "snmp":
		devs, err := svc.SNMPDevices(ctx)
		if err != nil {
			return s, err
		}
		if len(devs) == 0 {
			s.State, s.Reason = core.EngineNeedsSetup, "Set SNMP up on a device's page (Devices › the device › SNMP) to read it."
			return s, nil
		}
		if h := v.SNMP; h != nil {
			s.State = core.EngineRunning
			at, _ := parseTS(h.StartedAt)
			s.Running = append(s.Running, core.RunningJob{Engine: id, ID: h.ID, Label: "SNMP reads", StartedAt: at})
		}
		// A device whose saved secret this box cannot open is skipped by every read until it is typed again; one that moved
		// away from the read address it had is not read until a person sets it again.
		var lost, moved []string
		for _, d := range devs {
			switch {
			case d.SecretLost:
				lost = append(lost, cmpOrName(d.Name))
			case d.Blocked != nil && d.Blocked.Reason == sensoractive.SNMPMoved:
				moved = append(moved, fmt.Sprintf("%s moved to %s, away from its SNMP read address %s", cmpOrName(d.Name), d.IP, d.ReadFrom))
			}
		}
		if len(lost) > 0 {
			s.Reason = "The saved SNMP community or password of " + strings.Join(lost, ", ") + " was not restored (the backup was restored without its decryption key, or the box key changed), so it is skipped. Open the device's page, SNMP, Edit, enter it again and save."
			if len(lost) == len(devs) && s.State == core.EngineReady {
				s.State = core.EngineError
			}
		}
		if len(moved) > 0 {
			text := strings.Join(moved, "; ") + ": check the device, then set Read from on its page (SNMP, Edit) to keep reading it."
			if s.Reason != "" {
				text = s.Reason + " " + text
			}
			s.Reason = text
		}
	}
	return s, nil
}

// cmpOrName is a device's name for the card, or words for one without a name.
func cmpOrName(name string) string {
	if name == "" {
		return "A device"
	}
	return name
}

func orID(id, fallback string) string {
	if id == "" {
		return fallback
	}
	return id
}

// jobRun is an sa_job row as a card's last run.
func jobRun(h sensoractive.JobHead) *core.LastRun {
	at, ok := time.Time{}, false
	if h.FinishedAt != nil {
		at, ok = parseTS(*h.FinishedAt)
	}
	if !ok {
		if at, ok = parseTS(h.StartedAt); !ok {
			return nil
		}
	}
	r := &core.LastRun{At: at, Outcome: map[string]string{sensoractive.StatusDone: "ok", sensoractive.StatusStopped: "stopped", sensoractive.StatusFailed: "failed"}[h.Status]}
	if r.Outcome == "" {
		r.Outcome = "failed"
	}
	switch h.Kind {
	case sensoractive.KindSweep:
		r.Text = fmt.Sprintf("Swept %d addresses, %d new devices", h.Targets, h.NewDevices)
	case sensoractive.KindDevice:
		r.Text = "Scanned a device"
		if h.Reason == "scan_now" {
			r.Text = "Scanned a device a person picked"
		}
	case sensoractive.KindSNMP:
		r.Text = fmt.Sprintf("Read %d devices over SNMP", h.Targets)
	}
	if h.Error != "" && r.Outcome != "ok" {
		r.Text += ": " + h.Error
		if rr := []rune(r.Text); len(rr) > 300 {
			r.Text = string(rr[:300])
		}
	}
	return r
}

// manualJob is a run a person started as running[] shows it.
func manualJob(m sensoractive.ManualRun) core.RunningJob {
	j := core.RunningJob{Engine: "nmap-discovery", ID: m.ID, StartedAt: m.StartedAt, Progress: m.Progress}
	switch {
	case len(m.Assets) == 0:
		j.Label = "LAN sweep " + strings.Join(m.Ranges, ", ")
	case len(m.Assets) == 1:
		j.Label, j.TargetID = "Check "+m.Assets[0], m.Assets[0]
		if m.IP.IsValid() {
			j.Label = "Check " + m.IP.String()
		}
	default:
		j.Label = fmt.Sprintf("Check %d devices", len(m.Assets))
	}
	return j
}

func (e scanningEngines) setDiscovery(ctx context.Context, actor string, on bool) error {
	if e.d.Inventory == nil {
		return errors.New("vedette: scanning: the inventory is not wired")
	}
	return e.d.Inventory.SetDiscovery(ctx, actor, on)
}

func (e scanningEngines) osquery(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on("agent-intake"), State: core.EngineOff}
	if e.d.AgentIntake == nil {
		return s, nil
	}
	tokens, err := e.d.AgentIntake.ListTokens(ctx)
	if err != nil {
		return s, err
	}
	var last time.Time
	for _, t := range tokens {
		if t.LastReceived.After(last) {
			last = t.LastReceived
		}
	}
	if !last.IsZero() {
		s.Last = &core.LastRun{At: last, Outcome: "ok", Text: "Last report from an osquery agent"}
	}
	if s.Enabled {
		s.State = core.EngineReady
		if len(tokens) == 0 {
			s.State, s.Reason = core.EngineNeedsSetup, "Make an enrollment token and install osquery on a computer (Devices › Add devices)."
		}
	}
	return s, nil
}

func (e scanningEngines) wazuh(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on("agent-intake"), State: core.EngineOff}
	if e.d.AgentIntake == nil {
		return s, nil
	}
	w, err := e.d.AgentIntake.Wazuh(ctx)
	if err != nil {
		return s, err
	}
	if w != nil && !w.LastSync.IsZero() {
		s.Last = &core.LastRun{At: w.LastSync, Outcome: "ok", Text: fmt.Sprintf("Synced %d agents", w.Agents)}
		if w.Status == "error" {
			s.Last.Outcome, s.Last.Text = "failed", "The last sync failed"
		}
	}
	if !s.Enabled {
		return s, nil
	}
	switch {
	case w == nil:
		s.State, s.Reason = core.EngineNeedsSetup, "Connect your Wazuh server (Devices › Add devices)."
	case w.Status == "error":
		s.State, s.Reason = core.EngineError, w.Error
	default:
		s.State = core.EngineReady
		s.Next = nextStart(ctx, e.d, agentintake.WazuhScheduleKey)
	}
	return s, nil
}

// nextStart is when the schedule of key next starts, as the schedule editor shows it (the scan window applied); nil while it is
// off or unknown.
func nextStart(ctx context.Context, d deps, key string) *time.Time {
	if d.Schedules == nil {
		return nil
	}
	v, err := d.Schedules.Get(ctx, key)
	if err != nil || !v.Enabled {
		return nil
	}
	if len(v.Upcoming) > 0 {
		return &v.Upcoming[0]
	}
	return v.NextDueAt
}

// externalRun is the newest external scan in which engine's step ran (exposure INV-30, #861) as a card's last run; nil when none did.
// Those scans run on Scan now only (exposure has no schedule), so the cards of zap and openvas have no next run.
func (e scanningEngines) externalRun(ctx context.Context, engine string) (*core.LastRun, error) {
	if e.d.DB == nil {
		return nil, nil //nolint:nilnil // no database: no run
	}
	runs, err := exposureService(e.d).EngineRuns(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := runs[engine]
	if !ok {
		return nil, nil //nolint:nilnil // the step never ran
	}
	at, ok := parseTS(r.At)
	if !ok {
		return nil, nil //nolint:nilnil // never stored: the column holds the box's timestamps only
	}
	return &core.LastRun{At: at, Outcome: r.Outcome, Text: r.Text}, nil
}

// later is the newer of two last runs.
func later(a, b *core.LastRun) *core.LastRun {
	if a == nil || (b != nil && b.At.After(a.At)) {
		return b
	}
	return a
}

// nuclei is the card of the vulnerability checks: the scan module's LAN runs and the template step of the external scans (which run
// nuclei too), whichever ran last.
func (e scanningEngines) nuclei(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on("scan"), State: core.EngineOff}
	ext, err := e.externalRun(ctx, exposure.StepNuclei)
	if err != nil {
		return s, err
	}
	s.Last = ext
	if e.d.DB == nil || e.d.Audit == nil || e.d.Log == nil {
		return s, nil
	}
	v, err := scanService(e.d).Engine(ctx)
	if err != nil {
		return s, err
	}
	if l := v.Last; l != nil {
		at, ok := time.Time{}, false
		if l.EndedAt != nil {
			at, ok = parseTS(*l.EndedAt)
		}
		if !ok {
			at, ok = parseTS(l.StartedAt)
		}
		if ok {
			outcome := map[string]string{"done": "ok", "stopped": "stopped", "failed": "failed"}[l.Status]
			if outcome == "" {
				outcome = "partial"
			}
			s.Last = later(ext, &core.LastRun{At: at, Outcome: outcome, Text: fmt.Sprintf("Checked %d of %d devices, %d confirmed", l.Done, l.Total, l.Matched)})
		}
	}
	if !s.Enabled {
		return s, nil
	}
	s.Next = nextStart(ctx, e.d, scan.ScheduleKey)
	switch {
	case v.Running != nil:
		s.State = core.EngineRunning
		at, _ := parseTS(v.Running.StartedAt)
		s.Running = append(s.Running, core.RunningJob{Engine: "nuclei", ID: v.Running.ID, Label: fmt.Sprintf("Vulnerability checks of %d devices", v.Running.Total), StartedAt: at, Progress: v.Running.Progress})
	case v.BlockReason != nil && strings.HasPrefix(*v.BlockReason, "The vulnerability scanner"):
		s.State, s.Reason = core.EngineUnavailable, *v.BlockReason
	case v.BlockReason != nil:
		s.State, s.Reason = core.EngineNeedsSetup, *v.BlockReason
	default:
		s.State = core.EngineReady
	}
	return s, nil
}

// external is the exposure scan running now, if any: its card is the step it is at (the passive web checks: zap; OpenVAS: openvas;
// anything else: the ports, services and vulnerability checks).
func (e scanningEngines) external(ctx context.Context) (core.RunningJob, string, bool) {
	if e.d.DB == nil {
		return core.RunningJob{}, "", false
	}
	r := exposureService(e.d).CurrentScan(ctx)
	if r == nil || r.Status != exposure.RunRunning {
		return core.RunningJob{}, "", false
	}
	engine := "nuclei"
	switch {
	case r.Phase == exposure.PhaseGreenbone || (r.Progress != nil && r.Progress.Phase == "openvas"):
		engine = "openvas"
	case r.Progress != nil && r.Progress.Phase == "web":
		engine = "zap"
	}
	at, _ := parseTS(r.StartedAt)
	return core.RunningJob{Engine: engine, ID: r.ID, Label: r.TargetValue, TargetID: r.TargetID, StartedAt: at, Progress: r.Progress}, engine, true
}

// zap is the card of the passive web checks, a step of every external scan of a web port. It also lists the external scan running
// now in running[], whatever its step (one entry; the engine named is the step's), since that scan belongs to the External exposure
// module that both zap and openvas follow.
func (e scanningEngines) zap(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on(exposure.ModuleID), State: core.EngineOff}
	last, err := e.externalRun(ctx, exposure.StepZAP)
	if err != nil {
		return s, err
	}
	s.Last = last
	if !s.Enabled {
		return s, nil
	}
	j, engine, running := e.external(ctx)
	if running {
		s.Running = []core.RunningJob{j}
	}
	switch {
	case e.d.Reg != nil && e.d.Reg.ContainerOnly(): // ZAP runs as a container vedette-host starts (host/ops/zap.go)
		s.State, s.Reason = core.EngineUnavailable, notApplianceText
	case running && engine == "zap":
		s.State = core.EngineRunning
	default:
		s.State = core.EngineReady
	}
	return s, nil
}

func (e scanningEngines) openvas(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{State: core.EngineOff}
	if e.d.DB == nil {
		return s, nil
	}
	v, err := exposureService(e.d).GreenboneSetting(ctx)
	if err != nil {
		return s, err
	}
	if s.Last, err = e.externalRun(ctx, exposure.StepOpenVAS); err != nil {
		return s, err
	}
	s.Enabled = e.on(exposure.ModuleID) && v.Enabled
	if !s.Enabled {
		if v.State == exposure.GBUnavailable && v.Reason != nil {
			s.Reason = *v.Reason
		}
		return s, nil
	}
	switch v.State {
	case exposure.GBUnavailable:
		s.State = core.EngineUnavailable
	case exposure.GBStarting, exposure.GBLoading:
		s.State = core.EngineStarting
	case exposure.GBError:
		s.State = core.EngineError
	case exposure.GBOff:
		s.State = core.EngineOff
	default:
		s.State = core.EngineReady
	}
	if v.Reason != nil {
		s.Reason = *v.Reason
	}
	if _, engine, ok := e.external(ctx); ok && engine == "openvas" { // listed in running[] by zap's card
		s.State = core.EngineRunning
	}
	return s, nil
}

func (e scanningEngines) setOpenVAS(ctx context.Context, actor string, on bool) error {
	_, err := exposureService(e.d).SetGreenbone(ctx, actor, on)
	var ae *exposure.APIError
	if errors.As(err, &ae) { // low_memory, low_disk, not_appliance: as PUT /exposure/greenbone answers them
		return apierr.New(ae.HTTP, ae.Code, ae.Message)
	}
	return err
}

func (e scanningEngines) honeypot(ctx context.Context) (core.EngineStatus, error) {
	s := core.EngineStatus{Enabled: e.on("honeypot"), State: core.EngineOff}
	if !e.available("honeypot") {
		s.State, s.Reason = core.EngineUnavailable, notApplianceText
		return s, nil
	}
	if e.d.Honeypot == nil {
		return s, nil
	}
	o, err := e.d.Honeypot.Overview(ctx)
	if err != nil {
		return s, err
	}
	if o.Summary.LastHitAt != nil {
		if t, ok := parseTS(*o.Summary.LastHitAt); ok {
			s.Last = &core.LastRun{At: t, Outcome: "ok", Text: "Last trap hit"}
		}
	}
	if !s.Enabled {
		return s, nil
	}
	s.State, s.Reason = honeypotState(o)
	return s, nil
}

// honeypotState is the state of the switched-on honeypot card from the module's overview.
func honeypotState(o honeypot.Overview) (state, reason string) {
	switch {
	case o.TrapIPs.Enabled == 0:
		return core.EngineNeedsSetup, "Add a Trap IP (Intrusion detection › Honeypot)."
	case o.Problem != nil:
		return core.EngineError, *o.Problem
	case o.TrapIPs.Listening == 0 && slices.ContainsFunc(o.Traps, func(t honeypot.Trap) bool { return t.Enabled && t.State == honeypot.StateStarting }):
		// a change or a container start the host has not confirmed yet (busy right after an update, #889): not an error
		return core.EngineStarting, "The box is starting the honeypot container."
	}
	return core.EngineReady, ""
}

// ---- Scan the LAN now / Check this device now (sensor-active INV-21) ----

type discoveryRunner struct{ e scanningEngines }

func (r discoveryRunner) Run(ctx context.Context, actor string, targets []string, record func(*sql.Tx, core.RunConsent) error) (core.RunningJob, error) {
	if !r.e.on("sensor-active") {
		return core.RunningJob{}, core.ErrDiscoveryModuleOff
	}
	svc, err := sensorActiveService(ctx, r.e.d)
	if err != nil {
		return core.RunningJob{}, core.ErrNmapUnavailable
	}
	m, err := svc.StartManual(ctx, actor, targets, func(tx *sql.Tx, m sensoractive.ManualRun) error {
		c := core.RunConsent{ID: m.ID, Ranges: m.Ranges, Until: m.Until}
		for _, id := range m.Assets {
			if len(m.Assets) == 1 && m.IP.IsValid() {
				id = m.IP.String() + " (" + id + ")"
			}
			c.Devices = append(c.Devices, id)
		}
		return record(tx, c)
	})
	var te *sensoractive.TargetError
	var soon *sensoractive.TooSoonError
	switch {
	case err == nil:
		return manualJob(m), nil
	case errors.As(err, &te):
		return core.RunningJob{}, &core.RunRefusal{Target: te.Target, Code: te.Reason, Detail: te.Detail}
	case errors.As(err, &soon):
		return core.RunningJob{}, &core.RunTooSoon{RetryAfter: soon.RetryAfter}
	case errors.Is(err, sensoractive.ErrStopped):
		return core.RunningJob{}, core.ErrDiscoveryModuleOff // the module was turned off while the run was checked
	case errors.Is(err, sensoractive.ErrScanningOff):
		return core.RunningJob{}, core.ErrDiscoveryOff
	case errors.Is(err, sensoractive.ErrScopeNotConfirmed), errors.Is(err, sensoractive.ErrNoRanges):
		return core.RunningJob{}, core.ErrScopeNotConfirmed
	case errors.Is(err, sensoractive.ErrUnavailable):
		return core.RunningJob{}, core.ErrNmapUnavailable
	case errors.Is(err, sensoractive.ErrSlotBusy):
		return core.RunningJob{}, core.ErrNmapBusy
	}
	return core.RunningJob{}, err
}
