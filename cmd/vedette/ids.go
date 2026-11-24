package main

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	idsmodule "github.com/knt048/vedette/modules/ids"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/notify"
)

var (
	idsMu       sync.Mutex
	idsServices = map[*store.DB]*idsmodule.Service{}
)

// idsService builds the intrusion detection service once per database, so the handlers, the jobs, the logs hand-off and the overview
// share it (and the events it holds until the next flush).
func idsService(d deps) *idsmodule.Service {
	idsMu.Lock()
	defer idsMu.Unlock()
	if s := idsServices[d.DB]; s != nil {
		return s
	}
	cfg := idsmodule.Config{DB: d.DB, Log: d.Log, Clock: d.Clock}
	if d.Inventory != nil {
		cfg.Inventory = idsInventory{logsInventory{inv: d.Inventory, snmp: logsSNMP(d)}, notifyDevices{d.Inventory}}
	}
	cfg.Findings = idsFindings{d: &d}
	cfg.Incidents = idsIncidents{d: &d}
	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil
		cfg.Modules = d.Reg
	}
	if d.Bus != nil {
		cfg.Events = d.Bus
	}
	svc, err := idsmodule.NewService(cfg)
	if err != nil { // a missing database: a programming error in serve
		panic("vedette: " + err.Error())
	}
	idsServices[d.DB] = svc
	return svc
}

// idsJobs is the Jobs func of the ids entry in wiredModules.
func idsJobs(d deps) []jobs.Job { return idsService(d).Jobs() }

// idsReceived is the logs module's Config.Received: the lines it stored go to the ids module, which reads the IPS events among them
// in memory (no database write in the call). The service is looked up at the call, so the logs service may be built first.
func idsReceived(d deps) func(ctx context.Context, lines []logs.StoredLine) {
	return func(ctx context.Context, lines []logs.StoredLine) {
		if d.Reg != nil && !d.Reg.Enabled(idsmodule.ModuleID) {
			return
		}
		in := make([]idsmodule.Line, 0, len(lines))
		for _, l := range lines {
			if idsmodule.Reads(l.Kind) {
				in = append(in, idsmodule.Line{SourceID: l.SourceID, SourceName: l.SourceName, Kind: l.Kind, At: l.At, Text: l.Text})
			}
		}
		if len(in) > 0 {
			idsService(d).Offer(ctx, in)
		}
	}
}

// idsParticipant is the ids module's part of a device merge: the alerts of the merged device move to the one it joined (a deleted
// device's alerts keep their addresses; the foreign key clears the device).
func idsParticipant(svc *idsmodule.Service) lifecycle.Participant {
	return lifecycle.Participant{Name: "ids", DeviceMerged: svc.DeviceMerged}
}

// idsInventory answers which device has an address (the same rule as the log sources: the listed IP or the SNMP read address a person
// typed; an address two devices have names none) and the devices' names (the Devices page's).
type idsInventory struct {
	at    logsInventory
	names notifyDevices
}

func (a idsInventory) DevicesAt(ctx context.Context, ips []string) (map[string]string, error) {
	slices.Sort(ips)
	m, err := a.at.DevicesAt(ctx, slices.Compact(ips))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for ip, ds := range m {
		if len(ds) == 1 {
			out[ip] = ds[0].ID
		}
	}
	return out, nil
}

func (a idsInventory) Names(ctx context.Context, idList []string) (map[string]string, error) {
	st, err := a.names.DeviceStates(ctx, idList)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(st))
	for id, s := range st {
		name := s.Name
		if name == "" {
			name = s.Address
		}
		if name == "" {
			name = id
		}
		out[id] = name
	}
	return out, nil
}

// idsFindings gives the attacked devices' findings for the CVEs an alert names, with the status vocabulary of the findings contract.
// The findings module on this branch keeps its older statuses, so they are mapped here: an open finding has the status of its stored
// urgency layer (findings.LayerCode: under_attack, exploited, public_exploit, critical_edge, update_recommended), which findings rates
// again as soon as alerts arrive (urgencyOnAlerts); a handled one keeps its handling. An ignored device's findings are left out, as on
// every findings list, so an alert at it is rated by its rule alone (the urgency pass does not rate them either).
// The findings rebuild replaces this with findings.View and its one status.
type idsFindings struct{ d *deps }

func (a idsFindings) Linked(ctx context.Context, byDevice map[string][]string) (map[string][]idsmodule.LinkedFinding, error) {
	if a.d.Findings == nil || a.d.Reg != nil && !a.d.Reg.Enabled("findings") {
		return nil, nil
	}
	var ignored []string // a device a person ignored lists no finding: its findings neither make the alert critical nor count as affected
	if a.d.Inventory != nil {
		var err error
		if ignored, err = a.d.Inventory.IgnoredIDs(ctx); err != nil {
			return nil, err
		}
	}
	local, err := localOnlyCVEs(ctx, a.d, byDevice)
	if err != nil {
		return nil, err
	}
	out := map[string][]idsmodule.LinkedFinding{}
	for assetID, cves := range byDevice {
		if slices.Contains(ignored, assetID) {
			continue
		}
		recs, err := a.d.Findings.List(ctx, assetID)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if !slices.Contains(cves, r.CVE) {
				continue
			}
			// An open finding of a flaw that needs local or physical access does not make the alert an attack on an affected device:
			// network traffic can carry that exploit but cannot be its exploitation (findings.NeedsLocalAccess, the rule of layer 1 too).
			f := idsmodule.LinkedFinding{ID: r.ID, CVE: r.CVE, Affected: r.Status.Open() && !local[r.CVE]}
			switch r.Status {
			case findings.StatusPatched, findings.StatusMitigated, findings.StatusNotRelevant, findings.StatusFalsePositive:
				f.Status = string(r.Status)
			case findings.StatusRiskAccepted:
				f.Status = "accepted"
			default:
				f.Status = findings.LayerCode(r.Row.Urgency) // the stored layer: under_attack is findings' one rule (findings.Urgency)
			}
			out[assetID] = append(out[assetID], f)
		}
	}
	return out, nil
}

// localOnlyCVEs says which of the CVEs the alerts name need local or physical access, read from the CVSS score feeds picks (the
// same facts the urgency pass reads, also while feeds is off).
func localOnlyCVEs(ctx context.Context, d *deps, byDevice map[string][]string) (map[string]bool, error) {
	var cves []string
	for _, cs := range byDevice {
		cves = append(cves, cs...)
	}
	slices.Sort(cves)
	cves = slices.Compact(cves)
	if len(cves) == 0 || d.DB == nil {
		return nil, nil
	}
	facts, err := urgencyFacts(ctx, feeds.NewUrgencyReader(d.DB.Reader()), cves)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for cve, f := range facts {
		if findings.NeedsLocalAccess(f.CVSS) {
			out[cve] = true
		}
	}
	return out, nil
}

// idsIncidents finds an alert's intrusion incident in notify (nil while notify is off: the alert shows no incident).
type idsIncidents struct{ d *deps }

func (a idsIncidents) Intrusion(ctx context.Context, source, target string, at time.Time) (idsmodule.IncidentRef, bool, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled(notify.ModuleID) {
		return idsmodule.IncidentRef{}, false, nil
	}
	r, ok, err := newNotify(a.d).IncidentOf(ctx, notify.IncidentIntrusion, source, target, at)
	if err != nil || !ok {
		return idsmodule.IncidentRef{}, ok, err
	}
	return idsmodule.IncidentRef{ID: r.ID, Status: string(r.Status)}, true, nil
}

// clockOf is the box's clock (deps.Clock; time.Now when unset).
func clockOf(d *deps) time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}
