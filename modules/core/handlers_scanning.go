package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
)

// Settings › Scanning (#850, INV-40): one read of every scanning engine, the one writer of the shared safety block, the engine
// switches and "Scan the LAN now" / "Check this device now". Core serves /scanning so the page answers while any engine's module is
// off; it imports no module: cmd/vedette gives one port per engine (ScanEngine), the inventory's store of the safety block
// (SafetyStore) and active discovery's runner (DiscoveryRunner).

// CoreMemoryMB is core's own memory cap (the vedette container's --memory=2g, host/ops/quadlet.go): always counted in reserved_mb.
const CoreMemoryMB = 2048

// Engine groups, cost kinds and states of contract.ts (web/src/features/scanning).
const (
	EngineOff         = "off"
	EngineNeedsSetup  = "needs_setup"
	EngineStarting    = "starting"
	EngineReady       = "ready"
	EngineRunning     = "running"
	EngineError       = "error"
	EngineUnavailable = "unavailable"

	CostWhileOn      = "on"
	CostWhileRunning = "running"
)

// How an engine is switched (ScanEngine.Switch).
const (
	SwitchNone   = ""       // no switch of its own: 409 not_toggleable
	SwitchModule = "module" // the switch of its module (core's registry, audited core.module as PATCH /modules/{id})
	SwitchOwn    = "own"    // ScanEngine.Toggle (active discovery, the OpenVAS flag)
)

// SafetyStore is the inventory as the one store of the shared safety block (inventory INV-32).
type SafetyStore interface {
	Safety(ctx context.Context) (Safety, error)
	// SaveSafety validates and stores in; an error that is an *apierr.Error reaches the person as it is.
	SaveSafety(ctx context.Context, actor string, in SafetyInput) (Safety, []Adjustment, error)
	// AddRange adds one range to the scope in one transaction (read, append, store); the attestation covers what the dialog showed
	// (in.Shown, in.ShownConfirmedAt) and the new range, and a stored list or confirmation other than that is a *SafetyChanged
	// (scope_changed); a range the confirmed scope covers changes nothing. Its other errors as SaveSafety's.
	AddRange(ctx context.Context, actor string, in RangeAdd) (Safety, []Adjustment, error)
	// AddExclusion adds one exclusion in one transaction; one an exclusion covers changes nothing. Its errors as SaveSafety's.
	AddExclusion(ctx context.Context, actor, entry string) (Safety, error)
}

// Safety is the shared block as stored.
type Safety struct {
	LANRanges                []string
	ConfirmedAt, ConfirmedBy *string
	Days                     []int
	From, To                 string
	PacketsPerS              int
	RequestsPerS             int
	Exclusions               []string
	FragileKinds             []string
	RegularScanKinds         []string
	FragileDevices           int
	Version                  string // names the stored values (inventory SafetyVersion); a full save must name the one it read
}

// SafetyInput is PUT /scanning/safety.
type SafetyInput struct {
	LANRanges                      []string
	Confirmed                      bool
	Days                           []int
	From, To                       string
	PacketsPerS, RequestsPerS      int
	Exclusions                     []string
	FragileKinds, RegularScanKinds []string
	Version                        string // the version the page read: another one is a *SafetyChanged (safety_changed)
}

// RangeAdd is POST /scanning/safety/ranges: the range and what the dialog showed beside the tick.
type RangeAdd struct {
	Range            string
	Shown            []string
	ShownConfirmedAt *string // nil: shown as not confirmed
	Confirmed        bool
}

// ScopeCostInput is POST /scanning/safety/estimate: the scope, window and rate as typed in the form.
type ScopeCostInput struct {
	LANRanges, Exclusions []string
	Days                  []int
	From, To              string
	PacketsPerS           int
}

// ScopeCost is what one pass of active discovery over a scope costs (ScopeCost in contract.ts).
type ScopeCost struct {
	Addresses     int  `json:"addresses"`
	PassSeconds   int  `json:"pass_seconds"`
	WindowSeconds int  `json:"window_seconds"`
	Windows       int  `json:"windows"`
	WeekWindows   int  `json:"week_windows"`
	FitsWindow    bool `json:"fits_window"`
	FitsWeek      bool `json:"fits_week"`
}

// SafetyChanged refuses a write built on a block that changed since the person read it (409 Code: safety_changed, scope_changed;
// review #860 H1/M1). Nothing was stored; Current is the block now, which the answer carries (error.safety) for the page to show.
type SafetyChanged struct {
	Code, Message string
	Current       Safety
}

func (e *SafetyChanged) Error() string { return "core: scanning: " + e.Code }

// Adjustment is a range or exclusion normalized on save.
type Adjustment struct{ From, To string }

// ScanEngine is one card of the page, in display order.
type ScanEngine struct {
	ID, Group, Module string
	Preview           bool
	Follows           string   // the engine whose switch it obeys; "" when none
	Affects           []string // engines that stop too when it is turned off
	Cost              EngineCost
	Switch            string // SwitchNone, SwitchModule or SwitchOwn
	// Needs is a module turned on first when the engine is turned on (with_dependencies, else 409 missing_dependencies): sensor-active
	// for active discovery. Turning the engine off never turns it off.
	Needs string
	// Precheck refuses a switch before anything changes (active discovery on without a confirmed scope); nil = none.
	Precheck func(ctx context.Context, on bool) error
	// Toggle moves the engine's own switch (SwitchOwn) and writes its audit row.
	Toggle func(ctx context.Context, actor string, on bool) error
	// Status reads the card; it is called whether its module is on or off and must not block on a run.
	Status func(ctx context.Context) (EngineStatus, error)
}

// EngineCost is what an engine may take of the box's memory: RAMMB nil when not known (never an estimate).
type EngineCost struct {
	RAMMB     *int
	While     string // CostWhileOn or CostWhileRunning
	Container string // the container it shares with other engines; "" when the figure is its own
}

// EngineStatus is the live part of a card.
type EngineStatus struct {
	Enabled bool
	State   string
	Reason  string // "" = none
	Last    *LastRun
	Next    *time.Time
	Running []RunningJob
}

// LastRun is the newest run of an engine that ended (or the newest report of one that listens).
type LastRun struct {
	At      time.Time
	Outcome string // ok, partial, failed, stopped
	Text    string
}

// HistoryRun is one past (or running) run of a LAN engine or a public scan, for Settings › Scanning › History. The
// outcome text comes from what the run stored; it never claims a result nothing checked.
type HistoryRun struct {
	ID, Kind, Engine, Trigger, Label string
	TargetID                         string // "" when none
	StartedAt                        time.Time
	EndedAt                          *time.Time
	Outcome                          string // ok, partial, failed, stopped, running
	Text                             string
}

// historyMax is how many runs GET /scanning/history answers at most.
const historyMax = 200

// RunningJob is a job of an engine running now.
type RunningJob struct {
	Engine    string
	ID        string
	Label     string
	TargetID  string // "" when none
	StartedAt time.Time
	Progress  *progress.View
	Queued    bool // it has not started (or gave way): it waits for the run in its way or for the scanner; Progress says what for
}

// DiscoveryRunner starts "Scan the LAN now" (no targets) or "Check this device now" (targets) on active discovery (sensor-active).
// It calls record once the run passed every check and before anything is sent; an error of record refuses the run (nothing starts).
// Its errors: ErrDiscoveryModuleOff, ErrDiscoveryOff, ErrScopeNotConfirmed, ErrNmapBusy, ErrNmapUnavailable, a
// *RunTooSoon, a *RunRefusal, record's error, or a failure of the box.
type DiscoveryRunner interface {
	Run(ctx context.Context, actor string, targets []string, record func(tx *sql.Tx, c RunConsent) error) (RunningJob, error)
}

// RunConsent is what a person's run will scan, for its audit row (the consent): the run, and the ranges of a sweep or the devices
// of a check with their addresses.
type RunConsent struct {
	ID      string
	Ranges  []string // a sweep: the confirmed scope it covers
	Devices []string // a check: "id (ip)" of each device
	Until   time.Time
}

// RunTooSoon refuses a sweep within the least gap after the last one.
type RunTooSoon struct{ RetryAfter time.Duration }

func (e *RunTooSoon) Error() string { return "core: scanning: a sweep ran a moment ago" }

// The refusals of DiscoveryRunner.Run.
var (
	ErrDiscoveryModuleOff = errors.New("core: scanning: sensor-active is off")
	ErrDiscoveryOff       = errors.New("core: scanning: active discovery is off")
	ErrScopeNotConfirmed  = errors.New("core: scanning: the scope is not confirmed")
	ErrNmapBusy           = errors.New("core: scanning: discovery is running nmap now")
	ErrNmapUnavailable    = errors.New("core: scanning: nmap is not available")
)

// RunRefusal is one target of a run a person may not start: Code is unknown_device, out_of_scope or not_scannable; Detail the
// inventory's reason behind it.
type RunRefusal struct{ Target, Code, Detail string }

func (e *RunRefusal) Error() string { return "core: scanning: " + e.Target + ": " + e.Code }

// ScanningConfig wires ScanningHandlers. DB, Reg, Audit and Safety are required.
type ScanningConfig struct {
	DB        *store.DB
	Reg       *modreg.Registry
	Audit     *audit.Log
	Log       *slog.Logger
	Safety    SafetyStore
	Engines   []ScanEngine
	Discovery DiscoveryRunner                                                 // nil: the run answers 501
	Estimate  func(ctx context.Context, in ScopeCostInput) (ScopeCost, error) // POST /scanning/safety/estimate; nil: 501
	History   func(ctx context.Context, asset string) ([]HistoryRun, error)   // the runs of GET /scanning/history (asset "": every run; a device id: the runs that reached it), newest first; nil: none
	TimeZone  func(ctx context.Context) string                                // the organization's zone; nil or "": UTC
	MemoryMB  func() (int, bool)                                              // MemTotal of the box; nil or false: unknown
}

// ScanningHandlers implements GET /scanning, PUT /scanning/safety, POST /scanning/safety/ranges and /exclusions, PATCH /scanning/engines/{id} and POST
// /scanning/engines/nmap-discovery/run. Embed it in the composite handler.
type ScanningHandlers struct{ cfg ScanningConfig }

// NewScanningHandlers returns the handlers.
func NewScanningHandlers(c ScanningConfig) (*ScanningHandlers, error) {
	if c.DB == nil || c.Reg == nil || c.Audit == nil || c.Safety == nil {
		return nil, errors.New("core: ScanningConfig needs DB, Reg, Audit and Safety")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	return &ScanningHandlers{cfg: c}, nil
}

// ---- the views (contract.ts, encoded as JSON into the generated types) ----

type safetyView struct {
	Scope struct {
		LANRanges   []string `json:"lan_ranges"`
		ConfirmedAt *string  `json:"confirmed_at"`
		ConfirmedBy *string  `json:"confirmed_by"`
	} `json:"scope"`
	Window struct {
		Days     []int  `json:"days"`
		From     string `json:"from"`
		To       string `json:"to"`
		TimeZone string `json:"time_zone"`
	} `json:"window"`
	Speed struct {
		PacketsPerS  int `json:"packets_per_s"`
		RequestsPerS int `json:"requests_per_s"`
	} `json:"speed"`
	Exclusions []string `json:"exclusions"`
	Fragile    struct {
		Kinds            []string `json:"kinds"`
		RegularScanKinds []string `json:"regular_scan_kinds"`
		Devices          int      `json:"devices"`
	} `json:"fragile"`
	Version string `json:"version"`
}

type lastRunView struct {
	At      string `json:"at"`
	Outcome string `json:"outcome"`
	Text    string `json:"text"`
}

type costView struct {
	RAMMB     *int    `json:"ram_mb"`
	While     string  `json:"while"`
	Container *string `json:"container"`
}

type engineView struct {
	ID        string       `json:"id"`
	Group     string       `json:"group"`
	Module    string       `json:"module"`
	Enabled   bool         `json:"enabled"`
	CanToggle bool         `json:"can_toggle"`
	Follows   *string      `json:"follows"`
	Affects   []string     `json:"affects"`
	State     string       `json:"state"`
	Reason    *string      `json:"reason"`
	Preview   bool         `json:"preview"`
	Cost      costView     `json:"cost"`
	LastRun   *lastRunView `json:"last_run"`
	NextRunAt *string      `json:"next_run_at"`
}

type runningView struct {
	Engine    string         `json:"engine"`
	ID        string         `json:"id"`
	Label     string         `json:"label"`
	TargetID  *string        `json:"target_id"`
	StartedAt string         `json:"started_at"`
	Progress  *progress.View `json:"progress"`
	Queued    bool           `json:"queued"`
}

type scanningView struct {
	Safety  safetyView    `json:"safety"`
	Engines []engineView  `json:"engines"`
	Running []runningView `json:"running"`
	Box     struct {
		MemoryMB   *int `json:"memory_mb"`
		ReservedMB int  `json:"reserved_mb"`
	} `json:"box"`
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func listOf[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// encode turns a view into the generated type (the field names are the contract's).
func encode[T any](v any) (*T, error) {
	out, err := apijson.Into[T](v)
	if err != nil {
		return nil, fmt.Errorf("core: scanning: %w", err)
	}
	return out, nil
}

func (h *ScanningHandlers) safetyView(ctx context.Context, st Safety) safetyView {
	var v safetyView
	v.Scope.LANRanges, v.Scope.ConfirmedAt, v.Scope.ConfirmedBy = listOf(st.LANRanges), st.ConfirmedAt, st.ConfirmedBy
	v.Window.Days, v.Window.From, v.Window.To = listOf(st.Days), st.From, st.To
	v.Window.TimeZone = "UTC"
	if h.cfg.TimeZone != nil {
		if z := h.cfg.TimeZone(ctx); z != "" {
			v.Window.TimeZone = z
		}
	}
	v.Speed.PacketsPerS, v.Speed.RequestsPerS = st.PacketsPerS, st.RequestsPerS
	v.Exclusions = listOf(st.Exclusions)
	v.Fragile.Kinds, v.Fragile.RegularScanKinds, v.Fragile.Devices = listOf(st.FragileKinds), listOf(st.RegularScanKinds), st.FragileDevices
	v.Version = st.Version
	return v
}

// safetyErr turns a *SafetyChanged into its 409 with the current block; other errors pass as they are.
func (h *ScanningHandlers) safetyErr(ctx context.Context, err error) error {
	var ch *SafetyChanged
	if errors.As(err, &ch) {
		return apierr.New(http.StatusConflict, ch.Code, ch.Message).With("safety", h.safetyView(ctx, ch.Current))
	}
	return err
}

// view reads the whole page. A card whose port fails shows state error; the page still answers (the other cards are fine).
func (h *ScanningHandlers) view(ctx context.Context) (scanningView, error) {
	st, err := h.cfg.Safety.Safety(ctx)
	if err != nil {
		return scanningView{}, err
	}
	v := scanningView{Safety: h.safetyView(ctx, st), Engines: []engineView{}, Running: []runningView{}}
	type held struct {
		cost    EngineCost
		holding bool
	}
	var holds []held
	for _, e := range h.cfg.Engines {
		s, err := e.Status(ctx)
		if err != nil {
			h.cfg.Log.WarnContext(ctx, "scanning: reading an engine failed", "engine", e.ID, "error", err)
			s = EngineStatus{State: EngineError, Reason: "Vedette could not read this engine's state; the box log has the error."}
		}
		ev := engineView{
			ID: e.ID, Group: e.Group, Module: e.Module, Enabled: s.Enabled, CanToggle: e.Switch != SwitchNone, Follows: strOrNil(e.Follows),
			Affects: listOf(slices.Clone(e.Affects)), State: s.State, Reason: strOrNil(s.Reason), Preview: e.Preview,
			Cost: costView{RAMMB: e.Cost.RAMMB, While: e.Cost.While, Container: strOrNil(e.Cost.Container)},
		}
		if s.Last != nil {
			ev.LastRun = &lastRunView{At: store.FormatTS(s.Last.At), Outcome: s.Last.Outcome, Text: s.Last.Text}
		}
		if s.Next != nil {
			ev.NextRunAt = strOrNil(store.FormatTS(*s.Next))
		}
		v.Engines = append(v.Engines, ev)
		for _, r := range s.Running {
			v.Running = append(v.Running, runningView{Engine: r.Engine, ID: r.ID, Label: r.Label, TargetID: strOrNil(r.TargetID), StartedAt: store.FormatTS(r.StartedAt), Progress: r.Progress, Queued: r.Queued})
		}
		holds = append(holds, held{cost: e.Cost, holding: s.Enabled && (e.Cost.While == CostWhileOn || len(s.Running) > 0 || s.State == EngineRunning)})
	}
	// reserved_mb: core, plus every engine that holds memory now, a shared container counted once.
	v.Box.ReservedMB = CoreMemoryMB
	counted := map[string]bool{}
	for _, x := range holds {
		if !x.holding || x.cost.RAMMB == nil {
			continue
		}
		if c := x.cost.Container; c != "" {
			if counted[c] {
				continue
			}
			counted[c] = true
		}
		v.Box.ReservedMB += *x.cost.RAMMB
	}
	if h.cfg.MemoryMB != nil {
		if mb, ok := h.cfg.MemoryMB(); ok {
			v.Box.MemoryMB = &mb
		}
	}
	return v, nil
}

// ScanningGetScanning implements GET /scanning (viewer).
func (h *ScanningHandlers) ScanningGetScanning(ctx context.Context) (*oas.ScanningGetScanningOK, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, err
	}
	return encode[oas.ScanningGetScanningOK](v)
}

// ScanningGetScanningHistory implements GET /scanning/history (viewer): the runs of the LAN engines and the stored public scans,
// newest first, at most historyMax; with asset, only the runs that reached that device (the device page's Last checks).
func (h *ScanningHandlers) ScanningGetScanningHistory(ctx context.Context, params oas.ScanningGetScanningHistoryParams) (*oas.ScanningGetScanningHistoryOK, error) {
	type item struct {
		ID        string  `json:"id"`
		Kind      string  `json:"kind"`
		Engine    string  `json:"engine"`
		Trigger   string  `json:"trigger"`
		Label     string  `json:"label"`
		TargetID  *string `json:"target_id"`
		StartedAt string  `json:"started_at"`
		EndedAt   *string `json:"ended_at"`
		Outcome   string  `json:"outcome"`
		Text      string  `json:"text"`
	}
	out := struct {
		Items []item `json:"items"`
	}{Items: []item{}}
	if h.cfg.History != nil {
		runs, err := h.cfg.History(ctx, params.Asset.Or(""))
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(runs, func(a, b HistoryRun) int { return b.StartedAt.Compare(a.StartedAt) })
		for i, r := range runs {
			if i == historyMax && params.Asset.Or("") == "" { // a device's runs are capped per kind by the source
				break
			}
			it := item{ID: r.ID, Kind: r.Kind, Engine: r.Engine, Trigger: r.Trigger, Label: r.Label, TargetID: strOrNil(r.TargetID), StartedAt: store.FormatTS(r.StartedAt), Outcome: r.Outcome, Text: r.Text}
			if r.EndedAt != nil {
				e := store.FormatTS(*r.EndedAt)
				it.EndedAt = &e
			}
			out.Items = append(out.Items, it)
		}
	}
	return encode[oas.ScanningGetScanningHistoryOK](out)
}

// ScanningPutScanningSafety implements PUT /scanning/safety (admin): the inventory validates and stores the block, writes its audit
// row inventory.settings and publishes inventory.settings.changed.
func (h *ScanningHandlers) ScanningPutScanningSafety(ctx context.Context, req *oas.ScanningPutScanningSafetyReq) (*oas.ScanningPutScanningSafetyOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	in := SafetyInput{
		LANRanges: req.Scope.LanRanges, Confirmed: req.Scope.Confirmed, Days: req.Window.Days, From: req.Window.From, To: req.Window.To,
		PacketsPerS: req.Speed.PacketsPerS, RequestsPerS: req.Speed.RequestsPerS, Exclusions: req.Exclusions, Version: req.Version,
	}
	for _, k := range req.Fragile.Kinds {
		in.FragileKinds = append(in.FragileKinds, string(k))
	}
	for _, k := range req.Fragile.RegularScanKinds {
		in.RegularScanKinds = append(in.RegularScanKinds, string(k))
	}
	st, adjusted, err := h.cfg.Safety.SaveSafety(ctx, p.Email, in)
	if err != nil {
		return nil, h.safetyErr(ctx, err)
	}
	return encode[oas.ScanningPutScanningSafetyOK](h.savedView(ctx, st, adjusted))
}

// adjustedView is the adjusted list of an answer that saved ranges.
type adjustedView struct {
	safetyView
	Adjusted []map[string]string `json:"adjusted"`
}

func (h *ScanningHandlers) savedView(ctx context.Context, st Safety, adjusted []Adjustment) adjustedView {
	out := adjustedView{safetyView: h.safetyView(ctx, st), Adjusted: []map[string]string{}}
	for _, a := range adjusted {
		out.Adjusted = append(out.Adjusted, map[string]string{"from": a.From, "to": a.To})
	}
	return out
}

// ScanningPostScanningSafetyEstimate implements POST /scanning/safety/estimate (viewer): the cost of one pass over a scope as typed,
// before it is saved. Changes nothing.
func (h *ScanningHandlers) ScanningPostScanningSafetyEstimate(ctx context.Context, req *oas.ScanningPostScanningSafetyEstimateReq) (*oas.ScanningPostScanningSafetyEstimateOK, error) {
	if h.cfg.Estimate == nil {
		return nil, apierr.NotImplemented()
	}
	c, err := h.cfg.Estimate(ctx, ScopeCostInput{LANRanges: req.LanRanges, Exclusions: req.Exclusions, Days: req.Window.Days,
		From: req.Window.From, To: req.Window.To, PacketsPerS: req.PacketsPerS})
	if err != nil {
		return nil, err
	}
	return encode[oas.ScanningPostScanningSafetyEstimateOK](c)
}

// ScanningPostScanningSafetyRanges implements POST /scanning/safety/ranges (admin): "+ New range" where the person is (#842). The
// inventory adds the range in one transaction with the same rules, attestation, audit row (inventory.settings) and event as the PUT.
func (h *ScanningHandlers) ScanningPostScanningSafetyRanges(ctx context.Context, req *oas.ScanningPostScanningSafetyRangesReq) (*oas.ScanningPostScanningSafetyRangesOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	in := RangeAdd{Range: req.Range, Shown: req.ShownRanges, Confirmed: req.Confirm}
	if v, ok := req.ShownConfirmedAt.Get(); ok {
		in.ShownConfirmedAt = &v
	}
	st, adjusted, err := h.cfg.Safety.AddRange(ctx, p.Email, in)
	if err != nil {
		return nil, h.safetyErr(ctx, err)
	}
	return encode[oas.ScanningPostScanningSafetyRangesOK](h.savedView(ctx, st, adjusted))
}

// ScanningPostScanningSafetyExclusions implements POST /scanning/safety/exclusions (admin): "+ New exclusion" where the person is
// (#842), added in one transaction by the inventory (audited inventory.settings, inventory.settings.changed).
func (h *ScanningHandlers) ScanningPostScanningSafetyExclusions(ctx context.Context, req *oas.ScanningPostScanningSafetyExclusionsReq) (*oas.ScanningPostScanningSafetyExclusionsOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	st, err := h.cfg.Safety.AddExclusion(ctx, p.Email, req.Entry)
	if err != nil {
		return nil, h.safetyErr(ctx, err)
	}
	return encode[oas.ScanningPostScanningSafetyExclusionsOK](h.safetyView(ctx, st))
}

// ScanningPatchScanningEnginesID implements PATCH /scanning/engines/{id} (admin): the switch the engine maps to, audited by that
// switch, then the whole page.
func (h *ScanningHandlers) ScanningPatchScanningEnginesID(ctx context.Context, req *oas.ScanningPatchScanningEnginesIDReq, params oas.ScanningPatchScanningEnginesIDParams) (*oas.ScanningPatchScanningEnginesIDOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	i := slices.IndexFunc(h.cfg.Engines, func(e ScanEngine) bool { return e.ID == string(params.ID) })
	if i < 0 {
		return nil, apierr.NotFound()
	}
	e := h.cfg.Engines[i]
	on, withDeps := req.Enabled, req.WithDependencies.Or(false)
	if e.Switch == SwitchNone {
		follows := "it runs as a step of another scan"
		if e.Follows != "" {
			follows = "it follows " + e.Follows
		}
		return nil, apierr.New(http.StatusConflict, "not_toggleable", "This engine has no switch of its own: "+follows+".")
	}
	if e.Precheck != nil {
		if err := e.Precheck(ctx, on); err != nil {
			return nil, err
		}
	}
	if on && e.Needs != "" && !h.cfg.Reg.Enabled(e.Needs) {
		if !withDeps {
			return nil, apierr.New(http.StatusConflict, apierr.CodeMissingDeps, "Module "+e.Needs+" also needs to be on. Turn it on first, or turn them on together.").
				With("missing", []string{e.Needs})
		}
		if err := h.setModule(ctx, p.Email, e.Needs, true, true); err != nil {
			return nil, err
		}
	}
	var err error
	if e.Switch == SwitchModule {
		err = h.setModule(ctx, p.Email, e.Module, on, withDeps)
	} else {
		err = e.Toggle(ctx, p.Email, on)
	}
	if err != nil {
		return nil, err
	}
	v, err := h.view(ctx)
	if err != nil {
		return nil, err
	}
	return encode[oas.ScanningPatchScanningEnginesIDOK](v)
}

// setModule is PATCH /modules/{id}: the registry change and its audit row in one transaction, then the switch in memory.
func (h *ScanningHandlers) setModule(ctx context.Context, actor, id string, on, withDeps bool) error {
	if h.cfg.Reg.Enabled(id) == on {
		return nil
	}
	var ch modreg.Change
	err := h.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if on {
			ch, err = h.cfg.Reg.Enable(ctx, tx, actor, id, withDeps)
		} else {
			ch, err = h.cfg.Reg.Disable(ctx, tx, actor, id)
		}
		return err
	})
	if err != nil {
		return err
	}
	h.cfg.Reg.Publish(ch)
	return nil
}

// ScanningPostScanningEnginesNmapDiscoveryRun implements POST /scanning/engines/nmap-discovery/run (admin): the run starts in the
// background and is audited (scanning.run, the person's consent to scan now, like Scan now's).
func (h *ScanningHandlers) ScanningPostScanningEnginesNmapDiscoveryRun(ctx context.Context, req *oas.ScanningPostScanningEnginesNmapDiscoveryRunReq) (*oas.ScanningPostScanningEnginesNmapDiscoveryRunAccepted, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	if h.cfg.Discovery == nil {
		return nil, apierr.NotImplemented()
	}
	targets := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(targets, t) {
			targets = append(targets, t)
		}
	}
	if req.Targets != nil && len(targets) == 0 {
		return nil, apierr.Invalid("Name at least one device to check, or leave the list out to scan the whole network.")
	}
	// The audit row is the person's consent: written in the transaction that queues the run, before any packet; if it cannot be
	// written the run is not queued (review #857 M2). It names the run and what it covers.
	record := func(tx *sql.Tx, c RunConsent) error {
		detail := "check " + strings.Join(c.Devices, ", ") + " now, whatever the window"
		if len(c.Devices) == 0 {
			detail = "sweep of " + strings.Join(c.Ranges, ", ") + " and the scans of the devices it finds now, whatever the window, until " +
				store.FormatTS(c.Until) + " at the latest"
		}
		return h.cfg.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "scanning.run", Target: c.ID, Detail: clipRunes(detail, 1900)})
	}
	run, err := h.cfg.Discovery.Run(ctx, p.Email, targets, record)
	if err != nil {
		return nil, runError(err)
	}
	return encode[oas.ScanningPostScanningEnginesNmapDiscoveryRunAccepted](runningView{
		Engine: run.Engine, ID: run.ID, Label: run.Label, TargetID: strOrNil(run.TargetID), StartedAt: store.FormatTS(run.StartedAt), Progress: run.Progress,
		Queued: run.Queued,
	})
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// runError turns a refusal of DiscoveryRunner.Run into the API's answer.
func runError(err error) error {
	var rr *RunRefusal
	var soon *RunTooSoon
	switch {
	case errors.As(err, &soon):
		secs := max(1, int(soon.RetryAfter.Round(time.Second)/time.Second))
		return apierr.New(http.StatusConflict, "too_soon", fmt.Sprintf("The network was swept a moment ago. Start another sweep in %d minutes.", (secs+59)/60)).With("retry_after", secs)
	case errors.As(err, &rr):
		var e *apierr.Error
		switch rr.Code {
		case "unknown_device":
			e = apierr.New(http.StatusBadRequest, "unknown_device", "No device has the address or id "+clipRunes(rr.Target, 40)+". Let discovery find it first, or add it under Devices.")
		case "out_of_scope":
			e = apierr.New(http.StatusBadRequest, "out_of_scope", clipRunes(rr.Target, 40)+" is outside the confirmed scope, excluded, or the Vedette box itself, so it is not scanned.")
		default:
			e = apierr.New(http.StatusBadRequest, "not_scannable", clipRunes(rr.Target, 40)+" may not be scanned: "+refusalText(rr.Detail))
		}
		return e.With("target", rr.Target).With("reason", rr.Detail)
	case errors.Is(err, ErrDiscoveryModuleOff):
		return apierr.New(http.StatusConflict, "module_off", "Active discovery (the sensor-active module) is off. An admin can turn it on in Settings, Scanning.")
	case errors.Is(err, ErrDiscoveryOff):
		return apierr.New(http.StatusConflict, "engine_off", "Network discovery is off. Turn it on in Settings, Scanning first.")
	case errors.Is(err, ErrScopeNotConfirmed):
		return apierr.New(http.StatusBadRequest, "scope_not_confirmed", "Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.")
	case errors.Is(err, ErrNmapBusy):
		return apierr.New(http.StatusConflict, "busy", "A LAN sweep is already going on: it is the answer. Follow it on the Runs tab.")
	case errors.Is(err, ErrNmapUnavailable):
		return apierr.New(http.StatusServiceUnavailable, "scanner_unavailable", "The scanner is not available: the scan container or its nmap is missing. Check the box's services, then try again.")
	}
	return err
}

// refusalText is the inventory's reason in words.
func refusalText(reason string) string {
	switch reason {
	case "regular_scan_never":
		return "it is set to never be scanned, or its network scan is off on its page (Sources)."
	case "declared_by_hand":
		return "it was added by hand: turn its network scan on, on its page (Sources), first."
	case "no_ip":
		return "it has no IP address."
	case "too_many":
		return "at most 64 devices can be checked at once."
	}
	return "its safety settings do not allow it (" + reason + ")."
}
