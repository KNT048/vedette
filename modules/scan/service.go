package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/pack"
)

// Scope is what the inventory says about the scan scope (INV-11: scan only reads it, never writes the commitment).
type Scope struct {
	Networks    []string // lan_ranges
	ConfirmedAt string   // ISO time of the commitment; "" when it is not ticked
	ConfirmedBy string
}

// Inventory is the part of the inventory module scan needs. cmd/vedette adapts *inventory.Service to it.
type Inventory interface {
	Scope(ctx context.Context) (Scope, error)
	Devices(ctx context.Context) ([]Device, error)
	// VulnScanPolicy is inventory.VulnScanPolicy: explicit is true for a device a person picked in Scan now.
	VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (Decision, error)
	// VulnScanPolicies is VulnScanPolicy for many devices in one inventory read. A device that no longer
	// exists is absent from the map.
	VulnScanPolicies(ctx context.Context, assetIDs []string, explicit bool) (map[string]Decision, error)
	// Checks reads the shared window, check rate and exclusions, the inventory's (INV-16, inventory INV-32): the one home of them.
	Checks(ctx context.Context) (Checks, error)
	// SaveChecks writes them inside tx, the transaction of PUT /scans/config; Settle is called once tx is over, with whether it
	// committed (the inventory announces inventory.settings.changed then).
	SaveChecks(ctx context.Context, tx *sql.Tx, user string, c Checks) error
	Settle(ctx context.Context, tx *sql.Tx, committed bool)
}

// Config is what NewService needs. Only DB, Audit, Inventory and Log are required.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Inventory Inventory
	Runs      *run.Manager                             // every check is a run of this manager (core/run); register the kind before it starts
	Engine    Engine                                   // nil: the scanner is unavailable (INV-2), nothing is ever sent
	Pack      *pack.Index                              // the safe template pack of the scan image; nil: the scanner is unavailable
	Findings  Findings                                 // nil: results stay in the run, nothing is confirmed
	Identify  Identifier                               // nil: Scan now does not identify devices first; each says why
	OSPages   OSPages                                  // nil: the identification rows say the OS as they recorded it
	External  External                                 // nil: the list has no external targets
	Publisher Publisher                                // nil: no events
	KEV       KEVFeed                                  // nil: no catch-up of missed new_kev
	Location  func(ctx context.Context) *time.Location // the organization's time zone, the one the window and the schedule are read in (review H1); nil: UTC; a nil result: unknown, nothing automated starts
	Log       *slog.Logger
	Clock     func() time.Time // nil: time.Now
}

// Service owns the scan_ tables. Every mutation runs in one transaction with its core_audit row (SYS-3).
type Service struct {
	cfg Config
	now func() time.Time

	mu   sync.Mutex
	live *live // the run this process executes; one at a time (INV-3)
	// pending are the runs queued in core/run and not started yet, by id: what each was started with (the picks, the CVEs of a rescan,
	// the end of a window). They live in this process only.
	pending map[string]runSpec
	// dev is the device whose vulnerability check is running now (nil between devices): DeviceChanged stops that part alone when
	// the device may no longer be scanned (its network scan turned off).
	dev *devRun

	// busy counts Engine.Run calls that have not returned. After Stop now the run may show stopped before the worker
	// confirms (stopGrace), but no run starts while nuclei may still be running (POST-2, FORBID-3; review M2).
	busy atomic.Int32
}

// NewService returns the service. DB, Audit, Inventory and Log are required.
func NewService(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Inventory == nil || cfg.Log == nil {
		return nil, errors.New("scan: creating service: DB, Audit, Inventory and Log are required")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	s := &Service{cfg: cfg, now: now, pending: map[string]runSpec{}}
	if cfg.Runs != nil {
		if err := s.registerKind(); err != nil {
			return nil, fmt.Errorf("scan: creating service: %w", err)
		}
	}
	return s, nil
}

// loc is the organization's time zone, read at each use so a change in Settings applies at once (review H1). Never
// the process's zone: that is UTC in the container, and a 02:00 run of a UTC+7 office would start at 09:00. No
// Location wired means UTC. A wired Location that answers nil (the read failed or timed out, or the name is not a
// zone) means the zone is unknown: ok is false, and no automated run starts until it is back (fail closed, #164 review).
func (s *Service) loc(ctx context.Context) (*time.Location, bool) {
	if s.cfg.Location == nil {
		return time.UTC, true
	}
	if l := s.cfg.Location(ctx); l != nil {
		return l, true
	}
	s.cfg.Log.WarnContext(ctx, "scan: the organization time zone could not be read; no scheduled scan or KEV rescan starts until it can")
	return nil, false
}

// Commitment is who ticked the scope commitment and when (contract.ts ScanScope.commitment).
type Commitment struct {
	ConfirmedAt string `json:"confirmed_at"`
	By          string `json:"by"`
}

// ScopeView is contract.ts ScanScope.
type ScopeView struct {
	Networks   []string    `json:"networks"`
	Commitment *Commitment `json:"commitment"`
}

// ConfigView is contract.ts ScanConfigResponse.
type ConfigView struct {
	Config          Settings  `json:"config"`
	Scope           ScopeView `json:"scope"`
	CanScan         bool      `json:"can_scan"`
	BlockReason     *string   `json:"block_reason"`
	DangerousChecks bool      `json:"dangerous_checks"` // always false (INV-4)
	// Version is the shared safety block's (INV-16, inventory INV-32): a PUT that sends it back is refused with 409 safety_changed
	// when the block changed since (review #860 M1). "" without SharedChecks.
	Version string `json:"version"`
}

// ready is the scanner part of INV-2: an Engine that answers Ready.
func (s *Service) ready(ctx context.Context) bool {
	if s.cfg.Engine == nil {
		return false
	}
	if err := s.cfg.Engine.Ready(ctx); err != nil {
		s.cfg.Log.InfoContext(ctx, "scan: the scanner is not available", "error", err)
		return false
	}
	return true
}

// Config returns the settings with the scope, the commitment, and whether a scan can start.
func (s *Service) Config(ctx context.Context) (ConfigView, error) {
	c, err := s.settings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return ConfigView{}, err
	}
	return s.view(ctx, c)
}

func (s *Service) view(ctx context.Context, c Settings) (ConfigView, error) {
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return ConfigView{}, fmt.Errorf("scan: reading the scope: %w", err)
	}
	v := ConfigView{Config: c, Scope: ScopeView{Networks: sc.Networks}, Version: c.Version} // values and version of one read (r2 L3)
	if v.Scope.Networks == nil {
		v.Scope.Networks = []string{}
	}
	if sc.ConfirmedAt != "" {
		v.Scope.Commitment = &Commitment{ConfirmedAt: sc.ConfirmedAt, By: sc.ConfirmedBy}
		if v.Scope.Commitment.By == "" {
			v.Scope.Commitment.By = "—" // the mock's placeholder for an unknown name
		}
	}
	switch {
	case v.Scope.Commitment == nil:
		v.BlockReason = ptr(msgNoCommitment)
	case !s.scannerReady(ctx):
		v.BlockReason = ptr(msgScannerDown)
	}
	v.CanScan = v.BlockReason == nil
	return v, nil
}

func ptr[T any](v T) *T { return &v }

// SaveConfig applies a partial update (PRE-3, POST-3): dangerous checks are refused first (INV-4), then the merged
// configuration must pass INV-5 as a whole. The change and its audit row are one transaction.
func (s *Service) SaveConfig(ctx context.Context, user string, p Patch) (ConfigView, error) {
	if p.DangerousChecks != nil && *p.DangerousChecks {
		return ConfigView{}, fmt.Errorf("scan: saving the settings: %w", ErrDangerousLocked)
	}
	var wtx *sql.Tx // the write transaction, for the inventory's Settle
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		wtx = tx
		cur, err := s.settings(ctx, tx)
		if err != nil {
			return err
		}
		next := p.apply(cur)
		if err := next.validate(len(cur.Exclusions)); err != nil {
			return err
		}
		if err := saveSettings(ctx, tx, next, user, store.FormatTS(s.now())); err != nil {
			return err
		}
		// INV-16: the window, the rate and the exclusions are the inventory's; the save writes them there, in the same transaction,
		// so discovery and Settings › Scanning see the same values.
		if err := s.cfg.Inventory.SaveChecks(ctx, tx, user, Checks{Window: next.Window, Rate: next.Rate, Exclusions: next.Exclusions, Version: p.Version}); err != nil {
			return err
		}
		detail, err := json.Marshal(struct {
			Rate       int    `json:"rate"`
			Window     Window `json:"window"`
			Exclusions int    `json:"exclusions"`
			AutoRescan bool   `json:"auto_rescan"`
		}{next.Rate, next.Window, len(next.Exclusions), next.AutoRescan})
		if err != nil {
			return fmt.Errorf("scan: encoding the audit detail: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "scan.config", Target: "scan", Detail: string(detail)})
	})
	if wtx != nil {
		s.cfg.Inventory.Settle(ctx, wtx, err == nil)
	}
	if err != nil {
		return ConfigView{}, fmt.Errorf("scan: saving the settings: %w", err)
	}
	return s.Config(ctx) // the values and version as stored now, read together (r2 L3): never a version newer than the list it answers
}
