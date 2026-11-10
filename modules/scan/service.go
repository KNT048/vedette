package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/pack"
)

// Scope is what the inventory says about the scan scope (INV-11: scan only reads it, never writes the commitment).
type Scope struct {
	Networks    []string // lan_ranges
	ConfirmedAt string   // ISO time of the commitment (D-26); "" when it is not ticked
	ConfirmedBy string
}

// Inventory is the part of the inventory module scan needs. cmd/vedette adapts *inventory.Service to it.
type Inventory interface {
	Scope(ctx context.Context) (Scope, error)
	Devices(ctx context.Context) ([]Device, error)
	// VulnScanPolicy is inventory.VulnScanPolicy (D-126): explicit is true for a device a person picked in Scan now.
	VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (Decision, error)
}

// Config is what NewService needs. Only DB, Audit, Inventory and Log are required.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Inventory Inventory
	Engine    Engine         // nil: the scanner is unavailable (INV-2), nothing is ever sent
	Pack      *pack.Index    // the safe template pack of the scan image (D-125 (4)); nil: the scanner is unavailable
	Findings  Findings       // nil: results stay in the run, nothing is confirmed
	External  External       // nil: the list has no external targets
	Publisher Publisher      // nil: no events
	Location  *time.Location // the organization's time zone for the window and the schedule (nil: time.Local)
	Log       *slog.Logger
	Clock     func() time.Time // nil: time.Now
}

// Service owns the scan_ tables. Every mutation runs in one transaction with its core_audit row (SYS-3).
type Service struct {
	cfg Config
	now func() time.Time

	mu   sync.Mutex
	live *live // the run this process executes; one at a time (INV-3)
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
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	return &Service{cfg: cfg, now: now}, nil
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
	NextRun         *string   `json:"next_run"`
	Scope           ScopeView `json:"scope"`
	CanScan         bool      `json:"can_scan"`
	BlockReason     *string   `json:"block_reason"`
	DangerousChecks bool      `json:"dangerous_checks"` // always false (INV-4)
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

// Config returns the settings with the scope, the commitment, whether a scan can start and the next scheduled run.
func (s *Service) Config(ctx context.Context) (ConfigView, error) {
	c, err := loadSettings(ctx, s.cfg.DB.Reader())
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
	v := ConfigView{Config: c, Scope: ScopeView{Networks: sc.Networks}}
	if v.Scope.Networks == nil {
		v.Scope.Networks = []string{}
	}
	if sc.ConfirmedAt != "" {
		v.Scope.Commitment = &Commitment{ConfirmedAt: sc.ConfirmedAt, By: sc.ConfirmedBy}
		if v.Scope.Commitment.By == "" {
			v.Scope.Commitment.By = "—" // the mock's placeholder for an unknown name
		}
	}
	if t := c.NextRun(s.now(), s.cfg.Location); t != nil {
		ts := store.FormatTS(*t)
		v.NextRun = &ts
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
	var saved Settings
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		next := p.apply(cur)
		if err := next.validate(); err != nil {
			return err
		}
		if err := saveSettings(ctx, tx, next, user, store.FormatTS(s.now())); err != nil {
			return err
		}
		detail, err := json.Marshal(struct {
			Rate       int    `json:"rate"`
			Window     Window `json:"window"`
			Exclusions int    `json:"exclusions"`
			AutoRescan bool   `json:"auto_rescan"`
			Schedule   bool   `json:"schedule"`
		}{next.Rate, next.Window, len(next.Exclusions), next.AutoRescan, next.Schedule.Enabled})
		if err != nil {
			return fmt.Errorf("scan: encoding the audit detail: %w", err)
		}
		saved = next
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "scan.config", Target: "scan", Detail: string(detail)})
	})
	if err != nil {
		return ConfigView{}, fmt.Errorf("scan: saving the settings: %w", err)
	}
	return s.view(ctx, saved)
}
