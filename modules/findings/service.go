package findings

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// ServiceConfig is what NewService needs; Publisher and Clock may be nil.
type ServiceConfig struct {
	DB        *store.DB
	Audit     *audit.Log
	Publisher Publisher // nil: no events
	Inventory Inventory
	Feeds     Feeds
	Log       *slog.Logger
	Clock     func() time.Time // nil: time.Now
}

// Service owns fnd_finding and fnd_finding_history. Every mutation runs in one transaction with its
// history rows and its core_audit row (SYS-3); events go out after the commit.
type Service struct {
	cfg ServiceConfig
	now func() time.Time
}

// NewService returns the service. DB, Audit, Inventory, Feeds and Log are required.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Inventory == nil || cfg.Feeds == nil || cfg.Log == nil {
		return nil, fmt.Errorf("findings: creating service: DB, Audit, Inventory, Feeds and Log are required")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, now: now}, nil
}

type event struct {
	name    string
	payload any
}

// write runs fn in a write transaction, then publishes the events fn collected.
func (s *Service) write(ctx context.Context, fn func(tx *sql.Tx, now time.Time, emit func(name string, payload any)) error) error {
	var events []event
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		events = events[:0]
		return fn(tx, s.now().UTC().Truncate(time.Millisecond), func(name string, payload any) { events = append(events, event{name, payload}) })
	})
	if err != nil {
		return err
	}
	if s.cfg.Publisher == nil {
		return nil
	}
	for _, e := range events {
		if err := s.cfg.Publisher.Publish(ctx, e.name, e.payload); err != nil {
			s.cfg.Log.ErrorContext(ctx, "publishing a findings event failed", "event", e.name, "error", err)
		}
	}
	return nil
}

// Get returns one finding, or an error wrapping ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	return loadByID(ctx, s.cfg.DB.Reader(), id)
}

// List returns the findings of one asset, or of every asset when assetID is empty, newest first.
func (s *Service) List(ctx context.Context, assetID string) ([]Record, error) {
	return listRecords(ctx, s.cfg.DB.Reader(), assetID)
}

// UpsertResult says what an upsert did.
type UpsertResult struct {
	Created []string // ids of the findings created
	Touched int      // findings that already existed (open or closed) and only had last_seen refreshed
}

// OnMatchChanged handles inventory.match.changed: it reads the device and the exploited list and
// matches them (PRE-1). An unknown device is ErrUnknownAsset.
func (s *Service) OnMatchChanged(ctx context.Context, assetID string) (UpsertResult, error) {
	a, ok, err := s.cfg.Inventory.MatchInput(ctx, assetID)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("findings: reading the device to match: %w", err)
	}
	if !ok {
		return UpsertResult{}, fmt.Errorf("findings: matching device %q: %w", assetID, ErrUnknownAsset)
	}
	vulns, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("findings: reading the exploited list: %w", err)
	}
	return s.UpsertFromMatch(ctx, a, vulns)
}

// UpsertFromMatch matches the device's software against vulns and writes the result (INV-6, POST-1):
// a new pair becomes a suspected finding with its "created" history row and a
// findings.finding.created event; a pair that already exists, open or closed, is never created again
// or reopened: it only gets last_seen refreshed and, if open, a stronger basis (product to version).
// The matcher only adds, never removes.
func (s *Service) UpsertFromMatch(ctx context.Context, a Asset, vulns []Vuln) (UpsertResult, error) {
	var res UpsertResult
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		res = UpsertResult{}
		have, err := cvesOfAsset(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		m := MatchAsset(a, vulns, haveSet(have), now)
		for _, nm := range m.New {
			f, h := NewFinding(nm, now)
			if err := f.Validate(); err != nil {
				return fmt.Errorf("findings: new finding for %s: %w", nm.CVE, err)
			}
			r := Record{ID: store.NewID("f"), AssetID: a.ID, CVE: nm.CVE, Finding: f, FirstSeen: now, LastSeen: now}
			if err := insertRecord(ctx, tx, r); err != nil {
				return err
			}
			if err := insertHistory(ctx, tx, r.ID, h); err != nil {
				return err
			}
			if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.created", Target: r.ID,
				Detail: fmt.Sprintf("%s on %s, basis %s, %s", r.CVE, r.AssetID, r.Basis, r.Severity)}); err != nil {
				return err
			}
			emit(EventCreated, CreatedEvent{FindingID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Severity: r.Severity, Basis: r.Basis})
			res.Created = append(res.Created, r.ID)
		}
		for _, em := range m.Existing {
			r, err := loadByPair(ctx, tx, a.ID, em.CVE)
			if err != nil {
				return err
			}
			before := r.Finding
			r.Finding = r.ApplyMatch(em)
			r.LastSeen = now
			if err := r.Validate(); err != nil {
				return fmt.Errorf("findings: finding %s after a repeated match: %w", r.ID, err)
			}
			if err := updateRecord(ctx, tx, r); err != nil {
				return err
			}
			if r.Basis != before.Basis {
				if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.basis_raised", Target: r.ID,
					Detail: fmt.Sprintf("%s: %s to %s", r.CVE, before.Basis, r.Basis)}); err != nil {
					return err
				}
			}
			res.Touched++
		}
		return nil
	})
	if err != nil {
		return UpsertResult{}, err
	}
	return res, nil
}

// ConfirmFromScan records a positive scan result for a pair (PRE-2, POST-2). The finding must exist
// (scan targets come from findings). The change, its history row and the audit row are one
// transaction; findings.finding.status_changed goes out when the library says a person has to know.
func (s *Service) ConfirmFromScan(ctx context.Context, assetID, cve string, ev Evidence) (Record, error) {
	if !ValidCVE(cve) {
		return Record{}, fmt.Errorf("findings: confirming from scan: %w", ErrInvalidCVE)
	}
	var out Record
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if err != nil {
			return err
		}
		if ev.CheckedAt.IsZero() {
			ev.CheckedAt = now
		}
		was := r.Status
		o, err := r.ConfirmFromScan(ev, now)
		if err != nil {
			return err
		}
		if len(o.History) == 0 && !o.Notify {
			out = r // the same match was already recorded: nothing changes
			return nil
		}
		r.Finding = o.Finding
		r.LastSeen = now
		if err := r.Validate(); err != nil {
			return fmt.Errorf("findings: finding %s after a scan: %w", r.ID, err)
		}
		if err := updateRecord(ctx, tx, r); err != nil {
			return err
		}
		for _, h := range o.History {
			if err := insertHistory(ctx, tx, r.ID, h); err != nil {
				return err
			}
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.scan_confirmed", Target: r.ID,
			Detail: fmt.Sprintf("%s: %s to %s, template %s", r.CVE, was, r.Status, ev.Template)}); err != nil {
			return err
		}
		if o.Notify {
			emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status})
		}
		out, err = loadByID(ctx, tx, r.ID)
		return err
	})
	return out, err
}

// RescanClear records that a rescan no longer matches (history row rescan_clear). The status never
// changes: nothing closes without a person (FORBID-2).
func (s *Service) RescanClear(ctx context.Context, assetID, cve string) error {
	if !ValidCVE(cve) {
		return fmt.Errorf("findings: recording a clear rescan: %w", ErrInvalidCVE)
	}
	return s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if err != nil {
			return err
		}
		if err := insertHistory(ctx, tx, r.ID, ScanClear(now)); err != nil {
			return err
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.rescan_clear", Target: r.ID, Detail: r.CVE})
	})
}

// SetStatus applies a person's action (INV-3). user is the actor's email. On any error nothing is
// written. The checks run in the order the API reports them (library Finding.Apply).
func (s *Service) SetStatus(ctx context.Context, id string, action Action, note, user string) (Record, error) {
	var out Record
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		r, err := loadByID(ctx, tx, id)
		if err != nil {
			return err
		}
		was := r.Status
		f, h, err := r.Apply(action, note, user, now)
		if err != nil {
			return err
		}
		r.Finding = f
		if err := f.Validate(); err != nil {
			return fmt.Errorf("findings: finding %s after %s: %w", r.ID, action, err)
		}
		if err := updateRecord(ctx, tx, r); err != nil {
			return err
		}
		if err := insertHistory(ctx, tx, r.ID, h); err != nil {
			return err
		}
		detail := fmt.Sprintf("%s: %s", r.CVE, action)
		if h.Note != "" {
			detail += ": " + h.Note
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.status", Target: r.ID, Detail: detail}); err != nil {
			return err
		}
		if was != r.Status {
			emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status})
		}
		out, err = loadByID(ctx, tx, r.ID)
		return err
	})
	return out, err
}

// OnAssetDeleted handles inventory.asset.deleted: the device's findings, their history and, through
// the foreign keys of mitigation, their applied log and AI results go with it (INV-7). It returns
// how many findings were removed.
func (s *Service) OnAssetDeleted(ctx context.Context, assetID string) (int, error) {
	var n int64
	err := s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE asset_id = ?`, assetID)
		if err != nil {
			return fmt.Errorf("findings: deleting findings of device: %w", err)
		}
		if n, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("findings: deleting findings of device: %w", err)
		}
		if n == 0 {
			return nil
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.deleted_with_asset", Target: assetID,
			Detail: fmt.Sprintf("%d findings removed with the device", n)})
	})
	return int(n), err
}

func cvesOfAsset(ctx context.Context, q querier, assetID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT cve FROM fnd_finding WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, fmt.Errorf("findings: reading existing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("findings: reading existing findings: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func haveSet(cves []string) map[string]bool {
	m := make(map[string]bool, len(cves))
	for _, c := range cves {
		m[c] = true
	}
	return m
}
