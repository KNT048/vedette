package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// ScanDecision is the answer of ScanPolicy: may the box probe this device actively, and how fast.
type ScanDecision struct {
	Allowed bool
	Rate    int    // packets per second; 1 for the one gentle scan of a fragile device
	Reason  string // see the Reason* constants
}

// Reasons of a ScanDecision.
const (
	ReasonOK                 = "ok"
	ReasonFirstGentleScan    = "first_gentle_scan" // D-45: one scan at the lowest speed, then passive only
	ReasonDeclaredByHand     = "declared_by_hand"  // INV-5
	ReasonNoIP               = "no_ip"
	ReasonScanningOff        = "scanning_off"         // active.enabled is false
	ReasonScopeNotConfirmed  = "scope_not_confirmed"  // INV-7, D-26
	ReasonOutOfScope         = "out_of_scope"         // outside lan_ranges or in the exclusions
	ReasonFragilePassiveOnly = "fragile_passive_only" // D-45 after the first scan
)

// ScanPolicy decides whether sensor-active and scan may probe a device (PRE-3, POST-3; INV-5, 7, 8): a device
// declared by hand is never scanned; nothing outside lan_ranges or inside the exclusions is; a fragile device
// gets one gentle scan when first seen and then only if regular scans are allowed for it (regular_scan "never"
// beats the type setting). The time window is the scheduler's business, not this function's.
func (s *Service) ScanPolicy(ctx context.Context, assetID string) (ScanDecision, error) {
	db := s.db.Reader()
	var ip, firstScan sql.NullString
	var origin, kind, regular string
	var fragile bool
	err := db.QueryRowContext(ctx, `SELECT ip, origin, kind, fragile, regular_scan, first_scan_at FROM inv_asset WHERE id = ?`, assetID).Scan(&ip, &origin, &kind, &fragile, &regular, &firstScan)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanDecision{}, ErrNotFound
	} else if err != nil {
		return ScanDecision{}, fmt.Errorf("inventory: read device: %w", err)
	}
	st, err := loadSettings(ctx, db)
	if err != nil {
		return ScanDecision{}, err
	}
	deny := func(reason string) (ScanDecision, error) { return ScanDecision{Reason: reason}, nil }
	addr, perr := netip.ParseAddr(ip.String)
	switch {
	case origin == "manual":
		return deny(ReasonDeclaredByHand)
	case !ip.Valid || perr != nil:
		return deny(ReasonNoIP)
	case !st.Active.Enabled:
		return deny(ReasonScanningOff)
	case st.ScopeConfirmedAt == nil:
		return deny(ReasonScopeNotConfirmed)
	case !st.InScope(addr):
		return deny(ReasonOutOfScope)
	}
	if !fragile {
		return ScanDecision{Allowed: true, Rate: st.Active.Rate, Reason: ReasonOK}, nil
	}
	if !firstScan.Valid {
		return ScanDecision{Allowed: true, Rate: 1, Reason: ReasonFirstGentleScan}, nil
	}
	if regular == "allow" || (regular == "follow" && slices.Contains(st.RegularScanKinds, kind)) {
		return ScanDecision{Allowed: true, Rate: st.Active.Rate, Reason: ReasonOK}, nil
	}
	return deny(ReasonFragilePassiveOnly)
}

// MarkFirstScan records that the one gentle scan of a device happened (D-45); later calls change nothing.
func (s *Service) MarkFirstScan(ctx context.Context, assetID string) error {
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		res, err := tx.ExecContext(ctx, `UPDATE inv_asset SET first_scan_at = ? WHERE id = ? AND first_scan_at IS NULL`, s.now(), assetID)
		if err != nil {
			return fmt.Errorf("inventory: mark first scan: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			ok, err := assetExists(ctx, tx, assetID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrNotFound
			}
			return nil
		}
		return s.auditTx(ctx, tx, systemActor, "inventory.first_scan", deviceName(ctx, tx, assetID), assetID)
	})
}
