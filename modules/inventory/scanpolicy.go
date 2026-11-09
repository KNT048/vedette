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
	// ReasonUnclassifiedPassiveOnly: the kind is still unknown after the first scan, so the device may be
	// fragile; nothing heavier than the gentle scan until passive data, the gentle scan's results or a person
	// set its kind (D-84 (H1)).
	ReasonUnclassifiedPassiveOnly = "unclassified_passive_only"
	// ReasonBox: the machine Vedette runs on is never scanned (the sweep skips it too).
	ReasonBox = "box"
	// ReasonRegularScanNever: a person chose "never" for this device, for any kind: after the one gentle scan
	// it is passive only (conservative, like a per-asset "do not scan" in OT scanners; D-74).
	ReasonRegularScanNever = "regular_scan_never"
)

// ScanPolicy decides whether sensor-active and scan may probe a device (PRE-3, POST-3; INV-5, 7, 8): a device
// declared by hand and the box itself are never scanned; nothing outside lan_ranges or inside the exclusions is; a fragile device,
// and one whose kind is still unknown (it may be fragile), gets one gentle scan when first seen and then only
// if regular scans are allowed for it (regular_scan "never" beats the type setting; an unknown kind is in no
// type setting); "never" means never for every kind, after the one gentle scan. The time window is the scheduler's business, not this function's.
func (s *Service) ScanPolicy(ctx context.Context, assetID string) (ScanDecision, error) {
	db := s.db.Reader()
	var ip, firstScan sql.NullString
	var origin, kind, regular string
	var fragile, isBox bool
	err := db.QueryRowContext(ctx, `SELECT ip, origin, kind, fragile, regular_scan, first_scan_at, is_box FROM inv_asset WHERE id = ?`, assetID).Scan(&ip, &origin, &kind, &fragile, &regular, &firstScan, &isBox)
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
	case isBox:
		return deny(ReasonBox)
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
	return afterScope(st, kind, fragile, regular, firstScan.Valid), nil
}

// afterScope is the rest of the policy once the device is known to be scannable by origin, address and scope.
func afterScope(st Settings, kind string, fragile bool, regular string, hadFirstScan bool) ScanDecision {
	unclassified := kind == "unknown"
	if !fragile && !unclassified && regular != "never" {
		return ScanDecision{Allowed: true, Rate: st.Active.Rate, Reason: ReasonOK}
	}
	if !hadFirstScan {
		return ScanDecision{Allowed: true, Rate: 1, Reason: ReasonFirstGentleScan}
	}
	if regular == "allow" || (regular == "follow" && !unclassified && slices.Contains(st.RegularScanKinds, kind)) {
		return ScanDecision{Allowed: true, Rate: st.Active.Rate, Reason: ReasonOK}
	}
	if unclassified && !fragile {
		return ScanDecision{Reason: ReasonUnclassifiedPassiveOnly}
	}
	if fragile {
		return ScanDecision{Reason: ReasonFragilePassiveOnly}
	}
	return ScanDecision{Reason: ReasonRegularScanNever}
}

// ProtectedIPs lists the addresses a sweep must not probe, whatever MAC shows up there: the box itself,
// devices declared by hand, devices with regular_scan=never, and devices that already had their gentle scan and
// are fragile or unclassified without permission for regular scans (D-45, INV-5; D-84 (M2)). A fragile or
// unclassified device that has not had its gentle scan yet is not listed: its one gentle scan is the policy's.
func (s *Service) ProtectedIPs(ctx context.Context) ([]netip.Addr, error) {
	db := s.db.Reader()
	st, err := loadSettings(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT ip, origin, kind, fragile, regular_scan, first_scan_at IS NOT NULL, is_box FROM inv_asset WHERE ip IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read protected addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Addr
	for rows.Next() {
		var ip, origin, kind, regular string
		var fragile, hadFirst, isBox bool
		if err := rows.Scan(&ip, &origin, &kind, &fragile, &regular, &hadFirst, &isBox); err != nil {
			return nil, fmt.Errorf("inventory: read protected addresses: %w", err)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if isBox || origin == "manual" || regular == "never" || (hadFirst && !afterScope(st, kind, fragile, regular, hadFirst).Allowed) {
			out = append(out, addr)
		}
	}
	return out, rows.Err()
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
