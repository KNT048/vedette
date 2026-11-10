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
	f, st, err := s.scanFacts(ctx, assetID)
	if err != nil {
		return ScanDecision{}, err
	}
	switch {
	case f.isBox:
		return deny(ReasonBox), nil
	case f.origin == "manual":
		return deny(ReasonDeclaredByHand), nil
	case !f.addr.IsValid():
		return deny(ReasonNoIP), nil
	case !st.Active.Enabled:
		return deny(ReasonScanningOff), nil
	case st.ScopeConfirmedAt == nil:
		return deny(ReasonScopeNotConfirmed), nil
	case !st.InScope(f.addr):
		return deny(ReasonOutOfScope), nil
	}
	return afterScope(st, f.kind, f.fragile, f.regular, f.firstScan), nil
}

// VulnScanPolicy decides whether the vulnerability scanner (module scan) may probe a device (D-126). It is
// ScanPolicy without the sensor-active switch (scan has its own) and with one more input: explicit, true when a
// person picked this very device in "Scan now" (that pick is the consent, audited by the caller).
//
// Always refused: the box, no IP, scope not confirmed, outside lan_ranges or inside the exclusions, and
// regular_scan=never (absolute here, even with explicit; the person changes the setting first).
// A fragile device, an unclassified one (kind unknown) and one declared by hand are refused for schedules and the
// KEV rescan (explicit=false), and allowed when explicit. Fragile and unclassified ones run at a quarter of the
// configured rate (Active.Rate, packets per second, at least 1); a hand-declared one that is neither runs at the
// normal rate. regular_scan=allow, or a kind in regular_scan_kinds, lets a fragile or unclassified device be
// scanned at the normal rate without a pick (INV-8), but never a hand-declared one (INV-5). It never calls
// MarkFirstScan: the one gentle scan belongs to discovery.
func (s *Service) VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (ScanDecision, error) {
	f, st, err := s.scanFacts(ctx, assetID)
	if err != nil {
		return ScanDecision{}, err
	}
	switch {
	case f.isBox:
		return deny(ReasonBox), nil
	case !f.addr.IsValid():
		return deny(ReasonNoIP), nil
	case st.ScopeConfirmedAt == nil:
		return deny(ReasonScopeNotConfirmed), nil
	case !st.InScope(f.addr):
		return deny(ReasonOutOfScope), nil
	case f.regular == "never":
		return deny(ReasonRegularScanNever), nil
	}
	normal := ScanDecision{Allowed: true, Rate: st.Active.Rate, Reason: ReasonOK}
	unclassified := f.kind == "unknown"
	careful := f.fragile || unclassified
	permitted := f.regular == "allow" || (f.regular == "follow" && !unclassified && slices.Contains(st.RegularScanKinds, f.kind))
	switch {
	case f.origin == "manual" && !explicit:
		return deny(ReasonDeclaredByHand), nil
	case !careful, permitted:
		return normal, nil
	case explicit:
		return ScanDecision{Allowed: true, Rate: max(1, st.Active.Rate/4), Reason: ReasonOK}, nil
	case unclassified && !f.fragile:
		return deny(ReasonUnclassifiedPassiveOnly), nil
	}
	return deny(ReasonFragilePassiveOnly), nil
}

func deny(reason string) ScanDecision { return ScanDecision{Reason: reason} }

// scanFacts is what the scan policies decide on besides the settings: the device row.
type scanFacts struct {
	addr                      netip.Addr // zero when the device has no valid IP
	origin, kind, regular     string
	fragile, isBox, firstScan bool
}

func (s *Service) scanFacts(ctx context.Context, assetID string) (scanFacts, Settings, error) {
	db := s.db.Reader()
	var ip, firstScan sql.NullString
	var f scanFacts
	err := db.QueryRowContext(ctx, `SELECT ip, origin, kind, fragile, regular_scan, first_scan_at, is_box FROM inv_asset WHERE id = ?`, assetID).Scan(&ip, &f.origin, &f.kind, &f.fragile, &f.regular, &firstScan, &f.isBox)
	if errors.Is(err, sql.ErrNoRows) {
		return f, Settings{}, ErrNotFound
	} else if err != nil {
		return f, Settings{}, fmt.Errorf("inventory: read device: %w", err)
	}
	f.firstScan = firstScan.Valid
	if ip.Valid {
		f.addr, _ = netip.ParseAddr(ip.String)
	}
	st, err := loadSettings(ctx, db)
	return f, st, err
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
// unclassified device that has not had its gentle scan yet is not listed: its one gentle scan is the policy's. The
// addresses of Config.BoxOwnedIPs (the decoys of the honeypot) are listed too: they are the box.
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The addresses the box answers on besides its own device (the honeypot's decoys) are the box too.
	if s.boxOwned != nil {
		for _, a := range s.boxOwned(ctx) {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out, nil
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
