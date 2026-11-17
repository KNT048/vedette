package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
)

// ScanDecision is the answer of ScanPolicy: may the box probe this device actively, and how fast.
type ScanDecision struct {
	Allowed bool
	Rate    int    // packets per second; 1 for the one gentle scan of a fragile device
	Reason  string // see the Reason* constants
	// Careful and IP are set by VulnScanPolicy only (zero from ScanPolicy). Careful: the device is fragile or its
	// kind is still unknown, so a caller should go gently even when the decision allows the normal rate (the safe
	// side). IP: the address the decision was made for, from the same read; zero when the decision is a refusal.
	Careful bool
	IP      netip.Addr
	// Fragile, Unclassified and Never are set by ScanPolicy only, for every device that passed origin, address and scope: the device
	// is fragile, its kind is still unknown, a person set regular_scan=never. sensor-active's identification for Scan now picks its
	// scan shape from them, and refuses Never.
	Fragile, Unclassified, Never bool
}

// Reasons of a ScanDecision.
const (
	ReasonOK                 = "ok"
	ReasonFirstGentleScan    = "first_gentle_scan" // One scan at the lowest speed, then passive only
	ReasonDeclaredByHand     = "declared_by_hand"  // INV-5
	ReasonNoIP               = "no_ip"
	ReasonScanningOff        = "scanning_off"         // active.enabled is false
	ReasonScopeNotConfirmed  = "scope_not_confirmed"  // INV-7
	ReasonOutOfScope         = "out_of_scope"         // outside lan_ranges or in the exclusions
	ReasonFragilePassiveOnly = "fragile_passive_only" // fragile, after the first scan
	// ReasonUnclassifiedPassiveOnly: the kind is still unknown after the first scan, so the device may be
	// fragile; nothing heavier than the gentle scan until passive data, the gentle scan's results or a person
	// set its kind.
	ReasonUnclassifiedPassiveOnly = "unclassified_passive_only"
	// ReasonBox: the machine Vedette runs on is not scanned on its own: never by sensor-active (discovery, sweeps) nor by a
	// schedule or a KEV rescan; only a person's pick in Scan now scans it (VulnScanPolicy explicit).
	ReasonBox = "box"
	// ReasonRegularScanNever: a person chose "never" for this device, for any kind: after the one gentle scan
	// it is passive only (conservative, like a per-asset "do not scan" in OT scanners).
	ReasonRegularScanNever = "regular_scan_never"
	// ReasonSNMPOff: a person turned SNMP off for this device on its Sources card. SNMPPolicy only: ScanPolicy answers a
	// network scan turned off as ReasonRegularScanNever, the words every reader of a scan refusal already shows.
	ReasonSNMPOff = "snmp_off"
	// ReasonExcluded: the address is on the exclusion list, which nothing active ever touches. SNMPPolicy only: SNMP is not bound by
	// lan_ranges, so its refusal names the exclusions alone; ScanPolicy answers ReasonOutOfScope for both.
	ReasonExcluded = "excluded"
)

// The per-device setting of one active source (inv_asset.scan_source, snmp_source). "" is the default: on for a device a sensor
// found, off for one added by hand.
const (
	SourceOn  = "on"
	SourceOff = "off"
)

// ScanPolicy decides whether sensor-active and scan may probe a device (PRE-3, POST-3; INV-5, 7, 8): the box itself is never scanned,
// nor a device whose network scan a person turned off (answered as regular_scan_never with Never set: "set to never be
// scanned on its device page"), nor a device declared by hand until a person turns its network scan on; nothing outside lan_ranges or inside the exclusions is; a fragile device,
// and one whose kind is still unknown (it may be fragile), gets one gentle scan when first seen and then only
// if regular scans are allowed for it (regular_scan "never" beats the type setting; an unknown kind is in no
// type setting); "never" means never for every kind, after the one gentle scan. The time window is the scheduler's business, not this function's.
func (s *Service) ScanPolicy(ctx context.Context, assetID string) (ScanDecision, error) {
	f, st, err := s.scanFacts(ctx, assetID)
	if err != nil {
		return ScanDecision{}, err
	}
	if f.scanSrc == SourceOff && !f.isBox {
		d := deny(ReasonRegularScanNever)
		d.Never = true
		return d, nil
	}
	return decideActive(f, st, f.scanSrc, false), nil
}

// SNMPPolicy is ScanPolicy for the SNMP reads of sensor-active: the same rules, with the device's SNMP setting in place of its
// network scan setting. SNMP off refuses with ReasonSNMPOff; a device added by hand is read only once a person turned its SNMP on. Its
// network scan setting does not matter here: a device may be read with SNMP and never port-scanned. sensor-active adds its own SNMP
// rules on top (a fragile device is read, the box never, only approved devices, the credential's own scope). Inside lan_ranges the
// credential's "Send only to" list decides, as before; outside them only a device whose SNMP a person turned on is read (the
// person administers the device); the exclusions always win (ReasonExcluded), and the scan switch and the scope
// commitment hold too.
func (s *Service) SNMPPolicy(ctx context.Context, assetID string) (ScanDecision, error) {
	f, st, err := s.scanFacts(ctx, assetID)
	if err != nil {
		return ScanDecision{}, err
	}
	if f.snmpSrc == SourceOff && !f.isBox {
		return deny(ReasonSNMPOff), nil
	}
	return decideActive(f, st, f.snmpSrc, true), nil
}

// decideActive is the policy of one active source of the box (the network scan or SNMP) for a device whose setting for that source
// is not off: src is "on" or "" (the default). snmp: outside lan_ranges only a stored "on"; the exclusions always.
func decideActive(f scanFacts, st Settings, src string, snmp bool) ScanDecision {
	switch {
	case f.isBox:
		return deny(ReasonBox)
	case f.origin == "manual" && src != SourceOn:
		return deny(ReasonDeclaredByHand)
	case !f.addr.IsValid():
		return deny(ReasonNoIP)
	case !st.Active.Enabled:
		return deny(ReasonScanningOff)
	case st.ScopeConfirmedAt == nil:
		return deny(ReasonScopeNotConfirmed)
	case snmp && st.Excluded(f.addr):
		return deny(ReasonExcluded)
	// Outside lan_ranges SNMP reads only a device whose SNMP a person turned on (stored "on"): a credential's scope alone,
	// or the default "on" of a discovered device, never reaches past the LAN ranges, so no credential saved before per-device SNMP existed starts reading
	// there by itself. Inside them the credential's scope decides, as before.
	case snmp && !st.InScope(f.addr) && src != SourceOn, !snmp && !st.InScope(f.addr):
		return deny(ReasonOutOfScope)
	}
	d := afterScope(st, f.kind, f.fragile, f.regular, f.firstScan)
	d.Fragile, d.Unclassified, d.Never = f.fragile, f.kind == "unknown", f.regular == "never"
	return d
}

// VulnScanPolicy decides whether the vulnerability scanner (module scan) may probe a device. It is
// ScanPolicy without the sensor-active switch (scan has its own) and with one more input: explicit, true when a
// person picked this very device in "Scan now" (that pick is the consent, audited by the caller).
//
// Always refused: no IP, scope not confirmed, outside lan_ranges or inside the exclusions, regular_scan=never, a network scan
// turned off, and a device declared by hand whose network scan nobody turned on (INV-5): absolute here,
// even with explicit; the person changes the setting first. A device declared by hand with its network scan on is scanned like a
// discovered one.
// The box itself is refused unless explicit: a person may scan it, nothing automatic does; picked, it goes through
// the same checks as any device and runs at the normal rate.
// A fragile device and an unclassified one (kind unknown) are refused for schedules and the KEV rescan (explicit=false), and
// allowed when explicit, at a quarter of the configured rate (Active.Rate, packets per second, at least 1). regular_scan=allow,
// or a kind in regular_scan_kinds, lets a fragile or unclassified device be scanned at the normal rate without a pick (INV-8).
// It never calls MarkFirstScan: the one gentle scan belongs to discovery.
func (s *Service) VulnScanPolicy(ctx context.Context, assetID string, explicit bool) (ScanDecision, error) {
	f, st, err := s.scanFacts(ctx, assetID)
	if err != nil {
		return ScanDecision{}, err
	}
	return decideVuln(f, st, explicit), nil
}

// MaxPolicyBatch is the most ids VulnScanPolicies takes; more is refused (ErrInvalid), not truncated.
const MaxPolicyBatch = 4096

// VulnScanPolicies is VulnScanPolicy for many devices with one settings read and one device query. A device
// that does not exist (deleted since the caller listed it) is absent from the map; it does not fail the batch.
func (s *Service) VulnScanPolicies(ctx context.Context, assetIDs []string, explicit bool) (map[string]ScanDecision, error) {
	if len(assetIDs) > MaxPolicyBatch {
		return nil, invalid("at most %d devices per policy read, got %d", MaxPolicyBatch, len(assetIDs))
	}
	out := make(map[string]ScanDecision, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	db := s.db.Reader()
	st, err := loadSettings(ctx, db)
	if err != nil {
		return nil, err
	}
	args := make([]any, len(assetIDs))
	for i, id := range assetIDs {
		args[i] = id
	}
	// only constants and "?" placeholders are concatenated; the ids are bound
	rows, err := db.QueryContext(ctx, `SELECT id, `+scanCols+` FROM inv_asset WHERE id IN (?`+strings.Repeat(",?", len(args)-1)+`)`, args...) //nolint:gosec // G202: see above
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var f scanFacts
		if err := f.scan(rows, &id); err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		out[id] = decideVuln(f, st, explicit)
	}
	return out, rows.Err()
}

func decideVuln(f scanFacts, st Settings, explicit bool) ScanDecision {
	switch {
	case f.isBox && !explicit:
		return deny(ReasonBox)
	case !f.addr.IsValid():
		return deny(ReasonNoIP)
	case st.ScopeConfirmedAt == nil:
		return deny(ReasonScopeNotConfirmed)
	case !st.InScope(f.addr):
		return deny(ReasonOutOfScope)
	case f.regular == "never", f.scanSrc == SourceOff: // a network scan turned off is absolute too
		return deny(ReasonRegularScanNever)
	case f.origin == "manual" && f.scanSrc != SourceOn: // added by hand, network scan not turned on: off, even for a pick
		return deny(ReasonDeclaredByHand)
	}
	unclassified := f.kind == "unknown"
	careful := f.fragile || unclassified
	allow := func(rate int) ScanDecision {
		return ScanDecision{Allowed: true, Rate: rate, Reason: ReasonOK, Careful: careful, IP: f.addr}
	}
	permitted := f.regular == "allow" || (f.regular == "follow" && !unclassified && slices.Contains(st.RegularScanKinds, f.kind))
	switch {
	case !careful, permitted:
		return allow(st.Active.Rate)
	case explicit:
		return allow(max(1, st.Active.Rate/4))
	case unclassified && !f.fragile:
		return deny(ReasonUnclassifiedPassiveOnly)
	}
	return deny(ReasonFragilePassiveOnly)
}

func deny(reason string) ScanDecision { return ScanDecision{Reason: reason} }

// scanFacts is what the scan policies decide on besides the settings: the device row.
type scanFacts struct {
	addr                      netip.Addr // zero when the device has no valid IP
	origin, kind, regular     string
	scanSrc, snmpSrc          string // SourceOn, SourceOff or "" (the default)
	fragile, isBox, firstScan bool
}

// effectiveSources is a device's scan and SNMP settings as the policies apply them: off for both while a person ignores the device
// (#945: the stored choice of an admin is kept and comes back when the device is watched again).
const effectiveSources = `CASE WHEN ignored_at IS NOT NULL THEN 'off' ELSE coalesce(scan_source, '') END, CASE WHEN ignored_at IS NOT NULL THEN 'off' ELSE coalesce(snmp_source, '') END`

const scanCols = `ip, origin, kind, fragile, regular_scan, first_scan_at, is_box, ` + effectiveSources

// scan reads scanCols, after any leading destinations (the id of a batch row).
func (f *scanFacts) scan(r interface{ Scan(...any) error }, lead ...any) error {
	var ip, firstScan sql.NullString
	if err := r.Scan(append(lead, &ip, &f.origin, &f.kind, &f.fragile, &f.regular, &firstScan, &f.isBox, &f.scanSrc, &f.snmpSrc)...); err != nil {
		return err
	}
	f.kind = devicetypes.ActsAs(f.kind) // the policies are keyed on the 13 kinds; a type acts as one of them
	f.firstScan = firstScan.Valid
	if ip.Valid {
		f.addr, _ = netip.ParseAddr(ip.String)
	}
	return nil
}

func (s *Service) scanFacts(ctx context.Context, assetID string) (scanFacts, Settings, error) {
	db := s.db.Reader()
	var f scanFacts
	err := f.scan(db.QueryRowContext(ctx, `SELECT `+scanCols+` FROM inv_asset WHERE id = ?`, assetID))
	if errors.Is(err, sql.ErrNoRows) {
		return f, Settings{}, ErrNotFound
	} else if err != nil {
		return f, Settings{}, fmt.Errorf("inventory: read device: %w", err)
	}
	st, err := loadSettings(ctx, db)
	return f, st, err
}

// sweepSkips says whether the discovery sweep leaves the device out (ProtectedIPs): the box, a device added by hand whose network scan
// nobody turned on, one whose network scan is off, one set to "never",
// and a fragile or unclassified one after its first gentle scan. f.kind is the kind it acts as. The sweep never confirms such a device at
// its address, so its silence there says nothing (resolve, #829).
func sweepSkips(st Settings, f scanFacts) bool {
	return f.isBox || (f.origin == "manual" && f.scanSrc != SourceOn) || f.scanSrc == SourceOff || f.regular == "never" || (f.firstScan && !afterScope(st, f.kind, f.fragile, f.regular, f.firstScan).Allowed)
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

// BoxIPs lists the addresses that are the box: the IPv4 of its own device and the addresses of Config.BoxOwnedIPs (the decoys). It is
// the part of ProtectedIPs nothing may ever probe, apart from the devices discovery leaves to the passive sensors (SNMP reads
// fragile devices but never the box).
func (s *Service) BoxIPs(ctx context.Context) ([]netip.Addr, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT ip FROM inv_asset WHERE is_box = 1 AND ip IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the box addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Addr
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("inventory: read the box addresses: %w", err)
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			out = append(out, a)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the box addresses: %w", err)
	}
	if s.boxOwned != nil {
		for _, a := range s.boxOwned(ctx) {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// ProtectedIPs lists the addresses a sweep must not probe, whatever MAC shows up there: the box itself,
// devices declared by hand (unless a person turned their network scan on), devices whose network scan is off, devices with regular_scan=never, and devices that already had their gentle scan and
// are fragile or unclassified without permission for regular scans (INV-5). A fragile or
// unclassified device that has not had its gentle scan yet is not listed: its one gentle scan is the policy's. The
// addresses of Config.BoxOwnedIPs (the decoys of the honeypot) are listed too: they are the box.
func (s *Service) ProtectedIPs(ctx context.Context) ([]netip.Addr, error) {
	db := s.db.Reader()
	st, err := loadSettings(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT ip, origin, kind, fragile, regular_scan, first_scan_at IS NOT NULL, is_box, CASE WHEN ignored_at IS NOT NULL THEN 'off' ELSE coalesce(scan_source, '') END FROM inv_asset WHERE ip IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read protected addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Addr
	for rows.Next() {
		var ip, origin, kind, regular, scanSrc string
		var fragile, hadFirst, isBox bool
		if err := rows.Scan(&ip, &origin, &kind, &fragile, &regular, &hadFirst, &isBox, &scanSrc); err != nil {
			return nil, fmt.Errorf("inventory: read protected addresses: %w", err)
		}
		kind = devicetypes.ActsAs(kind)
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if sweepSkips(st, scanFacts{origin: origin, kind: kind, regular: regular, scanSrc: scanSrc, fragile: fragile, isBox: isBox, firstScan: hadFirst}) {
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

// MarkFirstScan records that the one gentle scan of a device happened; later calls change nothing.
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

// PendingGentleScans lists the devices whose one gentle scan is still to come (#714): discovered
// (or added by hand with its network scan turned on, and never one whose scan is off), kind unknown, not fragile, not set to never, not the box, with an IP and no first scan. Migration 0004 cleared the first scan of such
// devices seen before, so the gentle scan with titles reaches them; sensor-active queues them once per start, since only a new
// device's inventory.asset.discovered queues one otherwise. Read-only.
func (s *Service) PendingGentleScans(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM inv_asset WHERE (origin = 'discovered' OR scan_source = 'on') AND coalesce(scan_source, '') <> 'off' AND kind = 'unknown' AND fragile = 0
		AND regular_scan <> 'never' AND is_box = 0 AND ip IS NOT NULL AND first_scan_at IS NULL AND ignored_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices waiting for their gentle scan: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: read devices waiting for their gentle scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SNMPKnown lists, for the move of SNMP credentials to devices (sensor-active), the devices (not the box) an SNMP read has
// described (an snmp observation) and those whose SNMP switch a person stored on.
func (s *Service) SNMPKnown(ctx context.Context) (read, on []string, err error) {
	for _, q := range []struct {
		sql string
		out *[]string
	}{
		{`SELECT DISTINCT o.asset_id FROM inv_observation o JOIN inv_asset a ON a.id = o.asset_id WHERE o.source = 'snmp' AND a.is_box = 0 ORDER BY 1`, &read},
		{`SELECT id FROM inv_asset WHERE snmp_source = 'on' AND is_box = 0 ORDER BY 1`, &on},
	} {
		rows, err := s.db.Reader().QueryContext(ctx, q.sql)
		if err != nil {
			return nil, nil, fmt.Errorf("inventory: read the devices SNMP knows: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return nil, nil, fmt.Errorf("inventory: read the devices SNMP knows: %w", err)
			}
			*q.out = append(*q.out, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, nil, fmt.Errorf("inventory: read the devices SNMP knows: %w", err)
		}
	}
	return read, on, nil
}
