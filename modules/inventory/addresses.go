package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/knt048/vedette/core/store"
)

// One device, many addresses (INV-57). A device's main address is inv_asset.ip and inv_asset.mac: every identity rule (resolve,
// claimIP, ipTrust, the join rules) reads those columns. The other addresses it answers on, the interfaces of a firewall or a
// laptop's Wi-Fi and Ethernet, are rows of inv_asset_address. An address lives in one place only: the main columns of one device or one
// row; the writers here keep it so (claimIP and claimRowIP free an address from wherever it was, RecomputeAsset never makes a row's MAC
// a main MAC), and TestAddressesHaveOneHome checks it.

// The sources of an address row (inv_asset_address.source), an open vocabulary: the sensor that last saw the address on the device, or
// how it came to the device.
const (
	addrMerge = "merge" // a person's merge brought it; nothing has seen it since
)

// validAddrSource says whether s may be stored as an address row's source.
func validAddrSource(s string) bool {
	switch s {
	case addrMerge, "passive", "nmap", "scan", "agent", "snmp", "manual":
		return true
	}
	return false
}

// addressBound says whether a source reads at an address (a network scan), so what it read belongs to the address it scanned: a
// scan of one interface then replaces only that interface's readings and open ports (inv_software_reading.addr_id,
// inv_service.addr_id). An agent, SNMP and the passive sensor read the whole machine.
func addressBound(source string) bool { return source == "nmap" || source == "scan" }

// Address is one address of a device as GET /inventory/devices/{id} shows it.
type Address struct {
	IP  *string `json:"ip"`
	MAC *string `json:"mac"`
	// Main is the device's main address: the one lists show and every scan and read of the device goes to.
	Main bool `json:"main"`
	// Source is what last tied the address to the device: the sensor that last saw it there, "merge" for one a person's merge
	// brought that nothing has seen since, "manual" for the address a person typed.
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// extraAddr is one row of inv_asset_address.
type extraAddr struct {
	id, assetID      string
	ip, mac          sql.NullString
	source           string
	firstSeen, lastS string
}

const extraCols = `id, asset_id, ip, mac, source, first_seen, last_seen`

func scanExtra(sc interface{ Scan(...any) error }) (extraAddr, error) {
	var x extraAddr
	err := sc.Scan(&x.id, &x.assetID, &x.ip, &x.mac, &x.source, &x.firstSeen, &x.lastS)
	return x, err
}

// extraWhere reads the one row that holds an address: col is ip or mac.
func extraWhere(ctx context.Context, q querier, col, value string) (extraAddr, bool, error) {
	x, err := scanExtra(q.QueryRowContext(ctx, `SELECT `+extraCols+` FROM inv_asset_address WHERE `+col+` = ?`, value))
	if errors.Is(err, sql.ErrNoRows) {
		return extraAddr{}, false, nil
	}
	if err != nil {
		return extraAddr{}, false, fmt.Errorf("inventory: read the addresses: %w", err)
	}
	return x, true, nil
}

func extraByIP(ctx context.Context, q querier, ip string) (extraAddr, bool, error) {
	return extraWhere(ctx, q, "ip", ip)
}

func extraByMAC(ctx context.Context, q querier, mac string) (extraAddr, bool, error) {
	return extraWhere(ctx, q, "mac", mac)
}

// extrasOf reads the other addresses of a device, the one seen last first.
func extrasOf(ctx context.Context, q querier, assetID string) ([]extraAddr, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+extraCols+` FROM inv_asset_address WHERE asset_id = ? ORDER BY last_seen DESC, id`, assetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []extraAddr
	for rows.Next() {
		x, err := scanExtra(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read the addresses: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// touchExtra records a sighting of an address row by source at seenAt.
func touchExtra(ctx context.Context, tx *sql.Tx, id, source, seenAt string) error {
	if !validAddrSource(source) {
		source = addrMerge
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET last_seen = max(last_seen, ?), source = CASE WHEN ? >= last_seen THEN ? ELSE source END WHERE id = ?`,
		seenAt, seenAt, source, id); err != nil {
		return fmt.Errorf("inventory: touch an address: %w", err)
	}
	return nil
}

// addressOf is the id of the other address of device assetID that a scan of ip reached: "" when ip is the device's main address, not
// one of its addresses, or not given. A scan's readings and open ports are stored under it (addressBound).
func addressOf(ctx context.Context, tx *sql.Tx, assetID string, ip netip.Addr) (string, error) {
	if !ip.IsValid() {
		return "", nil
	}
	x, ok, err := extraByIP(ctx, tx, ip.String())
	if err != nil || !ok || x.assetID != assetID {
		return "", err
	}
	return x.id, nil
}

// releaseExtraIP takes ip away from an address row of another device: another machine answers there now (claimIP, claimRowIP). A
// row that still has its MAC stays (the interface is still that device's, at an address not known yet); a row known by that address
// only goes, and what a scan read at it joins the device's main address (unbindAddress). The device is announced (readdress).
func (s *Service) releaseExtraIP(ctx context.Context, tx *sql.Tx, o *outbox, x extraAddr) error {
	if x.mac.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET ip = NULL WHERE id = ?`, x.id); err != nil {
			return fmt.Errorf("inventory: free an address: %w", err)
		}
	} else if err := s.dropExtra(ctx, tx, x); err != nil {
		return err
	}
	if o != nil {
		o.readdress(x.assetID)
	}
	return nil
}

// dropExtra deletes an address row; what a scan read at it is the device's main address's from then on (unbindAddress).
func (s *Service) dropExtra(ctx context.Context, tx *sql.Tx, x extraAddr) error {
	if err := s.unbindAddress(ctx, tx, x.assetID, x.id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_asset_address WHERE id = ?`, x.id); err != nil {
		return fmt.Errorf("inventory: remove an address: %w", err)
	}
	return nil
}

// unbindAddress moves what a scan read at address row addrID of a device (readings and open ports) to the device's main address
// (an empty addr_id). Of two readings of one source and instance, or two rows of one port, the newer stays; the lines it touched are
// settled again. Nothing else is lost: the next scan of the main address replaces them as its own.
func (s *Service) unbindAddress(ctx context.Context, tx *sql.Tx, assetID, addrID string) error {
	lines, err := candidates(ctx, tx, `SELECT DISTINCT r.software_id FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
		WHERE w.asset_id = ? AND r.addr_id = ?`, assetID, addrID)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM inv_software_reading WHERE addr_id = ?1 AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?2) AND EXISTS (SELECT 1 FROM inv_software_reading g
			WHERE g.software_id = inv_software_reading.software_id AND g.source = inv_software_reading.source AND g.instance = inv_software_reading.instance
			AND g.addr_id = '' AND g.seen_at >= inv_software_reading.seen_at)`,
		`DELETE FROM inv_software_reading WHERE addr_id = '' AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?2) AND EXISTS (SELECT 1 FROM inv_software_reading k
			WHERE k.software_id = inv_software_reading.software_id AND k.source = inv_software_reading.source AND k.instance = inv_software_reading.instance AND k.addr_id = ?1)`,
		`UPDATE inv_software_reading SET addr_id = '' WHERE addr_id = ?1 AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?2)`,
		`DELETE FROM inv_service WHERE asset_id = ?2 AND addr_id = ?1 AND EXISTS (SELECT 1 FROM inv_service g WHERE g.asset_id = ?2 AND g.addr_id = ''
			AND g.port = inv_service.port AND g.proto = inv_service.proto AND g.source = inv_service.source AND g.seen_at >= inv_service.seen_at)`,
		`DELETE FROM inv_service WHERE asset_id = ?2 AND addr_id = '' AND EXISTS (SELECT 1 FROM inv_service k WHERE k.asset_id = ?2 AND k.addr_id = ?1
			AND k.port = inv_service.port AND k.proto = inv_service.proto AND k.source = inv_service.source)`,
		`UPDATE inv_service SET addr_id = '' WHERE asset_id = ?2 AND addr_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, addrID, assetID); err != nil {
			return fmt.Errorf("inventory: move what was read at an address: %w", err)
		}
	}
	now := s.now()
	for _, id := range lines {
		if _, err := s.settleLine(ctx, tx, id, now, nil); err != nil {
			return err
		}
	}
	return nil
}

// freeMainIP takes ip away from the main address of any device but id that may lose it (a discovered device, or one bound to a MAC or an
// agent: claimIP's rule) and announces it. It reports whether ip is still the main address of another device (one that keeps it: the
// box, a device added by hand known by its address only).
func freeMainIP(ctx context.Context, tx *sql.Tx, o *outbox, id, ip string) (held bool, err error) {
	var freed string
	switch err := tx.QueryRowContext(ctx, `UPDATE inv_asset SET ip = NULL, ip_confirmed_at = NULL WHERE ip = ? AND id <> ? AND is_box = 0
		AND (origin = 'discovered' OR mac IS NOT NULL OR agent_key IS NOT NULL) RETURNING id`, ip, id).Scan(&freed); {
	case err == nil:
		if o != nil {
			o.readdress(freed)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("inventory: free IP: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_asset WHERE ip = ? AND id <> ?)`, ip, id).Scan(&held); err != nil {
		return false, fmt.Errorf("inventory: read IP: %w", err)
	}
	return held, nil
}

// claimRowIP is claimIP for an address row: the interface with x's MAC was seen at ip, so the row takes ip (DHCP gave that interface a
// new address). The address is taken from another device's main address or row by claimIP's rules; nothing changes when ip is the
// device's own main address or a device that keeps its address holds it.
func (s *Service) claimRowIP(ctx context.Context, tx *sql.Tx, o *outbox, x extraAddr, ip netip.Addr) error {
	if !ip.IsValid() || x.ip.Valid && x.ip.String == ip.String() {
		return nil
	}
	var own bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_asset WHERE id = ? AND ip = ?)`, x.assetID, ip.String()).Scan(&own); err != nil {
		return fmt.Errorf("inventory: read device: %w", err)
	}
	if own {
		return nil
	}
	if held, err := freeMainIP(ctx, tx, o, x.assetID, ip.String()); err != nil || held {
		return err
	}
	if y, ok, err := extraByIP(ctx, tx, ip.String()); err != nil {
		return err
	} else if ok && y.id != x.id {
		if y.assetID == x.assetID { // two rows of one device: the one seen there now keeps the address
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET ip = NULL WHERE id = ?`, y.id); err != nil {
				return fmt.Errorf("inventory: move an address: %w", err)
			}
			if !y.mac.Valid {
				if err := s.dropExtra(ctx, tx, y); err != nil {
					return err
				}
			}
		} else if err := s.releaseExtraIP(ctx, tx, o, y); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET ip = ? WHERE id = ?`, ip.String(), x.id); err != nil {
		return fmt.Errorf("inventory: move an address: %w", err)
	}
	if o != nil {
		o.readdress(x.assetID)
	}
	return nil
}

// atExtraMAC is resolve for a hint whose MAC is one of a device's other addresses: that device, the row touched, its address moved to
// the hint's when the interface was seen elsewhere (claimRowIP).
func (s *Service) atExtraMAC(ctx context.Context, tx *sql.Tx, o *outbox, x extraAddr, c cleanObs) (string, error) {
	if err := touchExtra(ctx, tx, x.id, c.source, c.seenAt); err != nil {
		return "", err
	}
	return x.assetID, s.claimRowIP(ctx, tx, o, x, c.ip)
}

// atExtraIP is resolve for a hint whose address is one of a device's other addresses, when no device has the hint's MAC. It mirrors the
// rules of the main address: by address only, the device takes it when the row is known by its address only, was seen within ipTrust,
// or the discovery sweep could not have confirmed it (else a sensor's report or a list goes nowhere, and an agent's makes a device of its
// own); with a MAC nobody owns, a row known by its address only and seen within ipTrust binds it, and any other MAC there is another
// machine (a new device takes the address: claimIP). done is false when the hint goes on to make a new device.
func (s *Service) atExtraIP(ctx context.Context, tx *sql.Tx, x extraAddr, c cleanObs, cutoff string) (id string, done bool, err error) {
	fresh := x.lastS >= cutoff
	if c.mac != "" {
		if x.mac.Valid || !fresh {
			return "", false, nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET mac = ? WHERE id = ?`, c.mac, x.id); err != nil {
			return "", false, fmt.Errorf("inventory: set the MAC of an address: %w", err)
		}
		return x.assetID, true, touchExtra(ctx, tx, x.id, c.source, c.seenAt)
	}
	if !x.mac.Valid {
		return x.assetID, true, touchExtra(ctx, tx, x.id, c.source, c.seenAt)
	}
	if fresh {
		return x.assetID, true, nil
	}
	judged, err := sweptAwayAt(ctx, tx, x.assetID, netip.MustParseAddr(x.ip.String), cutoff)
	switch {
	case err != nil:
		return "", true, err
	case !judged:
		return x.assetID, true, nil
	case c.agent == "" || c.list:
		s.staleLog(ctx, x.assetID, c, x.lastS, staleSwept)
		return "", true, nil
	}
	return "", false, nil
}

// addressHolder is the device that has ip as its main address or as one of its others; "" when none.
func addressHolder(ctx context.Context, q querier, ip string) (string, error) {
	var id string
	err := q.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE ip = ?1 UNION ALL SELECT asset_id FROM inv_asset_address WHERE ip = ?1 LIMIT 1`, ip).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inventory: check IP: %w", err)
	}
	return id, nil
}

// Addresses reads every address of a device, the main one first, then the others, the one seen last first.
func (s *Service) addresses(ctx context.Context, q querier, id string) ([]Address, error) {
	var ip, mac, origin, first, last, confirmed sql.NullString
	var macSrc sql.NullString
	err := q.QueryRowContext(ctx, `SELECT a.ip, a.mac, a.origin, a.first_seen, a.last_seen, a.ip_confirmed_at, m.source FROM inv_asset a
		LEFT JOIN inv_observation m ON m.id = a.mac_obs_id WHERE a.id = ?`, id).Scan(&ip, &mac, &origin, &first, &last, &confirmed, &macSrc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFoundDevice()
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read device: %w", err)
	}
	out := []Address{}
	if ip.Valid || mac.Valid {
		src := macSrc.String
		switch {
		case src == "" && origin.String == "manual":
			src = "manual"
		case src == "":
			if err := q.QueryRowContext(ctx, `SELECT coalesce((SELECT source FROM inv_observation WHERE asset_id = ? AND source NOT IN ('manual', 'declared')
				ORDER BY seen_at DESC, id DESC LIMIT 1), 'passive')`, id).Scan(&src); err != nil {
				return nil, fmt.Errorf("inventory: read device: %w", err)
			}
		case src == "declared":
			src = "manual"
		}
		seen := last.String
		if confirmed.Valid && !mac.Valid {
			seen = confirmed.String
		}
		out = append(out, Address{IP: nullPtr(ip), MAC: nullPtr(mac), Main: true, Source: src, FirstSeen: first.String, LastSeen: seen})
	}
	extras, err := extrasOf(ctx, q, id)
	if err != nil {
		return nil, err
	}
	for _, x := range extras {
		out = append(out, Address{IP: nullPtr(x.ip), MAC: nullPtr(x.mac), Source: x.source, FirstSeen: x.firstSeen, LastSeen: x.lastS})
	}
	return out, nil
}

func nullPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

// addExtra stores an address row for a device: the IP and MAC that are no other device's (a caller that moves them frees them
// first). It returns the new row's id, "" when there was nothing to store.
func addExtra(ctx context.Context, tx *sql.Tx, assetID string, ip, mac sql.NullString, source, first, last string) (string, error) {
	if !ip.Valid && !mac.Valid {
		return "", nil
	}
	id := store.NewID("ad")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset_address (id, asset_id, ip, mac, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, assetID, ip, mac, source, first, last); err != nil {
		return "", fmt.Errorf("inventory: store an address: %w", err)
	}
	return id, nil
}

// otherAddressHits lists the devices one of whose other addresses holds the search text: an IP fragment, or a MAC fragment in any
// notation (macFragment), as Device.shows reads the main address.
func otherAddressHits(ctx context.Context, q querier, text string) (map[string]bool, error) {
	hex, isMAC := macFragment(text)
	if !isMAC {
		hex = "\x00" // no MAC fragment: matches no MAC
	}
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT asset_id FROM inv_asset_address WHERE instr(coalesce(ip, ''), ?) > 0 OR instr(coalesce(mac, ''), ?) > 0`, text, hex)
	if err != nil {
		return nil, fmt.Errorf("inventory: search the addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: search the addresses: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}
