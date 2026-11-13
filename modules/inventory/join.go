package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/store"
)

// chassisEvidence marks the mac observation a join leaves on the device it joined into (D-515): the chassis (base) MAC an LLDP
// frame names. It never becomes the device's MAC (RecomputeAsset skips it), and an observation that names only this MAC finds
// that device again instead of making a new one (resolve).
const chassisEvidence = "chassis"

// chassisBlock is how far above the base (chassis) MAC a switch numbers the MACs of its interfaces: Juniper, Cisco and HPE give
// each interface, the management port included, a MAC from a block that starts at the base MAC (D-515).
const chassisBlock = 0x7f

// netGear are the kinds an LLDP frame gives a network device that has a base MAC (capabilities Bridge, Router, WLAN AP), and a
// firewall a person or a better source named.
var netGear = []string{"switch", "router", "ap", "firewall"}

// sameDevice finds the device a device seen without an address is part of (D-515, W1-37): a switch heard by LLDP under its chassis
// MAC is the device that answers ARP and scans on its management address under another MAC of the same chassis. From strongest:
// (b) the two carry the same host name (LLDP system name); (c) the chassis MAC is the base of a block that holds the other device's
// MAC: same first five bytes, within chassisBlock above. Rule (a), the LLDP management address, waits for the sensor protocol to
// carry it (D-515). Only a discovered device with a MAC and no IP and a network kind joins, only into a device with an IP and a MAC
// of the same maker (OUI), and only when exactly one device fits. "" when none fits.
func sameDevice(ctx context.Context, tx *sql.Tx, id string) (into, why string, err error) {
	var ip, mac sql.NullString
	var origin string
	var isBox bool
	if err := tx.QueryRowContext(ctx, `SELECT ip, mac, origin, is_box FROM inv_asset WHERE id = ?`, id).Scan(&ip, &mac, &origin, &isBox); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("inventory: read device: %w", err)
	}
	if ip.Valid || !mac.Valid || origin != "discovered" || isBox || localMAC(mac.String) {
		return "", "", nil
	}
	oui := mac.String[:8]
	best, err := current(ctx, tx, id)
	if err != nil {
		return "", "", err
	}
	if k, ok := best["kind"]; !ok || !slices.Contains(netGear, devicetypes.ActsAs(k.value)) {
		return "", "", nil
	}
	if h, ok := best["hostname"]; ok {
		ids, err := candidates(ctx, tx, `SELECT id FROM inv_asset WHERE ip IS NOT NULL AND is_box = 0 AND lower(hostname) = lower(?) AND substr(mac, 1, 8) = ?`, h.value, oui)
		if err != nil {
			return "", "", err
		}
		if len(ids) == 1 {
			return ids[0], "the same name " + h.value, nil
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, mac FROM inv_asset WHERE ip IS NOT NULL AND is_box = 0 AND substr(mac, 1, 14) = ?`, mac.String[:14])
	if err != nil {
		return "", "", fmt.Errorf("inventory: find the chassis block: %w", err)
	}
	defer func() { _ = rows.Close() }()
	base := lastByte(mac.String)
	var ids []string
	for rows.Next() {
		var other, m string
		if err := rows.Scan(&other, &m); err != nil {
			return "", "", fmt.Errorf("inventory: find the chassis block: %w", err)
		}
		if d := lastByte(m) - base; d > 0 && d <= chassisBlock {
			ids = append(ids, other)
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", fmt.Errorf("inventory: find the chassis block: %w", err)
	}
	if len(ids) == 1 {
		return ids[0], "its chassis MAC " + mac.String + " is the base of the MAC block", nil
	}
	return "", "", nil
}

// joinInto moves device from into device into and deletes from (D-515): its observations (the MAC as the chassis mark), software
// and open ports; the approval, the suspicious flag, the notes and the scan choices a person made on it when into has none; one
// audit row inventory.merge. into keeps its id, address and MAC; the fields are folded again by the usual rules (RecomputeAsset).
func (s *Service) joinInto(ctx context.Context, tx *sql.Tx, from, into, why string) error {
	fromName, intoName := deviceName(ctx, tx, from), deviceName(ctx, tx, into)
	rows, err := tx.QueryContext(ctx, `SELECT field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?`, from)
	if err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, o := range list {
		if o.field == "mac" {
			if err := insertChassis(ctx, tx, into, o); err != nil {
				return err
			}
			continue
		}
		if err := insertPruned(ctx, tx, into, o.field, o.value, o.source, o.confidence, o.seenAt); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`UPDATE OR IGNORE inv_software SET asset_id = ? WHERE asset_id = ?`,
		`UPDATE OR IGNORE inv_service SET asset_id = ? WHERE asset_id = ?`,
		`UPDATE inv_asset SET
			approved = max(approved, (SELECT approved FROM inv_asset WHERE id = ?2)),
			approved_at = coalesce(approved_at, (SELECT approved_at FROM inv_asset WHERE id = ?2)),
			suspicious = max(suspicious, (SELECT suspicious FROM inv_asset WHERE id = ?2)),
			notes = coalesce(notes, (SELECT notes FROM inv_asset WHERE id = ?2)),
			regular_scan = CASE WHEN regular_scan = 'follow' THEN (SELECT regular_scan FROM inv_asset WHERE id = ?2) ELSE regular_scan END,
			fragile = CASE WHEN fragile_manual = 0 AND (SELECT fragile_manual FROM inv_asset WHERE id = ?2) = 1 THEN (SELECT fragile FROM inv_asset WHERE id = ?2) ELSE fragile END,
			fragile_manual = max(fragile_manual, (SELECT fragile_manual FROM inv_asset WHERE id = ?2)),
			first_seen = min(first_seen, (SELECT first_seen FROM inv_asset WHERE id = ?2)),
			last_seen = max(last_seen, (SELECT last_seen FROM inv_asset WHERE id = ?2))
			WHERE id = ?1`,
		`DELETE FROM inv_asset WHERE id = ?2`,
	} {
		if _, err := tx.ExecContext(ctx, q, into, from); err != nil {
			return fmt.Errorf("inventory: join devices: %w", err)
		}
	}
	return s.auditTx(ctx, tx, systemActor, "inventory.merge", intoName, fromName+" is the same device: "+why)
}

// insertChassis keeps the chassis MAC of a joined device on the device it joined into, marked chassisEvidence.
func insertChassis(ctx context.Context, tx *sql.Tx, into string, o obs) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence) VALUES (?, ?, 'mac', ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, field, source, value) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at), confidence = max(confidence, excluded.confidence)`,
		store.NewID("o"), into, o.value, o.source, o.confidence, o.seenAt, chassisEvidence)
	if err != nil {
		return fmt.Errorf("inventory: keep the chassis MAC: %w", err)
	}
	return nil
}

// chassisOwner is the device a join left the chassis MAC mac on, when it still has an address: an observation that names only that
// MAC (an LLDP frame) is about it.
func chassisOwner(ctx context.Context, tx *sql.Tx, mac string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT o.asset_id FROM inv_observation o JOIN inv_asset a ON a.id = o.asset_id
		WHERE o.field = 'mac' AND o.value = ? AND o.evidence = ? AND a.ip IS NOT NULL ORDER BY o.asset_id LIMIT 1`, mac, chassisEvidence).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inventory: find the chassis MAC: %w", err)
	}
	return id, nil
}

// current is the winning observation of each field of a device, before RecomputeAsset has written them.
func current(ctx context.Context, tx *sql.Tx, id string) (map[string]obs, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ? AND field IN ('kind', 'hostname')`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			return nil, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	return winners(list), nil
}

func candidates(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: find the same device: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: find the same device: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// localMAC reports a locally administered MAC (a random or virtual one): its first bytes name no maker, so no block can be read.
func localMAC(mac string) bool {
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err != nil || b&0x02 != 0
}

// lastByte is the last byte of a normalised MAC.
func lastByte(mac string) int {
	b, err := strconv.ParseUint(mac[strings.LastIndexByte(mac, ':')+1:], 16, 8)
	if err != nil {
		return -1 << 10
	}
	return int(b)
}

// joinSame runs sameDevice on every device a Record batch touched and joins each that fits (D-515). It returns the devices that are
// gone and those that received one; a joined device created in this very batch was never announced, so only an older one is
// announced deleted (findings drops its rows; the device that received it is matched again).
func (s *Service) joinSame(ctx context.Context, tx *sql.Tx, o *outbox, touched []string, created map[string]bool, before map[string]string) (map[string]bool, []string, error) {
	gone := map[string]bool{}
	var joined []string
	for _, id := range touched {
		into, why, err := sameDevice(ctx, tx, id)
		if err != nil || into == "" {
			if err != nil {
				return nil, nil, err
			}
			continue
		}
		if _, ok := before[into]; !ok {
			if before[into], err = matchView(ctx, tx, into); err != nil {
				return nil, nil, err
			}
		}
		if err := s.joinInto(ctx, tx, id, into, why); err != nil {
			return nil, nil, err
		}
		gone[id] = true
		if !slices.Contains(joined, into) {
			joined = append(joined, into)
		}
		if !created[id] {
			o.add(EventAssetDeleted, AssetEvent{AssetID: id})
		}
	}
	return gone, joined, nil
}
