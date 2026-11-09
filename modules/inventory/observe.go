package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// The inventory is what sensors and agents write to, through core/observe (they do not import this package).
var (
	_ observe.Sink         = (*Service)(nil)
	_ observe.SoftwareSink = (*Service)(nil)
)

const maxBatch = 5000

// maxClockSkew is how far into the future a sensor's clock may be before its time is replaced by ours.
const maxClockSkew = 5 * time.Minute

// RecordObservation stores one observation (PRE-1, POST-1). It is Record with a batch of one.
func (s *Service) RecordObservation(ctx context.Context, o observe.Observation) error {
	return s.Record(ctx, []observe.Observation{o})
}

// cleanObs is an observation that passed the boundary check.
type cleanObs struct {
	ip     netip.Addr
	mac    string // hint, normalised, may be ""
	field  string
	value  string
	source string
	conf   float64
	seenAt string
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// checkHint validates the device hint: a MAC or an IPv4 address, at least one.
func checkHint(h observe.AssetHint) (ip netip.Addr, mac string, err error) {
	if h.MAC != "" {
		m, ok := normMAC(h.MAC)
		if !ok {
			return ip, "", invalid("hint: not a MAC address")
		}
		mac = m
	}
	if h.IP.IsValid() {
		ip = h.IP.Unmap()
		if !ip.Is4() {
			return ip, "", invalid("hint: only IPv4 addresses are supported")
		}
	}
	if mac == "" && !ip.IsValid() {
		return ip, "", invalid("hint: a MAC or an IP is required")
	}
	return ip, mac, nil
}

func (s *Service) seen(t time.Time) string {
	now := s.clock()
	if t.IsZero() || t.After(now.Add(maxClockSkew)) {
		t = now
	}
	return store.FormatTS(t)
}

// check validates a batch before any write (SYS-2, SYS-6): the data comes from the network. "manual" is
// refused: only a person in the interface may claim the top rank.
func (s *Service) check(batch []observe.Observation) ([]cleanObs, error) {
	if len(batch) > maxBatch {
		return nil, invalid("a batch has at most %d observations", maxBatch)
	}
	out := make([]cleanObs, 0, len(batch))
	for i, o := range batch {
		ip, mac, err := checkHint(o.AssetHint)
		if err != nil {
			return nil, fmt.Errorf("observation %d: %w", i, err)
		}
		if !observe.ValidSource(o.Source) || o.Source == observe.Manual {
			return nil, invalid("observation %d: source %q is not allowed", i, o.Source)
		}
		if !observe.ValidField(o.Field) {
			return nil, invalid("observation %d: field %q is unknown", i, o.Field)
		}
		if math.IsNaN(o.Confidence) || o.Confidence < 0 || o.Confidence > 1 {
			return nil, invalid("observation %d: confidence must be between 0 and 1", i)
		}
		value := o.Value
		switch o.Field {
		case observe.MAC:
			m, ok := normMAC(value)
			if !ok {
				return nil, invalid("observation %d: value is not a MAC address", i)
			}
			value = m
		case observe.Kind:
			if !validKind(value) {
				return nil, invalid("observation %d: unknown device type", i)
			}
		default:
			if !cleanText(value) {
				return nil, invalid("observation %d: value must be 1 to %d printable characters", i, maxObsValue)
			}
		}
		out = append(out, cleanObs{ip: ip, mac: mac, field: string(o.Field), value: value, source: string(o.Source), conf: o.Confidence, seenAt: s.seen(o.SeenAt)})
	}
	return out, nil
}

// Record implements observe.Sink: the whole batch in one transaction (all or none). A device is found by
// MAC, then by IP; one that matches nothing is created unapproved (INV-9, POST-1).
func (s *Service) Record(ctx context.Context, batch []observe.Observation) error {
	clean, err := s.check(batch)
	if err != nil {
		return err
	}
	if len(clean) == 0 {
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		notify, err := notifyNew(ctx, tx)
		if err != nil {
			return err
		}
		created := map[string]bool{}
		touched := []string{}
		for _, c := range clean {
			id, isNew, err := s.resolve(ctx, tx, c)
			if err != nil {
				return err
			}
			if isNew {
				created[id] = true
				if err := s.auditTx(ctx, tx, systemActor, "inventory.discover", c.target(), id); err != nil {
					return err
				}
			}
			if !slices.Contains(touched, id) {
				touched = append(touched, id)
			}
			if err := insertObs(ctx, tx, id, c.field, c.value, c.source, c.conf, c.seenAt); err != nil {
				return err
			}
			if c.mac != "" && c.field != "mac" { // the MAC that found the device is itself an observation
				if err := insertObs(ctx, tx, id, "mac", c.mac, c.source, c.conf, c.seenAt); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, c.seenAt, id); err != nil {
				return fmt.Errorf("inventory: touch device: %w", err)
			}
		}
		for _, id := range touched {
			changed, err := s.RecomputeAsset(ctx, tx, id)
			if err != nil {
				return err
			}
			switch {
			case created[id]:
				o.add(EventAssetDiscovered, AssetEvent{AssetID: id, Notify: notify})
			case changed:
				o.add(EventAssetUpdated, AssetEvent{AssetID: id})
			}
		}
		return nil
	})
}

// target names the device a hint points to, for the audit row.
func (c cleanObs) target() string {
	if c.mac != "" {
		return c.mac
	}
	return c.ip.String()
}

// resolve finds the device a hint points to, or creates it. The MAC wins; with no known MAC the IP is used,
// and a device that already has another MAC does not own that IP any more: a discovered device gives it up
// (DHCP moved it), a declared one keeps it and the newcomer is created without an IP.
func (s *Service) resolve(ctx context.Context, tx *sql.Tx, c cleanObs) (id string, created bool, err error) {
	if c.mac != "" {
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE mac = ?`, c.mac).Scan(&id); {
		case err == nil:
			return id, false, s.claimIP(ctx, tx, id, c.ip)
		case !errors.Is(err, sql.ErrNoRows):
			return "", false, fmt.Errorf("inventory: find device by MAC: %w", err)
		}
	}
	if c.ip.IsValid() {
		var holderMAC sql.NullString
		switch err := tx.QueryRowContext(ctx, `SELECT id, mac FROM inv_asset WHERE ip = ?`, c.ip.String()).Scan(&id, &holderMAC); {
		case err == nil:
			if c.mac == "" {
				return id, false, nil
			}
			if !holderMAC.Valid {
				// Same device, first time its MAC is known. Set it now so the next observation of this batch finds the device
				// by MAC (RecomputeAsset only runs at the end of the batch).
				if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET mac = ? WHERE id = ?`, c.mac, id); err != nil {
					return "", false, fmt.Errorf("inventory: set MAC: %w", err)
				}
				return id, false, nil
			}
		case !errors.Is(err, sql.ErrNoRows):
			return "", false, fmt.Errorf("inventory: find device by IP: %w", err)
		}
	}
	now := c.seenAt
	id = store.NewID("a")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, mac, kind, origin, approved, fragile, first_seen, last_seen) VALUES (?, ?, 'unknown', 'discovered', 0, 0, ?, ?)`, id, nullStr(c.mac), now, now); err != nil {
		return "", false, fmt.Errorf("inventory: create device: %w", err)
	}
	return id, true, s.claimIP(ctx, tx, id, c.ip)
}

// claimIP gives ip to the device when it has none or when a discovered device holds it.
func (s *Service) claimIP(ctx context.Context, tx *sql.Tx, id string, ip netip.Addr) error {
	if !ip.IsValid() {
		return nil
	}
	var cur sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT ip FROM inv_asset WHERE id = ?`, id).Scan(&cur); err != nil {
		return fmt.Errorf("inventory: read device: %w", err)
	}
	if cur.Valid && cur.String == ip.String() {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = NULL WHERE ip = ? AND id <> ? AND origin = 'discovered' AND is_box = 0`, ip.String(), id); err != nil {
		return fmt.Errorf("inventory: free IP: %w", err)
	}
	// ponytail: a declared device that holds the IP keeps it; the update is then a no-op and this device stays as it was.
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM inv_asset WHERE ip = ?)`, ip.String(), id, ip.String()); err != nil {
		return fmt.Errorf("inventory: set IP: %w", err)
	}
	return nil
}

// insertObs appends an observation. An exact repeat of (device, field, source, value) moves seen_at forward
// and keeps the higher confidence; nothing else is ever changed or removed (INV-1).
func insertObs(ctx context.Context, tx *sql.Tx, assetID, field, value, source string, conf float64, seenAt string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, field, source, value) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at), confidence = max(confidence, excluded.confidence)`,
		store.NewID("o"), assetID, field, value, source, conf, seenAt)
	if err != nil {
		return fmt.Errorf("inventory: record observation: %w", err)
	}
	return nil
}

// RecomputeAsset folds the observations of a device into its current columns (DATA_MODEL 5.1 rule 3): per
// field the winner by source rank, confidence, seen_at, id. It is the only code that writes those columns, and
// it runs in the transaction of the insert and the audit row. It reports whether anything changed.
func (s *Service) RecomputeAsset(ctx context.Context, tx *sql.Tx, assetID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?`, assetID)
	if err != nil {
		return false, fmt.Errorf("inventory: read observations: %w", err)
	}
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("inventory: read observations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	best := winners(list)
	// A MAC another device already owns cannot become this device's MAC: take the best one that is free.
	if _, ok := best["mac"]; ok {
		cands := slices.DeleteFunc(slices.Clone(list), func(o obs) bool { return o.field != "mac" })
		slices.SortFunc(cands, func(a, b obs) int {
			switch {
			case better(a, b):
				return -1
			case better(b, a):
				return 1
			}
			return 0
		})
		delete(best, "mac")
		for _, c := range cands {
			var other string
			err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE mac = ? AND id <> ?`, c.value, assetID).Scan(&other)
			if errors.Is(err, sql.ErrNoRows) {
				best["mac"] = c
				break
			} else if err != nil {
				return false, fmt.Errorf("inventory: check MAC: %w", err)
			}
		}
	}
	var cur struct {
		kind, vendor, model, os, host, mac                   sql.NullString
		kindObs, vendorObs, modelObs, osObs, hostObs, macObs sql.NullString
		fragile, fragileManual                               bool
	}
	if err := tx.QueryRowContext(ctx, `SELECT kind, vendor, model, os, hostname, mac, kind_obs_id, vendor_obs_id, model_obs_id, os_obs_id, hostname_obs_id, mac_obs_id, fragile, fragile_manual
		FROM inv_asset WHERE id = ?`, assetID).Scan(&cur.kind, &cur.vendor, &cur.model, &cur.os, &cur.host, &cur.mac, &cur.kindObs, &cur.vendorObs, &cur.modelObs, &cur.osObs, &cur.hostObs, &cur.macObs, &cur.fragile, &cur.fragileManual); err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	val := func(f string) (any, any) {
		if o, ok := best[f]; ok {
			return o.value, o.id
		}
		return nil, nil
	}
	kindV, kindID := val("kind")
	if kindV == nil {
		kindV = "unknown"
	}
	vendorV, vendorID := val("vendor")
	modelV, modelID := val("model")
	osV, osID := val("os")
	hostV, hostID := val("hostname")
	macV, macID := val("mac")
	fragile := cur.fragile
	if !cur.fragileManual {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return false, err
		}
		fragile = slices.Contains(st.FragileKinds, kindV.(string))
	}
	same := func(ns sql.NullString, v any) bool {
		if v == nil {
			return !ns.Valid
		}
		return ns.Valid && ns.String == v.(string)
	}
	changed := cur.kind.String != kindV.(string) || !same(cur.vendor, vendorV) || !same(cur.model, modelV) || !same(cur.os, osV) || !same(cur.host, hostV) || !same(cur.mac, macV) ||
		!same(cur.kindObs, kindID) || !same(cur.vendorObs, vendorID) || !same(cur.modelObs, modelID) || !same(cur.osObs, osID) || !same(cur.hostObs, hostID) || !same(cur.macObs, macID) || fragile != cur.fragile
	if !changed {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET kind = ?, vendor = ?, model = ?, os = ?, hostname = ?, mac = ?,
		kind_obs_id = ?, vendor_obs_id = ?, model_obs_id = ?, os_obs_id = ?, hostname_obs_id = ?, mac_obs_id = ?, fragile = ? WHERE id = ?`,
		kindV, vendorV, modelV, osV, hostV, macV, kindID, vendorID, modelID, osID, hostID, macID, fragile, assetID); err != nil {
		return false, fmt.Errorf("inventory: recompute device: %w", err)
	}
	return true, nil
}
