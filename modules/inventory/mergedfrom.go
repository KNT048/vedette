package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// A person's merge is undone by Split off of the address the merged device brought: the split gives back that device as it was, not
// a new "Unknown" row. The merge keeps what the device brought on the kept one (inv_merged_from): its id, its main interface, its
// name in Vedette and the observations only it held; the split of that interface takes them back (its id when no device holds it).

// mergedFacts is inv_merged_from.facts.
type mergedFacts struct {
	Obs []mergedObs `json:"obs"`
	// TookName: the kept device had no name in Vedette and took the merged device's (joinAs); the split gives it back.
	TookName bool `json:"took_name,omitempty"`
}

type mergedObs struct {
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
	// Only: the kept device held no such observation before the merge, so it goes back with the split; the others are copied.
	Only bool `json:"only,omitempty"`
}

// rememberMerged keeps what device from brings to into in a person's merge, before the merge moves it: from's main interface, its
// name in Vedette and its observations, marked when into does not hold them (a MAC goes with its interface; a declared OS is decided
// again). Nothing is kept for a device without an address: there is nothing to split off.
func rememberMerged(ctx context.Context, tx *sql.Tx, into, from, now string) error {
	var ip, mac, fromName, intoName sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT f.ip, f.mac, f.user_name, i.user_name FROM inv_asset f, inv_asset i WHERE f.id = ? AND i.id = ?`, from, into).
		Scan(&ip, &mac, &fromName, &intoName); err != nil {
		return fmt.Errorf("inventory: read devices: %w", err)
	}
	if !ip.Valid && !mac.Valid {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT f.field, f.value, f.source, f.confidence, f.seen_at,
		NOT EXISTS (SELECT 1 FROM inv_observation i WHERE i.asset_id = ?2 AND i.field = f.field AND i.source = f.source AND i.value = f.value)
		FROM inv_observation f WHERE f.asset_id = ?1 AND f.source <> 'declared' AND f.field <> 'mac' ORDER BY f.field, f.source, f.value`, from, into)
	if err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	facts := mergedFacts{Obs: []mergedObs{}, TookName: !intoName.Valid && fromName.Valid}
	for rows.Next() {
		var o mergedObs
		if err := rows.Scan(&o.Field, &o.Value, &o.Source, &o.Confidence, &o.SeenAt, &o.Only); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read observations: %w", err)
		}
		facts.Obs = append(facts.Obs, o)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("inventory: read observations: %w", err)
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("inventory: keep the merged device: %w", err)
	}
	if len(raw) > 65536 { // more than any device holds; keep the interface and the name rather than refuse the merge
		raw, _ = json.Marshal(mergedFacts{Obs: []mergedObs{}, TookName: facts.TookName})
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_merged_from (asset_id, from_id, ip, mac, user_name, facts, merged_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, from_id) DO UPDATE SET ip = excluded.ip, mac = excluded.mac, user_name = excluded.user_name, facts = excluded.facts, merged_at = excluded.merged_at`,
		into, from, ip, mac, fromName, string(raw), now); err != nil {
		return fmt.Errorf("inventory: keep the merged device: %w", err)
	}
	return nil
}

// mergedFrom is a row of inv_merged_from.
type mergedFrom struct {
	fromID   string
	userName sql.NullString
	facts    mergedFacts
}

// mergedAt finds what a merge kept of the device whose main interface was the one split off (ip or mac of it), nil when none.
func mergedAt(ctx context.Context, tx *sql.Tx, id string, ip, mac sql.NullString) (*mergedFrom, error) {
	var m mergedFrom
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT from_id, user_name, facts FROM inv_merged_from WHERE asset_id = ? AND (ip = ? OR mac = ?) ORDER BY merged_at DESC LIMIT 1`,
		id, ip, mac).Scan(&m.fromID, &m.userName, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the merged device: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &m.facts); err != nil {
		return nil, fmt.Errorf("inventory: read the merged device: %w", err)
	}
	return &m, nil
}

// splitID is the id the device split off takes: the merged device's own when a merge kept it and no device holds it, else a new one.
func splitID(ctx context.Context, tx *sql.Tx, m *mergedFrom, fresh string) (string, error) {
	if m == nil {
		return fresh, nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE id = ?`, m.fromID).Scan(&n); err != nil {
		return "", fmt.Errorf("inventory: read devices: %w", err)
	}
	if n > 0 {
		return fresh, nil
	}
	return m.fromID, nil
}

// giveBack moves what a merge kept of the device back from id to the device split off as newID: its observations (one id held only
// through the merge leaves id, the others are copied), its name in Vedette (id's too, when id took it in the merge and still has it), and forgets the row.
func giveBack(ctx context.Context, tx *sql.Tx, id, newID string, m *mergedFrom) error {
	if m == nil {
		return nil
	}
	for _, o := range m.facts.Obs {
		if o.Only {
			if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = ? AND source = ? AND value = ?`, id, o.Field, o.Source, o.Value); err != nil {
				return fmt.Errorf("inventory: give the observations back: %w", err)
			}
		}
		if err := insertObs(ctx, tx, newID, o.Field, o.Value, o.Source, o.Confidence, o.SeenAt); err != nil {
			return err
		}
	}
	if m.userName.Valid {
		if m.facts.TookName {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = NULL WHERE id = ? AND user_name = ?`, id, m.userName.String); err != nil {
				return fmt.Errorf("inventory: give the name back: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = ? WHERE id = ?`, m.userName.String, newID); err != nil {
			return fmt.Errorf("inventory: give the name back: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_merged_from WHERE asset_id = ? AND from_id = ?`, id, m.fromID); err != nil {
		return fmt.Errorf("inventory: forget the merged device: %w", err)
	}
	return nil
}
