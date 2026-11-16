package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
)

// A device that answered a credential and has since moved to an address outside that credential's scope (#829 C4, J2). Its row
// followed it to the new address (the inventory joins by MAC), but the credential is never sent there on its own: the scope is the
// safety line of D-512, and a MAC can be copied, so the device at the new address is not proven to be the one that was vouched for.
// So nothing is read, and this says so instead of nothing: on the credential (GET /inventory/snmp moved_out), in Read now (a
// skipped row), on the device page and on the Scanning card. A person who adds the new address to the scope (typing the secret
// again, D-512) has it read again.
//
// sa_snmp_answer keeps, per credential and device, the address of the newest answer. Its rows go with their credential, with the
// device (inventory.asset.deleted), move with a merged device (inventory.asset.merged), and go when an edit narrows the scope so it
// no longer holds their address; the window's round also removes the rows of devices the inventory no longer has.

// SNMPMoved is one such device (SnmpMoved in contract.ts).
type SNMPMoved struct {
	DeviceID, Name, IP string
	Message            string // plain words for the person
}

// snmpMovedText is what a person is told about a device that moved out of a credential's scope.
func snmpMovedText(name string, ip netip.Addr) string {
	if name == "" {
		return fmt.Sprintf("A device that answered this credential moved to %s, outside the scope of this credential. If it is still that device, first check on the device itself that this is its address now (a copied network card looks the same), then add the address to the scope to keep reading it. Nothing is sent there until then.", ip)
	}
	return fmt.Sprintf("%s moved to %s, outside the scope of this credential. If it is still %s, first check on the device itself that this is its address now (a copied network card looks the same), then add the address to the scope to keep reading it. Nothing is sent there until then.", name, ip, name)
}

// snmpMovedOut lists, by credential id, the devices whose newest answer was with that credential at an address its scope holds, and
// whose current address is another one its scope does not hold: they moved out of it. A scope narrowed on purpose is not a move
// (the address did not change). A device another credential answered later is left out: that one reads it now. A device the
// inventory no longer has, or that has no address, is left out; gone lists the ones the inventory no longer has. Failures are
// logged and give an empty list: this only adds words, never stops a list or a read.
func (s *Service) snmpMovedOut(ctx context.Context, creds []snmpRow) (moved map[string][]SNMPMoved, gone []string) {
	type answer struct{ cred, asset, ip string }
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT credential_id, asset_id, ip FROM sa_snmp_answer ORDER BY asset_id, answered_at DESC, credential_id`)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
		return nil, nil
	}
	var all []answer
	for rows.Next() {
		var a answer
		if err := rows.Scan(&a.cred, &a.asset, &a.ip); err != nil {
			_ = rows.Close()
			s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
			return nil, nil
		}
		all = append(all, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
		return nil, nil
	}
	if len(all) == 0 {
		return nil, nil
	}
	addrs, err := s.inv.Addresses(ctx) // one read for every device; the inventory is asked about a device only to name it
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading device addresses for snmp failed", "error", err)
		return nil, nil
	}
	now := make(map[string]netip.Addr, len(addrs))
	for ip, id := range addrs {
		now[id] = ip
	}
	byID := make(map[string]snmpRow, len(creds))
	for _, c := range creds {
		byID[c.ID] = c
	}
	moved = map[string][]SNMPMoved{}
	for i, a := range all {
		if i > 0 && all[i-1].asset == a.asset {
			continue // the newest answer of each device decides (ordered by answered_at, newest first)
		}
		ip, ok := now[a.asset]
		if !ok { // no address now, or deleted: only the inventory can tell which
			if _, err := s.inv.Asset(ctx, a.asset); errors.Is(err, ErrNotFound) {
				gone = append(gone, a.asset)
			}
			continue
		}
		c, ok := byID[a.cred]
		was, err := netip.ParseAddr(a.ip)
		if !ok || err != nil || ip == was || !c.covers(was) || c.covers(ip) {
			continue
		}
		dev, err := s.inv.Asset(ctx, a.asset)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.log.WarnContext(ctx, "sensoractive: reading a device for snmp failed", "device", a.asset, "error", err)
			}
			continue
		}
		moved[c.ID] = append(moved[c.ID], SNMPMoved{DeviceID: a.asset, Name: dev.Name, IP: ip.String(), Message: snmpMovedText(dev.Name, ip)})
	}
	return moved, gone
}

// forgetSNMPAnswers removes the answers of devices the inventory no longer has (inventory.asset.deleted, the window's round).
func (s *Service) forgetSNMPAnswers(ctx context.Context, assets []string) error {
	if len(assets) == 0 {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, id := range assets {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_answer WHERE asset_id = ?`, id); err != nil {
				return fmt.Errorf("sensoractive: forget snmp answers: %w", err)
			}
		}
		return nil
	})
}

// forgetOutside removes the answers of credential id at addresses its new scope no longer holds (EditSNMP): a scope narrowed on purpose
// is not a move to report.
func forgetOutside(ctx context.Context, tx *sql.Tx, id string, scope []string) error {
	rows, err := tx.QueryContext(ctx, `SELECT asset_id, ip FROM sa_snmp_answer WHERE credential_id = ?`, id)
	if err != nil {
		return fmt.Errorf("sensoractive: read snmp answers: %w", err)
	}
	held := snmpRow{SNMPCredential: SNMPCredential{Scope: scope}}
	var drop []string
	for rows.Next() {
		var asset, ip string
		if err := rows.Scan(&asset, &ip); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sensoractive: read snmp answers: %w", err)
		}
		if a, err := netip.ParseAddr(ip); err != nil || !held.covers(a) {
			drop = append(drop, asset)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("sensoractive: read snmp answers: %w", err)
	}
	for _, asset := range drop {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_answer WHERE credential_id = ? AND asset_id = ?`, id, asset); err != nil {
			return fmt.Errorf("sensoractive: forget snmp answers: %w", err)
		}
	}
	return nil
}

// AssetDeleted handles inventory.asset.deleted: the device's SNMP answers go with it.
func (s *Service) AssetDeleted(ctx context.Context, assetID string) error {
	return s.forgetSNMPAnswers(ctx, []string{assetID})
}

// AssetMerged handles inventory.asset.merged {from, into} (published before from's asset.deleted): the answers of from become
// into's, the newer one kept where both answered the same credential.
func (s *Service) AssetMerged(ctx context.Context, from, into string) error {
	if from == "" || into == "" || from == into {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_answer (credential_id, asset_id, ip, answered_at)
			SELECT credential_id, ?, ip, answered_at FROM sa_snmp_answer WHERE asset_id = ?
			ON CONFLICT (credential_id, asset_id) DO UPDATE SET ip = excluded.ip, answered_at = excluded.answered_at
			WHERE excluded.answered_at > sa_snmp_answer.answered_at`, into, from); err != nil {
			return fmt.Errorf("sensoractive: merge snmp answers: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_answer WHERE asset_id = ?`, from); err != nil {
			return fmt.Errorf("sensoractive: merge snmp answers: %w", err)
		}
		return nil
	})
}
