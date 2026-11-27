package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
)

// A device a person removed stays removed (INV-59). Its row goes with everything known about it (DeleteDevice), and what identified it
// stays in inv_removed_id, so the sensors do not make it again: a burned-in or stable MAC, its addresses when it had no such MAC, and,
// when the person stopped its agent and the agent's token is shared by other machines, the machine's enrolment on that token
// (agent-intake refuses it: RemovedAgent). This is the inventory's tombstone; the device's row is never kept as a hidden one, so no
// reader can show it by mistake. Only the two places that create a found device read it (resolve, ownDevice), and agent-intake at
// enrolment. A person undoes it by forgetting the removal (Removed list) or by adding a device by hand at its address; an agent a
// person installs on the machine brings it back too (an osquery report creates the device and forgets the removal).

// Agent choices of a removal (DELETE /inventory/devices/{id}?agent=).
const (
	AgentKeep = "keep" // the agent is left alone: it adds the device back on its next report, so nothing is kept
	AgentStop = "stop" // the agent's record goes (and its token, when made for this device alone); the removal keeps the device out
)

// RemovedDevice is one row of the Removed list.
type RemovedDevice struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	IP        *string `json:"ip"`
	Agent     string  `json:"agent"` // none or stopped
	RemovedBy string  `json:"removed_by"`
	RemovedAt string  `json:"removed_at"`
	// Identifiers counts what keeps it out: MACs, addresses (a device known by no burned-in MAC) and agent enrolments.
	Identifiers int `json:"identifiers"`
}

// removedIdentifiers are what identified device id, read inside tx before its row goes: every MAC of the device that is no private
// (rotating) one; for a device with no MAC at all (a routed subnet, a device added by hand), every address of it. A private MAC
// blocks nothing, so it is not kept, and neither is the address of a device that has one: the next phone at that address is another.
func removedIdentifiers(ctx context.Context, tx *sql.Tx, id string) (macs, ips []string, err error) {
	read := func(q string) ([]string, error) {
		rows, err := tx.QueryContext(ctx, q, id)
		if err != nil {
			return nil, fmt.Errorf("inventory: read the removed device's identifiers: %w", err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return nil, fmt.Errorf("inventory: read the removed device's identifiers: %w", err)
			}
			out = append(out, v)
		}
		return out, rows.Err()
	}
	all, err := read(`SELECT mac FROM inv_asset WHERE id = ?1 AND mac IS NOT NULL UNION SELECT mac FROM inv_asset_address WHERE asset_id = ?1 AND mac IS NOT NULL ORDER BY 1`)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range all {
		if len(m) == 17 && !PrivateMAC(m) {
			macs = append(macs, m)
		}
	}
	if len(all) > 0 {
		return macs, nil, nil
	}
	ips, err = read(`SELECT ip FROM inv_asset WHERE id = ?1 AND ip IS NOT NULL UNION SELECT ip FROM inv_asset_address WHERE asset_id = ?1 AND ip IS NOT NULL ORDER BY 1`)
	return nil, ips, err
}

// keepRemoved writes the removal of device d (name and main address as they were) with its identifiers, inside the delete's tx. An
// identifier an older removal kept moves to this one. kept is false when nothing would recognise the device again.
func (s *Service) keepRemoved(ctx context.Context, tx *sql.Tx, d lifecycle.Delete, ip sql.NullString, macs, ips []string) (kept bool, err error) {
	agent := "none"
	var block string
	if d.StopAgent != nil && d.StopAgent.Stopped {
		agent, block = "stopped", d.StopAgent.Block
	}
	if len(macs) == 0 && len(ips) == 0 && block == "" {
		return false, nil // nothing would recognise it again
	}
	by := d.Actor
	if by == "" {
		by = systemActor
	}
	id := store.NewID("rm")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_removed (id, name, ip, agent, removed_by, removed_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, clip(d.Name, 256), ip, agent, clip(by, 256), s.now()); err != nil {
		return false, fmt.Errorf("inventory: keep the removal: %w", err)
	}
	put := func(kind, value string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO inv_removed_id (removed_id, kind, value) VALUES (?, ?, ?)
			ON CONFLICT (kind, value) DO UPDATE SET removed_id = excluded.removed_id`, id, kind, value)
		if err != nil {
			return fmt.Errorf("inventory: keep the removal: %w", err)
		}
		return nil
	}
	for _, m := range macs {
		if err := put("mac", m); err != nil {
			return false, err
		}
	}
	for _, a := range ips {
		if err := put("ip", a); err != nil {
			return false, err
		}
	}
	if block != "" {
		if err := put("agent", block); err != nil {
			return false, err
		}
	}
	return true, dropEmptyRemovals(ctx, tx)
}

// dropEmptyRemovals deletes the removals no identifier is left of (another removal took them, or a person's device brought them back).
func dropEmptyRemovals(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_removed WHERE NOT EXISTS (SELECT 1 FROM inv_removed_id i WHERE i.removed_id = inv_removed.id)`); err != nil {
		return fmt.Errorf("inventory: drop empty removals: %w", err)
	}
	return nil
}

// removedHit reports whether sighting c is of a device a person removed: its MAC was kept, or it has no MAC and its address was kept.
// Called only where a found device would be made (resolve, ownDevice), so it never touches a device that exists. mac is the card to
// test ("" for none).
func removedHit(ctx context.Context, tx *sql.Tx, mac string, ip netip.Addr) (bool, error) {
	if mac == "" && !ip.IsValid() {
		return false, nil
	}
	kind, value := "mac", mac
	if mac == "" {
		kind, value = "ip", ip.String()
	}
	var hit bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_removed_id WHERE kind = ? AND value = ?)`, kind, value).Scan(&hit); err != nil {
		return false, fmt.Errorf("inventory: read the removed devices: %w", err)
	}
	return hit, nil
}

// forgetRemovedAt forgets the removals that kept mac or ip, inside tx: the machine's own agent made its device again, or (shown true) a
// person added a device by hand at ip, which also forgets a removal whose device was shown at that address. It returns how many went.
func forgetRemovedAt(ctx context.Context, tx *sql.Tx, mac string, ip netip.Addr, shown bool) (int64, error) {
	var ipText string
	if ip.IsValid() {
		ipText = ip.String()
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM inv_removed WHERE id IN (
		SELECT removed_id FROM inv_removed_id WHERE (kind = 'mac' AND value = ?1 AND ?1 <> '') OR (kind = 'ip' AND value = ?2 AND ?2 <> '')
		UNION SELECT id FROM inv_removed WHERE ?3 AND ip = ?2 AND ?2 <> '')`, mac, ipText, shown)
	if err != nil {
		return 0, fmt.Errorf("inventory: forget a removal: %w", err)
	}
	return res.RowsAffected()
}

// RemovedDevices lists the removals that keep devices out, the newest first (GET /inventory/removed).
func (s *Service) RemovedDevices(ctx context.Context) ([]RemovedDevice, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT r.id, r.name, r.ip, r.agent, r.removed_by, r.removed_at,
		(SELECT count(*) FROM inv_removed_id i WHERE i.removed_id = r.id) FROM inv_removed r ORDER BY r.removed_at DESC, r.id`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the removed devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []RemovedDevice{}
	for rows.Next() {
		var r RemovedDevice
		var ip sql.NullString
		if err := rows.Scan(&r.ID, &r.Name, &ip, &r.Agent, &r.RemovedBy, &r.RemovedAt, &r.Identifiers); err != nil {
			return nil, fmt.Errorf("inventory: read the removed devices: %w", err)
		}
		r.IP = ptr(ip)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ForgetRemoved forgets one removal (DELETE /inventory/removed/{id}): the device comes back under To review the next time a sensor sees
// it, and its agent may enrol again. Audited.
func (s *Service) ForgetRemoved(ctx context.Context, actor, id string) error {
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		var name string
		err := tx.QueryRowContext(ctx, `SELECT name FROM inv_removed WHERE id = ?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.NotFound()
		}
		if err != nil {
			return fmt.Errorf("inventory: read the removal: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_removed WHERE id = ?`, id); err != nil {
			return fmt.Errorf("inventory: forget the removal: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.removal_forget", name, id)
	})
}

// RemovedAgent reports whether an agent enrolment (agent-intake's "osquery-host:<token>/<host identifier>") belongs to a device a
// person removed with its agent stopped: agent-intake refuses that enrolment.
func (s *Service) RemovedAgent(ctx context.Context, key string) (bool, error) {
	var hit bool
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_removed_id WHERE kind = 'agent' AND value = ?)`, key).Scan(&hit); err != nil {
		return false, fmt.Errorf("inventory: read the removed agents: %w", err)
	}
	return hit, nil
}

// keptOut is the removal check where a found device would be made for sighting c with card mac ("" for none): a sighting a removal
// kept out makes nothing (logged at most hourly). An osquery agent's report is a machine a person installed the agent on: it is never
// kept out, and it forgets the removals of its card and address, since the device is back by a person's doing (an agent whose token is
// shared and was stopped cannot enrol again: RemovedAgent).
func (s *Service) keptOut(ctx context.Context, tx *sql.Tx, c cleanObs, mac string) (bool, error) {
	if c.agent != "" {
		for _, m := range append([]string{mac}, c.agentMACs...) { // the cards it reports in this batch are its own
			if _, err := forgetRemovedAt(ctx, tx, m, c.ip, false); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	hit, err := removedHit(ctx, tx, mac, c.ip)
	if err != nil || !hit {
		return false, err
	}
	key := mac
	if key == "" {
		key = c.ip.String()
	}
	s.staleLog(ctx, key, c, "", staleRemoved)
	return true, nil
}
