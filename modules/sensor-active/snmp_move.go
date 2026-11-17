package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
)

// The move of the old SNMP credentials to the devices they covered (once, the first time SNMP is used after the
// upgrade). The rule:
//
//   - A device gets its own copy when its address is in a credential's scope and it has SNMP readings (an answer kept in
//     sa_snmp_answer, or an SNMP observation in the inventory) or a person stored its SNMP switch on. Its read address is its
//     IP, as the round read it. The box is never one.
//   - Several credentials cover it: the one it answered last (sa_snmp_answer), else the one that answered last of all
//     (sa_snmp.last_answer_at), else the first in the order the round tried them (oldest first).
//   - The secrets are opened and sealed again through core/secrets, one copy per device: an edit of one device never changes another.
//     A credential whose secret this box cannot open gives no copy: its devices are named in a notice to set up by hand.
//   - Every credential is then deleted with its secrets and its answers; a credential that covered no such device is deleted too.
//   - A notice per credential says what happened to it (sa_snmp_notice, until a person dismisses it), and one audit row
//     inventory.snmp_move per credential says it for the record. Nothing of a secret is in either.
//
// It runs in one transaction: all or nothing, and again at the next call when it failed. A device the person later edits has the
// settings of its own; the snmp_source switch of no device is changed (a copy outside the LAN ranges is read only where it was before:
// nothing starts reading outside the LAN by itself).

// legacyCred is an SNMP credential of the old kind (a scope of addresses, shared by devices).
type legacyCred struct {
	id, name, version, user, auth, priv, secretID, last4, privID, privLast4 string
	port                                                                    int
	scope                                                                   []netip.Prefix
	scopeText                                                               string
	lastAnswer                                                              string
}

func (c legacyCred) covers(ip netip.Addr) bool {
	return slices.ContainsFunc(c.scope, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// legacyAnswer is a row of sa_snmp_answer.
type legacyAnswer struct {
	cred, asset, at, descr, oid string
}

// moveCredentials moves the old SNMP credentials to devices, once (see above). Without secrets there is nothing to open: the
// credentials wait.
func (s *Service) moveCredentials(ctx context.Context) error {
	if s.secrets == nil || s.snmpMoved.Load() {
		return nil
	}
	s.snmpMoveMu.Lock()
	defer s.snmpMoveMu.Unlock()
	if s.snmpMoved.Load() {
		return nil
	}
	creds, err := s.legacyCreds(ctx)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		s.snmpMoved.Store(true)
		return nil
	}
	answers, err := s.legacyAnswers(ctx)
	if err != nil {
		return err
	}
	read, on, err := s.inv.SNMPKnown(ctx)
	if err != nil {
		return err
	}
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return err
	}
	ipOf := make(map[string]netip.Addr, len(addrs))
	for ip, id := range addrs {
		ipOf[id] = ip
	}
	candidates := map[string]bool{}
	for _, id := range append(slices.Clone(read), on...) {
		candidates[id] = true
	}
	for _, a := range answers {
		candidates[a.asset] = true
	}
	var ids []string
	for id := range candidates {
		if ip, ok := ipOf[id]; ok && !slices.Contains(box, ip) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	plan := map[string][]string{} // credential id -> devices it is copied to
	for _, id := range ids {
		if c := chooseCred(creds, answers, id, ipOf[id]); c != "" {
			plan[c] = append(plan[c], id)
		}
	}
	names := map[string]string{}
	for _, list := range plan {
		for _, id := range list {
			names[id] = ipOf[id].String()
			if a, err := s.inv.Asset(ctx, id); err == nil {
				names[id] = deviceName(a)
			}
		}
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		now := s.now()
		for _, c := range creds {
			devs := plan[c.id]
			text, detail, err := s.moveCred(ctx, tx, c, devs, ipOf, names, answers)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_notice (at, text) VALUES (?, ?)`, now, clip(text, 2000)); err != nil {
				return fmt.Errorf("sensoractive: snmp notice: %w", err)
			}
			if err := s.auditTx(ctx, tx, "system", "inventory.snmp_move", c.name, clip(detail, 1000)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_answer WHERE credential_id = ?`, c.id); err != nil {
				return fmt.Errorf("sensoractive: delete snmp answers: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp WHERE id = ?`, c.id); err != nil {
				return fmt.Errorf("sensoractive: delete snmp credential: %w", err)
			}
			for _, sid := range []string{c.secretID, c.privID} {
				if sid == "" {
					continue
				}
				if err := s.secrets.Delete(ctx, tx, sid); err != nil && !errors.Is(err, secrets.ErrNotFound) { // a row already gone is gone
					return fmt.Errorf("sensoractive: delete snmp secret: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sensoractive: move the snmp credentials to their devices: %w", err)
	}
	s.log.InfoContext(ctx, "sensoractive: snmp credentials moved to their devices", "credentials", len(creds), "devices", len(ids))
	s.snmpMoved.Store(true)
	return nil
}

// chooseCred is the credential device id at ip gets a copy of: among those whose scope holds ip, the one it answered last, else the
// one that answered last, else the first; "" when none holds it.
func chooseCred(creds []legacyCred, answers []legacyAnswer, id string, ip netip.Addr) string {
	var covering []legacyCred
	for _, c := range creds {
		if c.covers(ip) {
			covering = append(covering, c)
		}
	}
	if len(covering) == 0 {
		return ""
	}
	best, bestAt := "", ""
	for _, a := range answers {
		if a.asset == id && a.at > bestAt && slices.ContainsFunc(covering, func(c legacyCred) bool { return c.id == a.cred }) {
			best, bestAt = a.cred, a.at
		}
	}
	if best != "" {
		return best
	}
	for _, c := range covering {
		if c.lastAnswer > bestAt {
			best, bestAt = c.id, c.lastAnswer
		}
	}
	if best != "" {
		return best
	}
	return covering[0].id
}

// moveCred copies credential c to devices devs inside tx and returns the notice and the audit detail.
func (s *Service) moveCred(ctx context.Context, tx *sql.Tx, c legacyCred, devs []string, ipOf map[string]netip.Addr, names map[string]string,
	answers []legacyAnswer) (text, detail string, err error) {
	label := fmt.Sprintf("%q (%s, scope %s)", c.name, c.version, c.scopeText)
	if len(devs) == 0 {
		return "SNMP credential " + label + " was removed: it covered no device that had answered SNMP or had SNMP turned on. Its saved community or passwords are deleted: type them again when you set SNMP up on a device's page (Devices › the device › SNMP).",
			"removed: it covered no device that had answered SNMP or had SNMP turned on", nil
	}
	var named []string
	for _, id := range devs {
		named = append(named, fmt.Sprintf("%s (%s)", names[id], ipOf[id]))
	}
	secret, err := s.secrets.Open(ctx, tx, c.secretID, snmpSecretPurpose)
	defer clear(secret)
	var priv []byte
	if err == nil && c.privID != "" {
		priv, err = s.secrets.Open(ctx, tx, c.privID, snmpPrivPurpose)
		defer clear(priv)
	}
	// Any failure to open it (sealed under another key, a missing or damaged row) gives no copy: the move never stops on one
	// credential, and the notice names the devices to set up by hand.
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: an old snmp credential's secret could not be opened; not copied", "credential", c.id, "error", err)
		return "SNMP credential " + label + " was removed, but its saved community or password could not be opened on this box (it is missing, or the backup was restored without its decryption key), so " +
				strings.Join(named, ", ") + " were not set up. Set SNMP up on their pages.",
			"removed; its secret could not be opened, not copied to: " + strings.Join(named, ", "), nil
	}
	now := s.now()
	var copied []string
	for _, id := range devs {
		// A device that has settings of its own already, or whose address another device reads from, keeps what it has.
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sa_snmp_device WHERE asset_id = ? OR read_from = ?`, id, ipOf[id].String()).Scan(&n); err != nil {
			return "", "", fmt.Errorf("sensoractive: read snmp settings: %w", err)
		}
		if n > 0 {
			continue
		}
		sid, last4, err := s.secrets.Seal(ctx, tx, snmpSecretPurpose, secret, true)
		if err != nil {
			return "", "", fmt.Errorf("sensoractive: seal snmp secret: %w", err)
		}
		var pid any
		pl4 := ""
		if c.privID != "" {
			p, l4, err := s.secrets.Seal(ctx, tx, snmpPrivPurpose, priv, true)
			if err != nil {
				return "", "", fmt.Errorf("sensoractive: seal snmp privacy password: %w", err)
			}
			pid, pl4 = p, l4
		}
		// The answer this credential got from the device stays its state: it worked, and what it said is shown.
		var answeredAt, status, answer any
		for _, a := range answers {
			if a.cred == c.id && a.asset == id {
				b, _ := json.Marshal(sensorlink.SNMPValues{SysDescr: a.descr, SysObjectID: a.oid})
				answeredAt, status, answer = a.at, sensorlink.SNMPStatusOK, string(b)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_device (asset_id, read_from, read_from_default, version, username, auth, priv, secret_id, secret_last4,
			priv_secret_id, priv_last4, port, created_at, updated_at, last_checked_at, last_status, last_answer_at, answer)
			VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ipOf[id].String(), c.version, nullable(c.user), nullable(c.auth), nullable(c.priv), sid, last4, pid, pl4, portColumn(c.port), now, now,
			answeredAt, status, answeredAt, answer); err != nil {
			return "", "", fmt.Errorf("sensoractive: copy snmp credential: %w", err)
		}
		copied = append(copied, fmt.Sprintf("%s (%s)", names[id], ipOf[id]))
	}
	if len(copied) == 0 {
		return "SNMP credential " + label + " was removed: the devices it covered have SNMP settings of their own. Its saved community or passwords are deleted.",
			"removed: its devices have settings of their own", nil
	}
	return "SNMP credential " + label + " was copied to " + strings.Join(copied, ", ") + " and removed: SNMP is now set up on each device's page, read at the device's address.",
		"copied to: " + strings.Join(copied, ", "), nil
}

// legacyCreds reads the old SNMP credentials, in the order the round tried them.
func (s *Service) legacyCreds(ctx context.Context) ([]legacyCred, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, name, version, coalesce(username, ''), coalesce(auth, ''), coalesce(priv, ''), secret_id, secret_last4,
		coalesce(priv_secret_id, ''), priv_last4, coalesce(port, 161), scope, coalesce(last_answer_at, '') FROM sa_snmp ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyCred
	for rows.Next() {
		var c legacyCred
		var scope string
		if err := rows.Scan(&c.id, &c.name, &c.version, &c.user, &c.auth, &c.priv, &c.secretID, &c.last4, &c.privID, &c.privLast4, &c.port, &scope, &c.lastAnswer); err != nil {
			return nil, fmt.Errorf("sensoractive: read snmp credentials: %w", err)
		}
		var list []string
		if err := json.Unmarshal([]byte(scope), &list); err != nil { // a scope that cannot be read covers nothing: the credential is removed
			list = nil
		}
		c.scope, c.scopeText = exclusionPrefixes(list), strings.Join(list, " ") // an address or a range, as the scope is stored
		if len(list) == 0 {
			c.scopeText = "none readable"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// legacyAnswers reads sa_snmp_answer (the answers kept per credential and device since #829 C4).
func (s *Service) legacyAnswers(ctx context.Context) ([]legacyAnswer, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT credential_id, asset_id, answered_at, coalesce(sys_descr, ''), coalesce(sys_object_id, '') FROM sa_snmp_answer`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp answers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []legacyAnswer
	for rows.Next() {
		var a legacyAnswer
		if err := rows.Scan(&a.cred, &a.asset, &a.at, &a.descr, &a.oid); err != nil {
			return nil, fmt.Errorf("sensoractive: read snmp answers: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
