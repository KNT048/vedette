package sensoractive

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/sensorlink"
)

// What a person reads of a device's SNMP: its settings without the secrets, the state of its last read, what answered at
// its read address, and why nothing is sent to it now.

// SNMPDeviceOf is the SNMP of device id (GET /inventory/snmp/devices/{id}); a device without SNMP is State not_set_up. 404 when the
// inventory has no such device.
func (s *Service) SNMPDeviceOf(ctx context.Context, id string) (SNMPDevice, error) {
	if s.secrets == nil {
		return SNMPDevice{}, snmpOff()
	}
	a, err := s.inv.Asset(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return SNMPDevice{}, apierr.New(404, "not_found", "There is no device with this id.")
	}
	if err != nil {
		return SNMPDevice{}, err
	}
	row, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return SNMPDevice{}, err
	}
	if row == nil {
		return SNMPDevice{DeviceID: id, Name: a.Name, IP: a.IP, State: SNMPNotSetUp}, nil
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return SNMPDevice{}, err
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return SNMPDevice{}, err
	}
	return s.snmpView(ctx, a, *row, box, newScope(st)), nil
}

// SNMPDevices lists every device with SNMP set up, by name (GET /inventory/snmp: the Copy from list and the Scanning card). A device
// the inventory no longer has is left out (its settings go with inventory.asset.deleted).
func (s *Service) SNMPDevices(ctx context.Context) ([]SNMPDevice, error) {
	if s.secrets == nil {
		return nil, snmpOff()
	}
	rows, err := s.snmpRows(ctx, s.db.Reader())
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	box, err := s.inv.BoxIPs(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return nil, err
	}
	sc := newScope(st)
	out := make([]SNMPDevice, 0, len(rows))
	for _, r := range rows {
		a, err := s.inv.Asset(ctx, r.AssetID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s.snmpView(ctx, a, r, box, sc))
	}
	slices.SortFunc(out, func(x, y SNMPDevice) int {
		return cmp.Or(strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)), x.ReadFrom.Compare(y.ReadFrom), strings.Compare(x.DeviceID, y.DeviceID))
	})
	return out, nil
}

// ReadAddresses returns, by device id, the address a person typed as the device's SNMP read address. A read address left to the
// device's own IP is not here (it is only the IP the device had when saved, and says nothing once the device moves). Nothing else of
// the settings is read: no secret is opened and no policy is checked, so a caller that only matches addresses to devices (logs) costs
// the device nothing. A device the inventory no longer has may still be listed until inventory.asset.deleted is handled; the caller
// matches against its own device list.
func (s *Service) ReadAddresses(ctx context.Context) (map[string]netip.Addr, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT asset_id, read_from FROM sa_snmp_device WHERE read_from_default = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]netip.Addr{}
	for rows.Next() {
		var id, from string
		if err := rows.Scan(&id, &from); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(from); err == nil {
			out[id] = a
		}
	}
	return out, rows.Err()
}

// snmpView is what a person reads of row r of device a. Blocked says why nothing is sent now: a lost secret first, then the rules of
// snmpAllowed; a failure to decide is logged and says nothing (this only adds words, never stops a page).
func (s *Service) snmpView(ctx context.Context, a Asset, r snmpRow, box []netip.Addr, sc scope) SNMPDevice {
	d := SNMPDevice{DeviceID: r.AssetID, Name: a.Name, IP: a.IP, ReadFrom: r.ReadFrom, ReadFromDefault: r.ReadFromDefault, Version: r.Version,
		Username: r.Username, Auth: r.Auth, Priv: r.Priv, Port: r.Port, SecretLast4: r.SecretLast4, PrivLast4: r.PrivLast4,
		LastCheckedAt: r.LastCheckedAt, LastAnswerAt: r.LastAnswerAt, UpdatedAt: r.UpdatedAt, LastReason: r.LastStatus}
	switch r.LastStatus {
	case "":
		d.State = SNMPWaiting
	case sensorlink.SNMPStatusOK:
		d.State = SNMPWorking
	default:
		d.State = SNMPNotAnswering
		d.Error = snmpMessage(r.LastStatus, a.Name, a.IP, r, "")
	}
	if r.answer != "" {
		var v sensorlink.SNMPValues
		if err := json.Unmarshal([]byte(r.answer), &v); err == nil {
			f := identifySNMP(v)
			d.Answer = &f
		}
	}
	if s.secrets != nil {
		lost, err := s.snmpLost(ctx, s.db.Reader(), r)
		if err != nil {
			s.log.WarnContext(ctx, "sensoractive: checking a device's snmp secret failed", "device", r.AssetID, "error", err)
		}
		d.SecretLost = lost
	}
	why := ""
	if d.SecretLost {
		why = SNMPSecretLost
	} else {
		var err error
		if why, err = s.snmpAllowed(ctx, r, box, sc); err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.log.WarnContext(ctx, "sensoractive: reading a device's snmp policy failed", "device", r.AssetID, "error", err)
			}
			why = ""
		}
	}
	if why != "" {
		reason := why
		if !slices.Contains(snmpRefusals, why) && why != SNMPSecretLost {
			reason = SNMPUnavailable
		}
		msg := snmpMessage(reason, a.Name, a.IP, r, "the inventory's scan policy refuses this device ("+why+")")
		d.Blocked = &SNMPBlocked{Reason: reason, Message: msg}
	}
	return d
}

// SNMPNotices lists what the box changed by itself, oldest first (GET /inventory/snmp notices).
func (s *Service) SNMPNotices(ctx context.Context) ([]SNMPNotice, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, at, text FROM sa_snmp_notice ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp notices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SNMPNotice
	for rows.Next() {
		var n SNMPNotice
		var at string
		if err := rows.Scan(&n.ID, &at, &n.Text); err != nil {
			return nil, fmt.Errorf("sensoractive: read snmp notices: %w", err)
		}
		n.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, n)
	}
	return out, rows.Err()
}

// DismissSNMPNotices removes every notice (POST /inventory/snmp/notices/dismiss).
func (s *Service) DismissSNMPNotices(ctx context.Context) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sa_snmp_notice`)
		return err
	})
}
