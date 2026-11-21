package sensoractive

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/localnet"
)

// "Use these settings on similar devices" (INV-24): the settings of a device whose SNMP is set up are copied, secret included and
// on the box, to devices a person ticks in a checklist. It is the existing copy_from (SetSNMP) once per target, so every rule of a
// normal save holds: each target is read only at its own address, the read address is never changed by it, the secret is sealed again
// for the target, one audit row per target. The person's choice of targets is the consent for sending the secret there.

// codeHasOwnSettings is the per-device result of an apply that found settings the device saved itself.
const codeHasOwnSettings = "has_own_settings"

// MaxApplySimilar is the most devices one apply names.
const MaxApplySimilar = 50

// applyReadsFor bounds the background reads one apply queues.
const applyReadsFor = 15 * time.Minute

// SimilarDevice is a device that shares the maker or the type of another (Inventory.SimilarDevices).
type SimilarDevice struct {
	ID, IP, Vendor, Kind string
	SameMaker, SameType  bool
	Approved             bool
}

// SimilarFinder is an optional part of Inventory: the devices that share the maker or the type of a device.
type SimilarFinder interface {
	SimilarDevices(ctx context.Context, assetID string) ([]SimilarDevice, error)
}

// SNMPCandidate is one row of the checklist (SnmpSimilarDevice in contract.ts).
type SNMPCandidate struct {
	DeviceID, Name, Vendor, Kind string
	IP                           netip.Addr
	SameMaker, SameType          bool
	Approved                     bool
}

// SNMPApplyResult is the outcome for one requested device (SnmpApplyResult in contract.ts).
type SNMPApplyResult struct {
	DeviceID, Name string
	OK             bool
	Code, Message  string
}

// similarSource checks that device id has working-to-share settings: SNMP set up and its secrets readable.
func (s *Service) similarSource(ctx context.Context, id string) error {
	if s.secrets == nil {
		return snmpOff()
	}
	if _, err := s.inv.Asset(ctx, id); errors.Is(err, ErrNotFound) {
		return apierr.New(404, "not_found", "There is no device with this id.")
	} else if err != nil {
		return err
	}
	row, err := s.snmpRow(ctx, s.db.Reader(), id)
	if err != nil {
		return err
	}
	if row == nil {
		return apierr.New(409, SNMPNotSetUp, "SNMP is not set up for this device: there are no settings to use on other devices.")
	}
	if lost, _ := s.snmpLost(ctx, s.db.Reader(), *row); lost {
		return snmpSecretLost()
	}
	return nil
}

// SNMPSimilar lists the checklist of "Use these settings on similar devices": devices of the same maker or type as id that have no
// SNMP settings of their own (the inventory leaves out the box, ignored devices and devices without an address).
func (s *Service) SNMPSimilar(ctx context.Context, id string) ([]SNMPCandidate, error) {
	if err := s.similarSource(ctx, id); err != nil {
		return nil, err
	}
	f, ok := s.inv.(SimilarFinder)
	if !ok {
		return nil, snmpOff()
	}
	list, err := f.SimilarDevices(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, apierr.New(404, "not_found", "There is no device with this id.")
	}
	if err != nil {
		return nil, err
	}
	have, err := s.snmpDeviceIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []SNMPCandidate
	for _, d := range list {
		if have[d.ID] || d.ID == id {
			continue
		}
		ip, _ := netip.ParseAddr(d.IP)
		c := SNMPCandidate{DeviceID: d.ID, IP: ip, Vendor: d.Vendor, Kind: d.Kind, SameMaker: d.SameMaker, SameType: d.SameType, Approved: d.Approved}
		if a, err := s.inv.Asset(ctx, d.ID); err == nil {
			c.Name = a.Name
		}
		out = append(out, c)
	}
	slices.SortStableFunc(out, func(a, b SNMPCandidate) int {
		if a.SameMaker != b.SameMaker {
			if a.SameMaker {
				return -1
			}
			return 1
		}
		return cmp.Compare(strings.ToLower(cmp.Or(a.Name, a.DeviceID)), strings.ToLower(cmp.Or(b.Name, b.DeviceID)))
	})
	return out, nil
}

// snmpDeviceIDs is the set of devices that have SNMP settings.
func (s *Service) snmpDeviceIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT asset_id FROM sa_snmp_device`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read snmp settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("sensoractive: read snmp settings: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ApplySNMPToSimilar copies the SNMP settings of device id to the named devices, which must still be candidates (SNMPSimilar), and
// queues a read of each device it saved: the reads run in the background, one device at a time, as Check now would; the outcome is
// each device's SNMP state. One result per requested device, in order; a device that is refused (not a candidate, no address, the
// read address taken, a secret this box cannot open…) says why and nothing is saved on it. Audit: the per-device rows of a normal
// save ("copied from …") and one row for the action.
func (s *Service) ApplySNMPToSimilar(ctx context.Context, actor, id string, targets []string) ([]SNMPApplyResult, error) {
	if len(targets) == 0 || len(targets) > MaxApplySimilar {
		return nil, bad("bad_devices", fmt.Sprintf("Choose between 1 and %d devices.", MaxApplySimilar))
	}
	cands, err := s.SNMPSimilar(ctx, id)
	if err != nil {
		return nil, err
	}
	byID := map[string]SNMPCandidate{}
	for _, c := range cands {
		byID[c.DeviceID] = c
	}
	var out []SNMPApplyResult
	var saved []string
	seen := map[string]bool{}
	for _, t := range targets {
		if seen[t] {
			continue
		}
		seen[t] = true
		c, ok := byID[t]
		if !ok {
			out = append(out, SNMPApplyResult{DeviceID: t, Code: "not_a_candidate", Message: "This device is not a candidate any more: it has its own SNMP settings, is ignored, or is no longer of the same maker or type."})
			continue
		}
		r := SNMPApplyResult{DeviceID: t, Name: c.Name}
		// the same rule as reading: SNMP stays on local networks (a copied secret is never stored for an address nothing is sent to)
		if !c.IP.IsValid() || !localnet.Addr(c.IP) {
			r.Code, r.Message = "read_from_not_local", fmt.Sprintf("%s is not a local network address (%s): SNMP reads stay on your own networks.", c.IP, localnet.Names)
			out = append(out, r)
			continue
		}
		if _, err := s.SetSNMP(ctx, actor, t, SNMPInput{CopyFrom: id, onlyIfNone: true}); err != nil {
			var ae *apierr.Error
			if !errors.As(err, &ae) {
				return out, err // a failure of the box itself stops the action; what was saved stays saved and audited
			}
			r.Code, r.Message = ae.Code, ae.Message
		} else {
			r.OK = true
			saved = append(saved, t)
		}
		out = append(out, r)
	}
	name := id
	if a, err := s.inv.Asset(ctx, id); err == nil && a.Name != "" {
		name = a.Name
	}
	wctx := context.WithoutCancel(ctx)
	if err := s.db.Write(wctx, func(tx *sql.Tx) error {
		return s.auditTx(wctx, tx, actor, "inventory.snmp_apply_similar", name, fmt.Sprintf("%d of %d devices", len(saved), len(out)))
	}); err != nil {
		return out, err
	}
	s.queueReads(wctx, actor, saved)
	return out, nil
}

// queueReads reads the saved devices one after the other in the background (Check now's rules: logged in the probe log, every rule
// but the window). The caller has gone by then, so the context is detached and bounded.
func (s *Service) queueReads(ctx context.Context, actor string, ids []string) {
	if len(ids) == 0 {
		return
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(ctx, applyReadsFor)
		defer cancel()
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			if _, err := s.CheckSNMP(ctx, actor, id); err != nil {
				s.log.WarnContext(ctx, "sensoractive: the read queued after applying SNMP settings did not run", "asset", id, "error", err)
			}
		}
	}()
}
