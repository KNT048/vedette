package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// A device that answered a credential and has since moved to an address outside that credential's scope (#829 C4, J2). Its row
// followed it to the new address (the inventory joins by MAC), but the credential is never sent there on its own: the scope is the
// safety line of D-512, and a device someone else now has at the old address is not the one that was vouched for. So nothing is
// read, and this says so instead of nothing: on the credential (GET /inventory/snmp moved_out), in Read now (a skipped row), on the
// device page and on the Scanning card. Adding the new address to the scope reads it again.

// SNMPMoved is one such device (SnmpMoved in contract.ts).
type SNMPMoved struct {
	DeviceID, Name, IP string
	Message            string // plain words for the person
}

// snmpMovedText is what a person is told about a device that moved out of a credential's scope.
func snmpMovedText(name string, ip netip.Addr) string {
	if name == "" {
		name = "A device that answered this credential"
	}
	return fmt.Sprintf("%s moved to %s, outside the scope of this credential: add the address to the scope to keep reading it. Nothing is sent there until then.", name, ip)
}

// snmpMovedOut lists, by credential id, the devices that answered the credential (sa_snmp_answer) and whose current address its
// scope does not hold. A device another credential answered later is left out: that one reads it now. A device the inventory no
// longer has, or that has no address, is left out. Failures are logged and give an empty list: this only adds words, never stops
// a list or a read.
func (s *Service) snmpMovedOut(ctx context.Context, creds []snmpRow) map[string][]SNMPMoved {
	type answer struct{ cred, asset, at string }
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT credential_id, asset_id, answered_at FROM sa_snmp_answer ORDER BY asset_id, answered_at DESC, credential_id`)
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
		return nil
	}
	var all []answer
	for rows.Next() {
		var a answer
		if err := rows.Scan(&a.cred, &a.asset, &a.at); err != nil {
			_ = rows.Close()
			s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
			return nil
		}
		all = append(all, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		s.log.WarnContext(ctx, "sensoractive: reading snmp answers failed", "error", err)
		return nil
	}
	byID := make(map[string]snmpRow, len(creds))
	for _, c := range creds {
		byID[c.ID] = c
	}
	out := map[string][]SNMPMoved{}
	assets := map[string]*Asset{} // nil: not found or no address
	for i, a := range all {
		if i > 0 && all[i-1].asset == a.asset {
			continue // the newest answer of each device decides (ordered by answered_at, newest first)
		}
		c, ok := byID[a.cred]
		if !ok {
			continue
		}
		dev, seen := assets[a.asset]
		if !seen {
			d, err := s.inv.Asset(ctx, a.asset)
			switch {
			case errors.Is(err, ErrNotFound):
			case err != nil:
				s.log.WarnContext(ctx, "sensoractive: reading a device for snmp failed", "device", a.asset, "error", err)
			case d.IP.IsValid():
				dev = &d
			}
			assets[a.asset] = dev
		}
		if dev == nil || c.covers(dev.IP) {
			continue
		}
		out[c.ID] = append(out[c.ID], SNMPMoved{DeviceID: dev.ID, Name: dev.Name, IP: dev.IP.String(), Message: snmpMovedText(dev.Name, dev.IP)})
	}
	return out
}
