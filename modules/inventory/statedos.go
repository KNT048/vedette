package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// The operating system a network device states about itself (a switch's or firewall's SNMP system description, a Junos LLDP
// description on Juniper's own card) is a software line of the device like any other (core/productid StatedOS): it has an id, a
// history, findings and a fix, and no reader needs a made-up software row for it. Its reading has the instance "os" and the source
// of the statement (snmp, or passive for LLDP). Vedette's own SNMP read of the device's address always counts; an LLDP statement
// only when no SNMP answer reads one and the device's MAC is that OS vendor's card (lldpStated). When the device's own agent reports
// another OS, the agent's reading wins and the statement is no line. While a person's OS stands (INV-41), it replaces the statement:
// the line is the person's product and version (a reading of source manual, instance "os": the line's entry), or no line when the
// person's OS is not a network OS.

// syncStatedOS makes the "os" readings of a device follow its observations, in the transaction that recorded them. changed says a
// line moved.
func (s *Service) syncStatedOS(ctx context.Context, tx *sql.Tx, assetID, now string) (bool, error) {
	var mac sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT CASE WHEN ip IS NOT NULL THEN mac END FROM inv_asset WHERE id = ?`, assetID).Scan(&mac); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	snmp, snmpAt, err := osFromAt(ctx, tx, assetID, "snmp")
	if err != nil {
		return false, err
	}
	lldp, lldpAt, err := osFromAt(ctx, tx, assetID, "passive")
	if err != nil {
		return false, err
	}
	agent, err := osFrom(ctx, tx, assetID, "agent")
	if err != nil {
		return false, err
	}
	person, setAt, setBy, corrected, err := manualOS(ctx, tx, assetID)
	if err != nil {
		return false, err
	}
	var want *listed
	switch {
	case corrected: // a person's OS (INV-41) is what the device runs in place of every statement it corrects
		if p, v, _, ok := productid.StatedOS(person); ok {
			want = statedReading(p, v, sourceManual, setAt)
			want.reading.SetBy, want.reading.Confidence = setBy, 1
		}
	default:
		if p, v, _, ok := productid.StatedOS(snmp); ok {
			want = statedReading(p, v, "snmp", snmpAt)
		} else if p, v, vendor, ok := productid.StatedOS(lldp); ok && vendor != "" && lldpStated(lldp, mac.String) {
			want = statedReading(p, v, "passive", lldpAt)
		}
	}
	if want != nil && agent != "" && !corrected {
		if p, _, _, ok := productid.StatedOS(agent); !ok || p.Key != want.id.productKey && !strings.EqualFold(p.Product, want.id.product) {
			want = nil // the device's own agent reads another OS
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.software_id, r.source, ifnull(r.version, '') FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
		WHERE w.asset_id = ? AND r.instance = ? AND r.source IN ('snmp', 'passive', 'manual')`, assetID, instanceOS)
	if err != nil {
		return false, fmt.Errorf("inventory: read the stated OS: %w", err)
	}
	type held struct{ line, source, version string }
	var have []held
	for rows.Next() {
		var h held
		if err := rows.Scan(&h.line, &h.source, &h.version); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("inventory: read the stated OS: %w", err)
		}
		have = append(have, h)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return false, fmt.Errorf("inventory: read the stated OS: %w", err)
	}
	touched := map[string]bool{}
	wantLine := ""
	if want != nil {
		id, err := s.lineOf(ctx, tx, assetID, want.id, want.reading)
		if err != nil {
			return false, err
		}
		wantLine = id
		same := false
		for _, h := range have {
			same = same || h.line == id && h.source == want.reading.Source && h.version == want.reading.Version
		}
		if err := putReading(ctx, tx, id, want.reading, want.ev); err != nil { // the same statement again only moves its time
			return false, err
		}
		if !same {
			touched[id] = true
		}
	}
	for _, h := range have {
		if h.line == wantLine && want != nil && h.source == want.reading.Source {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE software_id = ? AND source = ? AND instance = ?`, h.line, h.source, instanceOS); err != nil {
			return false, fmt.Errorf("inventory: remove the stated OS: %w", err)
		}
		touched[h.line] = true
	}
	changed := false
	for id := range touched {
		var names map[[2]string][2]string
		if id == wantLine {
			names = map[[2]string][2]string{{want.reading.Source, instanceOS}: {want.id.vendor, want.id.product}}
		}
		st, err := s.settleLine(ctx, tx, id, now, names)
		if err != nil {
			return false, err
		}
		changed = changed || st.changed
	}
	return changed || len(touched) > 0, nil
}

// statedReading is the reading of a stated OS: the catalogue's product, the version the statement gives, its NVD name.
func statedReading(p productid.Product, version, source, seenAt string) *listed {
	cpe := ""
	for _, c := range p.CPEs {
		if c.Part == "o" && !c.Prefix {
			cpe = "cpe:2.3:" + c.Base() + ":*:*:*:*:*:*:*:*"
			break
		}
	}
	it := SoftwareItem{Display: p.Display, Vendor: p.Vendor, Product: p.Product, Version: version, CPE: cpe, KevKeys: p.KEV, Confidence: 0.9}
	id, v := identify(it, source)
	if p.Key != "" {
		id.productKey, id.line = p.Key, p.Line(v)
	}
	return &listed{id: id, reading: Reading{Source: source, Instance: instanceOS, Display: p.Display, Version: v, CPE: cpe, Confidence: 0.9, FirstSeen: seenAt, SeenAt: seenAt}}
}
