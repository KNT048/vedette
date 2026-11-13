package main

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// W1-32, D-510: the Juniper EX4200-48T of customer walk 1 is known only from LLDP (no IP, no software row). Its stated OS
// "JUNOS 15.1R7.9" reaches the matcher through the real wiring: the device's discovery runs findings, the EX flaw becomes a
// version finding, and the SRX-only one (same NVD range) does not, because CISA names SRX Series and the model is EX.
func TestWiringLLDPJunosSwitchGetsItsFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	now := time.Now().UTC()
	for _, v := range []struct{ cve, name string }{ // the box's rows (n23), NVD's "junos:*" before 20.4 for both
		{"CVE-2023-36845", "Juniper Junos OS EX Series and SRX Series PHP External Variable Modification Vulnerability"},
		{"CVE-2023-36846", "Juniper Junos OS SRX Series Missing Authentication for Critical Function Vulnerability"},
	} {
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			ts := store.FormatTS(now)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, date_added, ransomware, source_id, updated_at)
				VALUES (?, 'Juniper', 'Junos OS', 'juniper|junos os', ?, '2023-11-13', 0, 'cisa-kev', ?)`, v.cve, v.name, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?)`, v.cve, ts); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl)
				VALUES (?, 'cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*', '', '', '', '20.4')`, v.cve)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	mac := "3c:8a:b0:9c:85:80"
	var batch []observe.Observation
	for f, v := range map[observe.Field]string{observe.MAC: mac, observe.Kind: "switch", observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9", observe.Vendor: "Juniper Networks"} {
		batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.5, SeenAt: now})
	}
	if err := s.d.Inventory.Record(ctx, batch); err != nil {
		t.Fatal(err)
	}
	recs, err := s.d.Findings.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var cves []string
	for _, r := range recs {
		cves = append(cves, r.CVE)
		if r.Basis != "version" {
			t.Errorf("%s: basis %s", r.CVE, r.Basis)
		}
	}
	if !slices.Equal(cves, []string{"CVE-2023-36845"}) {
		t.Fatalf("findings of the LLDP switch: %v", cves)
	}
}
