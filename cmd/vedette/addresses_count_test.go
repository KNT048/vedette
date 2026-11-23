package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/modules/inventory"
)

// An interface of a firewall as a sensor sees it: its own address and burned-in MAC, read by passive capture and by a network scan.
type iface struct{ ip, mac string }

// firewallIfaces are three interfaces of one firewall, numbered by its maker from one MAC block.
var firewallIfaces = []iface{
	{"198.51.100.1", "00:09:0f:09:00:01"},
	{"198.51.100.65", "00:09:0f:09:00:02"},
	{"198.51.100.129", "00:09:0f:09:00:03"},
}

// scanIface is what a network scan reads on one interface: the web admin page on tcp/443 everywhere, SSH on tcp/22 on the second
// interface only, and the open ports.
func (s *stack) scanIface(t *testing.T, i int, f iface) {
	t.Helper()
	hint := observe.AssetHint{IP: mustAddr(t, f.ip)}
	sw := []observe.Software{{Display: "FortiOS web admin", Vendor: "Fortinet", Product: "FortiOS", Version: "7.0.12", Confidence: 0.8, Instance: "tcp/443"}}
	svc := []observe.Service{{Port: 443, Proto: "tcp", Name: "https", Product: "FortiOS", Version: "7.0.12", Confidence: 0.8}}
	if i == 1 {
		sw = append(sw, observe.Software{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.4", Confidence: 0.8, Instance: "tcp/22"})
		svc = append(svc, observe.Service{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "8.4", Confidence: 0.8})
	}
	if err := s.d.Inventory.ReplaceSoftware(t.Context(), hint, observe.Nmap, nil, sw); err != nil {
		t.Fatal(err)
	}
	if err := s.d.Inventory.ReplaceServices(t.Context(), hint, observe.Nmap, observe.ServiceScope{}, svc); err != nil {
		t.Fatal(err)
	}
}

// sight is a passive sensor seeing an interface: its address and MAC on the wire.
func (s *stack) sight(t *testing.T, f iface) {
	t.Helper()
	hint := observe.AssetHint{IP: mustAddr(t, f.ip), MAC: f.mac}
	if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: hint, Field: observe.MAC, Value: f.mac, Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
}

// firewallRows makes one device row per interface of the firewall, as a network sees it before anyone merges them: each row with its
// scan readings, open ports, a finding on its FortiOS line and, on the second row, a finding on its SSH line. A person decided the
// FortiOS finding of the second row and the SSH finding; every finding has its history. It returns the row ids in interface order.
func (s *stack) firewallRows(t *testing.T, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i, f := range firewallIfaces[:n] {
		ids[i] = s.seen(t, f.ip, f.mac, "firewall")
		s.scanIface(t, i, f)
	}
	finding := func(id, asset, cve, product string, person bool) {
		var line string
		if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM inv_software WHERE asset_id = ? AND product = ?`, asset, product).Scan(&line); err != nil {
			t.Fatalf("line %s of %s: %v", product, asset, err)
		}
		via, who, note := "data_corrected", "system", "Closed by Vedette: the version read is not affected."
		if person {
			via, who, note = "person", "person@example.com", "checked on the box: the admin page is not exposed"
		}
		s.exec(`INSERT INTO fnd_finding (id, asset_id, cve, software_id, detected, basis, verified, range_origin, fix_kind, fix_key, state, resolution,
			via, resolved_by, resolved_at, note, urgency, urgency_at, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, 0, 'device_version', 'no', 'nvd', 'unknown', 'unknown|unknown|', 'handled', 'false_positive', ?, ?, '2026-11-20T10:00:00.000Z', ?, 2,
			'2026-11-20T09:00:00.000Z', '2026-11-20T09:00:00.000Z', '2026-11-20T10:00:00.000Z', '2026-11-20T10:00:00.000Z')`, id, asset, cve, line, via, who, note)
		for _, e := range []struct{ ts, actor, kind, note string }{{"2026-11-20T09:00:00.000Z", "system", "opened", "matched"}, {"2026-11-20T10:00:00.000Z", who, "handled", note}} {
			detail, _ := json.Marshal(map[string]any{"note": e.note})
			s.exec(`INSERT INTO fnd_finding_event (finding_id, ts, actor, kind, detail) VALUES (?, ?, ?, ?, ?)`, id, e.ts, e.actor, e.kind, string(detail))
		}
	}
	for i, id := range ids {
		finding(fmt.Sprintf("f-fw-%d", i), id, "CVE-2024-21762", "FortiOS", i == 1)
		if i == 1 {
			finding("f-fw-ssh", id, "CVE-2024-6387", "OpenSSH", true)
		}
	}
	return ids
}

// hasTable says whether the schema has table (the address table exists only once a device can hold several addresses).
func (s *stack) hasTable(name string) bool {
	return s.count(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name) > 0
}

// addressFacts lists every IP and MAC devices ids answer on: their main address and, where the schema has them, their other addresses.
func (s *stack) addressFacts(ids []string) map[string]bool {
	s.t.Helper()
	out := map[string]bool{}
	q := `SELECT coalesce(ip, '') || '|' || coalesce(mac, '') FROM inv_asset WHERE id = ?1`
	if s.hasTable("inv_asset_address") {
		q += ` UNION ALL SELECT coalesce(ip, '') || '|' || coalesce(mac, '') FROM inv_asset_address WHERE asset_id = ?1`
	}
	for _, id := range ids {
		rows, err := s.d.DB.Reader().QueryContext(s.t.Context(), q, id)
		if err != nil {
			s.t.Fatal(err)
		}
		for rows.Next() {
			var pair string
			if err := rows.Scan(&pair); err != nil {
				s.t.Fatal(err)
			}
			ip, mac, _ := strings.Cut(pair, "|")
			for _, v := range []string{ip, mac} {
				if v != "" {
					out[v] = true
				}
			}
		}
		if err := rows.Close(); err != nil {
			s.t.Fatal(err)
		}
	}
	return out
}

// strings1 reads one text column of a query over the devices ids (as ?1 each), as a multiset.
func (s *stack) strings1(q string, ids []string) []string {
	s.t.Helper()
	var out []string
	for _, id := range ids {
		rows, err := s.d.DB.Reader().QueryContext(s.t.Context(), q, id)
		if err != nil {
			s.t.Fatalf("%s: %v", q, err)
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				s.t.Fatal(err)
			}
			out = append(out, v)
		}
		if err := rows.Close(); err != nil {
			s.t.Fatal(err)
		}
	}
	slices.Sort(out)
	return out
}

// deviceFacts is what the count test compares before and after: per kind, the facts of the devices ids as a multiset.
func (s *stack) deviceFacts(ids []string) map[string][]string {
	s.t.Helper()
	out := map[string][]string{
		"readings": s.strings1(`SELECT w.product || '|' || r.source || '|' || r.instance || '|' || ifnull(r.version, '') FROM inv_software_reading r
			JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id = ?1`, ids),
		"open ports": s.strings1(`SELECT port || '/' || proto || '|' || source FROM inv_service WHERE asset_id = ?1`, ids),
		"findings":   s.strings1(`SELECT DISTINCT cve FROM fnd_finding WHERE asset_id = ?1`, ids),
		"decisions and history": s.strings1(`SELECT e.ts || '|' || e.actor || '|' || e.kind || '|' || ifnull(json_extract(e.detail, '$.note'), '')
			FROM fnd_finding_event e JOIN fnd_finding f ON f.id = e.finding_id WHERE f.asset_id = ?1 AND e.actor <> 'system'`, ids),
	}
	for a := range s.addressFacts(ids) {
		out["addresses"] = append(out["addresses"], a)
	}
	slices.Sort(out["addresses"])
	return out
}

// missing counts the facts of want (a multiset) not found in got; for findings and decisions a fact is kept once it is there at all
// (a merge folds one CVE of one line into one finding, with the history of every copy).
func missing(kind string, want, got []string) int {
	n := 0
	have := map[string]int{}
	for _, g := range got {
		have[g]++
	}
	for _, w := range want {
		switch {
		case have[w] > 0 && (kind == "readings" || kind == "open ports" || kind == "addresses"):
			have[w]--
		case have[w] > 0:
		default:
			n++
		}
	}
	return n
}

// lostFacts counts, per kind, the facts of before not in after.
func lostFacts(before, after map[string][]string) (map[string]int, int) {
	lost := map[string]int{}
	total := 0
	for k, want := range before {
		lost[k] = missing(k, want, after[k])
		total += lost[k]
	}
	return lost, total
}

// duplicateFindings counts the findings of one device, CVE and software line beyond the first (the merge must fold them).
func (s *stack) duplicateFindings() int {
	return s.count(`SELECT coalesce(sum(n - 1), 0) FROM (SELECT count(*) AS n FROM fnd_finding GROUP BY asset_id, cve, ifnull(software_id, ''))`)
}

func fmtLost(lost map[string]int) string {
	var parts []string
	for k, n := range lost {
		parts = append(parts, fmt.Sprintf("%s %d", k, n))
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

// Count test of one device with many addresses: a firewall seen as one row per interface (2, then 3 interfaces, each scanned on its
// own address), merged by a person into one device. Every reading, open port, finding, decision with its history and address of every
// row must be on the device that stays; scanning each merged interface again must neither make the row again nor drop what another
// interface's scan read.
func TestMergedInterfacesLoseNothingCount(t *testing.T) {
	t.Parallel()
	for _, n := range []int{2, 3} {
		t.Run(fmt.Sprintf("%d interfaces", n), func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			ids := s.firewallRows(t, n)
			before := s.deviceFacts(ids)
			devices := s.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`)
			for _, from := range ids[1:] {
				if err := s.d.Inventory.Merge(t.Context(), "person@example.com", ids[0], from); err != nil {
					t.Fatal(err)
				}
			}
			lost, total := lostFacts(before, s.deviceFacts(ids[:1]))
			dup := s.duplicateFindings()
			t.Logf("merge of %d interface rows: %d facts lost (%s), %d findings duplicated", n, total, fmtLost(lost), dup)
			// the merged interfaces are seen and scanned again, as the next sweep and the next scan do
			for i, f := range firewallIfaces[:n] {
				if i > 0 {
					s.sight(t, f)
				}
				s.scanIface(t, i, f)
			}
			again := s.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`) - (devices - n + 1)
			lostScan, totalScan := lostFacts(before, s.deviceFacts(ids[:1]))
			t.Logf("after scanning every interface again: %d devices made again, %d facts missing on the device (%s)", again, totalScan, fmtLost(lostScan))
			if total != 0 || dup != 0 || again != 0 || totalScan != 0 {
				t.Errorf("merge of %d interfaces: lost %d (%s), duplicated %d; after a rescan %d devices made again and %d facts missing (%s)",
					n, total, fmtLost(lost), dup, again, totalScan, fmtLost(lostScan))
			}
		})
	}
}

// homeless counts the addresses held in two places at once: as the main address of two devices, as a device's main address and an
// address row, or in two rows (an address has one home, INV-57).
func (s *stack) homeless() int {
	return s.count(`SELECT count(*) FROM (SELECT v FROM (SELECT ip AS v FROM inv_asset WHERE ip IS NOT NULL UNION ALL SELECT ip FROM inv_asset_address WHERE ip IS NOT NULL
		UNION ALL SELECT mac FROM inv_asset WHERE mac IS NOT NULL UNION ALL SELECT mac FROM inv_asset_address WHERE mac IS NOT NULL) GROUP BY v HAVING count(*) > 1)`)
}

// Count test of the undo: the three interface rows merged in one step (POST merge with three ids), then the third interface split off
// again (POST split). Nothing of the three rows is lost over the two devices; the new device holds what the scan read at its address,
// the kept device the rest; the pair is never offered as possibly the same device again (their MACs are one maker's block, which
// would offer them); scanning and seeing the split interface again reaches the new device and makes none.
func TestSplitAfterMergeLosesNothingCount(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ids := s.firewallRows(t, 3)
	before := s.deviceFacts(ids)
	devices := s.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`)
	if got, err := s.d.Inventory.PossibleSameAs(t.Context(), ids[0]); err != nil || len(got) != 2 || got[0].Reason != inventory.ReasonMACBlock {
		t.Fatalf("before the merge the other interfaces are offered by their MAC block: %+v %v", got, err)
	}
	if code, v := s.do("POST", "/inventory/devices/"+ids[0]+"/merge", "admin", `{"from":["`+ids[1]+`","`+ids[2]+`"]}`); code != 200 {
		t.Fatalf("merge: %d %v", code, v)
	}
	lostMerge, totalMerge := lostFacts(before, s.deviceFacts(ids[:1]))
	code, v := s.do("POST", "/inventory/devices/"+ids[0]+"/split", "admin", `{"address":"`+firewallIfaces[2].ip+`"}`)
	if code != 200 {
		t.Fatalf("split: %d %v", code, v)
	}
	split := v["id"].(string)
	both := []string{ids[0], split}
	lost, total := lostFacts(before, s.deviceFacts(both))
	dup := s.duplicateFindings()
	own := s.deviceFacts([]string{split})
	t.Logf("merge of 3 interface rows in one step: %d facts lost (%s); split of one again: %d facts lost over both devices (%s), %d findings duplicated; the new device holds %d readings, %d open ports, addresses %v",
		totalMerge, fmtLost(lostMerge), total, fmtLost(lost), dup, len(own["readings"]), len(own["open ports"]), own["addresses"])
	if totalMerge != 0 || total != 0 || dup != 0 || len(own["readings"]) != 1 || len(own["open ports"]) != 1 ||
		!slices.Equal(own["addresses"], []string{firewallIfaces[2].mac, firewallIfaces[2].ip}) {
		t.Errorf("merge lost %d (%s); split lost %d (%s), duplicated %d; new device %v", totalMerge, fmtLost(lostMerge), total, fmtLost(lost), dup, own)
	}
	pairs, err := s.d.Inventory.PossibleSamePairs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	offered := 0
	for _, p := range pairs.Items {
		if (p.A.ID == ids[0] || p.B.ID == ids[0]) && (p.A.ID == split || p.B.ID == split) {
			offered++
		}
	}
	s.sight(t, firewallIfaces[2])
	s.scanIface(t, 2, firewallIfaces[2])
	again := s.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`) - (devices - 1)
	_, totalScan := lostFacts(before, s.deviceFacts(both))
	t.Logf("the split pair offered as the same device %d times; after seeing and scanning the split interface again: %d devices made, %d facts missing, %d addresses in two places",
		offered, again, totalScan, s.homeless())
	if offered != 0 || again != 0 || totalScan != 0 || s.homeless() != 0 {
		t.Errorf("offered %d, %d devices made again, %d facts missing, %d addresses in two places", offered, again, totalScan, s.homeless())
	}
	for _, r := range selfcheck.Run(t.Context(), s.d.DB.Reader(), selfcheck.Registered()) {
		if strings.HasPrefix(r.Name, "inventory.") && r.Failed() {
			t.Errorf("selfcheck %s: %d (%v)", r.Name, r.Count, r.Err)
		}
	}
}
