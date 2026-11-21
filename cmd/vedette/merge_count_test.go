package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// mergeFixture is testdata/merge-collisions.json: one server of an anonymised export of a real network.
type mergeFixture struct {
	Software []map[string]any `json:"software"`
	Services []map[string]any `json:"services"`
	Findings []map[string]any `json:"findings"`
	History  []map[string]any `json:"history"`
}

// insertRow writes one fixture row into table with the columns it has, after set changes some of them.
func (s *stack) insertRow(table string, row map[string]any, set map[string]any) {
	s.t.Helper()
	cols := make([]string, 0, len(row)+len(set))
	for k := range row {
		cols = append(cols, k)
	}
	for k := range set {
		if _, ok := row[k]; !ok {
			cols = append(cols, k)
		}
	}
	slices.Sort(cols)
	args := make([]any, len(cols))
	for i, c := range cols {
		args[i] = row[c]
		if v, ok := set[c]; ok {
			args[i] = v
		}
	}
	s.exec(`INSERT INTO `+table+` (`+strings.Join(cols, ", ")+`) VALUES (`+strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ")+`)`, args...)
}

// twoRowsOfOneMachine loads the fixture server twice, as two device rows of one machine (a network sensor's row and the row its agent
// made), each with its own copy of the same software, open ports, findings and their history, and gives each what a person or another
// module keeps about a device: a person's decision on some findings (different ones, and one CVE decided on both), an applied
// mitigation item, an AI result, a notice sent, SNMP settings, a done mark of a recommended update, a device check, a trap incident, a response event,
// a connection and an "I have this" answer. It returns the two device ids and how many rows the two copies share.
func (s *stack) twoRowsOfOneMachine(t *testing.T) (from, into string, colliding int) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "merge-collisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx mergeFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	from = s.seen(t, "10.0.18.40", "02:00:00:00:00:40", "server")
	into = s.seen(t, "10.0.18.41", "02:00:00:00:00:41", "server")
	// The agent's row saw everything an hour after the sensor's: its software, findings and their history carry later times.
	for _, dev := range []struct {
		id, tag, seen string
		later         time.Duration
	}{{from, "f", "2026-11-20T08:03:21.501Z", 0}, {into, "i", "2026-11-20T09:03:21.501Z", time.Hour}} {
		shift := func(ts any) any {
			at, err := time.Parse(time.RFC3339Nano, ts.(string))
			if err != nil {
				t.Fatal(err)
			}
			return store.FormatTS(at.Add(dev.later))
		}
		sw := func(id any) any {
			if id == nil {
				return nil
			}
			return id.(string) + "-" + dev.tag
		}
		for _, r := range fx.Software { // the export's agent rows as software lines read by osquery
			id := sw(r["id"])
			key := productid.Key(r["vendor"].(string), r["product"].(string))
			s.exec(`INSERT INTO inv_software (id, asset_id, product_key, display, vendor, product, cpe, version, pkg_version, pkg_source, packaged, source, confidence,
				seen_at, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'osquery', ?, ?, ?, ?)`,
				id, dev.id, key, r["display"], r["vendor"], r["product"], r["cpe"], r["version"], r["pkg_version"], r["pkg_source"], r["packaged"], r["confidence"], dev.seen, dev.seen, dev.seen)
			s.exec(`INSERT INTO inv_software_reading (software_id, source, display, version, pkg_version, pkg_source, packaged, cpe, confidence, first_seen, seen_at)
				VALUES (?, 'osquery', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, r["display"], r["version"], r["pkg_version"], r["pkg_source"], r["packaged"], r["cpe"], r["confidence"], dev.seen, dev.seen)
		}
		for _, r := range fx.Services {
			s.insertRow("inv_service", r, map[string]any{"id": r["id"].(string) + "-" + dev.tag, "asset_id": dev.id})
		}
		for _, r := range fx.Findings {
			s.insertRow("fnd_finding", r, map[string]any{"id": r["id"].(string) + "-" + dev.tag, "asset_id": dev.id, "software_id": sw(r["software_id"]),
				"first_seen": shift(r["first_seen"]), "last_seen": shift(r["last_seen"]), "resolved_at": shift(r["resolved_at"])})
		}
		for _, r := range fx.History {
			s.insertRow("fnd_finding_history", r, map[string]any{"id": r["id"].(string) + "-" + dev.tag, "finding_id": r["finding_id"].(string) + "-" + dev.tag,
				"ts": shift(r["ts"])})
		}
		if code, v := s.do("PUT", "/inventory/snmp/devices/"+dev.id, "admin", `{"version":"v2c","community":"community-`+dev.tag+`-0001"}`); code != 200 {
			t.Fatalf("SNMP of %s: %d %v", dev.id, code, v)
		}
	}
	colliding = len(fx.Software) + len(fx.Services) + len(fx.Findings) + 1 // + the SNMP settings
	f0, f1, f2 := fx.Findings[0]["id"].(string), fx.Findings[1]["id"].(string), fx.Findings[2]["id"].(string)
	decide := func(finding, who, note string) {
		s.exec(`UPDATE fnd_finding SET status = 'false_positive', resolved_by = ?, resolved_at = '2026-11-20T10:00:00.000Z', resolution_note = ?,
			resolution_reason = NULL WHERE id = ?`, who, note, finding)
		s.exec(`INSERT INTO fnd_finding_history (id, finding_id, ts, user, action, note) VALUES (?, ?, '2026-11-20T10:00:00.000Z', ?, 'false_positive', ?)`,
			"fh-"+finding, finding, who, note)
	}
	decide(f0+"-f", "person@example.com", "the module is not loaded on this server")
	decide(f0+"-i", "other@example.com", "checked with the vendor: not affected")
	decide(f1+"-f", "person@example.com", "kernel is livepatched")
	s.exec(`INSERT INTO notify_notice (id, created_at, product, cves) VALUES ('nt-merge-1', '2026-11-20T10:04:00.000Z', 'Linux servers (kernel)', '[]')`)
	s.exec(`INSERT INTO notify_notice_finding (notice_id, finding_id) VALUES ('nt-merge-1', ?)`, fx.Findings[3]["id"].(string)+"-f")
	s.exec(`INSERT INTO mit_applied (finding_id, item, ts, user) VALUES (?, 'workaround', '2026-11-20T10:05:00.000Z', 'person@example.com')`, f2+"-i")
	s.exec(`INSERT INTO mit_ai_output (finding_id, skill, payload, model, created_at) VALUES (?, 'explain', '{"text":"why"}', 'model-x', '2026-11-20T10:06:00.000Z')`, f2+"-f")
	sw := fx.Software[0]["id"].(string)
	s.exec(`INSERT INTO fnd_plan_done (item_key, asset_id, version, cves, done_by, done_at) VALUES (?, ?, ?, '[]', 'person@example.com', '2026-11-20T10:07:00.000Z')`,
		from+"/"+sw+"-f", from, fx.Software[0]["version"])
	s.exec(`INSERT INTO core_run (id, module, kind, lane, title, trigger, requested_by, subject_kind, subject_id, status, queued_at, started_at, ended_at, updated_at)
		VALUES ('run-merge-1', 'sensor-active', 'device_check', 'nmap', 'Check of host-44', 'manual', 'person@example.com', 'device', ?, 'done',
		'2026-11-20T10:08:00.000Z', '2026-11-20T10:08:00.000Z', '2026-11-20T10:09:00.000Z', '2026-11-20T10:09:00.000Z')`, from)
	s.exec(`INSERT INTO notify_incident (id, kind, title, link, severity, what, action, first_seen, last_seen, dedupe_key) VALUES ('inc-merge-1', 'trap',
		'A device touched a trap', '/honeypot', 'high', 'trap hit', 'look', '2026-11-20T10:10:00.000Z', '2026-11-20T10:10:00.000Z', ?)`, strings.Repeat("a", 64))
	s.exec(`INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES ('inc-merge-1', ?, 'host-44')`, from)
	s.exec(`INSERT INTO resp_events (id, trigger, ts, summary, fields, asset_id) VALUES ('ev-merge-1', 'manual', '2026-11-20T10:11:00.000Z', 'test', '{}', ?)`, from)
	s.exec(`INSERT INTO core_connection (id, name, name_key, kind, target, asset_id, auth_type, allow, updated_at) VALUES ('cn-merge-1', 'Server API', 'server api',
		'http', 'https://10.0.18.40', ?, 'none', '[]', '2026-11-20T10:12:00.000Z')`, from)
	s.exec(`INSERT INTO feeds_weekly_answer (key, answer, user_id, answered_at, device_added, device_id, have_since) VALUES ('linux|kernel', 'have', 'u-1',
		'2026-11-20T10:13:00.000Z', 1, ?, '2026-11-20')`, from)
	return from, into, colliding
}

// mergeFact is one kind of fact a module keeps about a device: q lists them for device ?1 as identity strings. After a merge every
// fact either device had must be found on the device that stays.
type mergeFact struct{ name, q string }

var mergeFacts = []mergeFact{
	{"software readings", `SELECT w.product_key || '|' || w.line || '|' || r.source || '|' || r.instance || '|' || ifnull(r.version, '') || '|' || ifnull(r.pkg_version, '')
		FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id WHERE w.asset_id = ?1`},
	{"open ports", `SELECT port || '/' || proto || '|' || source FROM inv_service WHERE asset_id = ?1`},
	{"findings", `SELECT cve FROM fnd_finding WHERE asset_id = ?1`},
	{"finding history", `SELECT f.cve || '|' || h.ts || '|' || h.user || '|' || h.action || '|' || ifnull(h.note, '') FROM fnd_finding_history h JOIN fnd_finding f ON f.id = h.finding_id WHERE f.asset_id = ?1`},
	{"mitigation", `SELECT f.cve || '|applied|' || m.item FROM mit_applied m JOIN fnd_finding f ON f.id = m.finding_id WHERE f.asset_id = ?1
		UNION SELECT f.cve || '|ai|' || m.skill FROM mit_ai_output m JOIN fnd_finding f ON f.id = m.finding_id WHERE f.asset_id = ?1`},
	{"done marks", `SELECT version || '|' || cves || '|' || done_by FROM fnd_plan_done WHERE asset_id = ?1`},
	{"device checks", `SELECT id FROM core_run WHERE module = 'sensor-active' AND subject_kind = 'device' AND subject_id = ?1`},
	{"incidents", `SELECT d.incident_id FROM notify_incident_device d JOIN notify_incident i ON i.id = d.incident_id WHERE d.asset_id = ?1 AND i.kind <> 'unknown_device'`},
	{"response events", `SELECT id FROM resp_events WHERE asset_id = ?1`},
	{"connections", `SELECT id FROM core_connection WHERE asset_id = ?1`},
	{"have answers", `SELECT key FROM feeds_weekly_answer WHERE device_id = ?1`},
	// A device has one SNMP setting: of two, the one not kept counts as kept only when a notice names it for the person.
	{"SNMP settings", `SELECT version || '|' || read_from FROM sa_snmp_device WHERE asset_id = ?1
		UNION SELECT 'v2c|' || ip.v FROM (SELECT '10.0.18.40' AS v UNION SELECT '10.0.18.41') ip, sa_snmp_notice n WHERE n.text LIKE '%Removed: SNMP v2c, read from ' || ip.v || ':%'`},
}

// dangling counts what still points at a device or a software row that is gone after a merge of from: rows naming from, and findings,
// version-needed items and done marks naming a software row no device has.
var dangling = []string{
	`SELECT count(*) FROM fnd_finding WHERE asset_id = ?1`,
	`SELECT count(*) FROM fnd_plan_done WHERE asset_id = ?1`,
	`SELECT count(*) FROM core_run WHERE module = 'sensor-active' AND subject_kind = 'device' AND subject_id = ?1`,
	`SELECT count(*) FROM sa_snmp_device WHERE asset_id = ?1`,
	`SELECT count(*) FROM notify_incident_device WHERE asset_id = ?1`,
	`SELECT count(*) FROM resp_events WHERE asset_id = ?1`,
	`SELECT count(*) FROM core_connection WHERE asset_id = ?1`,
	`SELECT count(*) FROM feeds_weekly_answer WHERE device_id = ?1`,
	`SELECT count(*) FROM fnd_finding f WHERE f.software_id LIKE 's-%' AND NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = f.software_id)`,
	`SELECT count(*) FROM fnd_version_needed v WHERE NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = v.software_id)`,
	`SELECT count(*) FROM notify_notice_finding n WHERE NOT EXISTS (SELECT 1 FROM fnd_finding f WHERE f.id = n.finding_id)`,
}

func (s *stack) factsOf(id string) map[string]map[string]bool {
	s.t.Helper()
	out := map[string]map[string]bool{}
	for _, f := range mergeFacts {
		rows, err := s.d.DB.Reader().QueryContext(s.t.Context(), f.q, id)
		if err != nil {
			s.t.Fatalf("%s: %v", f.name, err)
		}
		out[f.name] = map[string]bool{}
		for rows.Next() {
			var v sql.NullString
			if err := rows.Scan(&v); err != nil {
				s.t.Fatal(err)
			}
			out[f.name][v.String] = true
		}
		if err := rows.Close(); err != nil {
			s.t.Fatal(err)
		}
	}
	return out
}

// lostInMerge merges from into into as a person does and counts, per kind of fact, the facts of either device not found on into
// afterwards, and the rows left pointing at from or at a software row that is gone.
func (s *stack) lostInMerge(t *testing.T, from, into string) (map[string]int, error) {
	t.Helper()
	before := s.factsOf(from)
	for k, v := range s.factsOf(into) {
		for f := range v {
			before[k][f] = true
		}
	}
	if err := s.d.Inventory.Merge(t.Context(), "person@example.com", into, from); err != nil {
		return nil, err
	}
	after := s.factsOf(into)
	lost := map[string]int{}
	for _, f := range mergeFacts {
		for fact := range before[f.name] {
			if !after[f.name][fact] {
				lost[f.name]++
			}
		}
	}
	for _, q := range dangling {
		if n := s.count(q, from); n > 0 {
			lost["dangling: "+q[len("SELECT count(*) FROM "):strings.Index(q, " WHERE")]] += n
		}
	}
	return lost, nil
}

// Count test of the merge: two device rows of one machine that each hold a copy of the same 50 software rows, 3 open ports, 46
// findings with their history and an SNMP setting (100 colliding rows, from an anonymised export of a real network), plus what a
// person and the other modules keep about each. After the merge every fact of either row is on the device that stays and nothing
// points at the row that went.
func TestMergeLosesNothingCount(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	from, into, colliding := s.twoRowsOfOneMachine(t)
	lost, err := s.lostInMerge(t, from, into)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	var lines []string
	for k, n := range lost {
		total += n
		lines = append(lines, fmt.Sprintf("%s: %d", k, n))
	}
	slices.Sort(lines)
	t.Logf("merge of two rows with %d colliding rows: %d facts lost %v", colliding, total, lines)
	if total != 0 {
		t.Errorf("the merge lost %d facts: %s", total, strings.Join(lines, "; "))
	}
}
