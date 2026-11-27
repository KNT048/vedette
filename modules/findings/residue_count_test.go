package findings

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// The causes of the residue fixture's queue items.
const (
	causeGAOnly    = "ESXi: NVD lists exact older releases and 8.0 GA"   // the host runs 8.0 Update 3: no listed release is its own
	causeNoVersion = "ESXi: NVD names the product with no version"       // truly no affected versions
	causeOlderDSM  = "DSM: the vendor names fixes only on newer lines"   // 7.3.2 and 7.4.1, nothing about 7.2.1
	causeOwnLine   = "DSM: the vendor names the device's own line"       // a finding, never a question
	causeLineSafe  = "DSM: the vendor says the device's line is not hit" // nothing to ask
	causeExploited = "ESXi: exploited, VMware names the fixed U3 build"  // a finding, never a question
	causeFirewall  = "a firewall Vedette knows nothing to check by"      // a device added by a person
	causePending   = "a device nobody added yet, nothing to check by"    // not asked about
)

// residueWorld is a network shaped like a small office after a scan: two ESXi hosts that state 8.0 Update 3 (build 24022510), a Synology
// NAS a person declared as DSM 7.2.1-69057-5, a FortiGate a person added whose SNMP read fails and whose scan saw only an SSH port (no
// software line, an OS fingerprint guess only), and a second firewall nobody added yet. The CVE configurations are shaped like the
// real records (NVD lists ESXi releases one by one, and lists only 8.0 GA for a flaw VMware fixed in 8.0 Update 3d; Synology states its
// fixed releases per line, naming only its newest lines), numbered in a private range.
func residueWorld(t *testing.T) (*env, map[string]string) {
	t.Helper()
	esxiKey, dsmKey := productid.Key("VMware", "ESXi"), productid.Key("Synology", "DiskStation Manager")
	exact := func(cpes ...string) []Affected {
		var out []Affected
		for _, c := range cpes {
			out = append(out, Affected{CPE: c})
		}
		return out
	}
	esxiReleases := exact("cpe:2.3:o:vmware:esxi:7.0:-:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:7.0:update_1:*:*:*:*:*:*",
		"cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:7.0:update_3g:*:*:*:*:*:*", "cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*")
	dsmRecord := func(cve string, spans ...[3]string) Vuln { // Synology's record: DSM with no version, the fixed releases per line
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrg, Published: uncNew,
			Affected: exact("cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*"), Schemed: schemedRows(t, "synology-dsm", dsmKey, spans...)}
	}
	exploited := uncVuln("CVE-2026-81003", "VMware", "ESXi", uncNew, esxiReleases...)
	exploited.Schemed = schemedRows(t, "vmware-esxi", esxiKey, [3]string{"8.0", "ESXi80U3d-24585383", ""}, [3]string{"8.0", "ESXi80U2d-24585300", ""},
		[3]string{"7.0", "ESXi70U3s-24585291", ""})
	cases := []struct {
		cause string
		v     Vuln
	}{
		{causeGAOnly, Vuln{CVE: "CVE-2026-81001", NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: esxiReleases}}, // on no exploited list
		{causeNoVersion, uncVuln("CVE-2026-81002", "VMware", "ESXi", uncNew, exact("cpe:2.3:o:vmware:esxi:-:*:*:*:*:*:*:*")...)},
		{causeExploited, exploited},
		{causeOlderDSM, dsmRecord("CVE-2026-82001", [3]string{"7.3.2", "7.3.2-86009-2", ""}, [3]string{"7.4.1", "7.4.1-90080-1", ""})},
		{causeOlderDSM, dsmRecord("CVE-2026-82002", [3]string{"7.3.2", "7.3.2-86009-5", ""}, [3]string{"7.4.1", "7.4.1-90080-1", ""})},
		{causeOlderDSM, dsmRecord("CVE-2026-82003", [3]string{"7.3.2", "7.3.2-86009-5", ""})},
		{causeOwnLine, dsmRecord("CVE-2026-82004", [3]string{"7.2.1", "7.2.1-69057-6", ""}, [3]string{"7.3.2", "7.3.2-86009-2", ""})},
		{causeLineSafe, dsmRecord("CVE-2026-82005", [3]string{"7.2.1", "7.2.1", ""}, [3]string{"7.3.2", "7.3.2-86009-2", ""})},
	}
	e := newEnv(t)
	cause := map[string]string{}
	for _, c := range cases {
		e.feeds.vulns = append(e.feeds.vulns, c.v)
		cause[c.v.CVE] = c.cause
	}
	nas := Asset{ID: "nas-01", Name: "nas-01", Software: []Software{{ID: "s-nas", Display: "Synology DiskStation Manager", Vendor: "Synology",
		Product: "DiskStation Manager", Version: "7.2.1-69057-5", Source: "manual", KevKeys: []string{"synology|diskstation manager"}}}}
	fw := Asset{ID: "fw-01", Name: "fw-01", OS: "Fortinet FortiOS 6.x", MAC: "00:09:0f:00:00:01"}
	pending := Asset{ID: "fw-02", Name: "fw-02", OS: "Fortinet FortiOS 7.x", MAC: "00:09:0f:00:00:02"}
	devices := []Asset{esxiStated("esx-01", "8.0", "update_3", "24022510"), esxiStated("esx-02", "8.0", "update_3", "24022510"), nas, fw, pending}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for i, a := range devices {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Name: a.ID, Hostname: ptr(a.ID), IP: fmt.Sprintf("192.0.2.%d", 60+i), Kind: "server", Approved: a.ID != pending.ID}
		e.inv.match[a.ID] = a
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e, cause
}

// residueCounts is the Needs your input queue of residueWorld by item kind and cause, the open findings by cause, and how many queue
// items say the CVE "gives no affected versions" (a no_range_data question whose CVE lists no version of the software).
func residueCounts(t *testing.T) (items, findings map[string]int, noVersions int) {
	t.Helper()
	e, cause := residueWorld(t)
	in, err := e.svc.Input(t.Context(), "", "", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	items, findings = map[string]int{}, map[string]int{}
	for _, it := range flatInput(in.Items) {
		switch it.Kind {
		case "device_unchecked":
			c := causeFirewall
			if it.Device.ID == "fw-02" {
				c = causePending
			}
			items["device_unchecked / "+c]++
		case "question":
			c := ""
			switch {
			case it.CVE != nil:
				c = cause[*it.CVE]
			case len(it.CVEList) > 0:
				c = fmt.Sprintf("%s (%d CVEs)", cause[it.CVEList[0]], len(it.CVEList))
			}
			items[it.Question+" / "+c]++
			if it.Question == string(QuestionNoRangeData) && (it.Listed == nil || !*it.Listed) {
				noVersions++
			}
		default:
			items[it.Kind]++
		}
	}
	for _, c := range e.cvesOpen(t) {
		findings[cause[c]]++
	}
	return items, findings, noVersions
}

// cvesOpen is the CVE of every open finding.
func (e *env) cvesOpen(t *testing.T) []string {
	t.Helper()
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve FROM fnd_finding WHERE state = 'open' ORDER BY asset_id, cve`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// Class count: the Needs your input queue of a network shaped like a small office (residueWorld), by item kind and cause.
//
// Before: 7 items, all "gives no affected versions": 3 DSM questions whose records name fixes only on 7.3.2 and 7.4.1, 2 ESXi questions
// whose NVD list holds exact releases (8.0 GA among them, not 8.0 Update 3), 2 ESXi questions NVD names with no version; and nothing at
// all for the firewall Vedette cannot check, whose empty findings read as safe.
//
// After: one question per DSM line for the three ("the vendor names fixes only on newer releases"), the ESXi exact-release questions
// worded as what they are (listed releases, none of them this one), the two with truly no version kept as they were, and one item for
// the firewall a person added; the firewall nobody added, which has no finding, is counted in the one card of the devices not added
// yet with no open finding. The findings are the same (no new false negative): the CVE VMware fixed in
// 8.0 Update 3d is a finding on both hosts, the DSM CVE of the device's own line is a finding, the line DSM says is not hit is nothing.
func TestQueue_Count_ResidueByKindAndCause(t *testing.T) {
	t.Parallel()
	items, findings, noVersions := residueCounts(t)
	t.Logf("queue items by kind / cause:%s", countLines(items))
	t.Logf("open findings by cause:%s", countLines(findings))
	t.Logf("items worded \"gives no affected versions\": %d", noVersions)
	want := map[string]int{
		"no_range_data / " + causeGAOnly:      2,
		"no_range_data / " + causeNoVersion:   2,
		"older_line / " + causeOlderDSM:       3, // one question per CVE
		"device_unchecked / " + causeFirewall: 1,
		"devices_not_added":                   1, // the firewall nobody added (no finding): the grouped card
		"unconfirmed":                         2, // the exploited CVE on both hosts: a finding to confirm
	}
	if !maps.Equal(items, want) {
		t.Errorf("queue %v, want %v", items, want)
	}
	if want := map[string]int{causeExploited: 2, causeOwnLine: 1}; !maps.Equal(findings, want) {
		t.Errorf("findings %v, want %v", findings, want)
	}
	if noVersions != 2 {
		t.Errorf("%d items say \"gives no affected versions\", want 2 (only the CVE that lists no version)", noVersions)
	}
}

// The DSM line questions: one per CVE whose record names fixes only on newer lines, each with the device's line and the newest fixed
// release of each newer line for that CVE, answered on its own (Affected or Not affected); a CVE that joins later is its own question,
// and an answer given to the line's single question an earlier build asked still holds for each CVE it listed.
func TestOlderLine_OneQuestionPerCVE(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	qs, err := questionsOf(t.Context(), e.db.Reader(), "nas-01")
	if err != nil {
		t.Fatal(err)
	}
	var cves []string
	for _, q := range qs {
		if q.Kind != QuestionOlderLine {
			continue
		}
		cves = append(cves, q.CVE)
		if q.Detail.Line != "7.2.1" || len(q.Detail.Fixes) == 0 || q.Detail.Undecided == nil || q.Detail.Undecided.Reason != UndecidedBranchOnly {
			t.Errorf("%s: line %q fixes %v undecided %+v", q.CVE, q.Detail.Line, q.Detail.Fixes, q.Detail.Undecided)
		}
	}
	slices.Sort(cves)
	if want := []string{"CVE-2026-82001", "CVE-2026-82002", "CVE-2026-82003"}; !slices.Equal(cves, want) {
		t.Fatalf("older_line questions about %v, want %v", cves, want)
	}
	var first Question
	for _, q := range qs {
		if q.CVE == "CVE-2026-82001" {
			first = q
		}
	}
	if _, err := e.svc.AnswerQuestion(t.Context(), first.ID, AnswerNotAffected, "checked the advisories for 7.2.1", "it@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND answer IS NULL`); n != 2 {
		t.Errorf("%d open older_line questions after one answer and a match that changed nothing, want 2", n)
	}
	// an answer to the whole line, as an earlier build asked it, holds for every CVE it listed
	e.exec(`DELETE FROM fnd_question WHERE asset_id = 'nas-01'`)
	e.exec(`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at)
		VALUES ('q-line', 'nas-01', 's-nas', NULL, 'older_line', '{"cve_list":["CVE-2026-82001","CVE-2026-82002","CVE-2026-82003"],"line":"7.2.1"}', 3,
		'2026-11-01T00:00:00.000Z', 'not_affected', 'it@example.com', '2026-11-02T00:00:00.000Z')`)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2026-82009", Stamp: "x"}) // the pass reads again (a changed list)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND answer IS NULL`); n != 0 {
		t.Errorf("%d older_line questions asked again although the person answered the whole line", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = 'q-line' AND answer = 'not_affected'`); n != 1 {
		t.Error("the answer to the whole line was dropped")
	}
}

// A person's answer to one CVE's own question survives the grouping: that CVE keeps its question and answer and leaves the line question.
func TestOlderLine_AnAnsweredCVEKeepsItsOwnAnswer(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	// as an earlier build stored it: CVE-2026-82002 asked on its own, answered not affected by a person
	e.exec(`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at)
		VALUES ('q-old', 'nas-01', 's-nas', 'CVE-2026-82002', 'no_range_data', '{}', 1, '2026-11-01T00:00:00.000Z', 'not_affected', 'it@example.com', '2026-11-02T00:00:00.000Z')`)
	e.exec(`DELETE FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line'`)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = 'q-old' AND answer = 'not_affected'`); n != 1 {
		t.Error("the person's answer to CVE-2026-82002 was dropped by the grouping")
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND answer IS NULL`); n != 2 ||
		e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND cve = 'CVE-2026-82002'`) != 0 {
		t.Error("the CVE the person answered for is asked again as an older_line question")
	}
}

// A person's answer to a CVE holds whatever kind of question it answered (the version could not be compared, the platform was
// unknown...), as long as it was given for the version the line runs now: an answer given for an older version is asked again.
func TestOlderLine_AnAnswerOfAnyKindHoldsForItsVersion(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	e.exec(`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at) VALUES
		('q-same', 'nas-01', 's-nas', 'CVE-2026-82001', 'not_comparable', '{"version":"7.2.1-69057-5"}', 1, '2026-11-01T00:00:00.000Z', 'not_affected', 'it@example.com', '2026-11-02T00:00:00.000Z'),
		('q-older', 'nas-01', 's-nas', 'CVE-2026-82003', 'platform', '{"version":"7.2.1-69057-3"}', 1, '2026-11-01T00:00:00.000Z', 'not_affected', 'it@example.com', '2026-11-02T00:00:00.000Z')`)
	e.exec(`DELETE FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line'`)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = 'q-same' AND answer = 'not_affected'`); n != 1 {
		t.Error("the answer to CVE-2026-82001 given for the version the line runs was dropped because its question was another kind")
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = 'q-older'`); n != 0 {
		t.Error("an answer given for an older version of the line still decides CVE-2026-82003")
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND answer IS NULL AND cve IN ('CVE-2026-82002', 'CVE-2026-82003')`); n != 2 ||
		e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'nas-01' AND kind = 'older_line' AND cve = 'CVE-2026-82001'`) != 0 {
		t.Error("the line questions should ask about CVE-2026-82002 and CVE-2026-82003 only")
	}
}

// A person's answer to one CVE's own question holds when the question about that CVE changes kind (ranges arrived, so the version is
// now compared and cannot be): the CVE is not asked again for the same version.
func TestQuestions_AnAnswerHoldsWhenTheQuestionChangesKind(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	var asset, sw, cve, kind, version string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT asset_id, ifnull(software_id, ''), cve, kind, ifnull(json_extract(detail, '$.version'), '')
		FROM fnd_question WHERE cve IS NOT NULL ORDER BY rowid LIMIT 1`).Scan(&asset, &sw, &cve, &kind, &version); err != nil {
		t.Fatal(err)
	}
	other := "not_comparable"
	if kind == other {
		other = "no_range_data"
	}
	e.exec(`DELETE FROM fnd_question WHERE asset_id = '` + asset + `' AND cve = '` + cve + `'`)
	e.exec(`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at)
		VALUES ('q-kind', '` + asset + `', nullif('` + sw + `', ''), '` + cve + `', '` + other + `', json_object('version', '` + version + `'), 1,
		'2026-11-01T00:00:00.000Z', 'not_affected', 'it@example.com', '2026-11-02T00:00:00.000Z')`)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE id = 'q-kind' AND answer = 'not_affected'`); n != 1 {
		t.Errorf("the answer to %s was dropped when its question became %s", cve, kind)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = '` + asset + `' AND cve = '` + cve + `' AND answer IS NULL`); n != 0 {
		t.Errorf("%s is asked again (%d open) although a person answered it for this version", cve, n)
	}
}

// A device Vedette knows nothing to check by is one queue item and one badge, only once a person added it, and it cannot be answered
// "not affected": telling Vedette what runs there (a software line) settles it.
func TestNothingToCheck_QueueBadgeAndAnswer(t *testing.T) {
	t.Parallel()
	e, _ := residueWorld(t)
	in, err := e.svc.Input(t.Context(), "", "192.0.2.63", Page{Limit: PageMax}) // fw-01 by its address
	if err != nil {
		t.Fatal(err)
	}
	in.Items = flatInput(in.Items)
	if len(in.Items) != 1 || in.Items[0].Kind != "device_unchecked" || in.Items[0].Device.ID != "fw-01" {
		t.Fatalf("queue for the firewalls: %+v, want one device_unchecked for fw-01", in.Items)
	}
	st, err := e.svc.DeviceStatuses(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := st["fw-01"]; ok { // nothing to check is no possible CVE: the device gets no badge (its own prompt says what to add)
		t.Errorf("fw-01 badge %+v, want none", got)
	}
	if got, ok := st["fw-02"]; ok {
		t.Errorf("fw-02 (nobody added it) has badge %+v, want none", got)
	}
	if _, err := e.svc.AnswerQuestion(t.Context(), in.Items[0].ID, AnswerNotAffected, "it is a firewall", "it@example.com"); !errors.Is(err, ErrNotAnswerable) {
		t.Errorf("answering nothing_to_check: %v, want ErrNotAnswerable", err)
	}
	fw := e.inv.match["fw-01"]
	fw.Software = []Software{{ID: "s-fw", Display: "Fortinet FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.8", Source: "manual"}}
	e.inv.match["fw-01"] = fw
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'fw-01' AND kind = 'nothing_to_check'`); n != 0 {
		t.Errorf("fw-01 still asks what runs there after its firmware was added (%d)", n)
	}
	// each source of what runs there settles it on its own; a fingerprint guess does not
	for _, tc := range []struct {
		name string
		a    Asset
		want bool
	}{
		{"guess only", Asset{OS: "Fortinet FortiOS 6.x"}, true},
		{"stated over LLDP", Asset{StatedOS: "FortiOS v7.2.8"}, false},
		{"SNMP", Asset{SNMPOS: "FortiGate-60F v7.2.8"}, false},
		{"agent", Asset{AgentOS: "Ubuntu 24.04"}, false},
		{"a person", Asset{ManualOS: "FortiOS 7.2"}, false},
		{"only a line marked not installed", Asset{NotInstalled: []Software{{ID: "s-x", Display: "OpenSSH", Version: "9.6"}}}, true},
	} {
		if got := nothingToCheck(tc.a); got != tc.want {
			t.Errorf("%s: nothingToCheck %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ESXi 8.0.3 is not taken as later than NVD's exact 8.0 GA entry: NVD lists only "8.0:-" for flaws VMware fixed in 8.0 Update 3d (the
// exploited CVE of residueWorld, shaped like CVE-2025-22224), so reading GA as "before Update 3" would drop real exposure whenever
// VMware's own rows are missing. Such a question stays, worded as listed releases that do not include this one.
func TestLaterThan_ESXiUpdateIsNotLaterThanTheGAEntry(t *testing.T) {
	t.Parallel()
	c, err := ParseCPE("cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if laterThan(c, "8.0", "8.0.3") {
		t.Error("8.0.3 read as later than esxi:8.0:- (GA)")
	}
	a := esxiStated("esx-01", "8.0", "update_3", "24022510")
	v := Vuln{CVE: "CVE-2026-81004", NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: []Affected{
		{CPE: "cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*"}, {CPE: "cpe:2.3:o:vmware:esxi:8.0:-:*:*:*:*:*:*"}}}
	res := MatchAsset(a, []Vuln{v}, nil, uncNow)
	if len(res.New) != 0 {
		t.Fatalf("a finding from an exact release that is not the host's: %+v", res.New)
	}
	qs := questionsOfMatch(res)
	if len(qs) != 1 || qs[0].Kind != QuestionNoRangeData || !qs[0].Detail.Listed {
		t.Errorf("questions %+v, want one no_range_data with listed versions", qs)
	}
	if !strings.Contains(fmt.Sprint(qs), "CVE-2026-81004") {
		t.Errorf("the question is not about the CVE: %+v", qs)
	}
}

// exec runs one statement on the database.
func (e *env) exec(query string) {
	e.t.Helper()
	if err := e.db.Write(e.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), query)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}
