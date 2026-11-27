package main

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// row is one planted row: a table and the columns that differ from validColumns (or, for a column it does not list either, from
// the planted default).
type row struct {
	table string
	set   map[string]any
}

// edit changes the rows a case plants: holds[i] takes the columns of edit[i] on top of its own; a nil map leaves holds[i] out.
type edit map[int]map[string]any

// selfcheckCase proves that one invariant counts the rows that break its rule, and only those. holds are rows that keep the rule:
// planted on a freshly migrated database (CHECK constraints ignored, foreign keys kept) they count zero. Each break changes a few
// columns of those rows so that the rule breaks, and must count above zero: the break and the rows that hold differ only in the
// columns the break names, so the count comes from the invariant's own condition on them and not from a planted default that breaks
// the rule anyway. alsoHold are other shapes of the same rows that keep the rule (an exemption the rule allows, the other values of
// a list): each counts zero, so an invariant that counts too much fails too.
//
// An invariant that needs data no plant can fake (a value recomputed in Go from the clock or a scan's run items) names the test that
// breaks it instead, as "<file>:<test>", and counts names the function that test reads the count through: the test must call it and
// fail unless the count is a number above zero.
type selfcheckCase struct {
	rule     string
	holds    []row
	breaks   []edit
	alsoHold []edit
	drop     string // an index that would refuse the breaking rows; dropped first, so the count is what is tested
	noFK     bool   // planted with foreign keys off: the rule is that a reference has its row
	provedBy string
	counts   string
}

const (
	tsEarly = "2025-12-01T00:00:00.000Z"
	tsA     = "2026-01-01T00:00:00.000Z"
	tsB     = "2026-01-02T00:00:00.000Z"
	tsC     = "2026-01-03T00:00:00.000Z"
)

// validColumns are the values a planted row of the selfcheck cases takes where the case does not give one (the rows a foreign key
// makes the planter write too): values every invariant accepts, so a case's rows hold its rule unless the case says otherwise.
var validColumns = map[string]map[string]any{
	"fnd_finding": {"state": "open", "resolution": nil, "via": nil, "resolved_by": nil, "resolved_at": nil, "accepted_until": nil,
		"from_version": nil, "to_version": nil, "basis": string(findings.DetectDeviceVersion), "detected": 1, "range_origin": "nvd",
		"software_id": nil, "matched_version": nil, "fix_kind": string(findings.FixUpdate), "fix_version": "2.0", "fix_key": "acme|box|update|2.0", "fix_channel": "public"},
	"fnd_finding_event": {"kind": string(findings.EvCreated)},
	"fnd_question":      {"kind": string(findings.QuestionVersionNeeded), "software_id": nil},
	"core_schedule":     {"freq": string(schedule.Daily), "last_run_id": nil},
	"core_run": {"status": string(corerun.Queued), "ended_at": nil, "waiting_for": nil, "parent_id": nil, "schedule_id": nil,
		"total": 0, "done": 0},
	"core_run_step": {"status": string(corerun.Queued), "total": 0, "done": 0},
	"core_job_run":  {"started_at": tsA, "finished_at": tsB},
	"exp_target":    {"kind": "ip", "parent_id": nil, "enabled": 1},
	"exp_host":      {"child_target_id": nil},
	"exp_address":   {"host_id": nil},
	"exp_service":   {"state": "closed"},
	"exp_issue":     {"state": "open", "service_id": nil, "resolution": nil, "resolved_by": nil, "resolved_at": nil, "accepted_until": nil},
	"inv_asset": {"ip": nil, "mac": nil, "is_box": 0, "kind_obs_id": nil, "hostname_obs_id": nil, "mac_obs_id": nil, "vendor_obs_id": nil,
		"model_obs_id": nil, "os_obs_id": nil},
	"inv_software": {"state": "removed", "line": "", "version": nil, "pkg_version": nil, "cpe": nil, "differs": 0, "not_installed_at": nil,
		"removed_at": nil},
	"inv_software_reading": {"addr_id": "", "instance": "", "version": nil, "pkg_version": nil, "packaged": 0, "set_by": nil,
		"first_seen": tsA, "seen_at": tsA},
	"inv_service":  {"addr_id": ""},
	"feeds_cve":    {"published": nil},
	"feeds_signal": {"qualifies": 1},
}

// selfcheckCases has a case for every registered invariant (TestSelfcheck_EveryInvariantHasACase).
var selfcheckCases = map[string]selfcheckCase{
	"sqlite.foreign_key_violations": {rule: "every reference has its row (a finding, a question, a reading, a run step of a run that exists)", noFK: true,
		holds:  []row{{"fnd_finding", map[string]any{"asset_id": "a1"}}},
		breaks: []edit{{0: {"asset_id": danglingRef("gone")}}}},
	"core.job_run_ends_after_start": {rule: "a job run ends after it starts",
		holds:    []row{{"core_job_run", nil}},
		breaks:   []edit{{0: {"started_at": tsC}}},
		alsoHold: []edit{{0: {"finished_at": tsA}}}},

	"schedules.next_due_is_next_of_rule": {rule: "a schedule's next due time is the next time of its rule",
		provedBy: "core/schedule/invariants_test.go:TestAFreshBoxPassesTheSelfCheckWithNoOwnerRegistered", counts: "NextDueMismatches"},
	"schedules.known_frequency": {rule: "a schedule has a frequency the code knows",
		holds:    []row{{"core_schedule", nil}},
		breaks:   []edit{{0: {"freq": "never"}}},
		alsoHold: []edit{{0: {"freq": string(schedule.Interval)}}, {0: {"freq": string(schedule.Once)}}}},

	"runs.one_live_per_lane": {rule: "at most one run is running in each lane", drop: "core_run_live",
		holds:    []row{{"core_run", liveRun("r1", "running")}, {"core_run", map[string]any{"id": "r2", "lane": "lane-1"}}},
		breaks:   []edit{{1: {"status": "running"}}, {1: {"status": "stopping"}}},
		alsoHold: []edit{{1: {"status": "running", "lane": "lane-2"}}}},
	"runs.ended_have_ended_at": {rule: "a run has an end time exactly when it has ended",
		holds:    []row{{"core_run", map[string]any{"status": "done", "ended_at": tsB}}},
		breaks:   []edit{{0: {"ended_at": nil}}, {0: {"status": "running"}}},
		alsoHold: []edit{{0: {"status": "partial"}}, {0: {"status": "failed"}}, {0: {"status": "stopped"}}, {0: {"status": "queued", "ended_at": nil}}}},
	"runs.waiting_for_only_while_waiting": {rule: "a run says what it waits for exactly while it waits",
		holds:    []row{{"core_run", map[string]any{"status": "waiting", "waiting_for": "a sensor"}}},
		breaks:   []edit{{0: {"status": "running"}}, {0: {"waiting_for": nil}}},
		alsoHold: []edit{{0: {"status": "running", "waiting_for": nil}}}},
	"runs.known_status": {rule: "every run and step is in a known state",
		holds:    []row{{"core_run", map[string]any{"id": "r1"}}, {"core_run_step", map[string]any{"run_id": "r1", "seq": 1}}},
		breaks:   []edit{{0: {"status": "lost"}}, {1: {"status": "lost"}}},
		alsoHold: []edit{{0: {"status": "stopping"}, 1: {"status": "partial"}}}},
	"runs.progress_is_the_sum_of_steps": {rule: "a run with steps counts the work of its steps",
		holds: []row{{"core_run", map[string]any{"id": "r1", "total": 5, "done": 1}},
			{"core_run_step", map[string]any{"run_id": "r1", "seq": 1, "total": 3, "done": 1}},
			{"core_run_step", map[string]any{"run_id": "r1", "seq": 2, "total": 2, "done": 0}}},
		breaks:   []edit{{0: {"total": 4}}, {0: {"done": 2}}, {2: {"total": 3}}},
		alsoHold: []edit{{1: nil, 2: nil}}},

	"exposure.open_service_on_an_address_of_its_target": {rule: "an open service is on an address of its target",
		holds: []row{{"exp_target", map[string]any{"id": "t1"}}, {"exp_address", map[string]any{"target_id": "t1", "ip": "203.0.113.9"}},
			{"exp_service", map[string]any{"target_id": "t1", "ip": "203.0.113.9", "state": "open"}}},
		breaks:   []edit{{2: {"ip": "203.0.113.10"}}, {1: {"target_id": "t2"}}},
		alsoHold: []edit{{2: {"ip": "203.0.113.10", "state": "closed"}}}},
	"exposure.issue_on_a_service_of_its_target": {rule: "an issue about a service is about a service of its own target",
		holds:    []row{{"exp_service", map[string]any{"id": "s1", "target_id": "t1"}}, {"exp_issue", map[string]any{"service_id": "s1", "target_id": "t1"}}},
		breaks:   []edit{{1: {"target_id": "t2"}}},
		alsoHold: []edit{{1: {"target_id": "t2", "service_id": nil}}}},
	"exposure.one_active_scan_per_target": {rule: "a target has at most one scan going",
		holds: []row{{"core_run", liveRun("r1", "running")}, {"core_run", map[string]any{"id": "r2", "status": "done", "ended_at": tsB}},
			{"exp_scan", map[string]any{"run_id": "r1", "target_id": "t1"}}, {"exp_scan", map[string]any{"run_id": "r2", "target_id": "t1"}}},
		breaks: []edit{{1: {"status": "queued", "ended_at": nil}}, {1: {"status": "waiting", "waiting_for": "a sensor", "ended_at": nil}},
			{1: {"status": "running", "lane": "lane-2", "ended_at": nil}}, {1: {"status": "stopping", "lane": "lane-2", "ended_at": nil}}},
		alsoHold: []edit{{1: {"status": "queued", "ended_at": nil}, 3: {"target_id": "t2"}}}},
	"exposure.address_of_a_name_of_its_target": {rule: "a name's address belongs to the name's target",
		holds:    []row{{"exp_host", map[string]any{"id": "h1", "target_id": "t1"}}, {"exp_address", map[string]any{"host_id": "h1", "target_id": "t1"}}},
		breaks:   []edit{{1: {"target_id": "t2"}}},
		alsoHold: []edit{{1: {"target_id": "t2", "host_id": nil}}}},
	"exposure.handled_issue_says_how": {rule: "a handled issue says how, by whom and when; one not handled says none of it",
		holds: []row{{"exp_issue", map[string]any{"state": "handled", "resolution": "patched", "resolved_by": "admin@example.com", "resolved_at": tsA}}},
		breaks: []edit{{0: {"resolution": nil}}, {0: {"resolved_by": nil}}, {0: {"resolved_at": nil}}, {0: {"state": "open"}},
			{0: {"state": "open", "resolution": nil, "resolved_by": nil, "resolved_at": nil, "accepted_until": tsC}}},
		alsoHold: []edit{{0: {"state": "open", "resolution": nil, "resolved_by": nil, "resolved_at": nil}},
			{0: {"resolution": "accepted", "accepted_until": tsC}}}},
	"exposure.subdomain_target_under_its_parent": {rule: "a domain target under another domain target sits under it in the tree",
		holds: []row{{"exp_target", map[string]any{"id": "t1", "kind": "domain", "value": "acme.example"}},
			{"exp_target", map[string]any{"id": "t2", "kind": "domain", "value": "git.acme.example", "parent_id": "t1"}}},
		breaks:   []edit{{1: {"parent_id": nil}}, {1: {"parent_id": "t3"}}},
		alsoHold: []edit{{1: {"parent_id": nil, "value": "notacme.example"}}}},
	"exposure.name_scanned_by_one_target": {rule: "no name is scanned by two enabled targets",
		provedBy: "modules/exposure/tree_test.go:TestTree_ANameScannedTwiceIsCounted", counts: "treeCounts"},

	"inventory.chosen_observation_is_the_devices_own": {rule: "a device's chosen reading of a field is one of its own observations",
		holds: []row{{"inv_asset", map[string]any{"id": "a1", "kind_obs_id": "o1", "hostname_obs_id": "o1", "mac_obs_id": "o1",
			"vendor_obs_id": "o1", "model_obs_id": "o1", "os_obs_id": "o1"}}, {"inv_observation", map[string]any{"id": "o1", "asset_id": "a1"}}},
		breaks: []edit{{1: {"asset_id": "a2"}}, {0: {"kind_obs_id": "o-gone"}}, {0: {"hostname_obs_id": "o-gone"}}, {0: {"mac_obs_id": "o-gone"}},
			{0: {"vendor_obs_id": "o-gone"}}, {0: {"model_obs_id": "o-gone"}}, {0: {"os_obs_id": "o-gone"}}}},
	"inventory.one_line_per_product_and_train": {rule: "one software line per device, product and release train", drop: "inv_software_line_uq",
		holds: []row{{"inv_software", map[string]any{"id": "s1", "asset_id": "a1", "product_key": "acme|box", "line": ""}},
			{"inv_software", map[string]any{"id": "s2", "asset_id": "a1", "product_key": "acme|box", "line": "2"}}},
		breaks:   []edit{{1: {"line": ""}}},
		alsoHold: []edit{{1: {"line": "", "asset_id": "a2"}}, {1: {"line": "", "product_key": "acme|other"}}}},
	"inventory.line_value_is_the_resolvers": {rule: "a line's stored value, state and differs flag are what the resolver says of its readings",
		holds: []row{plantLine("s1", "acme|box", "", "1.0"), plantReading("s1", "osquery", "1.0"), plantReading("s1", "nmap", "1.0")},
		breaks: []edit{{0: {"version": "2.0"}}, {0: {"source": "nmap"}}, {0: {"pkg_version": "1.0-1"}}, {0: {"state": "not_installed"}},
			{2: {"version": "3.0"}}, // another release read by a weaker source: the line differs
			{1: nil},                // the agent's reading gone: the scan's is the line
			{1: nil, 2: nil},        // no reading: the resolver removes the line
			{2: {"source": "manual", "version": "0.9", "first_seen": tsEarly}}}, // a person's entry an agent outgrew has lapsed
		alsoHold: []edit{{0: {"state": "removed", "version": "2.0"}}, // a removed line keeps the value it had
			{0: {"state": "not_installed", "not_installed_at": tsB}}, // marked after the readings were first seen
			{0: {"differs": 1}, 2: {"version": "3.0"}},
			{2: {"source": "manual", "first_seen": tsEarly}}}}, // a person's entry an agent confirms
	"inventory.line_is_the_train_of_its_readings": {rule: "every reading of a line with a release is of the line's release train",
		holds: []row{plantLine("s1", "oracle|java se", "21", "21.0.7"), plantReading("s1", "osquery", "21.0.7"),
			plantLine("s3", "acme|box", "", "1.0"), plantReading("s3", "osquery", "1.0")}, // a product without trains
		breaks:   []edit{{0: {"line": "8"}}, {1: {"version": "17.0.2"}}},
		alsoHold: []edit{{1: {"version": nil}}, {3: {"version": "9.9"}}}}, // a reading with no release; any release of a product without trains
	"inventory.removed_line_has_no_reading": {rule: "a removed line has no reading",
		holds:    []row{{"inv_software", map[string]any{"id": "s1", "state": "present"}}, {"inv_software_reading", map[string]any{"software_id": "s1"}}},
		breaks:   []edit{{0: {"state": "removed"}}},
		alsoHold: []edit{{0: {"state": "removed"}, 1: nil}}},
	"inventory.address_has_one_home": {rule: "an address is the address of one device; what a scan read at an address is the device's",
		holds: []row{{"inv_asset", map[string]any{"id": "a1", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01"}},
			{"inv_asset_address", map[string]any{"id": "x1", "asset_id": "a1", "ip": "10.0.0.2", "mac": "00:00:5e:00:53:02"}},
			{"inv_software", map[string]any{"id": "s1", "asset_id": "a1"}},
			{"inv_software_reading", map[string]any{"software_id": "s1", "addr_id": "x1"}},
			{"inv_service", map[string]any{"asset_id": "a1", "addr_id": "x1"}}},
		breaks: []edit{{1: {"ip": "10.0.0.1"}}, {1: {"mac": "00:00:5e:00:53:01"}}, {1: {"asset_id": "a2"}}, {3: {"addr_id": "x-gone"}},
			{4: {"addr_id": "x-gone"}}}},
	"inventory.present_line_has_a_reading": {rule: "a present line has a reading",
		holds:    []row{{"inv_software", map[string]any{"id": "s1", "state": "present"}}, {"inv_software_reading", map[string]any{"software_id": "s1"}}},
		breaks:   []edit{{1: nil}},
		alsoHold: []edit{{0: {"state": "removed"}, 1: nil}}},

	"sensor-active.no_pending_run_about_a_deleted_device": {rule: "no queued or waiting check is about a device that was deleted",
		holds: []row{{"inv_asset", map[string]any{"id": "a1"}}, {"core_run", deviceRun("r1", "lane-1", "waiting", "a1")},
			{"core_run", deviceRun("r2", "lane-2", "stopped", "a-gone")}}, // a finished run stays as a log of the device it ran on
		breaks: []edit{{1: {"subject_id": "a-gone"}}, {1: {"subject_id": "a-gone", "status": "queued", "waiting_for": nil}},
			{2: {"status": "queued", "ended_at": nil}}},
		alsoHold: []edit{{1: {"subject_id": "a-gone", "status": "running", "waiting_for": nil}}, // it holds its lane until its work ends
			{1: {"subject_id": "a-gone", "module": "exposure"}}, {1: {"subject_id": "a-gone", "subject_kind": "target"}}}},

	"findings.handled_complete": {rule: "a finding is open exactly when it has no resolution; a handled one says how, by whom and when",
		holds: []row{{"fnd_finding", map[string]any{"state": "handled", "resolution": string(findings.ResolutionPatched),
			"via": string(findings.ViaPerson), "resolved_by": "admin@example.com", "resolved_at": tsA}}},
		breaks:   []edit{{0: {"resolution": nil}}, {0: {"via": nil}}, {0: {"resolved_by": nil}}, {0: {"resolved_at": nil}}, {0: {"state": "open"}}},
		alsoHold: []edit{{0: {"state": "open", "resolution": nil, "via": nil, "resolved_by": nil, "resolved_at": nil}}}},
	"findings.open_is_detected": {rule: "an open finding is one the latest match detects",
		holds:  []row{{"fnd_finding", nil}},
		breaks: []edit{{0: {"detected": 0}}},
		alsoHold: []edit{{0: {"detected": 0, "state": "handled", "resolution": string(findings.ResolutionPatched), "via": string(findings.ViaPerson),
			"resolved_by": "admin@example.com", "resolved_at": tsA}}}},
	"findings.version_moved_versions": {rule: "patch credit for a version move names two different versions",
		holds:    []row{{"fnd_finding", map[string]any{"via": string(findings.ViaVersionMoved), "from_version": "1.0", "to_version": "2.0"}}},
		breaks:   []edit{{0: {"to_version": "1.0"}}, {0: {"from_version": nil}}, {0: {"to_version": ""}}},
		alsoHold: []edit{{0: {"via": string(findings.ViaPerson), "to_version": "1.0"}}}},
	"findings.fix_key_names_stored_fix": {rule: "a finding's fix group names its stored fix",
		holds: []row{{"fnd_finding", nil}},
		breaks: []edit{{0: {"fix_version": "3.0"}}, {0: {"fix_kind": string(findings.FixDistroUpdate)}}, {0: {"fix_version": nil}},
			{0: {"fix_channel": string(findings.ChannelUbuntuPro)}}},
		alsoHold: []edit{{0: {"fix_kind": string(findings.FixNoneYet), "fix_version": nil, "fix_key": "acme|box|none_yet|"}},
			{0: {"fix_key": strings.Repeat("x", 400)}},                                                             // a key clipped at its limit is left out
			{0: {"fix_channel": string(findings.ChannelUbuntuPro), "fix_key": "acme|box|update|2.0|ubuntu_pro"}}}}, // a subscription's fix has a group of its own
	"findings.vocabulary": {rule: "every stored value of an open vocabulary is one the code knows",
		holds:    []row{{"fnd_finding", nil}},
		breaks:   []edit{{0: {"basis": "rumour"}}, {0: {"via": "rumour"}}, {0: {"fix_kind": "rumour"}}, {0: {"fix_channel": "rumour"}}},
		alsoHold: []edit{{0: {"basis": string(findings.DetectScan), "via": string(findings.ViaPerson), "fix_kind": string(findings.FixNoneYet)}}}},
	"findings.event_vocabulary": {rule: "every finding event is of a known kind",
		holds:  []row{{"fnd_finding_event", nil}},
		breaks: []edit{{0: {"kind": "rumour"}}}},
	"findings.question_vocabulary": {rule: "every question is of a known kind",
		holds:  []row{{"fnd_question", nil}},
		breaks: []edit{{0: {"kind": "rumour"}}}},
	"findings.matched_version_on_line": {rule: "a detected finding names a version its own software line runs",
		holds: []row{{"inv_software", map[string]any{"id": "s1", "asset_id": "a1", "version": "2.0", "pkg_version": "2.0-1"}},
			{"inv_software_reading", map[string]any{"software_id": "s1", "version": "2.5"}},
			{"fnd_finding", map[string]any{"asset_id": "a1", "software_id": "s1", "matched_version": "2.0"}}},
		breaks: []edit{{2: {"matched_version": "3.0"}}},
		alsoHold: []edit{{2: {"matched_version": "2.5"}}, {2: {"matched_version": "2.0-1"}}, {2: {"matched_version": "3.0", "basis": string(findings.DetectScan)}},
			{2: {"matched_version": "3.0", "detected": 0}}, {2: {"matched_version": "3.0", "basis": string(findings.DetectPerson)}},
			{2: {"matched_version": "3.0", "state": string(findings.StateHandled)}}, {2: {"matched_version": nil}},
			{2: {"matched_version": "3.0", "software_id": nil}}}},
	"findings.line_on_its_device": {rule: "a finding and a question name a software line of their own device",
		holds: []row{{"inv_software", map[string]any{"id": "s1", "asset_id": "a1"}}, {"inv_software", map[string]any{"id": "s2", "asset_id": "a2"}},
			{"fnd_finding", map[string]any{"asset_id": "a1", "software_id": "s1"}}, {"fnd_question", map[string]any{"asset_id": "a2", "software_id": "s2"}}},
		breaks:   []edit{{2: {"software_id": "s2"}}, {3: {"software_id": "s1"}}},
		alsoHold: []edit{{2: {"software_id": nil}}, {3: {"software_id": nil}}}},
	"findings.cve_in_catalogue": {rule: "every finding's CVE is in the catalogue",
		holds:  []row{{"feeds_cve", map[string]any{"cve": "CVE-2026-0001"}}, {"fnd_finding", map[string]any{"cve": "CVE-2026-0001"}}},
		breaks: []edit{{1: {"cve": "CVE-2026-0002"}}}},
	"findings.catalogue_retention": {rule: "an old catalogue CVE is kept only for an exploited-list entry, a qualifying signal or a finding",
		holds: []row{{"feeds_cve", map[string]any{"cve": "CVE-2001-0001", "published": "2001-01-01T00:00:00.000Z"}},
			{"fnd_finding", map[string]any{"cve": "CVE-2001-0001"}},
			{"feeds_kev", map[string]any{"cve": "CVE-2026-0002"}}, {"feeds_signal", map[string]any{"cve": "CVE-2026-0003"}}},
		breaks: []edit{{1: {"cve": "CVE-2026-0009"}}, {1: {"cve": "CVE-2026-0009"}, 3: {"cve": "CVE-2001-0001", "qualifies": 0}}},
		alsoHold: []edit{{1: {"cve": "CVE-2026-0009"}, 2: {"cve": "CVE-2001-0001"}}, {1: {"cve": "CVE-2026-0009"}, 3: {"cve": "CVE-2001-0001"}},
			{0: {"published": nil}, 1: {"cve": "CVE-2026-0009"}}}},
	"findings.range_precedence": {rule: "a CVE record's ranges never win over NVD's for the same finding, except a product with a version scheme",
		holds: []row{{"inv_software", map[string]any{"id": "s1", "asset_id": "a1", "vendor": "acme", "product": "box", "display": "Acme Box 2.0"}},
			{"feeds_cve_range", map[string]any{"cve": "CVE-2026-0001", "origin": "nvd"}},
			{"fnd_finding", map[string]any{"asset_id": "a1", "software_id": "s1", "cve": "CVE-2026-0001"}}},
		breaks: []edit{{2: {"range_origin": "cna"}}, {2: {"range_origin": "adp"}}},
		alsoHold: []edit{{1: {"origin": "cna"}, 2: {"range_origin": "cna"}}, {2: {"range_origin": "cna", "detected": 0}},
			{0: {"vendor": "citrix", "product": "netscaler gateway", "display": "Citrix NetScaler Gateway 14.1-12.30",
				"cpe": "cpe:2.3:a:citrix:netscaler_gateway:14.1-12.30:*:*:*:*:*:*:*"}, 2: {"range_origin": "cna"}}}},
	"findings.urgency_recomputed": {rule: "a finding's stored urgency is the urgency rule recomputed",
		provedBy: "cmd/vedette/urgency_wiring_test.go:TestUrgencyWiring_StoresTheLayersAndTheSelfcheckAgrees", counts: "urgencyMismatches"},
}

// plantLine is a present software line of device a1 whose stored value is an agent's reading of version, with no package release
// and no "differs".
func plantLine(id, productKey, train, version string) row {
	return row{"inv_software", map[string]any{"id": id, "asset_id": "a1", "product_key": productKey, "line": train, "state": "present",
		"source": "osquery", "version": version}}
}

// plantReading is what source reads of line id: version, with no package release, at the device's main address.
func plantReading(id, source, version string) row {
	return row{"inv_software_reading", map[string]any{"software_id": id, "source": source, "version": version}}
}

// deviceRun is a sensor-active check of a device in a lane, in status (a waiting one says what it waits for, an ended one when).
func deviceRun(id, lane, status, device string) map[string]any {
	r := map[string]any{"id": id, "module": "sensor-active", "lane": lane, "status": status, "subject_kind": "device", "subject_id": device}
	switch status {
	case "waiting":
		r["waiting_for"] = "a sensor"
	case "done", "partial", "failed", "stopped":
		r["ended_at"] = tsB
	}
	return r
}

// liveRun is a run in a lane that is going (status).
func liveRun(id, status string) map[string]any {
	return map[string]any{"id": id, "lane": "lane-1", "status": status}
}

// Every registered invariant has a case here, and every case names an invariant that is registered: an invariant is not added
// without a proof that it counts a break, and a case does not outlive its invariant.
func TestSelfcheck_EveryInvariantHasACase(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	for _, inv := range selfcheck.Registered() {
		registered[inv.Name] = true
		if _, ok := selfcheckCases[inv.Name]; !ok {
			t.Errorf("invariant %s has no case in selfcheckCases: plant rows that hold it and edits that break it, or name the test that does", inv.Name)
		}
	}
	for name, c := range selfcheckCases {
		if !registered[name] {
			t.Errorf("selfcheckCases names %s, which is not registered", name)
		}
		planted, named := len(c.holds) > 0 && len(c.breaks) > 0, c.provedBy != "" && c.counts != ""
		if c.rule == "" || planted == named || (!planted && (len(c.holds) > 0 || len(c.breaks) > 0)) {
			t.Errorf("case %s: give the rule and either rows that hold it with edits that break it, or the test that breaks it and the function it counts with", name)
		}
		for _, e := range slices.Concat(c.breaks, c.alsoHold) {
			if err := c.checkEdit(e); err != nil {
				t.Errorf("case %s: %v", name, err)
			}
		}
	}
}

// checkEdit says why an edit proves nothing: it names a row the case does not plant, changes no column, or sets a column to the
// value it holds already.
func (c selfcheckCase) checkEdit(e edit) error {
	if len(e) == 0 {
		return fmt.Errorf("an edit changes nothing")
	}
	for i, set := range e {
		if i < 0 || i >= len(c.holds) {
			return fmt.Errorf("an edit names row %d of %d", i, len(c.holds))
		}
		if set == nil {
			continue
		}
		if len(set) == 0 {
			return fmt.Errorf("an edit of row %d changes no column", i)
		}
		r := c.holds[i]
		for col, v := range set {
			old, given := r.set[col]
			if !given {
				old, given = validColumns[r.table][col]
			}
			if given && reflect.DeepEqual(old, v) {
				return fmt.Errorf("an edit sets %s.%s of row %d to %v, the value it holds already", r.table, col, i, v)
			}
		}
	}
	return nil
}

// positiveInt says e is an integer literal above zero: the other side of a test's "if n != 1 { t.Fatal… }".
func positiveInt(e ast.Expr) bool {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 { // int64(1)
		e = c.Args[0]
	}
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.INT {
		return false
	}
	n, err := strconv.ParseInt(l.Value, 0, 64)
	return err == nil && n > 0
}

// Each invariant counts the rows that break its rule and not the rows that keep it: on a fresh database the rows of its case that
// hold count zero, every shape that also holds counts zero, and every break counts above zero. A case proved by another test names a
// test that exists, reads the count through the function the case names, and fails unless that count is above zero.
func TestSelfcheck_EachInvariantCountsABreak(t *testing.T) {
	t.Parallel()
	invs := map[string]selfcheck.Invariant{}
	for _, inv := range selfcheck.Registered() {
		invs[inv.Name] = inv
	}
	for name, c := range selfcheckCases {
		inv, ok := invs[name]
		if !ok {
			continue // TestSelfcheck_EveryInvariantHasACase
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if c.provedBy != "" {
				file, test, _ := strings.Cut(c.provedBy, ":")
				path := filepath.Join("..", "..", file)
				src, err := os.ReadFile(path) //nolint:gosec // a path listed in this test
				if err != nil {
					t.Fatalf("%s names %s: %v", name, c.provedBy, err)
				}
				if err := namedTestProves(path, src, test, c.counts); err != nil {
					t.Errorf("%s: %s %v", name, c.provedBy, err)
				}
				return
			}
			if n, err := c.count(t, inv, nil); err != nil || n != 0 {
				t.Fatalf("%s (%s): the rows that hold count %d (%v), want 0", name, c.rule, n, err)
			}
			for _, e := range c.alsoHold {
				if n, err := c.count(t, inv, e); err != nil || n != 0 {
					t.Errorf("%s (%s): the rows with %s also hold but count %d (%v), want 0", name, c.rule, describe(e), n, err)
				}
			}
			for _, e := range c.breaks {
				if n, err := c.count(t, inv, e); err != nil || n == 0 {
					t.Errorf("%s (%s): the break %s counts %d (%v), want more than zero", name, c.rule, describe(e), n, err)
				}
			}
		})
	}
}

// count plants the rows of c changed by e on a fresh database and runs inv on it.
func (c selfcheckCase) count(t *testing.T, inv selfcheck.Invariant, e edit) (int64, error) {
	t.Helper()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "v.db")
	if err := writeMigrated(path); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	p := newPlanter(t, db)
	p.base = validColumns
	plant := func(ctx context.Context, tx *sql.Tx) error {
		if c.drop != "" {
			if _, err := tx.ExecContext(ctx, `DROP INDEX "`+c.drop+`"`); err != nil {
				return err
			}
		}
		if err := p.begin(ctx, tx); err != nil {
			return err
		}
		for i, r := range c.holds {
			set := maps.Clone(r.set)
			if change, ok := e[i]; ok {
				if change == nil {
					continue
				}
				if set == nil {
					set = map[string]any{}
				}
				maps.Copy(set, change)
			}
			if err := p.insert(ctx, tx, r.table, set); err != nil {
				return err
			}
		}
		return p.end(ctx, tx)
	}
	if c.noFK {
		raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String()) // SQLite's default: foreign keys off
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close() }()
		tx, err := raw.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := plant(ctx, tx); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	} else if err := db.Write(ctx, func(tx *sql.Tx) error { return plant(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
	res := selfcheck.Run(ctx, db.Reader(), []selfcheck.Invariant{inv})[0]
	return res.Count, res.Err
}

// describe is an edit as a test message shows it, rows in order.
func describe(e edit) string {
	var parts []string
	for _, i := range slices.Sorted(maps.Keys(e)) {
		if e[i] == nil {
			parts = append(parts, fmt.Sprintf("row %d left out", i))
			continue
		}
		var cols []string
		for _, col := range slices.Sorted(maps.Keys(e[i])) {
			cols = append(cols, fmt.Sprintf("%s=%v", col, e[i][col]))
		}
		parts = append(parts, fmt.Sprintf("row %d %s", i, strings.Join(cols, " ")))
	}
	return "{" + strings.Join(parts, "; ") + "}"
}

// namedTestProves says why the test named test in the Go source src does not prove a break: it is not there, it does not read the
// count through the function counts, or it never expects that count to be above zero.
func namedTestProves(path string, src []byte, test, counts string) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == test && fn.Body != nil {
			calls, nonzero := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					calls = calls || (counts != "" && funcName(x.Fun) == counts)
				case *ast.BinaryExpr:
					nonzero = nonzero || (x.Op == token.NEQ && (positiveInt(x.X) || positiveInt(x.Y)))
				}
				return true
			})
			if !calls {
				return fmt.Errorf("does not read the count through %q", counts)
			}
			if !nonzero {
				return fmt.Errorf("never expects a count above zero, so it cannot fail when the rule is broken")
			}
			return nil
		}
	}
	return fmt.Errorf("has no test %s", test)
}

// A named test proves a break only through its code: a call of the counting function and a comparison with a number above zero.
// Words in a comment or a message prove nothing.
func TestSelfcheck_NamedTestIsReadAsCode(t *testing.T) {
	t.Parallel()
	const head = "package x\n\nimport \"testing\"\n\nfunc TestBreak(t *testing.T) {\n"
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"calls and expects one":     {"\tif n := countBreaks(); n != 1 {\n\t\tt.Fatal(n)\n\t}\n", true},
		"calls through a method":    {"\tif _, n := e.countBreaks(); n != 2 {\n\t\tt.Fatal(n)\n\t}\n", true},
		"named only in a comment":   {"\t// countBreaks would say 1\n\tif n := other(); n != 1 {\n\t\tt.Fatal(n)\n\t}\n", false},
		"a longer name":             {"\tif n := countBreaksOld(); n != 1 {\n\t\tt.Fatal(n)\n\t}\n", false},
		"expects zero only":         {"\tif n := countBreaks(); n != 0 {\n\t\tt.Fatal(n)\n\t}\n", false},
		"nonzero only in a message": {"\tif n := countBreaks(); n != 0 {\n\t\tt.Fatal(\"want n != 1\")\n\t}\n", false},
		"nonzero only in a comment": {"\t// later: n != 1\n\tif n := countBreaks(); n != 0 {\n\t\tt.Fatal(n)\n\t}\n", false},
	} {
		err := namedTestProves("x_test.go", []byte(head+c.body+"}\n"), "TestBreak", "countBreaks")
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", name, err, c.ok)
		}
	}
}
