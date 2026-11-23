package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
)

// row is one planted row: a table and the columns that differ from the planted defaults.
type row struct {
	table string
	set   map[string]any
}

// selfcheckCase proves that one invariant counts the rows that break its rule: rows planted on a freshly migrated database (CHECK
// constraints ignored, foreign keys kept) must give a count above zero. An invariant that needs data no plant can fake (a value
// recomputed in Go from the catalogue, the clock or a scan's tree) names the test that breaks it instead, as "<file>:<test>".
type selfcheckCase struct {
	rule     string
	plant    []row
	drop     string // an index that would refuse the breaking rows; dropped first, so the count is what is tested
	noFK     bool   // planted with foreign keys off: the rule is that a reference has its row
	provedBy string
	control  []row // valid rows the invariant must not count: planted first, they count 0, and the break planted next to them counts
}

// selfcheckCases has a case for every registered invariant (TestSelfcheck_EveryInvariantHasACase).
var selfcheckCases = map[string]selfcheckCase{
	"sqlite.foreign_key_violations": {rule: "every reference has its row (a finding, a question, a reading, a run step of a run that exists)", noFK: true,
		plant: []row{{"fnd_finding", map[string]any{"asset_id": "gone", "software_id": nil}}}},
	"core.job_run_ends_after_start": {rule: "a job run ends after it starts",
		plant: []row{{"core_job_run", map[string]any{"started_at": "2026-01-02T00:00:00.000Z", "finished_at": "2026-01-01T00:00:00.000Z"}}}},

	"schedules.next_due_is_next_of_rule": {rule: "a schedule's next due time is the next time of its rule",
		provedBy: "core/schedule/invariants_test.go:TestAFreshBoxPassesTheSelfCheckWithNoOwnerRegistered"},
	"schedules.known_frequency": {rule: "a schedule has a frequency the code knows",
		plant: []row{{"core_schedule", map[string]any{"freq": "never", "last_run_id": nil}}}},

	"runs.one_live_per_lane": {rule: "at most one run is running in each lane", drop: "core_run_live",
		plant: []row{{"core_run", liveRun("r1", "running")}, {"core_run", liveRun("r2", "running")}}},
	"runs.ended_have_ended_at": {rule: "an ended run has an end time",
		plant: []row{{"core_run", map[string]any{"status": "done", "ended_at": nil, "parent_id": nil, "schedule_id": nil}}}},
	"runs.waiting_for_only_while_waiting": {rule: "a run says what it waits for only while it waits",
		plant: []row{{"core_run", map[string]any{"status": "running", "waiting_for": "a sensor", "parent_id": nil, "schedule_id": nil}}}},
	"runs.known_status": {rule: "every run is in a known state",
		plant: []row{{"core_run", map[string]any{"status": "lost", "parent_id": nil, "schedule_id": nil}}}},
	"runs.progress_is_the_sum_of_steps": {rule: "a run with steps counts the work of its steps",
		plant: []row{{"core_run", map[string]any{"id": "r1", "total": 5, "done": 0, "parent_id": nil, "schedule_id": nil}},
			{"core_run_step", map[string]any{"run_id": "r1", "seq": 1, "total": 3, "done": 0}}}},

	"exposure.open_service_on_an_address_of_its_target": {rule: "an open service is on an address of its target",
		plant: []row{{"exp_service", map[string]any{"state": "open", "ip": "203.0.113.9"}}}},
	"exposure.issue_on_a_service_of_its_target": {rule: "an issue about a service is about a service of its own target",
		plant: []row{{"exp_service", map[string]any{"id": "s1"}}, {"exp_issue", map[string]any{"service_id": "s1", "target_id": "t2"}}}},
	"exposure.one_active_scan_per_target": {rule: "a target has at most one scan going",
		plant: []row{{"core_run", liveRun("r1", "running")}, {"core_run", liveRun("r2", "queued")},
			{"exp_scan", map[string]any{"run_id": "r1"}}, {"exp_scan", map[string]any{"run_id": "r2"}}}},
	"exposure.address_of_a_name_of_its_target": {rule: "a name's address belongs to the name's target",
		plant: []row{{"exp_host", map[string]any{"id": "h1"}}, {"exp_address", map[string]any{"host_id": "h1", "target_id": "t2"}}}},
	"exposure.handled_issue_says_how": {rule: "a handled issue says how, by whom and when",
		plant: []row{{"exp_issue", map[string]any{"state": "handled", "resolution": nil}}}},
	"exposure.subdomain_target_under_its_parent": {rule: "a domain target under another domain target sits under it in the tree",
		provedBy: "modules/exposure/tree_test.go:TestTree_PlacementAndReparenting"},
	"exposure.name_scanned_by_one_target": {rule: "no name is scanned by two enabled targets",
		provedBy: "modules/exposure/tree_test.go:TestTree_ANameScannedTwiceIsCounted"},

	"inventory.chosen_observation_is_the_devices_own": {rule: "a device's chosen reading of a field is one of its own observations",
		plant: []row{{"inv_observation", map[string]any{"id": "o-other", "asset_id": "a-other"}}, {"inv_asset", map[string]any{"id": "a1", "ip": nil, "mac": nil, "kind_obs_id": "o-other"}}}},
	"inventory.one_line_per_product_and_train": {rule: "one software line per device, product and release train", drop: "inv_software_line_uq",
		plant: []row{{"inv_software", map[string]any{"id": "s1", "product_key": "acme|box", "line": ""}}, {"inv_software", map[string]any{"id": "s2", "product_key": "acme|box", "line": ""}}}},
	"inventory.line_value_is_the_resolvers": {rule: "a line's stored value, state and differs flag are what the resolver says of its readings",
		control: []row{plantLine("s1", "acme|box", "", "1.0"), plantReading("s1", "1.0")},
		plant:   []row{plantLine("s2", "acme|box", "x", "2.0"), plantReading("s2", "1.0"), {"inv_software", map[string]any{"state": "present", "source": "nmap", "version": "2.0"}}}},
	"inventory.line_is_the_train_of_its_readings": {rule: "every reading of a line with a release is of the line's release train",
		control: []row{plantLine("s1", "oracle|java se", "21", "21.0.7"), plantReading("s1", "21.0.7"), plantLine("s3", "acme|box", "", "1.0"), plantReading("s3", "1.0")},
		plant:   []row{plantLine("s2", "oracle|java se", "8", "21.0.7"), plantReading("s2", "21.0.7")}},
	"inventory.removed_line_has_no_reading": {rule: "a removed line has no reading",
		plant: []row{{"inv_software", map[string]any{"state": "removed"}}, {"inv_software_reading", nil}}},
	"inventory.address_has_one_home": {rule: "an address is the address of one device",
		plant: []row{{"inv_asset", map[string]any{"id": "a1", "ip": "10.0.0.1", "mac": nil}}, {"inv_asset_address", map[string]any{"asset_id": "a1", "ip": "10.0.0.1", "mac": nil}}}},
	"inventory.present_line_has_a_reading": {rule: "a present line has a reading",
		plant: []row{{"inv_software", map[string]any{"state": "present"}}}},

	"sensor-active.no_pending_run_about_a_deleted_device": {rule: "no queued or waiting check is about a device that was deleted",
		control: []row{{"inv_asset", map[string]any{"id": "a1", "ip": nil, "mac": nil}}, {"core_run", deviceRun("r1", "lane-1", "waiting", "a1")},
			{"core_run", deviceRun("r2", "lane-2", "stopped", "a-gone")}}, // a finished run stays as a log of the device it ran on
		plant: []row{{"core_run", deviceRun("r3", "lane-3", "queued", "a-gone")}}},

	"findings.handled_complete": {rule: "a finding is open exactly when it has no resolution; a handled one says how, by whom and when",
		plant: []row{{"fnd_finding", map[string]any{"state": "open", "resolution": "patched"}}}},
	"findings.version_moved_versions": {rule: "patch credit for a version move names two different versions",
		plant: []row{{"fnd_finding", map[string]any{"via": "version_moved", "from_version": "1.0", "to_version": "1.0"}}}},
	"findings.fix_key_names_stored_fix": {rule: "a finding's fix group names its stored fix",
		plant: []row{{"fnd_finding", map[string]any{"fix_key": "acme|box|update|1.0", "fix_kind": "update", "fix_version": "2.0"}}}},
	"findings.vocabulary": {rule: "every stored value of an open vocabulary is one the code knows",
		plant: []row{{"fnd_finding", map[string]any{"basis": "rumour"}}}},
	"findings.event_vocabulary": {rule: "every finding event is of a known kind",
		plant: []row{{"fnd_finding_event", map[string]any{"kind": "rumour"}}}},
	"findings.question_vocabulary": {rule: "every question is of a known kind",
		plant: []row{{"fnd_question", map[string]any{"kind": "rumour"}}}},
	"findings.matched_version_on_line": {rule: "a detected finding names a version its own software line runs",
		provedBy: "cmd/vedette/matchset_schemes_test.go:TestSelfcheck_MatchedVersionOnLine"},
	"findings.cve_in_catalogue": {rule: "every finding's CVE is in the catalogue",
		plant: []row{{"fnd_finding", map[string]any{"cve": "CVE-2026-0001"}}}},
	"findings.catalogue_retention": {rule: "an old catalogue CVE is kept only for an exploited-list entry, a qualifying signal or a finding",
		plant: []row{{"feeds_cve", map[string]any{"cve": "CVE-2001-0001", "published": "2001-01-01T00:00:00.000Z"}}}},
	"findings.range_precedence": {rule: "a CVE record's ranges never win over NVD's for the same finding, except a product with a version scheme",
		provedBy: "cmd/vedette/matchset_schemes_test.go:TestSelfcheck_RangePrecedenceResolvesTheLineProduct"},
	"findings.urgency_recomputed": {rule: "a finding's stored urgency is the urgency rule recomputed",
		provedBy: "cmd/vedette/urgency_wiring_test.go:TestUrgencyWiring_StoresTheLayersAndTheSelfcheckAgrees"},
}

// plantLine is a present software line of a device whose stored value is the version of one agent reading, with no "differs".
func plantLine(id, productKey, train, version string) row {
	return row{"inv_software", map[string]any{"id": id, "product_key": productKey, "line": train, "state": "present", "source": "osquery", "version": version,
		"pkg_version": nil, "differs": 0, "not_installed_at": nil, "removed_at": nil}}
}

// plantReading is what an agent reads of line id: version, with no package release, at the device's main address.
func plantReading(id, version string) row {
	return row{"inv_software_reading", map[string]any{"software_id": id, "source": "osquery", "instance": "", "version": version, "pkg_version": nil,
		"packaged": 0, "set_by": nil, "first_seen": "2026-01-01T00:00:00.000Z", "seen_at": "2026-01-01T00:00:00.000Z", "addr_id": ""}}
}

// deviceRun is a sensor-active check of a device in a lane, in status.
func deviceRun(id, lane, status, device string) map[string]any {
	return map[string]any{"id": id, "module": "sensor-active", "lane": lane, "status": status, "subject_kind": "device", "subject_id": device,
		"ended_at": nil, "waiting_for": nil, "parent_id": nil, "schedule_id": nil}
}

// liveRun is a run in a lane that is going (status), with no parent and no schedule.
func liveRun(id, status string) map[string]any {
	return map[string]any{"id": id, "lane": "lane-1", "status": status, "ended_at": nil, "waiting_for": nil, "parent_id": nil, "schedule_id": nil}
}

// Every registered invariant has a case here, and every case names an invariant that is registered: an invariant is not added
// without a proof that it counts a break, and a case does not outlive its invariant.
func TestSelfcheck_EveryInvariantHasACase(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	for _, inv := range selfcheck.Registered() {
		registered[inv.Name] = true
		if _, ok := selfcheckCases[inv.Name]; !ok {
			t.Errorf("invariant %s has no case in selfcheckCases: plant rows that break it, or name the test that does", inv.Name)
		}
	}
	for name, c := range selfcheckCases {
		if !registered[name] {
			t.Errorf("selfcheckCases names %s, which is not registered", name)
		}
		if c.rule == "" || (len(c.plant) == 0) == (c.provedBy == "") {
			t.Errorf("case %s: give the rule and either rows to plant or the test that breaks it", name)
		}
	}
}

// Each invariant counts the rows that break its rule: the rows of its case on a fresh database give a count above zero (a fresh
// database gives zero, TestSelfcheckFreshDatabaseHoldsEveryInvariant). A case proved by another test names a test that exists.
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
				b, err := os.ReadFile(filepath.Join("..", "..", file)) //nolint:gosec // a path listed in this test
				if err != nil || !strings.Contains(string(b), "func "+test+"(") {
					t.Fatalf("%s names %s, which is not a test of %s (%v)", name, test, file, err)
				}
				return
			}
			ctx := t.Context()
			path := filepath.Join(t.TempDir(), "v.db")
			if err := writeMigrated(path); err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			p := newPlanter(t, db)
			dropped := false
			plant := func(ctx context.Context, tx *sql.Tx, rows []row) error {
				if c.drop != "" && !dropped {
					if _, err := tx.ExecContext(ctx, `DROP INDEX "`+c.drop+`"`); err != nil {
						return err
					}
					dropped = true
				}
				if err := p.begin(ctx, tx); err != nil {
					return err
				}
				for _, r := range rows {
					if c.noFK {
						if err := p.write(ctx, tx, r.table, r.set, "INSERT", 8); err != nil { // depth 8: no referenced rows are written
							return err
						}
					} else if err := p.insert(ctx, tx, r.table, r.set); err != nil {
						return err
					}
				}
				return p.end(ctx, tx)
			}
			plantAll := func(rows []row) {
				t.Helper()
				if !c.noFK {
					if err := db.Write(ctx, func(tx *sql.Tx) error { return plant(ctx, tx, rows) }); err != nil {
						t.Fatal(err)
					}
					return
				}
				raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String()) // SQLite's default: foreign keys off
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = raw.Close() }()
				tx, err := raw.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := plant(ctx, tx, rows); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			if len(c.control) > 0 {
				plantAll(c.control)
				if res := selfcheck.Run(ctx, db.Reader(), []selfcheck.Invariant{inv})[0]; res.Err != nil || res.Count != 0 {
					t.Fatalf("%s (%s): the valid control rows count %d (%v), want 0", name, c.rule, res.Count, res.Err)
				}
			}
			plantAll(c.plant)
			res := selfcheck.Run(ctx, db.Reader(), []selfcheck.Invariant{inv})[0]
			if res.Err != nil || res.Count == 0 {
				t.Errorf("%s (%s): the planted break counts %d (%v), want more than zero", name, c.rule, res.Count, res.Err)
			}
		})
	}
}
