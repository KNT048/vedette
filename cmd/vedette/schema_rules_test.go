package main

import (
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules"
)

// jsonColumnAllowList is every JSON column there is, as "table.column". A JSON column holds a value that is read and written
// whole and never filtered, joined or counted. A new one needs a reason in review, so the list is exact: a column missing
// here fails, and so does an entry that no longer exists.
var jsonColumnAllowList = []string{
	"ai_activity.hooks",
	"ai_activity.links",
	"ai_activity.tools",
	"ai_knowledge_doc.jobs",
	"ai_result.payload",
	"ai_rule.jobs",
	"ai_setting.value",
	"core_connection.allow",
	"core_schedule.weekdays",
	"core_schedule.window_days",
	"core_setting.value",
	"exp_issue.cves",
	"exp_issue.detail",
	"exp_outside.answer",
	"exp_scan.summary",
	"exp_service.cert",
	"exp_target.last_check",
	"feeds_cve.cwe",
	"feeds_cve_range.platforms",
	"feeds_cve_ref.tags",
	"feeds_fetch_log.reject_reasons",
	"feeds_kev.links",
	"feeds_signal.detail",
	"feeds_source.distro_packages",
	"feeds_source.parser",
	"fnd_finding.evidence",
	"fnd_finding_event.detail",
	"fnd_question.detail",
	"fnd_reach_run.added",
	"fnd_reach_run.counts",
	"fnd_reach_run.unreachable",
	"hp_config.value",
	"hp_hits.events",
	"hp_trap_ips.services",
	"inv_setting.value",
	"logs_siem.events",
	"logs_siem.last_test",
	"mcp_tokens.scopes",
	"mit_ai_output.payload",
	"mit_pack.body",
	"mit_pack.compromise",
	"notify_channel.fields",
	"notify_channel.last_test",
	"notify_notice.cves",
	"notify_pending.notice",
	"notify_send.message",
	"notify_setting.value",
	"oidc_config.role_map",
	"rep_history.recipients",
	"rep_history.report",
	"rep_pdpl.org",
	"rep_pdpl.report",
	"rep_schedule.recipients",
	"rep_weekly_ai.summary",
	"resp_actions.ai",
	"resp_actions.approvals",
	"resp_actions.items",
	"resp_actions.sent_to",
	"resp_ai_notes.evidence",
	"resp_catalog.precheck",
	"resp_catalog.precheck_refuse",
	"resp_catalog.rollback",
	"resp_catalog.run",
	"resp_catalog.verify",
	"resp_events.fields",
	"resp_plans.reads",
	"resp_plans.steps",
	"resp_rules.actions",
	"resp_rules.conditions",
	"resp_settings.value",
	"sa_snmp_device.answer",
	"scan_event.devices",
}

// longValueListAllowList is every CHECK that restricts a column to more than five text values, as "table.column". An open
// vocabulary (reasons, kinds, sources) is text with a shape check and a Go enum, so it never needs a table rebuild when it grows.
var longValueListAllowList = []string{
	"ai_assignment.job",
	"ai_result.kind",
	"hp_hits.service",
	"hp_trap_ips.preset",
	"inv_observation.field",
	"inv_observation.source",
	"inv_service.source",
	"inv_setting.key",
	"notify_channel.type",
	"notify_incident.unsent_channel",
	"notify_pending.channel",
	"notify_send.channel",
	"resp_actions.status",
	"resp_events.trigger",
	"resp_log.kind",
	"resp_rules.trigger",
	"sa_probe.shape",
	"scan_event.result",
	"scan_probe.result",
}

// moduleTables migrates a fresh database module by module, as start-up does, and returns for each table the module that made it.
func moduleTables(t *testing.T) (owner map[string]string, tables []storetest.SchemaTable) {
	t.Helper()
	db := storetest.New(t)
	owner = map[string]string{}
	for _, s := range migrationSets(wiredModules()) {
		if err := store.Migrate(t.Context(), db, s.Module, s.FS); err != nil {
			t.Fatal(err)
		}
		for _, tb := range storetest.Schema(t, db) {
			if _, seen := owner[tb.Name]; !seen {
				owner[tb.Name] = s.Module
			}
		}
	}
	return owner, storetest.Schema(t, db)
}

// manifestInfo is what the schema rules read from MANIFEST.yaml.
type manifestInfo struct {
	prefix  string
	depends []string
}

func manifestInfos(t *testing.T) map[string]manifestInfo {
	t.Helper()
	loaded, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]manifestInfo{}
	for _, m := range loaded {
		b, err := fs.ReadFile(modules.Manifests, m.ID+"/MANIFEST.yaml")
		if err != nil {
			t.Fatal(err)
		}
		var raw struct {
			Prefix *string `yaml:"tables_prefix"`
		}
		if err := yaml.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		info := manifestInfo{depends: m.Depends}
		if raw.Prefix != nil {
			info.prefix = *raw.Prefix
		}
		out[m.ID] = info
	}
	return out
}

// Every table carries the prefix of the module that made it, and a foreign key leaves a module only for a module it depends on.
func TestSchemaTablesUseTheirModulePrefix(t *testing.T) {
	owner, tables := moduleTables(t)
	infos := manifestInfos(t)
	for _, tb := range tables {
		if strings.HasPrefix(tb.Name, "core_migration_") || tb.Name == "core_schema_epoch" {
			continue
		}
		mod := owner[tb.Name]
		info, ok := infos[mod]
		if !ok || info.prefix == "" {
			t.Errorf("table %s: module %q has no tables_prefix in its manifest", tb.Name, mod)
			continue
		}
		if !strings.HasPrefix(tb.Name, info.prefix) {
			t.Errorf("table %s made by module %s does not start with %s", tb.Name, mod, info.prefix)
		}
		for _, to := range tb.ForeignKeys {
			target := owner[to]
			if target == mod || slices.Contains(info.depends, target) {
				continue
			}
			t.Errorf("table %s (module %s) has a foreign key to %s (module %q), which is not in its depends %v", tb.Name, mod, to, target, info.depends)
		}
	}
}

// A CHECK that lists more than five text values is on the allow-list.
func TestLongValueListsAreTheAllowList(t *testing.T) {
	_, tables := moduleTables(t)
	var got []string
	for _, tb := range tables {
		for _, col := range storetest.LongValueLists(tb.SQL, 5) {
			got = append(got, tb.Name+"."+col)
		}
	}
	compareAllowList(t, "CHECK with a value list longer than five", got, longValueListAllowList)
}

// The JSON columns are exactly the allow-list.
func TestJSONColumnsAreTheAllowList(t *testing.T) {
	_, tables := moduleTables(t)
	var got []string
	for _, tb := range tables {
		for _, col := range storetest.JSONColumns(tb.SQL) {
			got = append(got, tb.Name+"."+col)
		}
	}
	compareAllowList(t, "JSON column", got, jsonColumnAllowList)
}

func compareAllowList(t *testing.T, what string, got, allowed []string) {
	t.Helper()
	slices.Sort(got)
	for _, g := range got {
		if !slices.Contains(allowed, g) {
			t.Errorf("%s %s is not on the allow-list (cmd/vedette/schema_rules_test.go)", what, g)
		}
	}
	for _, a := range allowed {
		if !slices.Contains(got, a) {
			t.Errorf("allow-list entry %s is stale: no such %s any more", a, what)
		}
	}
	if os.Getenv("DUMP_ALLOW") != "" {
		for _, g := range got {
			t.Logf("ALLOW %s", g)
		}
	}
}

// That docs/SCHEMA.sql equals the migrated schema is TestSchemaFileIsCurrent in schema_test.go.
