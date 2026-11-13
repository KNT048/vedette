package core

import "strings"

// The export policy of GET /core/data/export (INV-28, D-154): every column of every table of every module is listed here with what
// the export does with it. It is explicit on purpose, and fail-closed: a table or column that is not listed is NOT exported, and
// cmd/vedette's TestExport_PolicyClassifiesEveryColumn fails until whoever adds a column (any module) classifies it. The classes:
//
//	export  the value as stored
//	json    a JSON text: secret-looking keys are dropped at any depth, like /core/logs/export (logexport.Scrub, INV-13); text that is
//	        not JSON becomes null
//	jsonurl json, and every "url" key is cut to scheme and host (a webhook address is a bearer secret)
//	url     a URL as text: userinfo, path and query are cut, leaving scheme://host (other text stays as it is)
//	skip    never exported: a secret, a reference to a secret, a hash or nonce of sign-in state
//
// A table with skipAll is not exported at all (secrets, sign-in state, link state).
type tablePolicy struct {
	skipAll                          bool
	export, json, jsonURL, url, skip string
}

type exportClass string

const (
	classExport  exportClass = "export"
	classJSON    exportClass = "json"
	classJSONURL exportClass = "jsonurl"
	classURL     exportClass = "url"
	classSkip    exportClass = "skip"
)

// tblCoreConnection is the table of the connections. It is also the name of the purpose of their credentials, which only
// core/conn/internal/cred may spell (core/conn TestOnlyCredNamesTheCredentialPurpose scans for that literal), so it is written in two
// parts here: this is the name of a table, not a purpose.
const tblCoreConnection = "core_" + "connection"

// exportPolicy is keyed by table name.
var exportPolicy = map[string]tablePolicy{
	"ai_activity":            {export: "seq id ts job profile profile_id model trigger input_hash output_hash summary tokens_in tokens_out result outcome stop retried prev_hash hash", json: "hooks tools links"},
	"ai_downgrade":           {export: "id ts from_tier to_tier reason"},
	"ai_hook":                {export: "id name name_key when match_type pattern action message enabled created_at updated_at"},
	"ai_hook_state":          {export: "builtin_id enabled"},
	"ai_knowledge_chunk":     {export: "id doc_id seq text"},
	"ai_knowledge_doc":       {export: "id name size status chunks uploaded_at", json: "jobs"},
	"ai_memory":              {export: "id text source created_at last_used_at enabled"},
	"ai_memory_rejected":     {skipAll: true, skip: "digest rejected_at"}, // the box's own memory of what not to suggest again, not data to take away
	"ai_memory_suggestion":   {export: "id text created_at evidence"},
	"ai_read":                {export: "id ts connection_id connection_name tool job"}, // which connection tool the box read and when, never the output (D-311)
	"ai_skill_state":         {export: "id enabled"},
	"ai_rule":                {export: "id text enabled created_at updated_at", json: "jobs"},
	"ai_result":              {export: "id kind key inputs_hash model profile tokens_in tokens_out asked_by activity_id created_at", json: "payload"},
	"ai_assignment":          {export: "job primary_profile_id fallback_profile_id"},
	"ai_profile":             {export: "id name name_key kind api_style model key_last4 location monthly_budget created_at updated_at", url: "base_url", skip: "secret_id"},
	"ai_setting":             {export: "key updated_at updated_by", json: "value"},
	"core_audit":             {export: "seq id prev_hash hash ts user action target detail"},
	"core_chain_anchor":      {export: "chain last_pruned_id last_pruned_hash pruned_at"},
	"core_chain_head":        {export: "chain last_hash count updated_at"},
	tblCoreConnection:        {export: "id name name_key kind asset_id auth_type username key_fp pin pin_seen enabled status updated_at", json: "allow last_test", url: "target", skip: "secret_id"},
	"core_connection_tool":   {export: "connection_id name pos access description enabled ident"},
	"core_email_code":        {skipAll: true, skip: "user_id code_hash expires_at tries sent_at"},
	"core_email_code_send":   {skipAll: true, skip: "user_id sent_at kind"},
	"core_job_run":           {export: "id module job started_at finished_at status error"},
	"core_module":            {export: "id enabled enabled_at disabled_at version"},
	"core_org":               {export: "id name timezone setup_complete data_mode install_id"},
	"core_secret":            {skipAll: true, skip: "id purpose nonce ciphertext key_version last4 created_at rotated_at"},
	"core_sensor_cert":       {skipAll: true, skip: "serial role not_after retired_at"},
	"core_session":           {skipAll: true, skip: "id user_id token_hash csrf_hash device ip started_at last_seen expires_at revoked_at"},
	"core_setting":           {export: "key updated_at updated_by", json: "value"},
	"core_user":              {export: "id name email role cred_version twofa_method disabled created_at last_login sso_issuer sso_subject", skip: "password_hash temp_password_expires_at"},
	"core_user_totp":         {skipAll: true, skip: "user_id secret_id confirmed last_step created_at"},
	"exp_attempt":            {export: "id ts"},
	"exp_ignored":            {export: "value ignored_by ignored_at"},
	"exp_setting":            {export: "id auto interval_min last_run_at last_run_ok last_run_message last_deep_at last_full_ok_at"},
	"exp_snapshot":           {export: "id target_id date scanned_at", json: "hosts ports admin_panels certs counts"},
	"exp_target":             {export: "id kind value method verified_at commitment_by commitment_at commitment_version commitment_sentence commitment_user_id commitment_method created_at last_scan_at", json: "last_check", skip: "token"},
	"feeds_affected":         {export: "cve cpe start_incl start_excl end_incl end_excl"}, // D-500: public NVD data
	"feeds_affected_cve":     {export: "cve updated_at"},
	"feeds_fetch_log":        {export: "id source_id started_at finished_at status records_accepted records_rejected error bytes etag last_modified", json: "reject_reasons"},
	"feeds_ioc":              {export: "id type value first_seen last_seen"},
	"feeds_ioc_source":       {export: "ioc_id source_id last_seen confidence seen"},
	"feeds_source":           {export: "id builtin name kind format enabled interval_hours auth_type auth_header_name auth_username secret_last4 license created_at last_fetch last_success failures records status error etag last_modified mirror_etag mirror_last_modified catalog_version rev answered_by", json: "parser", url: "url default_url", skip: "secret_id"},
	"feeds_template":         {export: "cve"},
	"feeds_vuln":             {export: "cve vendor product product_key name description required_action date_added due_date ransomware epss epss_7d_ago has_template source_id updated_at kev_announced_at", json: "links"},
	"feeds_weekly_answer":    {export: "key answer user_id answered_at device_added device_id have_since"},
	"fnd_finding":            {export: "id asset_id cve status severity confidence basis first_seen last_seen resolved_by resolved_at resolution_note resolution_reason accepted_until", json: "evidence"}, // accepted_until: D-498
	"fnd_finding_history":    {export: "id finding_id ts user action note"},
	"fnd_version_needed":     {export: "asset_id software_id software version cves updated_at"}, // D-500
	"hp_config":              {export: "key updated_at updated_by", json: "value"},
	"hp_hits":                {export: "id ts kind service label port src_ip is_test excerpt trap_ip trap_hostname token_id conn_key conn_count", json: "events"},
	"hp_ignored_day":         {export: "day count"},
	"hp_tokens":              {export: "id type name value plant_at created_at", skip: "secret_id"},
	"hp_trap_ips":            {export: "id name ip preset vendor enabled mac created_at enabled_at", json: "services"},
	"inv_asset":              {export: "id ip mac hostname kind vendor model os vendor_obs_id model_obs_id os_obs_id kind_obs_id hostname_obs_id mac_obs_id origin approved approved_at fragile fragile_manual regular_scan first_scan_at suspicious is_box notes first_seen last_seen"},
	"inv_observation":        {export: "id asset_id field value source confidence seen_at evidence"},
	"inv_service":            {export: "id asset_id port proto name product version source confidence seen_at"},
	"inv_setting":            {export: "key updated_at updated_by", json: "value"},
	"inv_software":           {export: "id asset_id display vendor product version cpe source confidence seen_at"},
	"inv_software_kev":       {export: "software_id kev_key"},
	"mit_ai_output":          {export: "finding_id skill model profile created_at activity_id", json: "payload"},
	"mit_applied":            {export: "finding_id item ts user"},
	"mit_pack":               {export: "cve confirmed_by confirmed_at drafted_with pack_version", json: "body compromise"},
	"mit_pack_state":         {export: "id version installed_at"},
	"notify_approver":        {export: "channel_type user_id address name"},
	"notify_channel":         {export: "type configured enabled secret_last4 app_token_last4 bot_token_last4 url_last4 min_severity approvals rev updated_at", jsonURL: "fields", json: "last_test", skip: "secret_id app_token_secret_id bot_token_secret_id url_secret_id"},
	"notify_incident":        {export: "id kind attempt title link severity what action first_seen last_seen count status handled_by handled_at note dedupe_key unsent unsent_floor unsent_channel"},
	"notify_incident_device": {export: "incident_id asset_id name"},
	"oidc_config":            {export: "id client_id secret_last4 scopes groups_claim default_role updated_at ca_pem", json: "role_map", url: "issuer redirect_uri", skip: "secret_id"},
	"oidc_flow":              {skipAll: true, skip: "state_hash binding_hash nonce verifier issuer client_id redirect_uri created_at expires_at"},
	"notify_kev":             {export: "cve seen_at matched"},
	"notify_notice":          {export: "id created_at product", json: "cves"},
	"notify_notice_finding":  {export: "notice_id finding_id"},
	"notify_pending":         {export: "id channel notice_id reason due_at state claimed_at created_at attempts", json: "notice"},
	"notify_send":            {export: "id kind ref_id channel at ok error what link recipient delayed", json: "message", url: "to"},
	"intake_agent_tokens":    {export: "id name kind last4 created_at expires_at last_received created_by", skip: "token_hash"},                                                                                                                   // the hash never leaves (agent-intake INV-3)
	"intake_wazuh":           {export: "id username password_last4 interval_minutes tls_pin tls_pin_first_seen generation status last_sync next_pull agents packages error resume_after pass_packages updated_at", url: "url", skip: "secret_id"}, // the password stays in core_secret (agent-intake INV-6)
	"intake_osquery_nodes":   {export: "id token_id host_identifier hostname platform osquery_version enrolled_at last_seen last_result_at bound_ip bound_mac reported approved_at", skip: "node_key_hash"},                                       // the key hash never leaves
	"intake_prune_clock":     {export: "id last_run"},                                                                                                                                                                                             // when node-prune last ran (agent-intake POST-4)
	"mcp_tokens":             {export: "id name last4 created_at last_used", json: "scopes", skip: "token_hash"},                                                                                                                                  // the hash never leaves (mcp-server INV-3)
	"notify_send_notice":     {export: "send_id notice_id"},
	"notify_box":             {export: "id first_run_at discovery_told_at discovery_told_count"}, // when notify first ran (D-483 first-discovery window)
	"notify_setting":         {export: "key updated_at updated_by", json: "value"},
	"notify_tg_button":       {skipAll: true, skip: "request_id nonce_hash expires_at message_id chat_id state tries"},
	"notify_slack_button":    {skipAll: true, skip: "request_id channel_id ts expires_at state outcome tries"},
	"notify_slack_final":     {skipAll: true, skip: "request_id outcome at"},
	"notify_slack_team":      {skipAll: true, skip: "id rev team_id"},
	"logs_retention":         {export: "id days"},
	"logs_siem":              {export: "id enabled format host port proto secret_last4", json: "events last_test", url: "url", skip: "secret_id"},
	"logs_sources":           {export: "id kind name sender_ip proto port created_at signatures_since client_cert_sha256"},
	"rep_history":            {export: "id ts trigger status error", json: "recipients report"},
	"rep_pdpl":               {export: "id", json: "org report"},
	"rep_schedule":           {export: "id enabled zone day hour armed_at last_slot_at", json: "recipients"},
	"rep_weekly_ai":          {export: "id", json: "summary"},
	"resp_actions":           {export: "seq id source proposal_id rule_id rule_name trigger trigger_summary finding_id cve asset_id asset_name title risk status requested_at expires_at decided_at requires_approvals two_because note pre_approved", json: "approvals sent_to ai items"},
	"resp_ai_notes":          {export: "id ts kind title why confidence action_id target evidence"},
	"resp_allowlist":         {export: "value label"},
	"resp_block_entries":     {export: "value request_id item_id source reason added_at expires_at"},
	"resp_blocklist":         {export: "id token_last4 last_fetch_at last_fetch_from", skip: "token_hash secret_id"},
	"resp_catalog":           {export: "id builtin pack kind name description connection_id tool rollback_tool risk enabled ai_may_propose position precheck_expect", json: "run rollback verify precheck precheck_refuse"},
	"resp_done":              {export: "rule_id event_id at"},
	"resp_events":            {export: "seq id trigger ts summary device_kind asset_id finding_id cve processed", json: "fields"},
	"resp_hints":             {export: "id ts kind text from_request"},
	"resp_log":               {export: "seq id ts kind actor detail prev_hash hash"},
	"resp_plans":             {export: "id finding_id cve asset_id asset_name generated_at model profile path", json: "reads steps"},
	"resp_rules":             {export: "seq id name enabled live trigger pre_approved max_per_hour schedule_min template_id last_fired", json: "match conditions actions"},
	"resp_settings":          {export: "id updated_at", json: "value"},
	"resp_identity":          {export: "user_id channel address linked_at"},
	"resp_link_codes":        {skipAll: true, skip: "user_id channel address code_hash expires_at sent_at tries"},
	"resp_tokens":            {skipAll: true, skip: "token_hash kind decision action_id user_id address channel key_id expires_at used_at"},
	"sa_job":                 {export: "id kind reason started_at finished_at status targets new_devices error"},
	"sa_probe":               {export: "id time job_id shape rate hosts flags targets result"},
	"sa_queue":               {export: "asset_id queued_at reason attempts"},
	"sa_sweep":               {export: "id cursor updated_at"},
	"sa_first_pass":          {export: "id started_at"},
	"sa_snmp":                {export: "id name version username auth priv secret_last4 priv_last4 scope created_at updated_at last_answer_at answered", skip: "secret_id priv_secret_id"}, // the community and v3 passwords stay in core_secret (D-512)
	"scan_event":             {export: "id ts cve product latency_min run_id result", json: "devices"},
	"scan_probe":             {export: "id ts run_id ip label template request result"},
	"scan_run":               {export: "id trigger trigger_note started_at started_by ended_at status total done stop_reason stop_requested_at matched", json: "picked target_ids current results identification"},
	"scan_setting":           {export: "id win_from win_to rate stop_on_unresponsive unresponsive_after auto_rescan sched_enabled sched_frequency sched_weekday sched_at updated_at updated_by sched_last kev_read_at kev_read_cve", json: "days exclusions"},
	"sp_sensor":              {export: "id name interface span version last_seen devices_seen"},
	"sp_seq":                 {export: "sensor_id epoch last_seq"},
	"sp_span_stat":           {export: "sensor_id packets_per_s other_macs last_packet_at measured_at"},
}

// exportClasses is exportPolicy read once: table -> column -> class.
var exportClasses = func() map[string]map[string]exportClass {
	out := make(map[string]map[string]exportClass, len(exportPolicy))
	for tbl, p := range exportPolicy {
		out[tbl] = classesOf(p)
	}
	return out
}()

func classesOf(p tablePolicy) map[string]exportClass {
	m := map[string]exportClass{}
	for class, list := range map[exportClass]string{classExport: p.export, classJSON: p.json, classJSONURL: p.jsonURL, classURL: p.url, classSkip: p.skip} {
		for _, c := range strings.Fields(list) {
			m[c] = class
		}
	}
	return m
}

// ExportColumnClass is what the export does with table.column: "export", "json", "jsonurl", "url" or "skip"; "" when the column is
// not classified (it is then not exported). A table that is skipped whole answers "skip" for its columns.
func ExportColumnClass(table, column string) string {
	if p, ok := exportPolicy[table]; ok && p.skipAll {
		if _, listed := exportClasses[table][column]; listed {
			return string(classSkip)
		}
		return ""
	}
	return string(exportClasses[table][column])
}

// ExportPolicyColumns lists the columns the policy names for a table (every class), so a test can find a column that no longer exists.
func ExportPolicyColumns(table string) []string {
	out := make([]string, 0, len(exportClasses[table]))
	for c := range exportClasses[table] {
		out = append(out, c)
	}
	return out
}

// ExportTables lists the tables the policy knows, whole-skipped ones included.
func ExportTables() []string {
	out := make([]string, 0, len(exportPolicy))
	for t := range exportPolicy {
		out = append(out, t)
	}
	return out
}
