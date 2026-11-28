package core

import "strings"

// The export policy of GET /core/data/export (INV-28): every column of every table of every module is listed here with what
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
// A table with skipAll is not exported at all (secrets, sign-in state, link state, public data the box pulls again, such as
// feeds_epss and the indicator lists, and the tables of logs.db, which this export does not read). Every table of docs/SCHEMA.sql,
// in both databases, is listed.
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
	"ai_read":                {export: "id ts connection_id connection_name tool job"}, // which connection tool the box read and when, never the output
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
	"core_run":               {export: "id module kind lane title trigger trigger_note requested_by schedule_id subject_kind subject_id subject_label parent_id status waiting_for stop_reason error total done queued_at started_at ended_at updated_at"}, // runs (core/run): what the box scanned, when and how it ended
	"core_run_item":          {export: "run_id seq subject_kind subject_id label outcome note"},
	"core_run_log":           {export: "id run_id ts level text"},
	"core_run_step":          {export: "run_id seq name status total done note started_at ended_at"},
	"core_schedule":          {export: "id owner_module owner_key enabled paused_until freq every_minutes at_time month_day once_at tz window_mode window_from window_to next_due_at last_due_at last_run_id last_skip_reason last_skip_at updated_by updated_at", json: "weekdays window_days"}, // schedules (core/schedule): when each kind of work runs
	"core_secret":            {skipAll: true, skip: "id purpose nonce ciphertext key_version last4 created_at rotated_at"},
	"core_sensor_cert":       {skipAll: true, skip: "serial role not_after retired_at"},
	"core_session":           {skipAll: true, skip: "id user_id token_hash csrf_hash device ip started_at last_seen expires_at revoked_at"},
	"core_setting":           {export: "key updated_at updated_by", json: "value"},
	"core_user":              {export: "id name email role cred_version twofa_method disabled created_at last_login sso_issuer sso_subject", skip: "password_hash temp_password_expires_at"},
	"core_user_totp":         {skipAll: true, skip: "user_id secret_id confirmed last_step created_at"},
	"exp_address":            {export: "id host_id target_id ip family class first_seen last_seen"},
	"exp_attempt":            {export: "id ts"},
	"exp_consent":            {export: "target_id kind version text by_name user_id method disruptive at"},
	"exp_deep_setting":       {export: "target_id dos logins web_active data_change openvas speed updated_at updated_by", json: "skip_ports skip_paths"},
	"exp_host":               {export: "id target_id name source selected child_target_id cname first_seen last_seen"},
	"exp_ignored":            {export: "value ignored_by ignored_at"},
	"exp_issue":              {export: "id target_id service_id engine key title severity state resolution resolved_by resolved_at note accepted_until first_seen last_seen last_run_id opened_at exploited", json: "cves detail"},
	"exp_outside":            {export: "target_id ip checked_at checked_by found", json: "answer"},
	"exp_scan":               {export: "run_id target_id mode", json: "summary"},
	"exp_service":            {export: "id target_id ip port proto name product version cpe title is_web ident state first_seen last_seen last_run_id opened_at", json: "cert"},
	"exp_setting":            {export: "id last_run_at last_run_ok last_run_message last_deep_at last_full_ok_at greenbone greenbone_by greenbone_at greenbone_sync_at greenbone_sync_ok greenbone_sync_note"},
	"exp_target":             {export: "id parent_id kind value origin scope_mode enabled method verified_at created_at proof_method", json: "last_check", skip: "token ip_token"},
	"feeds_cve":              {skipAll: true, skip: "cve published modified nvd_status nvd_at record_at title description cwe solution workaround ssvc_exploitation ssvc_automatable ssvc_impact updated_at assigner"}, // Public NVD and CVE Program data, pulled again
	"feeds_cve_metric":       {skipAll: true, skip: "cve source version score vector"},                                                                                                                                 // Public CVSS scores, pulled again
	"feeds_cve_range":        {skipAll: true, skip: "id cve origin part vendor product cpe start_incl start_excl end_incl end_excl fixed version_type default_status platforms"},                                       // Public affected versions, pulled again
	"feeds_cve_ref":          {skipAll: true, skip: "cve url tags source"},                                                                                                                                             // Public references of CVE records, pulled again
	"feeds_epss_hist":        {skipAll: true, skip: "cve day epss"},                                                                                                                                                    // FIRST's public scores of a few days, pulled again
	"feeds_line_cve":         {skipAll: true, skip: "source_id product cve stated_at ref only_builds"},                                                                                                                 // Public vendor statements per release line, pulled again
	"feeds_line_status":      {skipAll: true, skip: "source_id product cve line status introduced last_affected fixed explicit platforms"},                                                                             // Public vendor statements per release line, pulled again
	"feeds_cna":              {skipAll: true, skip: "short_name source_id organization may_be_vendor"},                                                                                                                 // The CVE Program's public CNA list, pulled again
	"feeds_line_support":     {skipAll: true, skip: "product line source_id released assessed_until eol last_release"},                                                                                                 // Public release-line support dates, pulled again
	"feeds_kev":              {export: "cve list source_id vendor product name description required_action date_added due_date ransomware announced_at updated_at", json: "links"},
	"feeds_nvd_cursor":       {skipAll: true, skip: "selector url mode win_from win_to until next_index total"},        // Where an unfinished pull goes on
	"feeds_signal":           {export: "cve kind source first_seen stored_at last_seen qualifies url", json: "detail"}, // Why a CVE is urgent and since when: the box's own first sightings
	"feeds_distro_fix":       {export: "source_id distro release package cve status fixed_version pro reason"},         // Public Ubuntu/Debian data
	"feeds_epss":             {skipAll: true, skip: "cve epss percentile gen"},                                         // FIRST's public scores of every CVE (400,000 rows), pulled again daily
	"feeds_epss_baseline":    {skipAll: true, skip: "id url count score_date"},                                         // The yardstick of the next EPSS file and FIRST's day of the scores
	"feeds_winrel":           {export: "build server product display line ga ga_rev"},                                  // The Windows releases Microsoft lists; kept so a restore reads the same builds
	"feeds_winrel_update":    {export: "build server rev kb day hotpatch"},                                             // The monthly Windows updates Microsoft lists; kept so a restore names the same target builds
	"feeds_fetch_log":        {export: "id source_id started_at finished_at status records_accepted records_rejected error bytes etag last_modified", json: "reject_reasons"},
	"feeds_ioc":              {skipAll: true, skip: "id type value first_seen last_seen"},         // Indicator lists the box pulls again (a third party's list, such as Spamhaus DROP, is never redistributed)
	"feeds_ioc_source":       {skipAll: true, skip: "ioc_id source_id last_seen confidence seen"}, // Which feed lists which indicator: pulled again with the lists
	"feeds_source":           {export: "id builtin name kind format enabled auth_type auth_header_name auth_username secret_last4 license created_at last_fetch last_success failures records status error etag last_modified mirror_etag mirror_last_modified catalog_version catalog_released rev answered_by stale_watch_from stale_alerted_at stale_failed_since stale_failed_checks distro_packages", json: "parser kev_copies", url: "url default_url", skip: "secret_id"},
	"feeds_weekly_answer":    {export: "key answer user_id answered_at device_added device_id have_since"},
	"fnd_finding":            {export: "id asset_id cve software_id detected basis verified range_origin matched_version fix_kind fix_version fix_ref fix_key state resolution via resolved_by resolved_at note accepted_until from_version to_version urgency urgency_at first_seen last_seen updated_at fix_channel", json: "evidence"}, // one row per (device, CVE, software line)
	"fnd_finding_event":      {export: "id finding_id ts actor kind", json: "detail"},                                                                                                                                                                                                                                                     // the history of each finding, append-only
	"fnd_question":           {export: "id asset_id software_id cve kind cves asked_at answer answered_by answered_at check_key", json: "detail"},                                                                                                                                                                                         // what Vedette cannot decide without a person
	"fnd_line_statement":     {export: "statement_key cve product_key line stated_line record_hash page_hash status introduced fixed_in last_affected reason quote url host vendor_page quote_found model profile activity_id asked_by asked_at seen_at rejected_by rejected_at basis"},                                                   // the AI's reading of a vendor's public statement for one release line, no device data
	"fnd_line_research":      {export: "statement_key layer quote_check tokens", json: "detail"},                                                                                                                                                                                                                                          // how the customer's AI researched a release line: layers, pages read, tokens; no device data
	"fnd_identity":           {export: "publisher name kind choice fit vendor product record kev title reason candidates model activity_id by at"},                                                                                                                                                                                        // the AI's choice, or a person's rejection, of the catalogue product of a software name, no device data
	"fnd_possible_check":     {export: "check_key cve product_key line version evidence_hash decided_by verdict confidence reason quote model profile activity_id checked_by checked_at rejected_by rejected_at", json: "sources detail"},                                                                                                 // one check of a possible CVE per evidence identity: public advisory text and the verdict, no device data
	"fnd_coverage_run":       {export: "id ran_at", json: "counts"},                                                                                                                                                                                                                                                                       // M-14: the decision coverage of each match pass, counts only
	"fnd_reach_run":          {export: "id ran_at stamp total", json: "counts unreachable added"},                                                                                                                                                                                                                                         // INV-4e, #910: the KEV reachability audit, public feed data only
	"hp_config":              {export: "key updated_at updated_by", json: "value"},
	"hp_hits":                {export: "id ts kind service label port src_ip is_test excerpt trap_ip trap_hostname token_id conn_key conn_count handshake", json: "events"},
	"hp_ignored_day":         {export: "day count"},
	"hp_tokens":              {export: "id type name value plant_at created_at", skip: "secret_id"},
	"ids_alert":              {export: "id source sid signature category priority src_ip dst_ip dst_port proto src_asset_id dst_asset_id first_ts last_ts count dedupe_key"},
	"ids_alert_cve":          {export: "alert_id cve"},
	"hp_trap_ips":            {export: "id name ip preset vendor enabled mac created_at enabled_at", json: "services"},
	"inv_asset":              {export: "id ip mac hostname kind vendor model os vendor_obs_id model_obs_id os_obs_id kind_obs_id hostname_obs_id mac_obs_id origin approved approved_at fragile fragile_manual regular_scan first_scan_at suspicious is_box notes first_seen last_seen agent_key agent_ip ip_confirmed_at user_name scan_source snmp_source agent_source ignored_at review_earned_at"},
	"inv_observation":        {export: "id asset_id field value source confidence seen_at evidence first_seen"},
	"inv_service":            {export: "id asset_id port proto name product version detail source confidence seen_at read_at addr_id"},
	"inv_setting":            {export: "key updated_at updated_by", json: "value"},
	"inv_software":           {export: "id asset_id product_key line display vendor product cpe version pkg_version pkg_source packaged source set_by confidence seen_at differs state not_installed_by not_installed_at first_seen last_seen removed_at"},
	"inv_software_reading":   {export: "software_id source instance display version pkg_version pkg_source packaged cpe confidence set_by first_seen seen_at addr_id item_vendor item_product item_version item_kev item_instance"},
	"inv_catalogue_pass":     {export: "id revision target after updated_at"},                                                      // the product catalogue the stored lines were identified under
	"inv_software_event":     {export: "id asset_id software_id product_key display ts kind from_version to_version source actor"}, // the history of a software line
	"inv_source":             {export: "source first_seen"},
	"inv_detected_keep":      {export: "asset_id field detected kept_at kept_by"},                    // detected values a person chose not to switch to
	"inv_separate":           {export: "a b decided_by decided_at"},                                  // pairs a person kept separate
	"inv_hand_seen":          {export: "asset_id mac first_seen last_seen"},                          // #829: MACs seen at a hand-added device's address
	"inv_asset_address":      {export: "id asset_id ip mac source first_seen last_seen main_card"},   // a device's addresses besides its main one
	"inv_merged_from":        {export: "asset_id from_id ip mac user_name merged_at", json: "facts"}, // what a person's merge took in, for Split off
	"inv_merged_reading":     {export: "asset_id from_id software_id product_key line source instance shared"},
	"inv_removed":            {export: "id name ip agent removed_by removed_at"}, // devices a person removed, kept out of discovery
	"inv_removed_id":         {export: "removed_id kind value"},                  // what keeps each removed device out
	"mit_ai_output":          {export: "finding_id skill model profile created_at activity_id", json: "payload"},
	"mit_applied":            {export: "finding_id item ts user"},
	"mit_pack":               {export: "cve confirmed_by confirmed_at drafted_with pack_version", json: "body compromise"},
	"mit_pack_state":         {export: "id version installed_at"},
	"notify_approver":        {export: "channel_type user_id address name"},
	"notify_channel":         {export: "type configured enabled secret_last4 app_token_last4 bot_token_last4 url_last4 min_severity approvals rev updated_at", jsonURL: "fields", json: "last_test", skip: "secret_id app_token_secret_id bot_token_secret_id url_secret_id"},
	"notify_incident":        {export: "id kind attempt title link severity what action first_seen last_seen count status handled_by handled_at note dedupe_key unsent unsent_floor unsent_channel resolved_reason active_at first_run summary_id"},
	"notify_incident_device": {export: "incident_id asset_id name"},
	"oidc_config":            {export: "id client_id secret_last4 scopes groups_claim default_role updated_at ca_pem", json: "role_map", url: "issuer redirect_uri", skip: "secret_id"},
	"oidc_flow":              {skipAll: true, skip: "state_hash binding_hash nonce verifier issuer client_id redirect_uri created_at expires_at"},
	"notify_notice":          {export: "id event created_at product title severity unsent unsent_floor unsent_channel", json: "cves"},
	"notify_notice_finding":  {export: "notice_id finding_id layer"},
	"notify_pending":         {export: "id channel notice_id reason due_at state claimed_at created_at attempts", json: "notice"},
	"notify_send":            {export: "id kind ref_id channel at ok error what link recipient delayed resend_of", json: "message", url: "to"},
	"intake_agent_tokens":    {export: "id name kind last4 created_at expires_at last_received created_by first_enrolled_at device_id", skip: "token_hash"},                                                                                                                                                                                          // the hash never leaves (agent-intake INV-3)
	"intake_wazuh":           {export: "id username password_last4 tls_pin tls_pin_first_seen generation status last_sync next_pull agents packages error resume_after pass_packages updated_at", url: "url", skip: "secret_id"},                                                                                                                     // the password stays in core_secret (agent-intake INV-6)
	"intake_osquery_nodes":   {export: "id token_id host_identifier hostname platform osquery_version enrolled_at last_seen last_call_at last_result_at bound_ip bound_mac reported approved_at kernel win_name win_version win_target report_asked_at software_taken_at os_taken_at call_every_s call_gap_s report_every_s", skip: "node_key_hash"}, // the key hash never leaves
	"intake_prune_clock":     {export: "id last_run"},                                                                                                                                                                                                                                                                                                // when node-prune last ran (agent-intake POST-4)
	"intake_wazuh_agent":     {export: "agent_id generation ip mac seen_at"},                                                                                                                                                                                                                                                                         // where each Wazuh agent's data went (agent-intake, #849)
	"mcp_tokens":             {export: "id name last4 created_at last_used", json: "scopes", skip: "token_hash"},                                                                                                                                                                                                                                     // the hash never leaves (mcp-server INV-3)
	"notify_send_notice":     {export: "send_id notice_id"},
	"notify_box":             {export: "id first_run_at discovery_told_at discovery_told_count"}, // when notify first ran (the first-discovery window)
	"notify_setting":         {export: "key updated_at updated_by", json: "value"},
	"notify_summary":         {export: "id due_at state done_at"}, // the daily summary's marks (when it came due, what it did)
	"notify_tg_button":       {skipAll: true, skip: "request_id nonce_hash expires_at message_id chat_id state tries"},
	"notify_slack_button":    {skipAll: true, skip: "request_id channel_id ts expires_at state outcome tries"},
	"notify_slack_final":     {skipAll: true, skip: "request_id outcome at"},
	"notify_slack_team":      {skipAll: true, skip: "id rev team_id"},
	"logs_retention":         {export: "id days"},
	"logs_siem":              {export: "id enabled format host port proto secret_last4", json: "events last_test", url: "url", skip: "secret_id"},
	"logs_sources":           {export: "id kind name sender_ip proto port created_at signatures_since client_cert_sha256"},
	"rep_definition":         {export: "id name kind updated_at updated_by send_due_at send_by", json: "options recipients"},
	"rep_history":            {export: "id definition_id ts title period_from period_to trigger status error sent_by", json: "recipients document"},
	"rep_pdpl":               {export: "id", json: "org report"},
	"resp_actions":           {export: "seq id source proposal_id rule_id rule_name trigger trigger_summary finding_id cve asset_id asset_name title risk status requested_at expires_at decided_at requires_approvals two_because note pre_approved end_reason", json: "approvals sent_to ai items"},
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
	"sa_all_ports":           {export: "asset_id last_at outcome"},
	"sa_probe":               {export: "id time run_id shape rate hosts flags targets result"},
	"sa_snmp_device":         {export: "asset_id read_from read_from_default version username auth priv secret_last4 priv_last4 port created_at updated_at last_checked_at last_status last_answer_at answer", skip: "secret_id priv_secret_id"}, // the community and v3 passwords stay in core_secret
	"sa_snmp_notice":         {export: "id at text"},                                                                                                                                                                                             // which SNMP settings a merge of two devices kept
	"scan_event":             {export: "id ts cve product latency_min run_id result", json: "devices"},
	"scan_probe":             {export: "id ts run_id ip label template request result"},
	"scan_setting":           {export: "id stop_on_unresponsive unresponsive_after auto_rescan updated_at updated_by kev_read_at kev_read_cve"},
	"sp_sensor":              {export: "id name interface span version last_seen devices_seen"},
	"sp_seq":                 {export: "sensor_id epoch last_seq"},
	"sp_span_stat":           {export: "sensor_id packets_per_s other_macs last_packet_at measured_at"},

	// logs.db, the volume of the logs module (a database of its own next to vedette.db). This export reads vedette.db only: received
	// lines and bad-address hits leave through GET /core/logs/export (its device_logs and known_bad sources), with their own caps,
	// and the counters below are rebuilt from new lines. Listed so that every table of the schema has a policy.
	"logs_events":            {skipAll: true, skip: "id ts source_id line"},
	"logs_ioc_hits":          {skipAll: true, skip: "id ts src_ip dest dest_kind seen_via feeds confidence source_id blocked listed_as"},
	"logs_volume":            {skipAll: true, skip: "id line_bytes"},
	"logs_source_buckets":    {skipAll: true, skip: "source_id bucket lines"},
	"logs_source_seen":       {skipAll: true, skip: "source_id last_received"},
	"logs_signature_daily":   {skipAll: true, skip: "day source_id signature dest count first_seen sample mined"},
	"logs_signature_buckets": {skipAll: true, skip: "source_id bucket sig_hash count mined"},
	"logs_signature_addrs":   {skipAll: true, skip: "source_id bucket sig_hash addr count"},
	"logs_anomaly_sent":      {skipAll: true, skip: "source_id kind signature ref target bounded sent_at"},
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
