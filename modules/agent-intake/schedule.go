package agentintake

import (
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// scheduleQuery is one query of the config every valid node gets. The list is the text the approved GUI shows under "What Vedette asks
// osquery for" (web/src/features/inventory/agentConfig.ts, OSQUERY_SCHEDULE); a test compares the two. Snapshot-only, read-only tables,
// no exec, file, hash or curl table, no distributed queries (D-169 (1)).
type scheduleQuery struct {
	name, query, platform string
	interval              int
}

var schedule = []scheduleQuery{
	{name: "os_version", query: "SELECT name, version, major, minor, patch, build, platform, arch FROM os_version;", interval: 3600},
	{name: "system_info", query: "SELECT hostname, hardware_vendor, hardware_model FROM system_info;", interval: 86400},
	{name: "interfaces", query: "SELECT d.mac, a.address FROM interface_details d JOIN interface_addresses a USING (interface) WHERE a.address NOT LIKE '%:%' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE '169.254.%' AND d.mac != '00:00:00:00:00:00';", interval: 3600},
	{name: "deb_packages", query: "SELECT name, version, arch, source FROM deb_packages;", interval: 3600, platform: "linux"},
	{name: "rpm_packages", query: "SELECT name, version, release, arch, epoch FROM rpm_packages;", interval: 3600, platform: "linux"},
	{name: "programs", query: "SELECT name, version, publisher, install_date FROM programs;", interval: 3600, platform: "windows"},
	// D-516: the running kernel release ("7.0.0-43-generic"), its own one-row query (a column on every package row would make a
	// big host's package list longer than osquery's logger_tls_max_linesize, and osquery drops such a line whole).
	{name: "kernel_info", query: "SELECT version FROM kernel_info;", interval: 3600, platform: "linux"},
}

// The first report (D-503). osquery 5.12 runs a scheduled query when the Unix time is a multiple of its (splayed, ±10 %) interval, never at
// start (osquery/dispatcher/scheduler.cpp at 5.12.1), so with the hourly schedule a new machine showed its OS after up to an hour and
// its system_info after up to a day. Within firstReportWindow of its enrolment a node is asked every firstReportInterval seconds for each
// answer of its first report that the inventory has not taken yet (nodeRow.reported); osquery re-reads its config every 300 s
// (--config_refresh in the install scripts), so once the answers are in, the node is back on the schedule above within five minutes. A
// node that never matches its address (NAT) stops asking after the window.
const (
	firstReportInterval = 60
	firstReportWindow   = time.Hour
)

// firstReport maps each query to the answer of the first report it gives; the package queries are one answer (a host has one kind).
var firstReport = map[string]string{
	"os_version": "os_version", "system_info": "system_info", "interfaces": "interfaces",
	"deb_packages": "packages", "rpm_packages": "packages", "programs": "packages", "kernel_info": "packages",
}

// hasAnswer says whether the comma-separated list holds the answer.
func hasAnswer(reported, answer string) bool {
	return slices.Contains(strings.Split(reported, ","), answer)
}

// nodeSchedule is the interval of each query for this node at now: the first-report interval for an answer still missing in the first
// hour, the schedule's otherwise.
func nodeSchedule(n nodeRow, now time.Time) map[string]int {
	out := make(map[string]int, len(schedule))
	young := !n.enrolledAt.IsZero() && now.Sub(n.enrolledAt) < firstReportWindow
	for _, q := range schedule {
		out[q.name] = q.interval
		if young && !hasAnswer(n.reported, firstReport[q.name]) {
			out[q.name] = firstReportInterval
		}
	}
	return out
}

// configResponse is the body of config for a valid node, with the intervals of nodeSchedule.
func configResponse(intervals map[string]int) *oas.InventoryPostIntakeOsqueryConfigOK {
	m := make(oas.InventoryPostIntakeOsqueryConfigOKSchedule, len(schedule))
	for _, q := range schedule {
		item := oas.InventoryPostIntakeOsqueryConfigOKScheduleItem{Query: q.query, Interval: intervals[q.name], Snapshot: oas.NewOptBool(true)}
		if q.platform != "" {
			item.Platform = oas.NewOptString(q.platform)
		}
		m[q.name] = item
	}
	return &oas.InventoryPostIntakeOsqueryConfigOK{Schedule: oas.NewOptInventoryPostIntakeOsqueryConfigOKSchedule(m)}
}
