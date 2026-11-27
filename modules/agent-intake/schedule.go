package agentintake

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// scheduleQuery is one query of the config every valid node gets. The list is the text the approved GUI shows under "What Vedette asks
// osquery for" (web/src/features/inventory/agentConfig.ts, OSQUERY_SCHEDULE); a test compares the two. Snapshot-only, read-only tables,
// no exec, file, hash or curl table, no distributed queries.
type scheduleQuery struct {
	name, query, platform string
	interval              int
}

// programsQuery is the Windows package list with the versions the machine itself registers for what runs: each SQL Server
// instance's PatchLevel, and each installed version of the .NET shared frameworks. The registry arms are first: a compound SELECT
// takes its column names from the first, and their rows come before the list's. reg_key is the registry key of a registry row,
// empty on a program.
const programsQuery = `SELECT '' AS name, r.data AS version, '' AS publisher, '' AS install_date, r.key AS reg_key FROM registry r ` +
	`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL%\Setup' AND r.name = 'PatchLevel' ` +
	`UNION ALL SELECT '', r.name, '', '', r.key FROM registry r ` +
	`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\dotnet\Setup\InstalledVersions\%\sharedfx\%' AND r.type != 'subkey' ` +
	`UNION ALL SELECT '', r.name, '', '', r.key FROM registry r ` +
	`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\%\sharedfx\%' AND r.type != 'subkey' ` +
	`UNION ALL SELECT name, version, publisher, install_date, '' FROM programs;`

var schedule = []scheduleQuery{
	{name: "os_version", query: "SELECT name, version, major, minor, patch, build, platform, arch FROM os_version;", interval: 3600},
	// Hourly, not daily (N52 W-2): osquery runs a query when the Unix time is a multiple of its splayed interval, so a daily one first runs up
	// to ~26 hours after the first hour, and a renamed machine kept its old name a day. One row; Fleet asks its host vitals hourly too.
	{name: "system_info", query: "SELECT hostname, hardware_vendor, hardware_model FROM system_info;", interval: 3600},
	{name: "interfaces", query: "SELECT d.mac, a.address FROM interface_details d JOIN interface_addresses a USING (interface) WHERE a.address NOT LIKE '%:%' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE '169.254.%' AND d.mac != '00:00:00:00:00:00';", interval: 3600},
	{name: "deb_packages", query: "SELECT name, version, arch, source FROM deb_packages;", interval: 3600, platform: "linux"},
	{name: "rpm_packages", query: "SELECT name, version, release, arch, epoch FROM rpm_packages;", interval: 3600, platform: "linux"},
	// With the installed programs, the versions the machine registers for what runs, where an Uninstall entry does not say it:
	// - the build of each SQL Server instance (Setup\PatchLevel, cumulative and security updates included), whose release's own
	//   Uninstall entry has no version or the one it was installed with. The key pattern is exact: osquery lists the subkeys of
	//   "Microsoft SQL Server" and reads their Setup key, and only MSSQL<n>.<instance>\Setup PatchLevel is returned.
	// - each installed version of each .NET shared framework (Microsoft.NETCore.App, Microsoft.AspNetCore.App,
	//   Microsoft.WindowsDesktop.App): the runtime installers register one value per version under
	//   dotnet\Setup\InstalledVersions\<arch>\sharedfx\<framework> (both registry views are read), the list `dotnet --list-runtimes`
	//   prints. The Uninstall entries are not it: the host resolver's stays at the runtime that installed it, a hosting bundle's names
	//   several frameworks. Two levels below a fixed path, one value per installed version.
	// In the same query so the values and the list come in one snapshot (the mapper sets the rows from them; a query of its own would
	// arrive in another request). First, so a list cut at maxRows keeps them; marked by reg_key, '' on every program row.
	{name: "programs", query: programsQuery, interval: 3600, platform: "windows"},
	// The running kernel release ("7.0.0-43-generic"), its own one-row query (a column on every package row would make a
	// big host's package list longer than osquery's logger_tls_max_linesize, and osquery drops such a line whole).
	{name: "kernel_info", query: "SELECT version FROM kernel_info;", interval: 3600, platform: "linux"},
	// Windows's monthly update revision (UBR, the 4460 of 10.0.22631.4460), without which no Windows range of NVD can be
	// read. osquery (5.12 and later) reads it from the registry itself (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion, value
	// UBR) into os_version.revision, a Windows-only column: a query of its own, so the os_version query above stays valid on Linux
	// and an older osquery without the column fails this query alone. The registry table is read for one value only (programs).
	{name: "os_revision", query: "SELECT name, version, revision, arch FROM os_version;", interval: 3600, platform: "windows"},
	// INV-22: the ports the machine listens on and the program behind each, so a machine known only through its agent
	// has Open services. Loopback is left out on the machine; on Linux only the host's own network namespace (pid 1's) counts, not the
	// inside of its containers (net_namespace is a Linux-only column, so Windows has its own query without it).
	{name: "listening_ports", query: "SELECT DISTINCT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p USING (pid) WHERE l.port > 0 AND l.protocol IN (6, 17) AND l.address NOT LIKE '127.%' AND l.address != '::1' AND l.net_namespace = (SELECT net_namespace FROM process_namespaces WHERE pid = 1);", interval: 3600, platform: "linux"},
	{name: "listening_ports_windows", query: "SELECT DISTINCT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p USING (pid) WHERE l.port > 0 AND l.protocol IN (6, 17) AND l.address NOT LIKE '127.%' AND l.address != '::1';", interval: 3600, platform: "windows"},
}

// The first report. osquery 5.12 runs a scheduled query when the Unix time is a multiple of its (splayed, ±10 %) interval, never at
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
	// its own answer: asked every minute until a usable revision came, not until os_version did
	"os_revision": "os_revision",
	// INV-22: the open ports, taken when the inventory stored the list
	"listening_ports": "services", "listening_ports_windows": "services",
}

// hasAnswer says whether the comma-separated list holds the answer.
func hasAnswer(reported, answer string) bool {
	return slices.Contains(strings.Split(reported, ","), answer)
}

// nodeSchedule is the interval of each query for this node at now, asking from src: the first-report interval for an answer still missing
// in the first hour, and for the software queries while a person's ask is open (report.go askOpen), the schedule's otherwise. A node bound to an address that now asks from another (a laptop DHCP moved) is asked for
// its interfaces every firstReportInterval until a report binds it again (#829): its reports reach its device by the node meanwhile
// (ingest.go), but its new address only with that answer. A node behind NAT gets an unbound address with that answer and is back on
// the hourly schedule.
func nodeSchedule(n nodeRow, now time.Time, src netip.Addr) map[string]int {
	out := make(map[string]int, len(schedule))
	young := !n.enrolledAt.IsZero() && now.Sub(n.enrolledAt) < firstReportWindow
	src = src.Unmap().WithZone("")
	moved := n.boundIP.IsValid() && src.Is4() && src != n.boundIP
	asked := askOpen(n, now)
	for _, q := range schedule {
		out[q.name] = q.interval
		if young && !hasAnswer(n.reported, firstReport[q.name]) || moved && q.name == "interfaces" || asked && slices.Contains(reportQueries, q.name) {
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
