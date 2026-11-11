package agentintake

import "github.com/knt048/vedette/core/api/oas"

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
}

// configResponse is the body of config for a valid node.
func configResponse() *oas.InventoryPostIntakeOsqueryConfigOK {
	m := make(oas.InventoryPostIntakeOsqueryConfigOKSchedule, len(schedule))
	for _, q := range schedule {
		item := oas.InventoryPostIntakeOsqueryConfigOKScheduleItem{Query: q.query, Interval: q.interval, Snapshot: oas.NewOptBool(true)}
		if q.platform != "" {
			item.Platform = oas.NewOptString(q.platform)
		}
		m[q.name] = item
	}
	return &oas.InventoryPostIntakeOsqueryConfigOK{Schedule: oas.NewOptInventoryPostIntakeOsqueryConfigOKSchedule(m)}
}
