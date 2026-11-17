package findings

import (
	"cmp"
	"slices"
)

// DistroAlpine is the distribution id of Alpine's rows in Vuln.Distro (feeds' alpine-osv, D-605) and of the platform list's fixed lists.
const DistroAlpine = "alpine"

// StatesAlpine says whether the device's own OS statement says Alpine Linux (D-605): the OS a person set (inventory INV-41, which
// wins), else the OS its agent reports, else its answer to Vedette's SNMP read. Never the folded OS, which can be nmap's or DHCP's
// guess. The feeds module fetches Alpine's data only while some device does (DistroLister, D-570).
func StatesAlpine(a Asset) bool {
	return slices.Contains(platformsIn(cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS)), DistroAlpine)
}
