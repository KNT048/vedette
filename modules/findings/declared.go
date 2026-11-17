package findings

import (
	"regexp"
	"slices"
	"strings"
)

// The OS a person declared as a software row ("FortiGate", FortiOS v7.2.13) is the device's OS only where the matcher reads it as
// such. The device page (inventory INV-45) asks this file instead of keeping rules of its own, so the OS a device page shows is
// the OS its findings are decided on: one owner of the choice.

// leadingV is the "v" a release is often written with ("v7.2.13"); parseVersion reads it, and so does OSVersion.
var leadingV = regexp.MustCompile(`^[vV](\d)`)

// OSVersion is a version as the matcher reads it: trimmed, without a leading "v" before a digit ("v7.2.13" -> "7.2.13"). A network
// OS scheme orders the result (osRow.reads), and the device page shows it.
func OSVersion(v string) string { return leadingV.ReplaceAllString(strings.TrimSpace(v), "$1") }

// DeclaredOSRow is, of the candidate rows (ids of a's software a person declared as an OS or firmware, the preferred first), the one
// the matcher reads as the device's OS, with its version as the matcher reads it (OSVersion); "" when none: the OS the device
// states (its SNMP answer, its LLDP statement on its vendor's card) decides instead (deviceOS: a person's row without a version, or
// with one the OS's scheme cannot order, gives way), or the agent's Windows release row covers the row (withoutCoveredWindows).
func DeclaredOSRow(a Asset, candidates []string) (id, version string) {
	rows := deviceSoftware(a)
	if slices.ContainsFunc(rows, func(s Software) bool { return s.ID == osSoftwareID(a.ID) }) {
		return "", ""
	}
	for _, c := range candidates {
		if i := slices.IndexFunc(rows, func(s Software) bool { return s.ID == c }); i >= 0 {
			return c, OSVersion(rows[i].Version)
		}
	}
	return "", ""
}

// MatchedSoftware is the software the matcher reads for a device: its rows, with the OS the device states as a row of its own when
// that statement decides (deviceOS), less the rows that give way to it or to the agent's Windows release row.
func MatchedSoftware(a Asset) []Software { return deviceSoftware(a) }
