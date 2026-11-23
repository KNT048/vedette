package findings

import (
	"context"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
)

// ScanReach says why the vulnerability scan does not reach a device: one of the Scan* values, or "" (not known or no reason: the line
// then says nothing about the scan). cmd/vedette sets it; without it the line does not mention the scan.
type ScanReach func(ctx context.Context, assetID string) string

// The ScanReach answers.
const (
	ScanOutside   = "outside"    // outside the confirmed scan ranges
	ScanOff       = "off"        // network scanning is off
	ScanNoRanges  = "no_ranges"  // no scan ranges are confirmed yet
	ScanByHand    = "by_hand"    // the device was added by hand and is not scanned
	ScanDeviceOff = "device_off" // this device's own scan setting is off
)

var reachText = map[string]string{
	ScanOutside:   "the device is outside the confirmed scan ranges",
	ScanOff:       "network scanning is off",
	ScanNoRanges:  "no scan ranges are confirmed yet",
	ScanByHand:    "the device was added by hand and is not scanned",
	ScanDeviceOff: "scanning is turned off for this device",
}

// versionSourceText is who gave the version, as the sentence of WhySuspected says it ("<source> states ...").
var versionSourceText = map[string]string{
	VersionByAgent:  "The agent on the device",
	VersionBySNMP:   "The device's own SNMP answer",
	VersionByStated: "The device's own statement on the network",
	VersionByScan:   "A network scan (a guess from what a service answers)",
	VersionByManual: "A person (entered on the Devices page)",
}

// deviceStatedSource says whether a version source is the device itself over a channel that answers for it (INV-2): its own agent,
// or its answer to Vedette's SNMP read. An LLDP statement, a scan's banner or a person's entry is not.
func deviceStatedSource(src string) bool { return src == VersionByAgent || src == VersionBySNMP }

// WhySuspected is the sentence under a suspected finding that says why it is not confirmed and what would confirm it, built only from
// facts the box has: the version and who gave it, whether a check exists for the CVE (checkKnown, hasCheck) and how the scan
// stands to the device (reach, "" = not known). A fact that is not known is left out, never guessed. The ways to confirm come in
// order: the device reports its version itself over SNMP or through the agent, then a safe vulnerability check (named only when one
// exists for the CVE). A person's own confirmation is not in the sentence: only an admin can make it, so the finding page adds it for
// an admin. now dates an SNMP answer that is too old to confirm (SNMPFresh).
func WhySuspected(basis Basis, known *KnownVersion, checkKnown, hasCheck bool, reach string, now time.Time) string {
	var b strings.Builder
	byDevice := known != nil && deviceStatedSource(known.Source)
	stale := byDevice && known.Source == VersionBySNMP && (known.SeenAt == nil || !snmpFresh(*known.SeenAt, now))
	switch {
	case basis == BasisVersion && stale:
		since := "a while"
		if known.SeenAt != nil {
			since = orgtime.CalendarDay(*known.SeenAt)
		}
		b.WriteString("Version match only: " + versionSourceText[known.Source] + " stated " + clean(known.Software) + " " + clean(known.Version) +
			", inside NVD's affected range, but the device has not answered SNMP since " + since + ", so that version no longer confirms it.")
	case basis == BasisVersion && byDevice:
		b.WriteString("Version match only: " + versionSourceText[known.Source] + " states " + clean(known.Software) + " " + clean(known.Version) +
			", inside NVD's affected range, but that range does not clearly cover this release (no end, or listed for another edition or release), so the version alone does not confirm it.")
	case basis == BasisVersion && known != nil:
		src := versionSourceText[known.Source]
		if src == "" {
			src = "The device"
		}
		b.WriteString("Version match only: " + src + " states " + clean(known.Software) + " " + clean(known.Version) + ", inside NVD's affected range.")
	case basis == BasisVersion:
		b.WriteString("Version match only: the version of the software is inside NVD's affected range.")
	default:
		b.WriteString("Product match only: the device runs the product, but its version is not known, so it could not be compared with NVD's affected range.")
	}
	switch {
	case stale:
		b.WriteString(" It is confirmed by itself once the device answers SNMP again: check that SNMP is on and reachable for it.")
	case !byDevice:
		b.WriteString(" It is confirmed by itself once the device reports its version: turn on SNMP for the device, or install the agent on it.")
	}
	switch {
	case checkKnown && !hasCheck:
		b.WriteString(" No safe vulnerability check exists for this CVE.")
	case checkKnown && reach != "":
		b.WriteString(" A safe vulnerability check exists for this CVE: run the check to confirm it (none has run: " + reachText[reach] + ").")
	case checkKnown:
		b.WriteString(" A safe vulnerability check exists for this CVE: run the check to confirm it.")
	}
	return b.String() // the last way, a person's confirmation, is the page's to offer: only to the role that can confirm
}
