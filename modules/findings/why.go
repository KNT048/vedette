package findings

import (
	"context"
	"strings"
)

// ScanReach says how the vulnerability scan stands to a device: ScanCovered (its checks run on it), ScanOutside (outside the confirmed
// scan ranges), ScanOff (network scanning is off, here or for the device) or "" (not known: the line then says nothing about
// the scan). cmd/vedette sets it; without it the line does not mention the scan.
type ScanReach func(ctx context.Context, assetID string) string

// The ScanReach answers.
const (
	ScanCovered = "covered"
	ScanOutside = "outside"
	ScanOff     = "off"
)

// versionSourceText is who gave the version, as the sentence of WhySuspected says it ("<source> states ...").
var versionSourceText = map[string]string{
	VersionByAgent:  "The agent on the device",
	VersionBySNMP:   "The device's own SNMP answer",
	VersionByStated: "The device's own statement on the network",
	VersionByScan:   "A network scan (a guess from what a service answers)",
	VersionByManual: "A person (entered on the Devices page)",
}

// WhySuspected is the sentence under a suspected finding that says why it is not confirmed and what would confirm it, built only from
// facts the box has: the version and who gave it, whether a check exists for the CVE (checkKnown, hasCheck) and how the scan
// stands to the device (reach, "" = not known). A fact that is not known is left out, never guessed.
func WhySuspected(basis Basis, known *KnownVersion, checkKnown, hasCheck bool, reach string) string {
	var b strings.Builder
	switch {
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
	case checkKnown && !hasCheck:
		b.WriteString(" A vulnerability check would confirm it, but none exists for this CVE, so only a person can.")
	case checkKnown && reach == ScanOff:
		b.WriteString(" A vulnerability check can confirm it, but none has run: network scanning is off for this device.")
	case checkKnown && reach == ScanOutside:
		b.WriteString(" A vulnerability check can confirm it, but none has run: the device is outside the confirmed scan ranges.")
	case checkKnown && reach == ScanCovered:
		b.WriteString(" A vulnerability check can confirm it: a scan of this device runs it.")
	case checkKnown:
		b.WriteString(" A vulnerability check can confirm it.")
	}
	b.WriteString(" Or confirm it yourself.")
	return b.String()
}
