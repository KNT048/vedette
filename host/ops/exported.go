package ops

import (
	"context"
	"io"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Pure functions that the contract tests (modules/host) and the fuzz targets exercise from
// outside the package. They have no side effects and take no paths.

// ReadArchive walks a backup archive and hands each accepted member to sink (see readArchive for
// what is accepted). It never writes anywhere.
func ReadArchive(r io.Reader, sink func(name string, data []byte) error) error {
	return readArchive(r, func(name string, mr io.Reader, size int64) error {
		b, err := io.ReadAll(io.LimitReader(mr, size))
		if err != nil {
			return err
		}
		return sink(name, b)
	})
}

// ParseManifest validates the text of a backup manifest.
func ParseManifest(b []byte) (Manifest, error) { return parseManifest(b) }

// ValidateApt is the validator of the apt-get binary: the only argv shapes it may ever be given.
func ValidateApt(args []string) error { return validateApt(args) }

// ValidateSystemctl returns the validator of the systemctl binary for a given core unit.
func ValidateSystemctl(coreUnit string) func([]string) error { return validateSystemctl(coreUnit) }

// ValidateJournal is the validator of the journalctl binary.
func ValidateJournal(args []string) error { return validateJournal(args) }

// RandomID is a fresh 32-hex id (what a snapshot id looks like). Test support.
func RandomID() (string, error) { return randomHex(16) }

// ParseSnapshotMeta validates the text of a snapshot's snapshot.json.
func ParseSnapshotMeta(b []byte) (created time.Time, schema string, includesKey bool, err error) {
	m, err := parseSnapshotMeta(b)
	return m.created, m.DBSchema, m.IncludesKey, err
}

// ValidateNetplan is the validator of the netplan binary (production: "apply" only).
func ValidateNetplan(args []string) error { return validateNetplan(args) }

// ValidateChronyc is the validator of the chronyc binary.
func ValidateChronyc(args []string) error { return validateChronyc(args) }

// ParseARP validates one ARP frame (exactly 42 bytes) and reports its opcode, sender MAC and sender IP.
// The fuzz targets and the contract tests call it; the host's own code calls parseARP.
func ParseARP(b []byte) (op uint16, senderMAC [6]byte, senderIP [4]byte, err error) {
	p, err := parseARP(b)
	return p.Op, p.SenderMAC, p.SenderIP.As4(), err
}

// BinIP is the name of ip in the command runner (the literal is spelled once, here).
const BinIP = binIP

// BinConntrack is the name of conntrack in the command runner.
const BinConntrack = binConntrack

// BinAppArmorParser is the name of apparmor_parser in the command runner (D-458).
const BinAppArmorParser = binAppArmorParser

// AppArmorLoadArgs is the one argv apparmor_parser may be given (D-458).
func AppArmorLoadArgs() []string { return append([]string(nil), argsAppArmorLoad...) }

// ValidateAppArmorParser is the validator of apparmor_parser (D-458).
func ValidateAppArmorParser(args []string) error { return validateAppArmorParser(args) }

// ValidateConntrack is the validator of the conntrack binary: the one fixed delete of the stale syslog flows (D-268).
func ValidateConntrack(args []string) error { return validateConntrack(args) }

// ConntrackArgs is the one argv conntrack may be given.
func ConntrackArgs() []string { return append([]string(nil), argsConntrackSyslog...) }

// ReapplyDecoys is the re-apply hook with no configuration hint, for the contract tests.
func (o *Ops) ReapplyDecoys(ctx context.Context) error { return o.reapplyDecoys(ctx, nil) }

// ValidateIP is the grammar of ip (decoy commands), for the contract tests.
func ValidateIP(args []string) error { return validateIP(args) }

// ValidatePodman is the validator of the podman binary: "container inspect vedette-<service>" only.
func ValidatePodman(args []string) error { return validatePodman(args) }

// RunStart runs the body of container.start on a context of the caller's choosing and with no run
// context, for the tests of the timeout path. The host itself only reaches it through the command.
func (o *Ops) RunStart(ctx context.Context, a api.ContainerStartArgs) (any, error) {
	return o.runContainerStart(ctx, nil, a)
}

// BinIptables is the name of iptables in the command runner (the Docker forward rules, D-267).
const BinIptables = binIptables

// ValidateIptables is the validator of the iptables binary: the only argv shapes it may ever be given.
func ValidateIptables(args []string) error { return validateIptables(args) }
