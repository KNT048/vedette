package sensoractive

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/knt048/vedette/core/exec"
)

// scanKind says which of the three nmap command lines is built (D-84 (7)).
type scanKind int

const (
	kindSweep  scanKind = iota // host discovery: -sn
	kindNormal                 // service and OS identification
	kindGentle                 // the one gentle scan of a fragile device (D-45)
)

// MaxBatch is the most addresses one nmap run gets, so its XML stays small (D-84 (7)).
const MaxBatch = 64

// maxOutput caps what one nmap run may print; more means the run is discarded (INV-7).
const maxOutput = 8 << 20

const (
	flagPrivileged  = "--privileged" // use raw sockets granted by CAP_NET_RAW instead of checking for uid 0 (D-84 (8))
	flagNoDNS       = "-n"           // never resolve names: no packet may reach a resolver outside the scope (INV-1)
	flagMaxRate     = "--max-rate"   // limits port scanning and host discovery only; OS and version detection time themselves
	flagTopPorts    = "--top-ports"
	flagMaxRetries  = "--max-retries"
	flagTiming      = "-T2"
	flagHostTimeout = "--host-timeout" // bounds the time one host may take, which --max-rate does not
	flagXML         = "-oX"
)

// Host time limits (D-84 (7)): a gentle scan is slow by design, a normal one has -sV and -O to finish.
const (
	gentleHostTimeout = "15m"
	normalHostTimeout = "30m"
)

// name is the short template id stored in sa_probe.shape.
func (k scanKind) name() string {
	switch k {
	case kindSweep:
		return "sweep"
	case kindNormal:
		return "normal"
	case kindGentle:
		return "gentle"
	}
	return ""
}

// flagsFor is the whole flag part of the command line of a kind: the only three shapes nmap is ever run with.
// -sV makes nmap run the scripts of its "version" category (and nothing else), -O has its own timing; no
// script flag, no -A and no -sC exists (FORBID-3, FORBID-6). The gentle shape has neither -sV nor -O: on a
// fragile device even the version scripts are too much (PLC protocol probes).
func flagsFor(kind scanKind, rate int) ([]string, error) {
	if rate < 1 || rate > 1000 {
		return nil, fmt.Errorf("sensoractive: rate %d is outside 1..1000", rate)
	}
	r := strconv.Itoa(rate)
	switch kind {
	case kindSweep:
		return []string{flagPrivileged, "-sn", flagNoDNS, flagMaxRate, r}, nil
	case kindNormal:
		return []string{flagPrivileged, "-sS", "-sV", "-O", flagNoDNS, flagMaxRate, r, flagTopPorts, "1000", flagHostTimeout, normalHostTimeout}, nil
	case kindGentle:
		return []string{flagPrivileged, "-sS", flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	}
	return nil, errors.New("sensoractive: unknown scan kind")
}

// atoi accepts only plain decimal digits (no sign, no spaces, no leading zero).
func atoi(s string) (int, bool) {
	if s == "" || len(s) > 4 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// validTarget: a LAN range can only hold private unicast IPv4 addresses (RFC 1918), so nothing else may ever
// be named, whatever the caller says (0/8, 127/8, 169.254/16, 100.64/10, multicast, reserved and broadcast
// are all outside 10/8, 172.16/12 and 192.168/16).
func validTarget(a netip.Addr) bool { return a.IsValid() && a.Is4() && a.Zone() == "" && a.IsPrivate() }

// buildNmapArgs builds an nmap command line only from private IPv4 addresses, an integer rate and the fixed
// flags above (INV-4, FORBID-3). The shape is: the flags of the kind, -oX -, then the targets.
func buildNmapArgs(kind scanKind, rate int, targets []netip.Addr) ([]string, error) {
	if len(targets) == 0 || len(targets) > MaxBatch {
		return nil, fmt.Errorf("sensoractive: a run needs 1 to %d targets, got %d", MaxBatch, len(targets))
	}
	args, err := flagsFor(kind, rate)
	if err != nil {
		return nil, err
	}
	args = append(args, flagXML, "-")
	for _, t := range targets {
		if !validTarget(t) {
			return nil, fmt.Errorf("sensoractive: target %q is not a private IPv4 address", t)
		}
		args = append(args, t.String())
	}
	return args, nil
}

// ValidateNmapArgs is the Validate func of the nmap Binary: it re-checks the whole argv before the process
// starts, independently of how buildNmapArgs made it (SYS-2). It accepts exactly the three shapes of flagsFor
// (sweep, normal, gentle), where only the rate of sweep and normal varies, then "-oX -", then 1 to MaxBatch
// canonical, unique, private IPv4 addresses. Everything else is rejected.
func ValidateNmapArgs(args []string) error {
	i := slices.Index(args, flagXML)
	if i < 0 || i+1 >= len(args) || args[i+1] != "-" {
		return errors.New("argv must contain -oX -")
	}
	flags := args[:i]
	rate := 1
	if j := slices.Index(flags, flagMaxRate); j >= 0 && j+1 < len(flags) {
		if n, ok := atoi(flags[j+1]); ok {
			rate = n
		}
	}
	if !slices.ContainsFunc([]scanKind{kindSweep, kindNormal, kindGentle}, func(k scanKind) bool {
		want, err := flagsFor(k, rate)
		return err == nil && slices.Equal(flags, want)
	}) {
		return fmt.Errorf("flags %q are not one of the three allowed command shapes", flags)
	}
	targets := args[i+2:]
	if len(targets) == 0 || len(targets) > MaxBatch {
		return fmt.Errorf("a run needs 1 to %d targets, got %d", MaxBatch, len(targets))
	}
	uniq := make(map[string]bool, len(targets))
	for _, t := range targets {
		a, err := netip.ParseAddr(t)
		if err != nil || !validTarget(a) || a.String() != t || uniq[t] {
			return fmt.Errorf("target %q is not a canonical, unique, private IPv4 address", t)
		}
		uniq[t] = true
	}
	return nil
}

// NmapBinary is the allowlist entry for nmap: an absolute path to the OS package's binary, the validator
// above, and the output cap. Register it with core/exec.NewRunner.
func NmapBinary(path string) exec.Binary {
	return exec.Binary{Name: nmapName, Path: path, Validate: ValidateNmapArgs, MaxOutput: maxOutput}
}

const nmapName = "nmap"
