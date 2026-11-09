package sensoractive

import (
	"errors"
	"fmt"
	"net/netip"
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
	flagPrivileged = "--privileged" // use raw sockets granted by CAP_NET_RAW instead of checking for uid 0 (D-84 (8))
	flagNoDNS      = "-n"           // never resolve names: no packet may reach a resolver outside the scope (INV-1)
	flagMaxRate    = "--max-rate"
	flagTopPorts   = "--top-ports"
	flagVersionInt = "--version-intensity"
	flagMaxRetries = "--max-retries"
	flagTiming     = "-T2"
	flagXML        = "-oX"
)

// plainFlags are the flags that take no value. -O and -sV are the only detection options; no NSE script flag,
// no -A, no -sC is in the grammar (FORBID-3, FORBID-6).
var plainFlags = map[string]bool{"-sn": true, "-sS": true, "-sV": true, "-O": true, flagNoDNS: true, flagTiming: true, flagPrivileged: true}

// valuedFlags are the flags followed by one value, and the values each accepts.
var valuedFlags = map[string]func(string) bool{
	flagMaxRate:    func(v string) bool { n, ok := atoi(v); return ok && n >= 1 && n <= 1000 },
	flagTopPorts:   func(v string) bool { return v == "100" || v == "1000" },
	flagVersionInt: func(v string) bool { return v == "0" },
	flagMaxRetries: func(v string) bool { return v == "1" },
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

// buildNmapArgs builds an nmap command line only from IPv4 addresses, an integer rate and the fixed flags
// above (INV-4, FORBID-3). The shape is: --privileged, the scan flags, -oX -, then the targets.
func buildNmapArgs(kind scanKind, rate int, targets []netip.Addr) ([]string, error) {
	if len(targets) == 0 || len(targets) > MaxBatch {
		return nil, fmt.Errorf("sensoractive: a run needs 1 to %d targets, got %d", MaxBatch, len(targets))
	}
	if rate < 1 || rate > 1000 {
		return nil, fmt.Errorf("sensoractive: rate %d is outside 1..1000", rate)
	}
	var args []string
	switch kind {
	case kindSweep:
		args = []string{flagPrivileged, "-sn", flagNoDNS, flagMaxRate, strconv.Itoa(rate)}
	case kindNormal:
		args = []string{flagPrivileged, "-sS", "-sV", "-O", flagNoDNS, flagMaxRate, strconv.Itoa(rate), flagTopPorts, "1000"}
	case kindGentle:
		args = []string{flagPrivileged, "-sS", "-sV", flagVersionInt, "0", flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagTopPorts, "100"}
	default:
		return nil, errors.New("sensoractive: unknown scan kind")
	}
	args = append(args, flagXML, "-")
	for _, t := range targets {
		if !t.IsValid() || !t.Is4() || t.Zone() != "" {
			return nil, fmt.Errorf("sensoractive: target %q is not an IPv4 address", t)
		}
		args = append(args, t.String())
	}
	return args, nil
}

// ValidateNmapArgs is the Validate func of the nmap Binary: it re-checks the whole argv before the process
// starts, independently of how buildNmapArgs made it (SYS-2). It accepts exactly: --privileged first, then
// flags from the allowlist (each at most once, a valued flag followed by an accepted value), then "-oX -",
// then 1 to MaxBatch canonical IPv4 addresses, each at most once. -sn excludes the other scan types.
func ValidateNmapArgs(args []string) error {
	if len(args) == 0 || args[0] != flagPrivileged {
		return errors.New("argv must start with " + flagPrivileged)
	}
	seen := map[string]bool{flagPrivileged: true}
	i := 1
	for ; i < len(args) && args[i] != flagXML; i++ {
		a := args[i]
		if seen[a] {
			return fmt.Errorf("flag %q listed twice", a)
		}
		switch ok := valuedFlags[a]; {
		case plainFlags[a]:
		case ok != nil:
			if i+1 >= len(args) || !ok(args[i+1]) {
				return fmt.Errorf("flag %q has no accepted value", a)
			}
			i++
		default:
			return fmt.Errorf("token %q is not allowed", a)
		}
		seen[a] = true
	}
	if i+1 >= len(args) || args[i] != flagXML || args[i+1] != "-" {
		return errors.New("argv must contain -oX -")
	}
	if seen["-sn"] && (seen["-sS"] || seen["-sV"] || seen["-O"]) {
		return errors.New("-sn cannot be combined with other scan types")
	}
	if !seen["-sn"] && !seen["-sS"] {
		return errors.New("argv names no scan type")
	}
	targets := args[i+2:]
	if len(targets) == 0 || len(targets) > MaxBatch {
		return fmt.Errorf("a run needs 1 to %d targets, got %d", MaxBatch, len(targets))
	}
	uniq := make(map[string]bool, len(targets))
	for _, t := range targets {
		a, err := netip.ParseAddr(t)
		if err != nil || !a.Is4() || a.String() != t || uniq[t] {
			return fmt.Errorf("target %q is not a canonical, unique IPv4 address", t)
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
