// Package nmapargv builds and checks the only five nmap command lines Vedette ever runs (D-84 (7), D-113, D-501, D-511).
// It is a leaf: standard library only (plus core/localnet, itself standard library only, D-461), no database and
// no core/exec, because the sensor binary links it and
// both sides (core before it hands a job over, the worker before it starts nmap) use the same code (SYS-2).
package nmapargv

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/knt048/vedette/core/localnet"
)

// Kind says which of the five nmap command lines is built (D-84 (7), D-501, D-511).
type Kind int

// The five kinds, one per command shape.
const (
	Sweep    Kind = iota // host discovery: -sn
	Normal               // service and OS identification
	Gentle               // the one gentle scan of a fragile device (D-45)
	Versions             // service identification without OS detection: a person's pick of a device of unknown kind (D-501)
	// GentleTitles is the gentle scan of a device whose kind is unknown and that nobody made fragile (D-511, lead decision on #714):
	// the gentle command line plus http-title and ssl-cert on the web and TLS ports it finds open (one GET of / and one TLS
	// handshake per port), each script capped by --script-timeout. A fragile device keeps Gentle exactly.
	GentleTitles
)

// kinds is every Kind, in the order Validate and KindOf try them.
var kinds = []Kind{Sweep, Normal, Gentle, Versions, GentleTitles}

// IsGentle reports whether the shape is one of the gentle scans (Gentle, GentleTitles): rate 1, top 100 ports, no -sV or -O, so it
// never says anything about software and only adds ports (D-45, D-350 (5)).
func (k Kind) IsGentle() bool { return k == Gentle || k == GentleTitles }

// MaxBatch is the most addresses one nmap run gets, so its XML stays small (D-84 (7)).
const MaxBatch = 64

// MaxOutput caps what one nmap run may print; more means the run is discarded (INV-7).
const MaxOutput = 8 << 20

const (
	flagPrivileged    = "--privileged" // use raw sockets granted by CAP_NET_RAW instead of checking for uid 0 (D-84 (8))
	flagNoDNS         = "-n"           // never resolve names: no packet may reach a resolver outside the scope (INV-1)
	flagMaxRate       = "--max-rate"   // limits port scanning and host discovery only; OS and version detection time themselves
	flagTopPorts      = "--top-ports"
	flagMaxRetries    = "--max-retries"
	flagTiming        = "-T2"
	flagHostTimeout   = "--host-timeout" // bounds the time one host may take, which --max-rate does not
	flagXML           = "-oX"
	flagScript        = "--script"
	flagScriptTimeout = "--script-timeout"
)

// Scripts is the exact NSE script list of the normal and versions shapes. D-504: two scripts that send an NTLM NEGOTIATE (type 1)
// with no credentials and read the CHALLENGE (type 2) the device answers with: its own Windows version and build, and its names.
// Neither ever sends an AUTHENTICATE (type 3), so nothing logs in. rdp-ntlm-info runs only on an open RDP port, http-ntlm-info only
// on an open HTTP port, with a GET of "/" (nmap's http library follows a few redirects, only on the same host, port and scheme,
// never with credentials). D-511: http-title (the same GET of "/", read for its <title>) and ssl-cert (one TLS handshake on a port
// -sV found TLS on, read for the certificate's subject), both in nmap's "default, safe" categories: what the device states about
// itself (a FortiGate's certificate names its model, J-Web's title the switch). A fixed list, never a category or a wildcard;
// smb-os-discovery is left out because it opens an anonymous, then a guest, SMB session (a logon attempt).
const Scripts = "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert"

// TitleScripts is the exact NSE script list of the GentleTitles shape (D-511): the page title and the certificate subject, both in
// nmap's "default, safe" categories, read only from ports their portrules match (web and TLS ports).
const TitleScripts = "http-title,ssl-cert"

// titleScriptTimeout caps each script of GentleTitles, so a device that answers slowly cannot stretch the gentle scan (D-511).
const titleScriptTimeout = "20s"

// Host time limits (D-84 (7)): a gentle scan is slow by design, a normal one has -sV and -O to finish.
const (
	gentleHostTimeout = "15m"
	normalHostTimeout = "30m"
)

// Name is the short template id stored in sa_probe.shape and sent as the shape of a job.
func (k Kind) Name() string {
	switch k {
	case Sweep:
		return "sweep"
	case Normal:
		return "normal"
	case Gentle:
		return "gentle"
	case Versions:
		return "versions"
	case GentleTitles:
		return "gentle_titles"
	}
	return ""
}

// Flags is the whole flag part of the command line of a kind: the only five shapes nmap is ever run with.
// -sV makes nmap run the scripts of its "version" category, -O has its own timing; the only other scripts are the fixed
// Scripts list of the normal and versions shapes (D-504); no category, no -A and no -sC exists (FORBID-3, FORBID-6). The gentle
// shape has neither -sV, -O nor a script: on a fragile device even the version scripts are too much (PLC protocol probes). The
// versions shape is the normal one without -O: OS detection sends malformed probes that are the riskiest part for an OT stack,
// and a device of unknown kind may be one (D-501).
func Flags(kind Kind, rate int) ([]string, error) {
	if rate < 1 || rate > 1000 {
		return nil, fmt.Errorf("nmapargv: rate %d is outside 1..1000", rate)
	}
	r := strconv.Itoa(rate)
	switch kind {
	case Sweep:
		return []string{flagPrivileged, "-sn", flagNoDNS, flagMaxRate, r}, nil
	case Normal:
		return []string{flagPrivileged, "-sS", "-sV", "-O", flagScript, Scripts, flagNoDNS, flagMaxRate, r, flagTopPorts, "1000", flagHostTimeout, normalHostTimeout}, nil
	case Gentle:
		return []string{flagPrivileged, "-sS", flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	case Versions:
		return []string{flagPrivileged, "-sS", "-sV", flagScript, Scripts, flagNoDNS, flagMaxRate, r, flagTopPorts, "1000", flagHostTimeout, normalHostTimeout}, nil
	case GentleTitles:
		return []string{flagPrivileged, "-sS", flagScript, TitleScripts, flagScriptTimeout, titleScriptTimeout, flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	}
	return nil, errors.New("nmapargv: unknown scan kind")
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

// validTarget: a LAN range can only hold local IPv4 addresses (RFC 1918 or the RFC 6598 shared space 100.64/10,
// localnet.Addr, D-461), so nothing else may ever be named, whatever the caller says (0/8, 127/8, 169.254/16, the
// rest of 100/8, multicast, reserved and broadcast are all outside 10/8, 172.16/12, 192.168/16 and 100.64/10).
func validTarget(a netip.Addr) bool { return a.IsValid() && a.Zone() == "" && localnet.Addr(a) }

// Build builds an nmap command line only from private IPv4 addresses, an integer rate and the fixed
// flags above (INV-4, FORBID-3). The shape is: the flags of the kind, -oX -, then the targets.
func Build(kind Kind, rate int, targets []netip.Addr) ([]string, error) {
	if len(targets) == 0 || len(targets) > MaxBatch {
		return nil, fmt.Errorf("nmapargv: a run needs 1 to %d targets, got %d", MaxBatch, len(targets))
	}
	args, err := Flags(kind, rate)
	if err != nil {
		return nil, err
	}
	args = append(args, flagXML, "-")
	for _, t := range targets {
		if !validTarget(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not a private IPv4 address", t)
		}
		args = append(args, t.String())
	}
	return args, nil
}

// Validate is the Validate func of the nmap Binary: it re-checks the whole argv before the process
// starts, independently of how Build made it (SYS-2). It accepts exactly the five shapes of Flags
// (sweep, normal, gentle, versions, gentle_titles), where only the rate of sweep, normal and versions varies, then "-oX -", then 1 to MaxBatch
// canonical, unique, private IPv4 addresses. Everything else is rejected.
func Validate(args []string) error {
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
	if !slices.ContainsFunc(kinds, func(k Kind) bool {
		want, err := Flags(k, rate)
		return err == nil && slices.Equal(flags, want)
	}) {
		return fmt.Errorf("flags %q are not one of the five allowed command shapes", flags)
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

// KindOf is the Kind whose Name is shape: the shape field of a job on the sensor link.
func KindOf(shape string) (Kind, bool) {
	for _, k := range kinds {
		if k.Name() == shape {
			return k, true
		}
	}
	return 0, false
}

// Parse is the inverse of Build: it takes a whole argv that Validate accepts and returns the kind, the rate and the
// targets it was built from (the rate of a gentle line is its fixed 1). It lets the dispatcher turn the argv core
// has already checked into a job that carries no argv (D-111 (3)).
func Parse(args []string) (Kind, int, []netip.Addr, error) {
	if err := Validate(args); err != nil {
		return 0, 0, nil, err
	}
	i := slices.Index(args, flagXML)
	flags := args[:i]
	rate := 1
	if j := slices.Index(flags, flagMaxRate); j >= 0 && j+1 < len(flags) {
		if n, ok := atoi(flags[j+1]); ok {
			rate = n
		}
	}
	targets := make([]netip.Addr, 0, len(args)-i-2)
	for _, t := range args[i+2:] {
		targets = append(targets, netip.MustParseAddr(t)) // Validate proved each is canonical
	}
	for _, k := range kinds {
		if want, err := Flags(k, rate); err == nil && slices.Equal(flags, want) {
			return k, rate, targets, nil
		}
	}
	return 0, 0, nil, errors.New("nmapargv: argv matches no shape") // unreachable after Validate
}
