// Package nmapargv builds and checks the only eight nmap command lines Vedette ever runs (D-84 (7), D-113, D-501, D-511, D-514,
// D-526).
// It is a leaf: standard library only (plus core/localnet and core/egressip for which addresses are local or public, D-461,
// D-514, and modules/scan/commonports for the external shape's ports, all standard library only), no database and
// no core/exec, because the sensor binary links it and
// both sides (core before it hands a job over, the worker before it starts nmap) use the same code (SYS-2).
package nmapargv

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// Kind says which of the eight nmap command lines is built (D-84 (7), D-501, D-511, D-514, D-526).
type Kind int

// The eight kinds, one per command shape.
const (
	Sweep    Kind = iota // host discovery: -sn
	Normal               // service and OS identification
	Gentle               // the one gentle scan of a fragile device (D-45)
	Versions             // service identification without OS detection: a person's pick of a device of unknown kind (D-501)
	// GentleTitles is the gentle scan of a device whose kind is unknown and that nobody made fragile (D-511, lead decision on #714):
	// the gentle command line plus http-title and ssl-cert on the web and TLS ports it finds open (one GET of / and one TLS
	// handshake per port), each script capped by --script-timeout. A fragile device keeps Gentle exactly.
	GentleTitles
	// External is service identification on the box's own verified public IP for exposure (D-514, exposure INV-19): -sV over the
	// fixed TCP list of the surface scan (commonports), at ExternalRate, with no -O and no --script (only what -sV runs itself). It
	// is the only shape whose target is public, and it takes exactly one; every other shape takes local addresses only. Whether
	// the address is the box's own is not grammar: core checks it before it hands the job out, the worker again before nmap.
	External
	// ExternalFull is the deep scan of the box's own verified public IP once an administrator accepted the target's testing terms
	// (FULL-4, D-526, exposure FULL-1): every TCP port (-p-), -sV, and nmap's "default", "safe" and "vuln" scripts without the
	// "dos", "brute", "external" and "broadcast" ones (FullScripts), at FullRate, bounded by FullHostTimeout. Same target rule
	// and the same two own-IP fences as External.
	ExternalFull
	// ExternalDisruptive is ExternalFull with the "dos" and "brute" scripts too (DisruptiveScripts): only with the terms' extra
	// tick, off by default.
	ExternalDisruptive
)

// kinds is every Kind, in the order Validate and KindOf try them.
var kinds = []Kind{Sweep, Normal, Gentle, Versions, GentleTitles, External, ExternalFull, ExternalDisruptive}

// ExternalRate is the fixed --max-rate of the external shape (packets a second): 98 ports with 2 retries are a few hundred SYNs,
// a few seconds at this rate, gentle on the customer's own router (plan exposure-real-vulns §3).
const ExternalRate = 100

// ExternalPorts is the -p value of the external shape: the ports of commonports.List, ascending, comma-separated.
var ExternalPorts = func() string {
	ns := commonports.Numbers()
	ss := make([]string, len(ns))
	for i, n := range ns {
		ss[i] = strconv.Itoa(n)
	}
	return strings.Join(ss, ",")
}()

// The host discovery probes of the sweep (D-523). nmap's own -sn default for an address outside the box's segment is an ICMP
// echo, a SYN to 443, an ACK to 80 and an ICMP timestamp request (https://nmap.org/book/man-host-discovery.html); a Windows PC
// with its firewall on drops all four. The Nmap book's strategy chapter asks for a diverse set and ranks 80, 443, 21, 23, 22 and
// 3389 among the SYN ports most likely to answer (https://nmap.org/book/host-discovery-strategies.html); 135, 139 and 445 are
// Windows, 554 and 8000 cameras and recorders, 8080 web admin pages, 9100 printers. On the box's own Ethernet segment nmap
// sends one ARP request instead and none of these (it does that for any -P option when it has raw sockets).
const (
	sweepSYNPorts = "21,22,23,80,135,139,443,445,554,3389,8000,8080,9100"
	sweepACKPorts = "80,443"
)

// SweepProbes is how many probes the sweep sends one address behind a router in one round: -PE and -PP (one ICMP packet each),
// one SYN per port of -PS and one ACK per port of -PA. nmap stops probing an address once it answers, and may send a silent
// address another round, so it is the least an address that never answers costs.
var SweepProbes = 2 + strings.Count(sweepSYNPorts, ",") + 1 + strings.Count(sweepACKPorts, ",") + 1

// lanMaxRetries caps the retransmissions of a normal or versions scan's port probes (D-523): nmap's default allows ten, -T4 six
// (https://nmap.org/book/man-performance.html); a LAN loses few packets, and a lossy Wi-Fi client stops stretching a run.
const lanMaxRetries = "3"

// externalHostTimeout bounds -sV on the one host, inside exposure's 5-minute step (ServicesTimeout there) with room for the
// wait for the nmap slot and the own-IP checks.
const externalHostTimeout = "3m"

// The two full shapes (FULL-4, D-526), tuned from nmap's reference guide:
// https://nmap.org/book/man-performance.html (--max-rate "only affect[s] port scans and host discovery"; version detection and
// scripts time themselves; "A host that times out is skipped. No port table, OS detection, or version detection results are
// printed for that host"; the default allows ten retransmissions, -T5 two), https://nmap.org/book/man-nse.html and
// https://nmap.org/book/nse-usage.html#nse-categories (categories, boolean expressions), https://nmap.org/book/man-port-specification.html
// (-p- is every port from 1 through 65535).
//
// The arithmetic of the port scan: 65535 SYNs. A port that answers (open with a SYN/ACK, closed with an RST) costs one probe;
// a port the customer's router drops (filtered, the usual case behind a home router) costs the probe plus at most fullRetries
// retransmissions, so at most 3 × 65535 = 196,605 probes, 655 s (11 min) at FullRate; nmap "usually only does one
// retransmission" on a link without loss, 131,070 probes, 437 s (7.3 min). At ExternalRate (100/s) the worst case would be
// 33 minutes for the port scan alone. Then -sV on the open ports (at most commonports.MaxBelievableOpen are believed) and the
// scripts, which nmap runs in parallel, each capped by fullScriptTimeout. FullHostTimeout leaves room for both: an address nmap
// gives up on prints no port table at all (ErrHostTimedOut in sensor-active), so the bound is generous rather than tight.
// What the N100 must measure (D-526): the wall time of a full run on kien's own IP (port scan, -sV and scripts apart: the probe
// row's start and end, nmap's own <finished elapsed>), whether the router stays usable during it, and how many scripts printed.
const (
	// FullRate is the fixed --max-rate of the full shapes (packets a second): three times ExternalRate, so the worst case of the
	// port scan is 11 minutes; 300 SYNs of 60 bytes a second are 144 kbit/s, nothing for the link, and the router drops most of
	// them in its firewall.
	FullRate = 300
	// FullHostTimeout bounds one full run: port scan (at most 11 min), -sV and the scripts. exposure's step bound of a deep scan
	// (FullServicesTimeout there) is this plus the waits around it; cmd/vedette holds the two together in a test.
	FullHostTimeout = 60 * time.Minute
	fullHostTimeout = "60m"
	// fullRetries is -T5's --max-retries (nmap's default is 10): the path from the box to its own public IP is the LAN and the
	// router, where probes are rarely lost; it caps the cost of the dropped ports above.
	fullRetries = "2"
	// fullScriptTimeout caps each script (-T5 uses 10m, its most aggressive bound): a slow vuln check still finishes, a script
	// that hangs on a service cannot eat the host's hour, and a brute-force script of the disruptive shape stops after 5 minutes
	// (unpwdb's own time limit is 10 minutes at the default timing).
	fullScriptTimeout = "5m"
	// FullScripts is the --script expression of ExternalFull: what the terms describe, without denial of service and password
	// guessing (the extra tick). "external" scripts send data to third parties (whois, geolocation, vulners.com…), a new data flow
	// leaving the box (rules/legal.md, PRIVACY); "broadcast" scripts send on the box's own LAN, not to the target. No --script-args.
	FullScripts = "(default or safe or vuln) and not (dos or brute or external or broadcast)"
	// DisruptiveScripts is the --script expression of ExternalDisruptive: the denial-of-service and brute-force scripts too.
	DisruptiveScripts = "(default or safe or vuln or dos or brute) and not (external or broadcast)"
)

// IsExternal reports whether the shape is one of the three whose single target is the box's own public IP (External,
// ExternalFull, ExternalDisruptive): the own-IP fences apply to all three.
func (k Kind) IsExternal() bool { return k == External || k.IsFull() }

// IsFull reports whether the shape is one of the two deep scans of an accepted target (D-526).
func (k Kind) IsFull() bool { return k == ExternalFull || k == ExternalDisruptive }

// ExternalRateOf is the one rate an external shape runs at: FullRate for the full shapes, ExternalRate for External.
func ExternalRateOf(k Kind) int {
	if k.IsFull() {
		return FullRate
	}
	return ExternalRate
}

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
	case External:
		return "external"
	case ExternalFull:
		return "external_full"
	case ExternalDisruptive:
		return "external_disruptive"
	}
	return ""
}

// Flags is the whole flag part of the command line of a kind: the only eight shapes nmap is ever run with. The external shape takes
// only ExternalRate, the full ones only FullRate (any other rate is an error, so a job can never carry a faster one).
// -sV makes nmap run the scripts of its "version" category, -O has its own timing; the only other scripts are the fixed
// Scripts list of the normal and versions shapes (D-504) and the two fixed category expressions of the full shapes, which
// only ever name the box's own public IP after its testing terms were accepted (D-526); no other category, no -A, no -sC and no
// --script-args exists (FORBID-3, FORBID-6). The gentle
// shape has neither -sV, -O nor a script: on a fragile device even the version scripts are too much (PLC protocol probes). The
// versions shape is the normal one without -O: OS detection sends malformed probes that are the riskiest part for an OT stack,
// and a device of unknown kind may be one (D-501). D-523 tuned the shapes to nmap's own guidance: the sweep's discovery probes
// (SweepProbes) and --max-retries 3 on normal and versions. No
// shape names --allports (version detection then also probes TCP 9100, where some printers print whatever they are sent,
// https://nmap.org/book/man-version-detection.html).
func Flags(kind Kind, rate int) ([]string, error) {
	if rate < 1 || rate > 1000 {
		return nil, fmt.Errorf("nmapargv: rate %d is outside 1..1000", rate)
	}
	r := strconv.Itoa(rate)
	switch kind {
	case Sweep:
		return []string{flagPrivileged, "-sn", "-PE", "-PP", "-PS" + sweepSYNPorts, "-PA" + sweepACKPorts, flagNoDNS, flagMaxRate, r}, nil
	case Normal:
		return []string{flagPrivileged, "-sS", "-sV", "-O", flagScript, Scripts, flagNoDNS, flagMaxRate, r, flagMaxRetries, lanMaxRetries, flagTopPorts, "1000", flagHostTimeout, normalHostTimeout}, nil
	case Gentle:
		return []string{flagPrivileged, "-sS", flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	case Versions:
		return []string{flagPrivileged, "-sS", "-sV", flagScript, Scripts, flagNoDNS, flagMaxRate, r, flagMaxRetries, lanMaxRetries, flagTopPorts, "1000", flagHostTimeout, normalHostTimeout}, nil
	case GentleTitles:
		return []string{flagPrivileged, "-sS", flagScript, TitleScripts, flagScriptTimeout, titleScriptTimeout, flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	case External:
		if rate != ExternalRate {
			return nil, fmt.Errorf("nmapargv: the external shape runs at %d packets/s, not %d", ExternalRate, rate)
		}
		// -Pn: the box's own address need not answer a ping (routers drop it); it is up by definition.
		return []string{flagPrivileged, "-sS", "-sV", "-Pn", flagNoDNS, flagMaxRate, r, flagMaxRetries, "2", flagHostTimeout, externalHostTimeout, "-p", ExternalPorts}, nil
	case ExternalFull, ExternalDisruptive:
		if rate != FullRate {
			return nil, fmt.Errorf("nmapargv: the %s shape runs at %d packets/s, not %d", kind.Name(), FullRate, rate)
		}
		scripts := FullScripts
		if kind == ExternalDisruptive {
			scripts = DisruptiveScripts
		}
		// The only category expressions any shape names (FORBID-3, D-526); one argv element each, never through a shell.
		return []string{flagPrivileged, "-sS", "-sV", "-Pn", flagNoDNS, "-p-", flagScript, scripts, flagScriptTimeout, fullScriptTimeout,
			flagMaxRate, r, flagMaxRetries, fullRetries, flagHostTimeout, fullHostTimeout}, nil
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

// validExternal: the external shape names one public IPv4 address (egressip.IsPublicIPv4: not private, CGNAT, loopback,
// link-local, documentation, multicast or reserved), written as plain IPv4 (D-514).
func validExternal(a netip.Addr) bool { return a.Is4() && a.Zone() == "" && egressip.IsPublicIPv4(a) }

// targetRule checks the targets of a kind: one public address for the external shapes, 1..MaxBatch local ones for the others.
func targetRule(kind Kind, n int) (ok func(netip.Addr) bool, err error) {
	if kind.IsExternal() {
		if n != 1 {
			return nil, fmt.Errorf("nmapargv: the %s shape takes exactly one target, got %d", kind.Name(), n)
		}
		return validExternal, nil
	}
	if n == 0 || n > MaxBatch {
		return nil, fmt.Errorf("nmapargv: a run needs 1 to %d targets, got %d", MaxBatch, n)
	}
	return validTarget, nil
}

// Build builds an nmap command line only from private IPv4 addresses (the external shape: one public one), an integer rate and
// the fixed flags above (INV-4, FORBID-3). The shape is: the flags of the kind, -oX -, then the targets.
func Build(kind Kind, rate int, targets []netip.Addr) ([]string, error) {
	valid, err := targetRule(kind, len(targets))
	if err != nil {
		return nil, err
	}
	args, err := Flags(kind, rate)
	if err != nil {
		return nil, err
	}
	args = append(args, flagXML, "-")
	for _, t := range targets {
		if !valid(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not allowed in the %s shape", t, kind.Name())
		}
		args = append(args, t.String())
	}
	return args, nil
}

// Validate is the Validate func of the nmap Binary: it re-checks the whole argv before the process
// starts, independently of how Build made it (SYS-2). It accepts exactly the eight shapes of Flags
// (sweep, normal, gentle, versions, gentle_titles, external, external_full, external_disruptive), where only the rate of sweep,
// normal and versions varies, then "-oX -", then 1 to MaxBatch canonical, unique, private IPv4 addresses (the three external
// shapes: exactly one canonical public IPv4 address).
// Everything else is rejected.
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
	k := slices.IndexFunc(kinds, func(k Kind) bool {
		want, err := Flags(k, rate)
		return err == nil && slices.Equal(flags, want)
	})
	if k < 0 {
		return fmt.Errorf("flags %q are not one of the eight allowed command shapes", flags)
	}
	targets := args[i+2:]
	valid, err := targetRule(kinds[k], len(targets))
	if err != nil {
		return err
	}
	uniq := make(map[string]bool, len(targets))
	for _, t := range targets {
		a, err := netip.ParseAddr(t)
		if err != nil || !valid(a) || a.String() != t || uniq[t] {
			return fmt.Errorf("target %q is not a canonical, unique address the %s shape allows", t, kinds[k].Name())
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
