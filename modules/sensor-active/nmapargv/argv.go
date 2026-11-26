// Package nmapargv builds and checks the only eleven nmap command lines Vedette ever runs.
// It is a leaf: standard library only (plus core/localnet and core/egressip for which addresses are local or public,
// and modules/scan/commonports for the external shape's ports, all standard library only), no database and
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

// Kind says which of the eleven nmap command lines is built.
type Kind int

// The eleven kinds, one per command shape.
const (
	Sweep    Kind = iota // host discovery: -sn
	Normal               // service and OS identification
	Gentle               // the one gentle scan of a fragile device
	Versions             // service identification without OS detection: a person's pick of a device of unknown kind
	// GentleTitles is the gentle scan of a device whose kind is unknown and that nobody made fragile (lead decision on #714):
	// the gentle command line plus TitleScripts on the ports it finds open, each script capped by --script-timeout. Per web port
	// that is one GET of /, one GET of /xmldata?item=all (http-hp-ilo-info) and one POST of a SOAP RetrieveServiceContent to /sdk
	// (vmware-version); per TLS port one more handshake (ssl-cert). Every answer is read, nothing is sent with a login. A fragile
	// device keeps Gentle exactly: no script, no -sV, no UDP.
	GentleTitles
	// External is the default scan of the box's own verified public IP for exposure (exposure INV-19), in nmap runs of the
	// same name: first port discovery (-sS, no -sV) over nmap's own ExternalTopPorts most common TCP ports (--top-ports, read from
	// the nmap-services of the nmap the box installed, never copied here), then -sS -sV in batches (BatchFlags: at most
	// MaxBatchPorts ports each, each with its own host timeout, ExternalBatches orders them): the surface scan's list
	// (commonports), the reviewed admin ports, then the ports the discovery found open outside both (at most
	// commonports.MaxBelievableOpen). nmap's --host-timeout drops every result of a host that times out, so batches keep what
	// finished. -sV only ever reads open ports. The fixed list always gets its -sV batches, whatever the discovery said. All at
	// ExternalRate, with no -O and no --script (only what -sV runs itself). It is the only shape whose target is public outside the full ones, and it takes
	// exactly one; every other shape takes local addresses only. Whether the address is the box's own is not grammar: core checks
	// it before it hands each job out, the worker again before nmap.
	External
	// ExternalFull is the deep scan of the box's own verified public IP once an administrator accepted the target's testing terms
	// (exposure FULL-1): every TCP port (-p-), -sV, and nmap's "default", "safe" and "vuln" scripts without the
	// "dos", "brute", "external" and "broadcast" ones (FullScripts), at FullRate, bounded by FullHostTimeout. Same target rule
	// and the same two own-IP fences as External.
	ExternalFull
	// ExternalDisruptive is the last step of a deep scan whose run allows the disruptive checks (the terms' extra tick, a person's
	// scan): the "dos" and "brute" scripts and the login and crash checks (DisruptiveScripts) on the open ports the scan's ExternalFull
	// run found (-p, 1..commonports.MaxBelievableOpen ascending ports), with -sV so the scripts' port rules know the services, at
	// FullRate, bounded by DisruptiveHostTimeout. It runs after every other step of the scan, so a ban or an overloaded firewall
	// costs only this step. Like PortVersions its -p list varies (FlagsFor): the job carries the ports.
	ExternalDisruptive
	// AllPorts is the weekly scan of every TCP port of one LAN device that is not fragile: port discovery only
	// (-sS -p-, no -sV, no script, no -O), at most AllPortsMaxRate packets a second, --max-retries 1, bounded by AllPortsHostTimeout.
	// The open ports it finds that the normal scan does not cover get one PortVersions run. Local targets only, like every LAN shape.
	AllPorts
	// Extra follows every normal or versions scan of a LAN device: -sS -sV and the four scripts over ExtraPorts (the surface
	// list and the reviewed admin ports, ports.go), at the same rate, so a service moved off its usual port is identified too. The
	// device's result is the two runs together.
	Extra
	// PortVersions is the follow-up of an AllPorts run: -sS -sV and the four scripts on 1..MaxPortVersions
	// ports the weekly run found open that the normal scan does not cover, at the normal LAN rate. It is the only shape whose -p
	// list varies: the job carries the ports (sensor protocol, nmap jobs, "ports").
	PortVersions
)

// kinds is every Kind, in the order Validate and KindOf try them.
var kinds = []Kind{Sweep, Normal, Gentle, Versions, GentleTitles, External, ExternalFull, AllPorts, Extra}

// MaxPortVersions is the most ports one PortVersions run reads: -sV and the scripts time themselves (--max-rate does not
// bound them), so the weekly follow-up stays as small as a normal scan of a device with a few services.
const MaxPortVersions = 20

// The weekly scan of every port of a LAN device. 65535 SYNs, half-open (-sS: no connection is completed); a port that
// answers (open, or closed with an RST: the usual case on a LAN host) costs one probe, a port a host firewall drops costs two
// (--max-retries 1), so at AllPortsMaxRate one run sends at most 131,070 probes: 11 minutes when the device answers, at most 22
// when it drops everything. No -sV and no script (review r1 H2: those time themselves and open full connections; a device that
// answers on every port would get them on thousands); the PortVersions follow-up reads at most MaxPortVersions ports.
// 100 SYNs of 60 bytes a second are 48 kbit/s on the LAN. AllPortsHostTimeout leaves room for a slower rate (the settings' rate
// when lower, down to AllPortsMinRate: 44 minutes for a device that drops everything); a run it cuts prints no port table and
// changes nothing (INV-8).
const (
	AllPortsMaxRate     = 100
	AllPortsMinRate     = 50 // below it the scan does not fit AllPortsHostTimeout safely: the weekly run is not made (Health says why)
	AllPortsHostTimeout = 90 * time.Minute
	// AllPortsWindowRoom is the window a weekly run needs left to start (review r2 L2): the discovery's host timeout and the
	// follow-up's (the normal shapes' 30 minutes).
	AllPortsWindowRoom  = AllPortsHostTimeout + 30*time.Minute
	allPortsHostTimeout = "90m"
	allPortsRetries     = "1"
)

// ExternalRate is the fixed --max-rate of the external shape (packets a second), gentle on the customer's own router: the
// discovery's ExternalTopPorts SYNs with at most 2 retransmissions each are at most 3,000 probes, 30 seconds at this rate; each -sV
// batch's port scan (at most MaxBatchPorts ports) about a second more.
const ExternalRate = 100

// ExternalTopPorts is the --top-ports count of the external discovery: nmap's most common TCP ports by its own frequency data.
// The list itself is never written into Vedette (nmap-services is under the Nmap Public Source License): nmap picks it when it
// runs, and the parser reads back the ports it probed from its <scaninfo services>. Nessus probes about 4,790 ports by default,
// Qualys' standard list about 2,800, typical attack-surface tools 200 to 300; with ExtraPortNumbers this probes about 1,070.
const ExternalTopPorts = 1000

// MaxBatchPorts is the most ports one -sV batch of the external shape names: nmap reads about 20 ports at a time at the default
// timing, so a batch is about two rounds of -sV even when every port answers and holds the connection.
const MaxBatchPorts = 40

// The host timeouts of the external runs. The discovery needs about 30 seconds in the worst case (every port dropped, see
// ExternalRate); 2 minutes leave room for nmap slowing down on a lossy path. Each -sV batch gets a host timeout the caller picks
// from the time left (BatchFlags takes whole seconds from BatchMinTimeout to BatchMaxTimeout): BatchMaxTimeout covers two rounds
// of -sV probes on ports that accept and hold the connection; below BatchMinTimeout a batch is not started. exposure's step bound
// (ServicesTimeout there) holds the discovery and at least one batch, the waits for the worker and the own-IP checks; cmd/vedette
// holds them together in a test.
const (
	ExternalDiscoveryTimeout = 2 * time.Minute
	BatchMinTimeout          = time.Minute
	BatchMaxTimeout          = 2 * time.Minute
	externalDiscoveryTimeout = "2m"
)

// The host discovery probes of the sweep. nmap's own -sn default for an address outside the box's segment is an ICMP
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

// lanMaxRetries caps the retransmissions of a normal or versions scan's port probes: nmap's default allows ten, -T4 six
// (https://nmap.org/book/man-performance.html); a LAN loses few packets, and a lossy Wi-Fi client stops stretching a run.
const lanMaxRetries = "3"

// The two full shapes, tuned from nmap's reference guide:
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
// What a test box must measure: the wall time of a full run on its own public IP (port scan, -sV and scripts apart: the probe
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
	// DisruptiveHostTimeout bounds the disruptive scripts' run on the open ports: -sV on at most commonports.MaxBelievableOpen ports
	// (the default intensity), then the scripts in parallel, each capped by fullScriptTimeout.
	DisruptiveHostTimeout = 30 * time.Minute
	disruptiveHostTimeout = "30m"
)

// FullScripts is the --script value of ExternalFull: an explicit list (scripts.go, review r1 M2/M3), never a category expression,
// so a newer nmap's scripts stay out until reviewed. What the terms describe, without denial of service and password guessing
// (the extra tick); no "external" script (third parties: whois, geolocation, vulners.com…), no "broadcast" one (the box's own LAN)
// and none of excludedScripts. No --script-args.
var FullScripts = strings.Join(fullScripts, ",")

// DisruptiveScripts is the --script value of ExternalDisruptive: disruptiveExtra (denial of service, brute force and the login
// and crash checks of disruptiveMoved), sorted. The scripts of FullScripts ran in the scan's ExternalFull run before.
var DisruptiveScripts = func() string {
	all := slices.Clone(disruptiveExtra)
	slices.Sort(all)
	return strings.Join(all, ",")
}()

// IsExternal reports whether the shape is one of the three whose single target is the box's own public IP (External,
// ExternalFull, ExternalDisruptive): the own-IP fences apply to all three.
func (k Kind) IsExternal() bool { return k == External || k.IsFull() }

// IsFull reports whether the shape is one of the two deep scans of an accepted target.
func (k Kind) IsFull() bool { return k == ExternalFull || k == ExternalDisruptive }

// ExternalRateOf is the one rate an external shape runs at: FullRate for the full shapes, ExternalRate for External.
func ExternalRateOf(k Kind) int {
	if k.IsFull() {
		return FullRate
	}
	return ExternalRate
}

// IsGentle reports whether the shape is one of the gentle scans (Gentle, GentleTitles): rate 1, top 100 ports, no -sV or -O, so it
// never says anything about software and only adds ports.
func (k Kind) IsGentle() bool { return k == Gentle || k == GentleTitles }

// MaxBatch is the most addresses one nmap run gets, so its XML stays small.
const MaxBatch = 64

// MaxOutput caps what one nmap run may print; more means the run is discarded (INV-7).
const MaxOutput = 8 << 20

const (
	flagPrivileged    = "--privileged" // use raw sockets granted by CAP_NET_RAW instead of checking for uid 0
	flagNoDNS         = "-n"           // never resolve names: no packet may reach a resolver outside the scope (INV-1)
	flagMaxRate       = "--max-rate"   // limits port scanning and host discovery only; OS and version detection time themselves
	flagTopPorts      = "--top-ports"
	flagMaxRetries    = "--max-retries"
	flagTiming        = "-T2"
	flagHostTimeout   = "--host-timeout" // bounds the time one host may take, which --max-rate does not
	flagXML           = "-oX"
	flagStats         = "--stats-every" // #830: nmap adds a <taskprogress> element to its XML this often; no packet more is sent
	flagScript        = "--script"
	flagScriptTimeout = "--script-timeout"
	// flagVersionAll (--version-intensity 9) makes -sV try every probe of nmap-service-probes on a port no earlier probe matched
	// (in the full shapes): only the two full shapes have it. nmap stops at a port's first hard match, so a service a probe named costs what
	// it did; a port with no match, or with only a soft match (a bare "http" of an unrecognised web app: service_scan.cc nextProbe
	// skips other probes only below intensity 9), gets every remaining probe: 104 TCP probes in all instead of 30 (nmap-service-probes
	// of nmap 7.95/master), 534 s of totalwaitms instead of 156 s for a port that holds every probe open without answering. nmap
	// reads 20 ports at once at the default timing (desired_par), so the worst case (40 such ports, commonports.MaxBelievableOpen)
	// is about 18 minutes of -sV, which with the port scan (at most 11) and the scripts (each at most fullScriptTimeout, in
	// parallel) stays inside FullHostTimeout. A typical deep scan gets longer by its soft-matched ports: compare sa_probe's p50/p95
	// of external_full on a test box before and after. The External shape keeps the default: its -sV batches' host timeouts are at most 2
	// minutes. https://nmap.org/book/man-version-detection.html, https://nmap.org/book/vscan-technique.html
	flagVersionAll = "--version-all"
)

// Scripts is the exact NSE script list of the normal and versions shapes. Two scripts that send an NTLM NEGOTIATE (type 1)
// with no credentials and read the CHALLENGE (type 2) the device answers with: its own Windows version and build, and its names.
// Neither ever sends an AUTHENTICATE (type 3), so nothing logs in. rdp-ntlm-info runs only on an open RDP port, http-ntlm-info only
// on an open HTTP port, with a GET of "/" (nmap's http library follows a few redirects, only on the same host, port and scheme,
// never with credentials). http-title (the same GET of "/", read for its <title>) and ssl-cert (one TLS handshake on a port
// -sV found TLS on, read for the certificate's subject), both in nmap's "default, safe" categories: what the device states about
// itself (a FortiGate's certificate names its model, J-Web's title the switch). A fixed list, never a category or a wildcard;
// smb-os-discovery is left out because it opens an anonymous, then a guest, SMB session (a logon attempt).
const Scripts = "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version"

// TitleScripts is the exact NSE script list of the GentleTitles shape: the page title and the certificate subject, both in
// nmap's "default, safe" categories, read only from ports their portrules match (web and TLS ports).
const TitleScripts = "http-title,ssl-cert,http-hp-ilo-info,vmware-version"

// titleScriptTimeout caps each script of GentleTitles, so a device that answers slowly cannot stretch the gentle scan.
const titleScriptTimeout = "20s"

// StatsEvery is how often nmap writes its progress into the XML (--stats-every, #830): the phase it is in, how far, and its own
// estimate of the time left. The worker reads those lines while nmap runs (sensor protocol 6.6); core's parser skips them.
const StatsEvery = "5s"

// StatsFlags is the progress part of every command line, before -oX - (#830). The probe log stores it with the flags of the shape
// (INV-9: the row shows what was run).
func StatsFlags() []string { return []string{flagStats, StatsEvery} }

// Host time limits: a gentle scan is slow by design, a normal one has -sV and -O to finish.
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
	case AllPorts:
		return "all_ports"
	case Extra:
		return "extra_ports"
	case PortVersions:
		return "port_versions"
	}
	return ""
}

// Flags is the whole flag part of the command line of a kind: the fixed shapes nmap is ever run with (port_versions, whose -p list
// varies, is FlagsFor's). The external shape takes
// only ExternalRate, the full ones only FullRate (any other rate is an error, so a job can never carry a faster one).
// -sV makes nmap run the scripts of its "version" category, -O has its own timing; the only other scripts are the fixed
// Scripts list of the normal and versions shapes and the two fixed category expressions of the full shapes, which
// only ever name the box's own public IP after its testing terms were accepted; no other category, no -A, no -sC and no
// --script-args exists (FORBID-3, FORBID-6). The gentle
// shape has neither -sV, -O nor a script: on a fragile device even the version scripts are too much (PLC protocol probes). The
// versions shape is the normal one without -O: OS detection sends malformed probes that are the riskiest part for an OT stack,
// and a device of unknown kind may be one. The shapes are tuned to nmap's own guidance: the sweep's discovery probes
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
	case Extra:
		return []string{flagPrivileged, "-sS", "-sV", flagScript, Scripts, flagNoDNS, flagMaxRate, r, flagMaxRetries, lanMaxRetries, "-p", ExtraPorts, flagHostTimeout, normalHostTimeout}, nil
	case AllPorts:
		if rate > AllPortsMaxRate {
			return nil, fmt.Errorf("nmapargv: the all_ports shape runs at most %d packets/s, not %d", AllPortsMaxRate, rate)
		}
		return []string{flagPrivileged, "-sS", flagNoDNS, flagMaxRate, r, flagMaxRetries, allPortsRetries, "-p-", flagHostTimeout, allPortsHostTimeout}, nil
	case PortVersions:
		return nil, errors.New("nmapargv: the port_versions shape needs its ports (FlagsFor)")
	case GentleTitles:
		return []string{flagPrivileged, "-sS", flagScript, TitleScripts, flagScriptTimeout, titleScriptTimeout, flagNoDNS, flagTiming, flagMaxRetries, "1", flagMaxRate, "1", flagHostTimeout, gentleHostTimeout, flagTopPorts, "100"}, nil
	case External:
		if rate != ExternalRate {
			return nil, fmt.Errorf("nmapargv: the external shape runs at %d packets/s, not %d", ExternalRate, rate)
		}
		// The discovery run; its -sV batches are BatchFlags' (their ports and host timeouts vary). -Pn: the box's own address need not answer a ping
		// (routers drop it); it is up by definition.
		return []string{flagPrivileged, "-sS", "-Pn", flagNoDNS, flagMaxRate, r, flagMaxRetries, "2", flagHostTimeout, externalDiscoveryTimeout,
			flagTopPorts, strconv.Itoa(ExternalTopPorts)}, nil
	case ExternalFull:
		if rate != FullRate {
			return nil, fmt.Errorf("nmapargv: the %s shape runs at %d packets/s, not %d", kind.Name(), FullRate, rate)
		}
		// The reviewed explicit script list of scripts.go, never a category expression (FORBID-3); one argv element, never through a shell.
		return []string{flagPrivileged, "-sS", "-sV", flagVersionAll, "-Pn", flagNoDNS, "-p-", flagScript, FullScripts, flagScriptTimeout, fullScriptTimeout,
			flagMaxRate, r, flagMaxRetries, fullRetries, flagHostTimeout, fullHostTimeout}, nil
	case ExternalDisruptive:
		return nil, errors.New("nmapargv: the external_disruptive shape needs its ports (FlagsFor)")
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
// localnet.Addr), so nothing else may ever be named, whatever the caller says (0/8, 127/8, 169.254/16, the
// rest of 100/8, multicast, reserved and broadcast are all outside 10/8, 172.16/12, 192.168/16 and 100.64/10).
func validTarget(a netip.Addr) bool { return a.IsValid() && a.Zone() == "" && localnet.Addr(a) }

// validExternal: the external shape names one public IPv4 address (egressip.IsPublicIPv4: not private, CGNAT, loopback,
// link-local, documentation, multicast or reserved), written as plain IPv4.
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

// FlagsFor is Flags with the ports of a PortVersions run (1..MaxPortVersions distinct ports, ascending) or of an ExternalDisruptive
// run (1..commonports.MaxBelievableOpen); every other kind takes none, and External without ports is its discovery run (its -sV
// batches are BatchFlags', with their host timeout).
func FlagsFor(kind Kind, rate int, ports []int) ([]string, error) {
	if kind == ExternalDisruptive {
		return disruptiveFlags(rate, ports)
	}
	if kind != PortVersions {
		if len(ports) != 0 {
			return nil, fmt.Errorf("nmapargv: the %s shape takes no port list here (an external -sV batch is BatchFlags')", kind.Name())
		}
		return Flags(kind, rate)
	}
	if rate < 1 || rate > 1000 {
		return nil, fmt.Errorf("nmapargv: rate %d is outside 1..1000", rate)
	}
	if len(ports) == 0 || len(ports) > MaxPortVersions {
		return nil, fmt.Errorf("nmapargv: a port_versions run reads 1 to %d ports, got %d", MaxPortVersions, len(ports))
	}
	list, err := portList(ports)
	if err != nil {
		return nil, err
	}
	return []string{flagPrivileged, "-sS", "-sV", flagScript, Scripts, flagNoDNS, flagMaxRate, strconv.Itoa(rate), flagMaxRetries, lanMaxRetries,
		"-p", list, flagHostTimeout, normalHostTimeout}, nil
}

// disruptiveFlags is the flag part of an ExternalDisruptive run: the disruptive scripts on 1..commonports.MaxBelievableOpen ascending,
// distinct open ports, -sV first (the scripts' port rules read the service names), at FullRate.
func disruptiveFlags(rate int, ports []int) ([]string, error) {
	if rate != FullRate {
		return nil, fmt.Errorf("nmapargv: the %s shape runs at %d packets/s, not %d", ExternalDisruptive.Name(), FullRate, rate)
	}
	if len(ports) == 0 || len(ports) > commonports.MaxBelievableOpen {
		return nil, fmt.Errorf("nmapargv: an external_disruptive run reads 1 to %d ports, got %d", commonports.MaxBelievableOpen, len(ports))
	}
	list, err := portList(ports)
	if err != nil {
		return nil, err
	}
	return []string{flagPrivileged, "-sS", "-sV", "-Pn", flagNoDNS, "-p", list, flagScript, DisruptiveScripts, flagScriptTimeout, fullScriptTimeout,
		flagMaxRate, strconv.Itoa(rate), flagMaxRetries, fullRetries, flagHostTimeout, disruptiveHostTimeout}, nil
}

// portList writes ascending, distinct ports 1..65535 as a plain comma-separated -p value.
func portList(ports []int) (string, error) {
	list := make([]string, len(ports))
	for i, p := range ports {
		if p < 1 || p > 65535 || (i > 0 && p <= ports[i-1]) {
			return "", errors.New("nmapargv: the ports of a run must be ascending, distinct, 1..65535")
		}
		list[i] = strconv.Itoa(p)
	}
	return strings.Join(list, ","), nil
}

// ExternalBatches is the ordered -sV batches of the External shape after a discovery that found open (nil when it found nothing
// usable): the surface scan's list (commonports, the highest yield: what is exposed by mistake or on purpose most often), then the
// reviewed admin ports, then the ports of open outside both. Each group is cut into as few batches of at most MaxBatchPorts as it
// takes, of about equal size, each ascending. More than commonports.MaxBelievableOpen ports of open outside the fixed list is an
// error (the caller then names the fixed list alone).
func ExternalBatches(open []int) ([][]int, error) {
	var extra []int
	for _, p := range open {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("nmapargv: port %d is outside 1..65535", p)
		}
		if !slices.Contains(ExtraPortNumbers, p) {
			extra = append(extra, p)
		}
	}
	slices.Sort(extra)
	extra = slices.Compact(extra)
	if len(extra) > commonports.MaxBelievableOpen {
		return nil, fmt.Errorf("nmapargv: %d open ports outside the fixed list, more than %d", len(extra), commonports.MaxBelievableOpen)
	}
	var admin []int
	for _, p := range ExtraPortNumbers {
		if !slices.Contains(commonports.Numbers(), p) {
			admin = append(admin, p)
		}
	}
	var out [][]int
	for _, group := range [][]int{commonports.Numbers(), admin, extra} {
		out = append(out, cut(group, MaxBatchPorts)...)
	}
	return out, nil
}

// cut splits ports into ceil(len/max) runs of about equal size, in order; nil for no ports.
func cut(ports []int, most int) [][]int {
	if len(ports) == 0 {
		return nil
	}
	n := (len(ports) + most - 1) / most
	var out [][]int
	for i := range n {
		out = append(out, slices.Clone(ports[i*len(ports)/n:(i+1)*len(ports)/n]))
	}
	return out
}

// BatchFlags is one -sV batch of the External shape: 1..MaxBatchPorts ascending, distinct ports, at ExternalRate, with a host
// timeout of whole seconds from BatchMinTimeout to BatchMaxTimeout. The -sV options are those of the shape before the batches:
// -sS -sV -Pn -n --max-rate 100 --max-retries 2.
func BatchFlags(rate int, ports []int, host time.Duration) ([]string, error) {
	if rate != ExternalRate {
		return nil, fmt.Errorf("nmapargv: the external shape runs at %d packets/s, not %d", ExternalRate, rate)
	}
	if len(ports) == 0 || len(ports) > MaxBatchPorts {
		return nil, fmt.Errorf("nmapargv: an external -sV batch reads 1 to %d ports, got %d", MaxBatchPorts, len(ports))
	}
	if host < BatchMinTimeout || host > BatchMaxTimeout || host%time.Second != 0 {
		return nil, fmt.Errorf("nmapargv: an external -sV batch's host timeout %s is not whole seconds from %s to %s", host, BatchMinTimeout, BatchMaxTimeout)
	}
	list, err := portList(ports)
	if err != nil {
		return nil, err
	}
	return []string{flagPrivileged, "-sS", "-sV", "-Pn", flagNoDNS, flagMaxRate, strconv.Itoa(rate), flagMaxRetries, "2", flagHostTimeout,
		strconv.Itoa(int(host/time.Second)) + "s", "-p", list}, nil
}

// BuildBatch is Build of one -sV batch of the External shape (BatchFlags) on its one public target.
func BuildBatch(rate int, ports []int, host time.Duration, targets []netip.Addr) ([]string, error) {
	valid, err := targetRule(External, len(targets))
	if err != nil {
		return nil, err
	}
	args, err := BatchFlags(rate, ports, host)
	if err != nil {
		return nil, err
	}
	args = append(args, flagStats, StatsEvery, flagXML, "-")
	for _, t := range targets {
		if !valid(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not allowed in the %s shape", t, External.Name())
		}
		args = append(args, t.String())
	}
	return args, nil
}

// hostTimeoutOf reads the --host-timeout of flags written as whole seconds ("90s"); 0 otherwise.
func hostTimeoutOf(flags []string) time.Duration {
	i := slices.Index(flags, flagHostTimeout)
	if i < 0 || i+1 >= len(flags) {
		return 0
	}
	v, ok := strings.CutSuffix(flags[i+1], "s")
	if !ok {
		return 0
	}
	n, ok := atoi(v)
	if !ok {
		return 0
	}
	return time.Duration(n) * time.Second
}

// HostTimeoutOf is the host timeout of an argv Validate accepts that is an external -sV batch; 0 for every other line.
func HostTimeoutOf(args []string) time.Duration {
	i := slices.Index(args, flagXML)
	if i < 2 {
		return 0
	}
	if k, _, ports, ok := shapeOf(args[:i-2]); !ok || k != External || ports == nil {
		return 0
	}
	return hostTimeoutOf(args[:i-2])
}

// BuildFor is Build with the ports of a PortVersions or an ExternalDisruptive run (one target).
func BuildFor(kind Kind, rate int, ports []int, targets []netip.Addr) ([]string, error) {
	if kind == PortVersions && len(targets) != 1 {
		return nil, fmt.Errorf("nmapargv: a port_versions run takes exactly one target, got %d", len(targets))
	}
	valid, err := targetRule(kind, len(targets))
	if err != nil {
		return nil, err
	}
	args, err := FlagsFor(kind, rate, ports)
	if err != nil {
		return nil, err
	}
	args = append(args, flagStats, StatsEvery, flagXML, "-")
	for _, t := range targets {
		if !valid(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not allowed in the %s shape", t, kind.Name())
		}
		args = append(args, t.String())
	}
	return args, nil
}

// portsOf reads the -p list of flags that may be a PortVersions line or an external -sV batch: plain decimal ports separated by
// commas; nil otherwise.
func portsOf(flags []string) []int {
	i := slices.Index(flags, "-p")
	if i < 0 || i+1 >= len(flags) || len(flags[i+1]) > 6*max(MaxBatchPorts, MaxPortVersions, commonports.MaxBelievableOpen) {
		return nil
	}
	var out []int
	for _, f := range strings.Split(flags[i+1], ",") {
		n, ok := atoi5(f)
		if !ok {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// atoi5 accepts a port written as plain decimal digits, no sign, no leading zero.
func atoi5(s string) (int, bool) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
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

// shapeOf is the kind, rate and ports of the flag part of an argv: one of the fixed shapes, a PortVersions line whose flags are
// exactly FlagsFor of its own rate and ports, or an external -sV batch whose flags are exactly BatchFlags of its own rate, ports and
// host timeout.
func shapeOf(flags []string) (Kind, int, []int, bool) {
	rate := 1
	if j := slices.Index(flags, flagMaxRate); j >= 0 && j+1 < len(flags) {
		if n, ok := atoi(flags[j+1]); ok {
			rate = n
		}
	}
	for _, k := range kinds {
		if want, err := Flags(k, rate); err == nil && slices.Equal(flags, want) {
			return k, rate, nil, true
		}
	}
	if ports := portsOf(flags); ports != nil {
		if want, err := FlagsFor(PortVersions, rate, ports); err == nil && slices.Equal(flags, want) {
			return PortVersions, rate, ports, true
		}
		if want, err := FlagsFor(ExternalDisruptive, rate, ports); err == nil && slices.Equal(flags, want) {
			return ExternalDisruptive, rate, ports, true
		}
		if want, err := BatchFlags(rate, ports, hostTimeoutOf(flags)); err == nil && slices.Equal(flags, want) {
			return External, rate, ports, true
		}
	}
	return 0, 0, nil, false
}

// Build builds an nmap command line only from private IPv4 addresses (the external shape: one public one), an integer rate and
// the fixed flags above (INV-4, FORBID-3). The shape is: the flags of the kind, --stats-every StatsEvery -oX -, then the targets.
func Build(kind Kind, rate int, targets []netip.Addr) ([]string, error) {
	valid, err := targetRule(kind, len(targets))
	if err != nil {
		return nil, err
	}
	args, err := Flags(kind, rate)
	if err != nil {
		return nil, err
	}
	args = append(args, flagStats, StatsEvery, flagXML, "-")
	for _, t := range targets {
		if !valid(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not allowed in the %s shape", t, kind.Name())
		}
		args = append(args, t.String())
	}
	return args, nil
}

// Validate is the Validate func of the nmap Binary: it re-checks the whole argv before the process
// starts, independently of how Build made it (SYS-2). It accepts exactly the eleven shapes of FlagsFor
// (sweep, normal, gentle, versions, gentle_titles, external, external_full, external_disruptive, all_ports, extra_ports,
// port_versions), where only the rate of sweep, normal, versions, all_ports (at most AllPortsMaxRate), extra_ports and
// port_versions varies, and the -p list of port_versions (1..MaxPortVersions ascending ports), of external_disruptive
// (1..commonports.MaxBelievableOpen ascending ports) and of an external -sV batch (1..MaxBatchPorts ascending ports, with its host
// timeout, BatchFlags), then "--stats-every 5s -oX -", then 1 to MaxBatch
// canonical, unique, private IPv4 addresses (port_versions: exactly one; the three external shapes: exactly one canonical public
// IPv4 address).
// Everything else is rejected.
func Validate(args []string) error {
	i := slices.Index(args, flagXML)
	if i < 2 || i+1 >= len(args) || args[i+1] != "-" || args[i-2] != flagStats || args[i-1] != StatsEvery {
		return errors.New("argv must contain --stats-every " + StatsEvery + " -oX -")
	}
	flags := args[:i-2]
	kind, _, _, ok := shapeOf(flags)
	if !ok {
		return fmt.Errorf("flags %q are not one of the eleven allowed command shapes", flags)
	}
	targets := args[i+2:]
	if kind == PortVersions && len(targets) != 1 {
		return fmt.Errorf("the port_versions shape takes exactly one target, got %d", len(targets))
	}
	valid, err := targetRule(kind, len(targets))
	if err != nil {
		return err
	}
	uniq := make(map[string]bool, len(targets))
	for _, t := range targets {
		a, err := netip.ParseAddr(t)
		if err != nil || !valid(a) || a.String() != t || uniq[t] {
			return fmt.Errorf("target %q is not a canonical, unique address the %s shape allows", t, kind.Name())
		}
		uniq[t] = true
	}
	return nil
}

// KindOf is the Kind whose Name is shape: the shape field of a job on the sensor link.
func KindOf(shape string) (Kind, bool) {
	switch shape {
	case PortVersions.Name():
		return PortVersions, true
	case ExternalDisruptive.Name():
		return ExternalDisruptive, true
	}
	for _, k := range kinds {
		if k.Name() == shape {
			return k, true
		}
	}
	return 0, false
}

// Parse is the inverse of Build: it takes a whole argv that Validate accepts and returns the kind, the rate and the
// targets it was built from (the rate of a gentle line is its fixed 1). It lets the dispatcher turn the argv core
// has already checked into a job that carries no argv.
func Parse(args []string) (Kind, int, []netip.Addr, error) {
	k, rate, _, targets, err := ParseFor(args)
	return k, rate, targets, err
}

// ParseFor is Parse with the ports of a PortVersions or ExternalDisruptive line or of an external -sV batch (nil for every other line; a batch's host
// timeout is HostTimeoutOf's).
func ParseFor(args []string) (Kind, int, []int, []netip.Addr, error) {
	if err := Validate(args); err != nil {
		return 0, 0, nil, nil, err
	}
	i := slices.Index(args, flagXML)
	k, rate, ports, ok := shapeOf(args[:i-2])
	if !ok {
		return 0, 0, nil, nil, errors.New("nmapargv: argv matches no shape") // unreachable after Validate
	}
	targets := make([]netip.Addr, 0, len(args)-i-2)
	for _, t := range args[i+2:] {
		targets = append(targets, netip.MustParseAddr(t)) // Validate proved each is canonical
	}
	return k, rate, ports, targets, nil
}
