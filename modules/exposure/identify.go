package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// Service identification on the box's own public IP and the comparison with exploited CVEs (S-EXP-2, CONTRACT INV-19, INV-20).
// Both steps sit behind a port so that the scan container's nmap -sV (sensor-active, owned by another module) and the
// KEV/NVD matcher (findings and feeds) are wired by cmd/vedette; exposure reads no other module's tables.

// The S-EXP-2 rows. A ServiceRow came from the network (nmap printed what the port answered), so it is untrusted and sanitize
// limits it before it is stored (INV-10, INV-19).
type (
	// ServiceRow is what service identification read on one open TCP port.
	ServiceRow struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Name    string `json:"name"`    // nmap's service name: "http", "ssl/http" (tunnel="ssl"), "ssh", "tcpwrapped"
		Product string `json:"product"` // "Apache httpd"; "" when nmap named none
		Version string `json:"version"` // "2.4.49"; "" when the service sent none
		CPE     string `json:"cpe"`     // the application CPE 2.2 URI nmap printed ("cpe:/a:apache:http_server:2.4.49"); "" when none
		Extra   string `json:"extra"`   // nmap's extrainfo ("(Debian)", "Ubuntu Linux; protocol 2.0"); "" when none
		// Method is how nmap named the service: "probed" (a probe's answer matched), "table" (only the usual service of the
		// port number: not confirmed), "" when not known (a snapshot from an older release). Conf is nmap's confidence 1..10, 0 when absent.
		Method string `json:"method,omitempty"`
		Conf   int    `json:"conf,omitempty"`
	}
	// CheckRow is one kind of probe a scan sent, or one comparison it made, with what it found and when (RFC 3339, UTC).
	CheckRow struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
		At   string `json:"at"`
	}
	// NotCheckedRow is one thing a scan did not check, and why.
	NotCheckedRow struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	// VulnRow is an exploited CVE (CISA KEV) that matches an identified service. Basis is "version" (the version is inside an NVD
	// range) or "product" (only the product matches: no version range could decide). DateAdded is the day CISA listed it. Backport
	// names the distribution the service says it is packaged by ("Debian"), "" when none: a distribution backports fixes without
	// changing the upstream version, so a version in range is weaker evidence there (INV-20). Basis "template": a safe template
	// matched (INV-23). Basis "greenbone": Greenbone named the CVE and it is on the list (INV-25), next to any other row. Template is the id of the template that ran for this CVE and TemplateResult its outcome ("matched",
	// "no_match", "error"; "" when none ran). Basis "js_library": Retire.js names the CVE for a JavaScript library version ZAP saw on a
	// page (zaprules.go); IP is then the page's host, a name for a domain.
	VulnRow struct {
		IP             string  `json:"ip"`
		Port           int     `json:"port"`
		CVE            string  `json:"cve"`
		Name           string  `json:"name"`
		Basis          string  `json:"basis"`
		Summary        string  `json:"summary"`
		DateAdded      *string `json:"date_added"`
		Ransomware     bool    `json:"ransomware"`
		Backport       string  `json:"backport"`
		Template       string  `json:"template"`
		TemplateResult string  `json:"template_result"`
		QoD            int     `json:"qod,omitempty"` // basis "greenbone": Greenbone's quality of detection (INV-25)
	}
	// GapRow is a service whose product has exploited CVEs that only a version would decide, and nmap read no version.
	GapRow struct {
		IP       string   `json:"ip"`
		Port     int      `json:"port"`
		Software string   `json:"software"`
		CVEs     []string `json:"cves"`
	}
)

// ServiceScanner identifies the service and version on the TCP ports of the box's own verified public IP (nmap -sV in the scan
// container, S-EXP-2). The scan calls it after the runner, only for an IP target that passed the gate (INV-1, INV-13); ip is that
// target. The implementation keeps its own fences (the worker checks again that ip is the box's own egress) and writes every probe
// to the probe log before it is sent (LEGAL §3). Services are untrusted; Ports is how many TCP ports it probed and Probed which ones
// (INV-22 counts a port as checked only by a scan that probed it). A step that could not run for a reason the page may show (the
// module is off, the scanner is busy) returns *Unavailable.
type ServiceScanner interface {
	ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error)
}

// PortsFirstScanner is implemented by a ServiceScanner that runs a deep scan (ScanTarget.Mode.Full) in two nmap runs: the port scan
// of every TCP port (ScanOpenPorts), then -sV and the scripts on the open ports it found (ScanOpenServices, ports ascending, at
// most commonports.MaxBelievableOpen). The scan leaves out of the second run the ports the target's settings skip and those its own
// network answers (INV-44), and does not start it when no port is left. ScanOpenPorts returns ErrPortsFirstUnsupported when the
// scan container runs the deep scan in one run only (an older worker): the scan then calls ScanServices, as before. Errors are
// ScanServices' (*Unavailable, ErrServicesTimedOut, ErrAnswersEverywhere: more than commonports.MaxBelievableOpen ports open).
type PortsFirstScanner interface {
	ScanOpenPorts(ctx context.Context, t ScanTarget, ip netip.Addr) (OpenPorts, error)
	ScanOpenServices(ctx context.Context, t ScanTarget, ip netip.Addr, ports []int) (ServiceScan, error)
}

// ErrPortsFirstUnsupported says the scan container runs a deep scan in one run (every TCP port with -sV and the scripts); nothing was
// sent.
var ErrPortsFirstUnsupported = errors.New("exposure: the scan container runs the deep scan in one run")

// OpenPorts is what a deep scan's port scan of every TCP port found: the open TCP ports (untrusted: the scan keeps 1..65535,
// sorted and distinct), how many ports it probed, and Refused (a closed reply came, so the address answered).
type OpenPorts struct {
	Open    []int
	Ports   int
	Refused bool
}

// ServiceScan is what one service identification read.
type ServiceScan struct {
	Services []ServiceRow
	Ports    int
	// Probed are the TCP ports the default scan probed, ascending: nmap's own most common ports (as nmap said it probed them) and
	// the fixed list. nil when the scanner does not say (a deep scan, which probes every port).
	Probed []int
	// DiscoveryCut: nmap's search of its most common ports did not finish, so Probed is only the fixed list's finished -sV batches.
	DiscoveryCut bool
	// AnswersEverywhere: the address answers on almost every port (a router or SYN proxy); Services holds only the ports of the fixed
	// list and the reviewed admin ports where -sV named a real service. The other ports of those lists stay in Probed, but exposure
	// does not count them as checked (answeredPorts).
	AnswersEverywhere bool
	// Unfinished are the ports whose -sV batch timed out, printed nothing usable or was not started this run: not in Probed (this
	// run never calls them closed), and the scanner reads them first next time.
	Unfinished []int
	// Refused: nmap got a closed reply (a TCP reset) on at least one port of the address, so the address answered this run even when
	// no port was open.
	Refused bool
	// The NSE script results of a deep scan (ScanMode.Full): nmap's "default", "safe" and
	// "vuln" scripts (and "dos", "brute" with the disruptive checks) on the open ports and the host. Untrusted; sanitizeScripts
	// limits them before they are stored. nil for a scan that is not deep.
	Scripts []ScriptRow
	// Split: the deep scan ran in two runs (PortsFirstScanner); Listed are the open ports of the target its port scan found, the
	// ports the second run read (none: it did not run). Set by the scan, not by a scanner.
	Split  bool
	Listed []int
}

// ScriptRow is one NSE script result of a deep scan. Port is the open TCP port it ran on, 0
// for a script about the whole host (smb-vuln-ms17-010 is one); ID is nmap's script name; Output its text (printable, line breaks
// kept, at most maxScriptOutput runes; "Output not stored: it can hold credentials." for a script that can print them);
// Findings the findings of nmap's vulns library, read by the scanner from the script's structured output only (never from text a
// service controls).
type ScriptRow struct {
	IP       string          `json:"ip"`
	Port     int             `json:"port"`
	ID       string          `json:"id"`
	Output   string          `json:"output"`
	Findings []ScriptFinding `json:"findings"`
}

// ScriptFinding is one finding of a script: State "vulnerable" (the script confirmed it),
// "likely" (LIKELY VULNERABLE) or "not_vulnerable"; Title the script's name for it; CVEs its CVE ids.
type ScriptFinding struct {
	State string   `json:"state"`
	Title string   `json:"title"`
	CVEs  []string `json:"cves"`
}

// vulnerable says the row has a finding the script confirmed.
func (r ScriptRow) vulnerable() bool {
	return slices.ContainsFunc(r.Findings, func(f ScriptFinding) bool { return f.State == "vulnerable" })
}

// Matcher compares identified services with the exploited CVEs: the CISA KEV list with the NVD version ranges the feeds keep
// (exploited CVEs only). It is pure with respect to exposure: it reads the list and returns rows, it stores nothing. A
// list that cannot be read for a reason the page may show returns *Unavailable.
type Matcher interface {
	Match(ctx context.Context, services []ServiceRow) (Matches, error)
}

// Matches is the result of a Matcher: the matched CVEs, the services that need a version, how many services were compared with
// entries of the list (Compared: the list has exploited CVEs under the product name nmap reports), the services whose product
// name the list has no entry under (Unlisted: "nginx (igor_sysoev:nginx)"), and how many exploited CVEs the list held (Listed).
type Matches struct {
	Vulns    []VulnRow
	Gaps     []GapRow
	Compared int
	Unlisted []string
	Listed   int
	// RuledOut are the exploited CVEs not listed because the service names another platform than the one the CVE affects
	// (an OpenSSH that says it is Ubuntu's build against an Alpine-only flaw); each is a "checked" line with its reason.
	RuledOut []RuledOutRow
}

// RuledOutRow is one exploited CVE a Matcher ruled out on a port, with the reason the page shows (untrusted text inside).
type RuledOutRow struct {
	IP     string
	Port   int
	CVE    string
	Reason string
}

// Unavailable is the error of a ServiceScanner or a Matcher whose step did not run, with a reason the page shows as is. Any other
// error is logged and shown as a failure without its text. Pending says the engine is on but not ready yet (its image is still
// downloading): the step is skipped with the reason, and the run ends partly done, never done.
type Unavailable struct {
	Reason  string
	Pending bool
}

func (e *Unavailable) Error() string { return e.Reason }

// The errors of a ServiceScanner whose nmap ran but whose result says nothing about the services:
// ErrAnswersEverywhere, the address answered on more than commonports.MaxBelievableOpen
// ports (a router or SYN proxy answering for all of them), so its rows are not services; ErrServicesTimedOut, nmap hit its
// limit on the address (its --host-timeout) and printed no port table. Each is its own "Not checked" line, never "0 services".
var (
	ErrAnswersEverywhere = errors.New("exposure: the address answers on almost every port")
	ErrServicesTimedOut  = errors.New("exposure: service identification did not finish within nmap's limit for one address")
)

// The lines of what a scan did not check (INV-19). They are sentences the page shows under "Not checked".
const (
	notUDP          = "UDP ports: the scan connects over TCP only."
	notOtherPortsIP = "TCP ports outside the fixed list of commonly exposed ports."
	// notOtherPortsProbed replaces notOtherPortsIP once service identification said which ports it probed (%s: "1052 ports");
	// notOtherPortsCut when its search of nmap's most common ports did not finish ("2 minutes": nmapargv.ExternalDiscoveryTimeout).
	notOtherPortsProbed = "TCP ports other than the %s this scan probed: nmap's 1000 most common ports and the fixed list of commonly exposed ports."
	notOtherPortsCut    = "TCP ports outside the fixed list of commonly exposed ports: nmap's search of its 1000 most common ports did not finish this time."
	// notAnswersEverywhereKept is the line of a default scan of an address that answers on almost every port: service
	// identification still read the fixed list and the reviewed admin ports, and only the ports where a service named itself were kept ("40":
	// commonports.MaxBelievableOpen).
	// notServicesUnfinished is the line of a default scan some of whose -sV batches did not finish (%s: "25 ports").
	notServicesUnfinished    = "Service identification of %s did not finish this time (nmap's time limit for each batch of ports, or too little time left); the next scan reads them first."
	notAnswersEverywhereKept = "More than 40 ports answered, more than a normal box exposes: a router or firewall that answers for every port looks like this. Only the ports of the fixed list and of the admin ports list where a service named itself were kept; the other ports may be the firewall answering."
	notOtherPortsDom         = "Other ports of the names under this domain: names get web checks by name only; ports are scanned only on the box's own verified public IP."
	notNonExploited          = "Vulnerabilities that are not known to be exploited: only the CISA list of exploited vulnerabilities (KEV) is compared."
	notServicesDom           = "Service identification (nmap -sV): it runs on the box's own verified public IP only, not on the names of a domain."
	// NotSetUpServices is the line of every scan while no ServiceScanner is wired (the scan container's nmap -sV is not set up).
	NotSetUpServices = "Service identification (nmap -sV) is not set up on this box yet."
	notServicesFail  = "Service identification (nmap -sV) failed, so no service versions were read. The box log has the error."
	notServicesSlow  = "Service identification (nmap -sV) did not finish within 8 minutes, so no service versions were read."
	// The lines of ErrServicesTimedOut and ErrAnswersEverywhere. "2 minutes" and "up to 2" are nmapargv's host timeouts of the
	// external shape's runs (ExternalDiscoveryTimeout, BatchMaxTimeout; cmd/vedette holds them in a test); "40" is
	// commonports.MaxBelievableOpen: change them together. The second line serves the surface scan's count and nmap's alike.
	notServicesGaveUp    = "Service identification (nmap) did not finish within nmap's limit for one address (2 minutes to find the open ports, up to 2 for each batch of ports it identifies), so no service versions were read. Services may still be open there; scan again later."
	notAnswersEverywhere = "More than 40 of the ports checked answered, more than a normal box exposes: a router or firewall that answers for every port looks like this, so service identification and the template checks were skipped. If real services run here, forward only the ports you use."
	notMatcher           = "Comparison with exploited vulnerabilities is not set up on this box yet."
	notMatchFail         = "The list of exploited vulnerabilities could not be read, so the identified services were not compared. Try again later."
)

// Limits of what identification hands over (INV-19). Ports are at most 65535 per IP, and the scan probes a fixed list of about
// 100; a field longer than its limit is dropped, not cut, so a cut version can never match a range it does not belong to.
const (
	maxServices    = 256
	maxServiceName = 40
	maxProduct     = 120
	maxVersion     = 64
	maxCPE         = 200
	maxLines       = 50
	maxLineText    = 300
	maxUnlisted    = 20
)

// ServicesTimeout bounds service identification: a scanner that hangs ends as a "Not checked" line and the rest of the scan is
// kept. The default scan is two nmap runs (port discovery over nmap's most common ports, up to 2 minutes, then -sV on the open ones,
// up to 3), each with the worker's own-IP check and its pickup, plus up to a minute's wait for the box's one nmap slot: 8 minutes.
// cmd/vedette holds it to nmapargv's host timeouts in a test.
const ServicesTimeout = 8 * time.Minute

// The step bound of a deep scan. nmap's full shapes give up on the address after 60 minutes
// (nmapargv.FullHostTimeout, its --host-timeout); the scanner also waits up to 2 minutes for the box's one nmap slot and checks
// the address and the terms again (about a minute), so the step gets 70 minutes. FullHostLimit is nmap's limit as the line of
// ErrServicesTimedOut says it. cmd/vedette holds both to nmapargv in a test.
// FullPortsLimit and FullListLimit are nmap's limits for one address in the deep scan's two runs (the port scan of every TCP port,
// then the services and scripts on the open ones): both runs, with the waits and checks before each, fit FullServicesTimeout.
const (
	FullServicesTimeout = 70 * time.Minute
	FullHostLimit       = 60 * time.Minute
	FullPortsLimit      = 36 * time.Minute
	FullListLimit       = 30 * time.Minute
)

// The lines of a deep scan's service step, with its own bounds in them (%d minutes).
const (
	notOtherPortsDeep        = "Every TCP port: the deep scan's nmap run did not finish, so only the fixed list of commonly exposed ports was checked."
	notDeepSlow              = "The deep scan (nmap on every TCP port, with its scripts) did not finish within %d minutes, so no service versions were read."
	notDeepGaveUp            = "The deep scan (nmap on every TCP port, with its scripts) did not finish within %d minutes, nmap's limit for one address, so no service versions were read. Services may still be open there; scan again later."
	notAnswersEverywhereDeep = "More than 40 TCP ports answered the deep scan, more than a normal box exposes: a router or firewall that answers for every port looks like this, so its service and script results and the template checks were skipped. If real services run here, forward only the ports you use."
)

// The lines of a deep scan that ran in two nmap runs (PortsFirstScanner).
const (
	// notDeepGaveUpSplit: one of the deep scan's two nmap runs reached nmap's limit for one address.
	notDeepGaveUpSplit = "The deep scan's nmap run did not finish within nmap's limit for one address (%d minutes for the port scan of every TCP port, %d for the services and scripts on the open ones), so no service versions were read. Services may still be open there; scan again later."
	// notServicesNoOpen is the service step of a deep scan whose port scan found no open port of the target: nothing was sent.
	notServicesNoOpen = "Not needed: the port scan found no open TCP port of this address, so there was no service to identify and no port for nmap's scripts."
	// notServicesGone: ports the port scan found open that the service run then did not see open (they stopped answering between
	// the two runs): the scan says nothing about them (%s: the ports, %s: it or them).
	notServicesGone = "The port scan found %s open that the service identification moments later did not, so this scan says nothing about %s."
)

// Limits of the script results kept per scan. sensor-active already cut each output to
// maxScriptOutput runes; a deep scan of a box with a few web ports prints a few dozen results, so maxScripts keeps all of a real
// one (findings first, sanitizeScripts) and bounds what a hostile answer can make the snapshot hold (300 × 2000 runes).
const (
	maxScripts        = 300
	maxScriptOutput   = 2000
	maxScriptFindings = 20
	maxScriptCVEs     = 20
)

var scriptIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`) // nmap's script names

// identify is the service step of a scan (INV-19), after the runner and before the snapshot is stored: the line of what the
// runner checked, the lines of what a scan never checks, then service identification of the box's own IP. Without a
// ServiceScanner the scan records NotSetUpServices and is stored as before. Only a stop of the run ends the scan here: a failed
// or unavailable identification is a "Not checked" line, and the rest of the result is kept.
func (s *Service) identify(ctx context.Context, st ScanTarget, c Content) (Content, error) {
	if len(c.Checks) == 0 {
		c.Checks = append(c.Checks, runnerCheck(st.Kind, c, store.FormatTS(s.clock())))
	}
	c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "udp", Text: notUDP})
	if st.Kind != KindIP {
		if !st.Mode.Full { // With the testing terms each address gets the deep scan (deepDomain), whose lines replace these
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsDom}, NotCheckedRow{Kind: "services", Text: notServicesDom})
		}
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "non_exploited", Text: notNonExploited})
		if !st.Mode.Full {
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesDom})
		}
		c.NotChecked = append(c.NotChecked, surfaceNotChecked(c.Hosts, st.Mode.Full)...) // INV-27
		return c, nil
	}
	if !st.Mode.Full { // a deep scan probes every TCP port; its "ports" line is said by identifyIP
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsIP})
	}
	c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "non_exploited", Text: notNonExploited})
	ip, err := netip.ParseAddr(st.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return c, fmt.Errorf("exposure: identifying services on %q: %w", st.Value, err)
	}
	c, err = s.identifyIP(ctx, st, ip, c)
	// A port only service identification found (a deep scan probes every TCP port, the runner a fixed list) is an open port
	// of the target too: the counts, the first sentence, the day diff, INV-22 and the outside view (INV-21) read the ports.
	c.Ports = addServicePorts(c.Ports, c.Services, c.Scripts, ip.String())
	return c, err
}

// sweepTrusted says a deep scan's nmap step on every TCP port of ip, which finished with the services got and every service batch,
// can be trusted to have seen every open port there: it saw at least one, and it saw each port the runner found open on ip this run
// (ports, before the step adds its own). A sweep that saw nothing, or missed a port that answered the runner minutes before, met an
// address that stopped answering it (a firewall or IPS cutting in, a link going down): what it did not see says nothing.
// A sweep that saw no open port at all is trusted only when nmap got closed replies (TCP resets) there (refused): the address
// answered it, it just has nothing open.
func sweepTrusted(ports []PortRow, got []ServiceRow, ip string, refused bool) bool {
	seen := map[int]bool{}
	for _, r := range got {
		if r.IP == ip {
			seen[r.Port] = true
		}
	}
	if len(seen) == 0 && !refused {
		return false
	}
	for _, p := range ports {
		if ipKey(p.IP) == ip && !seen[p.Port] {
			return false
		}
	}
	return true
}

// sweepCut says a deep sweep of ip that is not trusted shows the address stopped answering it while it ran: it missed a port the runner
// saw open there minutes before, and saw no port the runner did not (a sweep that sees ports the runner missed was answered). A sweep
// that saw nothing where the runner saw nothing met an address that answered nothing at all: that is the address's verdict, not a cut.
func sweepCut(ports []PortRow, got []ServiceRow, ip string) bool {
	runner := map[int]bool{}
	for _, p := range ports {
		if ipKey(p.IP) == ip {
			runner[p.Port] = true
		}
	}
	missed := false
	seen := map[int]bool{}
	for _, r := range got {
		if r.IP == ip {
			if !runner[r.Port] {
				return false
			}
			seen[r.Port] = true
		}
	}
	for p := range runner {
		missed = missed || !seen[p]
	}
	return missed
}

// addServicePorts appends a PortRow for each service on ip whose port the rows do not have yet, then says on each row of ip how its
// service was identified and what the deep scan's scripts read there (identifyPorts).
func addServicePorts(ports []PortRow, services []ServiceRow, scripts []ScriptRow, ip string) []PortRow {
	have := map[string]bool{}
	for _, p := range ports {
		have[fmt.Sprintf("%s:%d", ipKey(p.IP), p.Port)] = true
	}
	for _, r := range services {
		if k := fmt.Sprintf("%s:%d", r.IP, r.Port); !have[k] && r.IP == ip {
			have[k] = true
			ports = append(ports, PortRow{IP: r.IP, Port: r.Port, Service: r.Name, Product: strings.TrimSpace(r.Product + " " + r.Version)})
		}
	}
	return identifyPorts(ports, services, scripts, ip)
}

// identifyIP is service identification of one address, then its templates (INV-19, INV-23): an IP target's own address, or one address
// of a domain's names at the domain's terms depth (deepIP), whose ScanTarget then carries the domain (and its scope).
func (s *Service) identifyIP(ctx context.Context, st ScanTarget, ip netip.Addr, c Content) (Content, error) {
	// A deep scan probes every TCP port, so its "ports" line is said only when that run did not
	// finish (notDeep); the bound of its step and the numbers of its lines are its own.
	limit, slow, gaveUp, everywhere := ServicesTimeout, notServicesSlow, notServicesGaveUp, notAnswersEverywhere
	notDeep := func() {}
	if st.Mode.Full {
		limit, slow, gaveUp, everywhere = FullServicesTimeout, fmt.Sprintf(notDeepSlow, int(FullServicesTimeout/time.Minute)), fmt.Sprintf(notDeepGaveUp, int(FullHostLimit/time.Minute)), notAnswersEverywhereDeep
		notDeep = func() { c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsDeep}) }
	}
	rs := runStepsOf(ctx) // nil inside the step of one of a domain's addresses, which covers all of this
	if s.cfg.Services == nil {
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: NotSetUpServices})
		rs.skip(ctx, stepKeyPorts, NotSetUpServices)
		rs.skip(ctx, stepKeyServices, NotSetUpServices)
		return s.runTemplates(ctx, st, netip.Addr{}, c) // no services, so it only says why it did not run
	}
	// The surface scan already saw the address answer on almost every port. A deep scan is not sent (-sV on every port of a SYN
	// proxy would only run into its hour); the default scan still reads the fixed list and keeps the ports that named a service.
	surfaceEverywhere := answersEverywhere(c.Ports, ip)
	if surfaceEverywhere && st.Mode.Full {
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: notAnswersEverywhere})
		rs.skip(ctx, stepKeyPorts, notAnswersEverywhere)
		rs.skip(ctx, stepKeyServices, notAnswersEverywhere)
		return c, nil
	}
	sctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	rs.start(ctx, stepKeyPorts)
	res, split, err := s.scanServices(sctx, st, ip, c.Ports)
	if split {
		gaveUp = fmt.Sprintf(notDeepGaveUpSplit, int(FullPortsLimit/time.Minute), int(FullListLimit/time.Minute))
	}
	var un *Unavailable
	switch {
	case err == nil:
		got := []ServiceRow{}
		for _, r := range sanitizeServices(res.Services) {
			if r.IP == ip.String() && (!res.Split || slices.Contains(res.Listed, r.Port)) { // a row of another address, or of a port the run was not given, is never the target's: dropped
				got = append(got, r)
			}
		}
		got = slices.DeleteFunc(got, func(r ServiceRow) bool { return st.Skips(r.Port) }) // a port this target's settings skip is not observed
		if !res.Split {                                                                   // the split's port scan already left them out
			res, got = s.dropPathServices(ctx, ip.String(), res, got) // INV-44: a port the box's own network answers is not the target's
		}
		c.Services = append(c.Services, got...)
		if !st.Mode.Full && (res.AnswersEverywhere || surfaceEverywhere) {
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notAnswersEverywhereKept})
		}
		// INV-22: the ports this scan checked on ip. A port whose -sV batch did not finish is never among them, whatever the scanner
		// said: it got no service identification, so this scan cannot have missed a service there.
		unfinished := sanitizeProbed(res.Unfinished)
		var gone []int // the split's port scan found these open, its service run did not: not missed by the sweep, not read either
		if res.Split {
			gone = slices.DeleteFunc(slices.Clone(res.Listed), func(p int) bool {
				return slices.ContainsFunc(got, func(r ServiceRow) bool { return r.Port == p })
			})
			unfinished = sanitizeProbed(append(unfinished, gone...))
		}
		probed := slices.DeleteFunc(sanitizeProbed(res.Probed), func(p int) bool { _, in := slices.BinarySearch(unfinished, p); return in || st.Skips(p) })
		if !st.Mode.Full && len(probed) > 0 {
			if covered := answeredPorts(probed, got, res.AnswersEverywhere || surfaceEverywhere); len(covered) > 0 {
				if c.Probed == nil {
					c.Probed = map[string][]int{}
				}
				c.Probed[ip.String()] = covered
			}
			line := fmt.Sprintf(notOtherPortsProbed, plural(len(probed), "port"))
			if res.DiscoveryCut {
				line = notOtherPortsCut
			}
			for i, n := range c.NotChecked {
				if n.Kind == "ports" && n.Text == notOtherPortsIP {
					c.NotChecked[i].Text = line
				}
			}
		}
		ob := s.observerOf(ctx) // the sweep is a probe source of the run's verdicts (observe.go)
		cut := ""
		if st.Mode.Full { // INV-22: one miss of a trusted sweep is enough; an untrusted one checks only the fixed list
			swept := got
			if res.Split { // the sweep is the port scan: what it found open, whatever the service run then read
				swept = listedRows(ip.String(), res.Listed)
			}
			var trusted bool
			trusted, cut = sweepVerdict(c.Ports, swept, ip.String(), res.Refused, unfinished)
			if len(gone) > 0 {
				cut = fmt.Sprintf(notServicesGone, plural(len(gone), "TCP port"), itThem(len(gone), "it", "them"))
			}
			ob.noteSweep(ip.String(), sweepFacts{ran: cut == "", trusted: trusted && len(unfinished) == 0, cut: cut, unfin: unfinished})
		}
		if res.Refused { // a closed port answered: the address was reachable in this scan
			ob.noteResets(ip.String())
		}
		if n := len(unfinished); n > 0 && !st.Mode.Full {
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: fmt.Sprintf(notServicesUnfinished, plural(n, "port"))})
		}
		// Only what a probe named counts as identified; the guesses and the unknown ones are said apart
		read := servicesRead(got)
		text := fmt.Sprintf("Service identification (nmap -sV): %s.", read)
		noOpen := res.Split && len(res.Listed) == 0 // the deep scan's port scan found nothing open: the service run did not start
		switch {
		case !st.Mode.Full && len(probed) > 0: // the default scan: -sV read only the open ones of the ports it probed
			text = fmt.Sprintf("Port scan (nmap) of %s, then service identification (nmap -sV) of the open ones: %s.", plural(len(probed), "TCP port"), read)
		case noOpen:
			text = "Port scan (nmap) of every TCP port: no open port, so service identification (nmap -sV) and nmap's scripts had nothing to read."
		case res.Split:
			text = fmt.Sprintf("Port scan (nmap) of every TCP port, then service identification (nmap -sV) of the %d open ones: %s.", len(res.Listed), read)
		case res.Ports > 0:
			text = fmt.Sprintf("Service identification (nmap -sV) on %s: %s.", plural(res.Ports, "TCP port"), read)
		}
		if st.Mode.Full { // the script results of the deep scan, kept apart from the services
			// With no open port the scripts had nothing to run on: an earlier script result of the address is not seen any more, as
			// when the one run on every port found nothing.
			c.ScriptsRan = append(c.ScriptsRan, ip.String())
			vuln := 0
			for _, r := range sanitizeScripts(res.Scripts) {
				if r.IP == ip.String() && !st.Skips(r.Port) {
					c.Scripts = append(c.Scripts, r)
					if r.vulnerable() {
						vuln++
					}
				}
			}
			if !noOpen {
				text += fmt.Sprintf(" nmap's scripts: %s, %d saying VULNERABLE.", plural(len(c.Scripts), "result"), vuln)
			}
		}
		c.Checks = append(c.Checks, CheckRow{Kind: "services", Text: text, At: store.FormatTS(s.clock())})
		if cut != "" { // the sweep did not see everything it probed: its step and the run say so
			rs.end(ctx, stepKeyPorts, corerun.Partial, portsNote(st.Mode.Full, len(got), len(probed))+" "+cut)
			rs.problem(cut)
		} else {
			rs.end(ctx, stepKeyPorts, corerun.Done, portsNote(st.Mode.Full, len(got), len(probed)))
		}
		switch {
		case noOpen:
			rs.skip(ctx, stepKeyServices, notServicesNoOpen)
		case len(gone) > 0: // the port step of the split ended before the service run: this step says what it could not read
			rs.end(ctx, stepKeyServices, corerun.Partial, text+" "+cut)
		default:
			rs.end(ctx, stepKeyServices, corerun.Done, text)
		}
	case ctx.Err() != nil: // the run was stopped: nothing is stored
		return c, err
	case errors.Is(err, ErrAnswersEverywhere): // nmap saw it although the surface scan did not: no rows, no templates
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: everywhere})
		rs.end(ctx, stepKeyPorts, corerun.Done, everywhere)
		rs.skip(ctx, stepKeyServices, everywhere)
		return c, nil
	case errors.Is(err, ErrServicesTimedOut):
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: gaveUp})
		rs.endFirstOpen(ctx, corerun.Failed, gaveUp, stepKeyPorts, stepKeyServices)
		s.identificationCut(ctx, ip, gaveUp)
	case errors.As(err, &un):
		why := "Service identification (nmap -sV) did not run: " + clipText(un.Reason, 200)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: why})
		rs.skip(ctx, stepKeyPorts, why) // not a failure of the scan: the box cannot run it now, and says why
		rs.skip(ctx, stepKeyServices, why)
	case sctx.Err() != nil:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: slow})
		rs.endFirstOpen(ctx, corerun.Failed, slow, stepKeyPorts, stepKeyServices)
		s.identificationCut(ctx, ip, slow)
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: service identification failed", "target", st.Value, "ip", ip, "error", err)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: notServicesFail})
		rs.endFirstOpen(ctx, corerun.Failed, notServicesFail, stepKeyPorts, stepKeyServices)
		s.identificationCut(ctx, ip, notServicesFail)
	}
	if err != nil {
		notDeep()
	}
	return s.runTemplates(ctx, st, ip, c) // INV-23: safe templates for the exploited CVEs the services match
}

// scanServices is service identification of ip by the ServiceScanner. A deep scan whose scanner runs it in two runs
// (PortsFirstScanner) first scans every TCP port, then runs -sV and the scripts only on the open ports it found: without the ports
// the target's settings skip and those the box's own network answers (INV-44: left out and said once, as dropPathServices does), and
// not at all when none is left. The port step ends with the first run (partly done when the sweep was cut, sweepVerdict against
// runner, the ports the runner found open this run) and the service step starts with the second. split says the first run ran
// (whatever came of the second); a scanner that runs the deep scan in one run gets ScanServices, as a scan that is not deep does.
func (s *Service) scanServices(ctx context.Context, st ScanTarget, ip netip.Addr, runner []PortRow) (ServiceScan, bool, error) {
	pf, ok := s.cfg.Services.(PortsFirstScanner)
	if !st.Mode.Full || !ok {
		res, err := s.cfg.Services.ScanServices(ctx, st, ip)
		return res, false, err
	}
	found, err := pf.ScanOpenPorts(ctx, st, ip)
	switch {
	case errors.Is(err, ErrPortsFirstUnsupported): // an older scan container: the one run on every port, as before
		res, err := s.cfg.Services.ScanServices(ctx, st, ip)
		return res, false, err
	case err != nil:
		return ServiceScan{}, true, err
	}
	open := slices.DeleteFunc(sanitizeProbed(found.Open), st.Skips)
	if path := s.networkPorts(ctx, ip.String(), open); len(path) > 0 {
		open = slices.DeleteFunc(open, func(p int) bool { return path[p] })
		s.leftOut(ctx, ip.String(), path)
	}
	res := ServiceScan{Ports: found.Ports, Refused: found.Refused, Split: true, Listed: open, Services: []ServiceRow{}}
	if len(open) == 0 || ctx.Err() != nil { // nothing to read: the second run is not started (identifyIP ends both steps)
		return res, true, ctx.Err()
	}
	rs := runStepsOf(ctx)
	if _, cut := sweepVerdict(runner, listedRows(ip.String(), open), ip.String(), found.Refused, nil); cut != "" {
		rs.end(ctx, stepKeyPorts, corerun.Partial, portsNote(true, len(open), 0)+" "+cut)
	} else {
		rs.end(ctx, stepKeyPorts, corerun.Done, portsNote(true, len(open), 0))
	}
	rs.start(ctx, stepKeyServices)
	got, err := pf.ScanOpenServices(ctx, st, ip, open)
	if err != nil {
		return ServiceScan{}, true, err
	}
	got.Ports, got.Split, got.Listed, got.Refused = found.Ports, true, open, got.Refused || found.Refused
	return got, true, nil
}

// listedRows are the open ports a deep scan's port scan found on ip, as rows for sweepVerdict.
func listedRows(ip string, ports []int) []ServiceRow {
	out := make([]ServiceRow, 0, len(ports))
	for _, p := range ports {
		out = append(out, ServiceRow{IP: ip, Port: p})
	}
	return out
}

// sweepVerdict is whether a deep scan's sweep of every TCP port of ip, which saw swept open, can be trusted (sweepTrusted), and why
// its results are cut ("" when they are not): service batches that did not finish (unfinished), or a sweep that missed ports the
// runner found open moments before.
func sweepVerdict(runner []PortRow, swept []ServiceRow, ip string, refused bool, unfinished []int) (bool, string) {
	trusted := sweepTrusted(runner, swept, ip, refused)
	switch {
	case len(unfinished) > 0:
		return trusted, fmt.Sprintf("Service identification of %s did not finish, so this scan says nothing about %s.", plural(len(unfinished), "port"), itThem(len(unfinished), "it", "them"))
	case !trusted && sweepCut(runner, swept, ip):
		return trusted, "The sweep missed ports that accepted a connection moments before (a firewall or an IPS may have started dropping this box), so only the fixed list of common ports counts as checked."
	}
	return trusted, ""
}

// identificationCut records that service identification of ip failed: the ports it would have probed have no verdict but unknown,
// and the run is partly done.
func (s *Service) identificationCut(ctx context.Context, ip netip.Addr, why string) {
	s.observerOf(ctx).noteCut(ip.String(), why)
	runStepsOf(ctx).problem(why)
}

// portsNote is what the port discovery found: open the open ports -sV read, of the probed ports the default scan probed.
func portsNote(full bool, open, probed int) string {
	if full || probed == 0 {
		return plural(open, "open TCP port") + " found."
	}
	return fmt.Sprintf("%s found among the %s probed.", plural(open, "open TCP port"), plural(probed, "port"))
}

// answeredPorts is what of probed counts as checked for INV-22. Normally all of it. When the address answers on almost every port, the
// scanner drops each port where -sV named no service (it may be the firewall answering), so such a port says nothing about a real
// service there: only the fixed list (the runner TCP-connects it and reports what is open) and the ports whose service was kept count.
func answeredPorts(probed []int, kept []ServiceRow, everywhere bool) []int {
	if !everywhere {
		return probed
	}
	return slices.DeleteFunc(slices.Clone(probed), func(p int) bool {
		return !slices.Contains(commonports.Numbers(), p) && !slices.ContainsFunc(kept, func(r ServiceRow) bool { return r.Port == p })
	})
}

// sanitizeProbed keeps the ports of a scanner's Probed that are TCP ports, ascending and distinct; nil when there is none.
func sanitizeProbed(ports []int) []int {
	var out []int
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// answersEverywhere says the surface scan saw more than commonports.MaxBelievableOpen ports of ip open; ports of
// another address are not counted.
func answersEverywhere(ports []PortRow, ip netip.Addr) bool {
	n := 0
	for _, p := range ports {
		if ipKey(p.IP) == ip.String() {
			n++
		}
	}
	return n > commonports.MaxBelievableOpen
}

// identificationIncomplete says this IP scan has a "Not checked" line of service identification (it was not set up, did not run,
// failed, did not finish, or was skipped on an address that answers on every port), and returns that line: the later steps then
// say they did not run because of it, never "no services were identified".
func identificationIncomplete(c Content) (bool, string) {
	for _, n := range c.NotChecked {
		if n.Kind == "services" {
			return true, n.Text
		}
	}
	return false, ""
}

// runnerCheck says what the scan module's surface scan checked (INV-12), for a runner that reports no check lines of its own.
func runnerCheck(k Kind, c Content, at string) CheckRow {
	if k == KindDomain {
		return CheckRow{Kind: "names", At: at, Text: fmt.Sprintf("Names under the domain from certificate-transparency logs (crt.sh), the domain's MX and NS records and a list of common names, looked up through the box's DNS resolver: %s; each checked by name on ports 80 and 443 (one GET / and the certificate on 443). %s open in all.",
			plural(len(c.Hosts), "name"), plural(len(c.Ports), "port"))}
	}
	return CheckRow{Kind: "ports", At: at, Text: fmt.Sprintf("TCP connect to the fixed list of commonly exposed ports, then one GET / on each open web port and a TLS handshake on each TLS port: %s open.",
		plural(len(c.Ports), "port"))}
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// vulnSet is a scan's content with the exploited CVEs matched on it (withVulns): the input of the match issues.
type vulnSet struct {
	Content
	ID          string
	Vulns       []VulnRow
	VersionGaps []GapRow
}

// withVulns fills the exploited CVEs of a scan's content from its services and today's list (INV-20), with the line of what was
// compared, and says whether the comparison ran (so a match it no longer finds is gone). Nothing identified: nothing to compare. A
// matcher that is missing or fails is a "Not checked" line, never "no exploited CVE".
func (s *Service) withVulns(ctx context.Context, snap *vulnSet) bool {
	snap.Vulns, snap.VersionGaps = []VulnRow{}, []GapRow{}
	ran := s.withServiceVulns(ctx, snap)
	s.withWebVersions(ctx, snap)    // The rule list and the versions ZAP read, after the services
	s.withGreenboneVulns(ctx, snap) // INV-25: after every other row, never changing one
	return ran
}

func (s *Service) withServiceVulns(ctx context.Context, snap *vulnSet) bool {
	if len(snap.Services) == 0 {
		return s.cfg.Matcher != nil
	}
	if s.cfg.Matcher == nil {
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: notMatcher})
		return false
	}
	m, err := s.cfg.Matcher.Match(ctx, snap.Services)
	var un *Unavailable
	switch {
	case errors.As(err, &un):
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: "The identified services were not compared with exploited vulnerabilities: " + clipText(un.Reason, 200)})
		return false
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: comparing services with exploited vulnerabilities failed", "snapshot", snap.ID, "error", err)
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: notMatchFail})
		return false
	}
	snap.Vulns, snap.VersionGaps = nz(m.Vulns), nz(m.Gaps)
	markTemplates(snap.Vulns, snap.Templates) // INV-23 first: a confirmed row is not a "maybe patched"
	backported := markBackports(snap.Vulns, snap.Services)
	// "N of M services", never "N identified services": the services line counts what was identified, and a service a probe named
	// without a product the list has entries under is identified but not compared.
	of := plural(len(snap.Services), "service")
	text := fmt.Sprintf("%d of %s compared with today's CISA list of exploited vulnerabilities (%d entries) and its NVD version ranges: %s.",
		m.Compared, of, m.Listed, plural(len(m.Vulns), "exploited CVE")+" matched")
	if backported > 0 {
		text = strings.TrimSuffix(text, ".") + fmt.Sprintf(", %d of them on a distribution package that may carry a backported fix.", backported)
	}
	if len(m.Gaps) > 0 {
		text += fmt.Sprintf(" %s could not be checked: no version was read.", plural(len(m.Gaps), "service"))
	}
	if n := len(snap.Services) - m.Compared - len(m.Unlisted); n > 0 {
		text += fmt.Sprintf(" %s gave no product to look up, so not compared.", plural(n, "service"))
	}
	snap.Checks = append(snap.Checks, CheckRow{Kind: "cve", Text: text, At: store.FormatTS(s.clock())})
	for i, r := range m.RuledOut { // Not listed, and the page says why (Tenable's and Qualys's "not applicable" reason)
		if i == maxUnlisted {
			break
		}
		snap.Checks = append(snap.Checks, CheckRow{Kind: "cve", Text: fmt.Sprintf("%s on port %d is not listed: %s", r.CVE, r.Port, clipText(r.Reason, 400)),
			At: store.FormatTS(s.clock())})
	}
	for i, p := range m.Unlisted {
		if i == maxUnlisted {
			break
		}
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: fmt.Sprintf(
			"%s: not compared. The list of exploited vulnerabilities has no entry under the product name nmap reports for it, so Vedette cannot tell.", clipText(p, 160))})
	}
	return true
}

// The distributions whose packages keep the upstream version and backport security fixes, as nmap prints them in a version or its
// extrainfo ("2.4.25 (Debian)", "7.4p1 Debian 10+deb9u7", "Ubuntu Linux; protocol 2.0").
var distros = []string{"Debian", "Ubuntu", "Raspbian", "Red Hat", "CentOS", "Rocky", "AlmaLinux", "Oracle Linux", "Fedora", "SUSE", "Amazon Linux", "Alpine"}

// markBackports marks each match by version on a service that names its distribution (INV-20): its basis stays "version" but the
// row says the distribution may have backported the fix, and the summary says how to check. It returns how many it marked.
func markBackports(vulns []VulnRow, services []ServiceRow) int {
	hint := map[string]string{}
	for _, s := range services {
		for _, d := range distros {
			if strings.Contains(strings.ToLower(s.Extra+" "+s.Version), strings.ToLower(d)) {
				hint[fmt.Sprintf("%s:%d", s.IP, s.Port)] = d
				break
			}
		}
	}
	n := 0
	for i, v := range vulns {
		d := hint[fmt.Sprintf("%s:%d", v.IP, v.Port)]
		if d == "" || v.Basis != "version" {
			continue
		}
		vulns[i].Backport = d
		vulns[i].Summary = strings.TrimSpace(v.Summary + " " + d + " may have backported the fix without changing the version: check the installed package version against " + d + "'s security tracker.")
		n++
	}
	return n
}

// ---- limits (INV-19) ----

var lineKind = regexp.MustCompile(`^[a-z_]{1,32}$`)

// field accepts untrusted text only if it is printable UTF-8 of at most n runes; otherwise it is "" (absent): fail closed.
func field(v string, n int) string {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > n || strings.ContainsFunc(v, func(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) }) {
		return ""
	}
	return v
}

// cpeURI accepts a CPE 2.2 URI as nmap prints it: printable ASCII without spaces, starting with "cpe:/", at most maxCPE bytes.
func cpeURI(v string) string {
	if len(v) > maxCPE || !strings.HasPrefix(v, "cpe:/") {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

// sanitizeServices keeps at most maxServices rows, one per IPv4 address and port; a row with an address or port that is not one is
// dropped, and each text that is not printable or too long is emptied.
func sanitizeServices(in []ServiceRow) []ServiceRow {
	out := []ServiceRow{}
	seen := map[netip.AddrPort]bool{}
	for _, r := range in {
		if len(out) >= maxServices {
			break
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() || r.Port < 1 || r.Port > 65535 {
			continue
		}
		key := netip.AddrPortFrom(ip, uint16(r.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ServiceRow{IP: ip.String(), Port: r.Port, Name: field(r.Name, maxServiceName), Product: field(r.Product, maxProduct),
			Version: field(r.Version, maxVersion), CPE: cpeURI(r.CPE), Extra: field(r.Extra, maxProduct), Method: serviceMethod(r.Method),
			Conf: min(max(r.Conf, 0), 10)})
	}
	return out
}

// sanitizeScripts keeps the script rows of an IPv4 address and a port 0..65535 (0: the host) with an
// id of nmap's form (others are dropped), each output printable with its line breaks and cut to maxScriptOutput runes, each
// finding of a known state (at most maxScriptFindings) with a printable title and CVE ids of the right form (at most
// maxScriptCVEs); the rows with a VULNERABLE finding first, then those with a LIKELY one, at most maxScripts, so the cap drops the
// rest first (INV-10).
func sanitizeScripts(in []ScriptRow) []ScriptRow {
	out := []ScriptRow{}
	for _, r := range in {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() || r.Port < 0 || r.Port > 65535 || !scriptIDRE.MatchString(r.ID) {
			continue
		}
		findings := []ScriptFinding{}
		for _, f := range r.Findings {
			if len(findings) == maxScriptFindings || !slices.Contains([]string{"vulnerable", "likely", "not_vulnerable"}, f.State) {
				continue
			}
			cves := []string{}
			for _, c := range f.CVEs {
				if len(cves) < maxScriptCVEs && cveID.MatchString(c) && !slices.Contains(cves, c) {
					cves = append(cves, c)
				}
			}
			findings = append(findings, ScriptFinding{State: f.State, Title: field(f.Title, maxProduct), CVEs: cves})
		}
		text := strings.Map(func(r rune) rune {
			if r != '\n' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
				return -1
			}
			return r
		}, strings.ToValidUTF8(r.Output, ""))
		out = append(out, ScriptRow{IP: ip.String(), Port: r.Port, ID: r.ID, Output: strings.TrimSpace(clipText(text, maxScriptOutput)), Findings: findings})
	}
	rank := func(r ScriptRow) int {
		switch {
		case r.vulnerable():
			return 0
		case slices.ContainsFunc(r.Findings, func(f ScriptFinding) bool { return f.State == "likely" }):
			return 1
		}
		return 2
	}
	slices.SortStableFunc(out, func(a, b ScriptRow) int { return rank(a) - rank(b) })
	return out[:min(len(out), maxScripts)]
}

// sanitizeChecks keeps at most maxLines check lines with a kind of the right shape, a text and a time; others are dropped.
func sanitizeChecks(in []CheckRow) []CheckRow {
	out := []CheckRow{}
	for _, r := range in {
		at, err := time.Parse(time.RFC3339, r.At)
		text := field(r.Text, maxLineText)
		if len(out) >= maxLines || err != nil || text == "" || !lineKind.MatchString(r.Kind) {
			continue
		}
		out = append(out, CheckRow{Kind: r.Kind, Text: text, At: store.FormatTS(at)})
	}
	return out
}

func sanitizeNotChecked(in []NotCheckedRow) []NotCheckedRow {
	out := []NotCheckedRow{}
	for _, r := range in {
		text := field(r.Text, maxLineText)
		if len(out) >= maxLines || text == "" || !lineKind.MatchString(r.Kind) {
			continue
		}
		out = append(out, NotCheckedRow{Kind: r.Kind, Text: text})
	}
	return out
}
