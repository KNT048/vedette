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

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// Service identification on the box's own public IP and the comparison with exploited CVEs (S-EXP-2, CONTRACT INV-19, INV-20,
// D-553). Both steps sit behind a port so that the scan container's nmap -sV (sensor-active, owned by another module) and the
// KEV/NVD matcher (findings and feeds) are wired by cmd/vedette; exposure reads no other module's tables.

// The S-EXP-2 rows. A ServiceRow came from the network (nmap printed what the port answered), so it is untrusted and sanitize
// limits it before it is stored (INV-10, INV-19).
type (
	// ServiceRow is what service identification read on one open TCP port.
	ServiceRow struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Name    string `json:"name"`    // nmap's service name: "http", "ssl/http" (tunnel="ssl", D-522), "ssh", "tcpwrapped"
		Product string `json:"product"` // "Apache httpd"; "" when nmap named none
		Version string `json:"version"` // "2.4.49"; "" when the service sent none
		CPE     string `json:"cpe"`     // the application CPE 2.2 URI nmap printed ("cpe:/a:apache:http_server:2.4.49"); "" when none
		Extra   string `json:"extra"`   // nmap's extrainfo ("(Debian)", "Ubuntu Linux; protocol 2.0"); "" when none
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
	// page (D-565, zaprules.go); IP is then the page's host, a name for a domain.
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
// to the probe log before it is sent (LEGAL §3). Services are untrusted; Ports is how many TCP ports it probed. A step that could
// not run for a reason the page may show (the module is off, the scanner is busy) returns *Unavailable.
type ServiceScanner interface {
	ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error)
}

// ServiceScan is what one service identification read.
type ServiceScan struct {
	Services []ServiceRow
	Ports    int
	// FULL-4 (Trưởng), for Mlee: the NSE script results of a deep scan (ScanMode.Full, D-526): nmap's "default", "safe" and
	// "vuln" scripts (and "dos", "brute" with the disruptive tick) on the open ports and the host. Untrusted; sanitizeScripts
	// limits them before they are stored. nil for a scan that is not deep.
	Scripts []ScriptRow
}

// ScriptRow is one NSE script result of a deep scan (FULL-4 (Trưởng), for Mlee: D-526). Port is the open TCP port it ran on, 0
// for a script about the whole host (smb-vuln-ms17-010 is one); ID is nmap's script name; Output its text (printable, line breaks
// kept, at most maxScriptOutput runes); CVEs the CVE ids it names; Vulnerable that the script itself says VULNERABLE (nmap's
// vulns library: a confirmed finding, not "LIKELY VULNERABLE").
type ScriptRow struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	ID         string   `json:"id"`
	Output     string   `json:"output"`
	CVEs       []string `json:"cves"`
	Vulnerable bool     `json:"vulnerable"`
}

// Matcher compares identified services with the exploited CVEs: the CISA KEV list with the NVD version ranges the feeds keep
// (D-553: exploited CVEs only). It is pure with respect to exposure: it reads the list and returns rows, it stores nothing. A
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
}

// Unavailable is the error of a ServiceScanner or a Matcher whose step did not run, with a reason the page shows as is. Any other
// error is logged and shown as a failure without its text.
type Unavailable struct{ Reason string }

func (e *Unavailable) Error() string { return e.Reason }

// The errors of a ServiceScanner whose nmap ran but whose result says nothing about the services (D-522, N5; TUNE-1a, a change
// to Mlee's module by the scan side): ErrAnswersEverywhere, the address answered on more than commonports.MaxBelievableOpen
// ports (a router or SYN proxy answering for all of them), so its rows are not services; ErrServicesTimedOut, nmap hit its
// 3-minute limit on the address and printed no port table. Each is its own "Not checked" line, never "0 services".
var (
	ErrAnswersEverywhere = errors.New("exposure: the address answers on almost every port")
	ErrServicesTimedOut  = errors.New("exposure: service identification did not finish within 3 minutes")
)

// The lines of what a scan did not check (INV-19). They are sentences the page shows under "Not checked".
const (
	notUDP           = "UDP ports: the scan connects over TCP only."
	notOtherPortsIP  = "TCP ports outside the fixed list of commonly exposed ports."
	notOtherPortsDom = "Other ports of the names under this domain: names get web checks by name only; ports are scanned only on the box's own verified public IP."
	notNonExploited  = "Vulnerabilities that are not known to be exploited: only the CISA list of exploited vulnerabilities (KEV) is compared."
	notServicesDom   = "Service identification (nmap -sV): it runs on the box's own verified public IP only, not on the names of a domain."
	// NotSetUpServices is the line of every scan while no ServiceScanner is wired (the scan container's nmap -sV is not set up).
	NotSetUpServices = "Service identification (nmap -sV) is not set up on this box yet."
	notServicesFail  = "Service identification (nmap -sV) failed, so no service versions were read. The box log has the error."
	notServicesSlow  = "Service identification (nmap -sV) did not finish within 5 minutes, so no service versions were read."
	// D-522 (N5): the lines of ErrServicesTimedOut and ErrAnswersEverywhere. "3 minutes" is nmapargv's --host-timeout of the
	// external shape (externalHostTimeout); "40" is commonports.MaxBelievableOpen: change them together.
	notServicesGaveUp    = "Service identification (nmap -sV) did not finish within 3 minutes, nmap's limit for one address, so no service versions were read. Services may still be open there; scan again later."
	notAnswersEverywhere = "More than 40 of the 98 ports checked answered, more than a normal box exposes: a router or firewall that answers for every port looks like this, so service identification and the template checks were skipped. If real services run here, forward only the ports you use."
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

// ServicesTimeout bounds service identification, like the 5-minute cap of the surface runner: a scanner that hangs ends as a
// "Not checked" line and the rest of the scan is kept.
const ServicesTimeout = 5 * time.Minute

// FULL-4 (Trưởng), for Mlee: the step bound of a deep scan (D-526). nmap's full shapes give up on the address after 60 minutes
// (nmapargv.FullHostTimeout, its --host-timeout); the scanner also waits up to 2 minutes for the box's one nmap slot and checks
// the address and the terms again (about a minute), so the step gets 70 minutes. FullHostLimit is nmap's limit as the line of
// ErrServicesTimedOut says it. cmd/vedette holds both to nmapargv in a test.
const (
	FullServicesTimeout = 70 * time.Minute
	FullHostLimit       = 60 * time.Minute
)

// FULL-4 (Trưởng), for Mlee: the lines of a deep scan's service step (D-526), with its own bounds in them (%d minutes).
const (
	notOtherPortsDeep        = "Every TCP port: the deep scan's nmap run did not finish, so only the fixed list of commonly exposed ports was checked."
	notDeepSlow              = "The deep scan (nmap on every TCP port, with its scripts) did not finish within %d minutes, so no service versions were read."
	notDeepGaveUp            = "The deep scan (nmap on every TCP port, with its scripts) did not finish within %d minutes, nmap's limit for one address, so no service versions were read. Services may still be open there; scan again later."
	notAnswersEverywhereDeep = "More than 40 TCP ports answered the deep scan, more than a normal box exposes: a router or firewall that answers for every port looks like this, so its service and script results and the template checks were skipped. If real services run here, forward only the ports you use."
)

// FULL-4 (Trưởng), for Mlee: limits of the script results kept per scan (D-526). sensor-active already cut each output to
// maxScriptOutput runes; a deep scan of a box with a few web ports prints a few dozen results, so maxScripts keeps all of a real
// one (findings first, sanitizeScripts) and bounds what a hostile answer can make the snapshot hold (300 × 2000 runes).
const (
	maxScripts      = 300
	maxScriptOutput = 2000
	maxScriptCVEs   = 20
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
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsDom}, NotCheckedRow{Kind: "services", Text: notServicesDom},
			NotCheckedRow{Kind: "non_exploited", Text: notNonExploited}, NotCheckedRow{Kind: "templates", Text: notTemplatesDom})
		return c, nil
	}
	// FULL-4 (Trưởng), for Mlee: a deep scan probes every TCP port (D-526), so its "ports" line is said only when that run did not
	// finish (notDeep); the bound of its step and the numbers of its lines are its own.
	limit, slow, gaveUp, everywhere := ServicesTimeout, notServicesSlow, notServicesGaveUp, notAnswersEverywhere
	notDeep := func() {}
	if st.Mode.Full {
		limit, slow, gaveUp, everywhere = FullServicesTimeout, fmt.Sprintf(notDeepSlow, int(FullServicesTimeout/time.Minute)), fmt.Sprintf(notDeepGaveUp, int(FullHostLimit/time.Minute)), notAnswersEverywhereDeep
		notDeep = func() { c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsDeep}) }
	} else {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "ports", Text: notOtherPortsIP})
	}
	c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "non_exploited", Text: notNonExploited})
	if s.cfg.Services == nil {
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: NotSetUpServices})
		return s.runTemplates(ctx, st, netip.Addr{}, c) // no services, so it only says why it did not run
	}
	ip, err := netip.ParseAddr(st.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return c, fmt.Errorf("exposure: identifying services on %q: %w", st.Value, err)
	}
	if answersEverywhere(c.Ports, ip) { // D-522 (N5): the surface scan already saw it; nmap -sV is not sent at all
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: notAnswersEverywhere})
		return c, nil
	}
	sctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	res, err := s.cfg.Services.ScanServices(sctx, st, ip)
	var un *Unavailable
	switch {
	case err == nil:
		got := []ServiceRow{}
		for _, r := range sanitizeServices(res.Services) {
			if r.IP == ip.String() { // a row of another address is never the target's: dropped (the scanner was asked about ip only)
				got = append(got, r)
			}
		}
		c.Services = append(c.Services, got...)
		text := fmt.Sprintf("Service identification (nmap -sV): %s identified.", plural(len(got), "service"))
		if res.Ports > 0 {
			text = fmt.Sprintf("Service identification (nmap -sV) on %s: %s identified.", plural(res.Ports, "TCP port"), plural(len(got), "service"))
		}
		if st.Mode.Full { // FULL-4 (Trưởng), for Mlee: the script results of the deep scan, kept apart from the services
			vuln := 0
			for _, r := range sanitizeScripts(res.Scripts) {
				if r.IP == ip.String() {
					c.Scripts = append(c.Scripts, r)
					if r.Vulnerable {
						vuln++
					}
				}
			}
			text += fmt.Sprintf(" nmap's scripts: %s, %d saying VULNERABLE.", plural(len(c.Scripts), "result"), vuln)
		}
		c.Checks = append(c.Checks, CheckRow{Kind: "services", Text: text, At: store.FormatTS(s.clock())})
	case ctx.Err() != nil: // the run was stopped: nothing is stored
		return c, err
	case errors.Is(err, ErrAnswersEverywhere): // nmap saw it although the surface scan did not: no rows, no templates
		notDeep()
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: everywhere})
		return c, nil
	case errors.Is(err, ErrServicesTimedOut):
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: gaveUp})
	case errors.As(err, &un):
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: "Service identification (nmap -sV) did not run: " + clipText(un.Reason, 200)})
	case sctx.Err() != nil:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: slow})
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: service identification failed", "target", st.Value, "error", err)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "services", Text: notServicesFail})
	}
	if err != nil {
		notDeep()
	}
	return s.runTemplates(ctx, st, ip, c) // INV-23: safe templates for the exploited CVEs the services match
}

// answersEverywhere says the surface scan saw more than commonports.MaxBelievableOpen ports of ip open (D-522, N5); ports of
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
// say they did not run because of it, never "no services were identified" (D-522, M1 of the TUNE-1a review).
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
		return CheckRow{Kind: "names", At: at, Text: fmt.Sprintf("Names under the domain from certificate-transparency logs (crt.sh): %s; each checked by name on ports 80 and 443 (one GET / and the certificate on 443). %s open in all.",
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

// withVulns fills the snapshot's exploited CVEs from its services and today's list (INV-20), with the line of what was compared.
// Nothing identified: nothing to compare, and the stored lines already say why. A matcher that is missing or fails is a
// "Not checked" line, never "no exploited CVE".
func (s *Service) withVulns(ctx context.Context, snap *Snapshot) {
	snap.Vulns, snap.VersionGaps = []VulnRow{}, []GapRow{}
	s.withServiceVulns(ctx, snap)
	s.withWebVersions(ctx, snap)    // D-565: the rule list and the versions ZAP read, after the services
	s.withGreenboneVulns(ctx, snap) // INV-25: after every other row, never changing one
}

func (s *Service) withServiceVulns(ctx context.Context, snap *Snapshot) {
	if len(snap.Services) == 0 {
		return
	}
	if s.cfg.Matcher == nil {
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: notMatcher})
		return
	}
	m, err := s.cfg.Matcher.Match(ctx, snap.Services)
	var un *Unavailable
	switch {
	case errors.As(err, &un):
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: "The identified services were not compared with exploited vulnerabilities: " + clipText(un.Reason, 200)})
		return
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: comparing services with exploited vulnerabilities failed", "snapshot", snap.ID, "error", err)
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: notMatchFail})
		return
	}
	snap.Vulns, snap.VersionGaps = nz(m.Vulns), nz(m.Gaps)
	markTemplates(snap.Vulns, snap.Templates) // INV-23 first: a confirmed row is not a "maybe patched"
	backported := markBackports(snap.Vulns, snap.Services)
	text := fmt.Sprintf("%s of %d compared with today's CISA list of exploited vulnerabilities (%d entries) and its NVD version ranges: %s.",
		plural(m.Compared, "identified service"), len(snap.Services), m.Listed, plural(len(m.Vulns), "exploited CVE")+" matched")
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
	for i, p := range m.Unlisted {
		if i == maxUnlisted {
			break
		}
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: fmt.Sprintf(
			"%s: not compared. The list of exploited vulnerabilities has no entry under the product name nmap reports for it, so Vedette cannot tell.", clipText(p, 160))})
	}
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
			Version: field(r.Version, maxVersion), CPE: cpeURI(r.CPE), Extra: field(r.Extra, maxProduct)})
	}
	return out
}

// FULL-4 (Trưởng), for Mlee: sanitizeScripts keeps the script rows of an IPv4 address and a port 0..65535 (0: the host) with an
// id of nmap's form (others are dropped), each output printable with its line breaks and cut to maxScriptOutput runes, each CVE
// id of the right form (at most maxScriptCVEs); the findings first (VULNERABLE, then those naming a CVE), at most maxScripts, so
// the cap drops the rest first (INV-10, D-526).
func sanitizeScripts(in []ScriptRow) []ScriptRow {
	out := []ScriptRow{}
	for _, r := range in {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() || r.Port < 0 || r.Port > 65535 || !scriptIDRE.MatchString(r.ID) {
			continue
		}
		cves := []string{}
		for _, c := range r.CVEs {
			if len(cves) < maxScriptCVEs && cveID.MatchString(c) && !slices.Contains(cves, c) {
				cves = append(cves, c)
			}
		}
		text := strings.Map(func(r rune) rune {
			if r != '\n' && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
				return -1
			}
			return r
		}, strings.ToValidUTF8(r.Output, ""))
		out = append(out, ScriptRow{IP: ip.String(), Port: r.Port, ID: r.ID, Output: strings.TrimSpace(clipText(text, maxScriptOutput)), CVEs: cves, Vulnerable: r.Vulnerable})
	}
	rank := func(r ScriptRow) int {
		switch {
		case r.Vulnerable:
			return 0
		case len(r.CVEs) > 0:
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

// serviceText is how a service reads in a diff: "Apache httpd 2.4.49", or nmap's service name when it named no product.
func serviceText(r ServiceRow) string {
	if r.Product == "" {
		return r.Name
	}
	return strings.TrimSpace(r.Product + " " + r.Version)
}
