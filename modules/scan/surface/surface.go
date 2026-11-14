// Package surface is the external-surface scan of the scan module (D-229), the exposure.Runner behind "Scan now" of External
// exposure (S-EXP-1). It follows D-57 (7) and LEGAL §3: active probes only on verified assets.
//
//   - The box's own public IP (a verified IP target): a TCP connect to a fixed list of ports (commonPorts), then one GET of "/" on
//     the open web ports and a TLS handshake on the TLS ports (admin pages, the Server header, certificates).
//   - A verified domain: its names from certificate-transparency logs (crt.sh), the apex's MX and NS hosts under it and the common
//     names of content/wordlist that resolve (D-567), each resolved (A, AAAA, CNAME) through the box's resolver, classed and listed. A name that points at a
//     public address gets HTTP checks by name only: one GET of "/" on port 80 and on 443 (with the certificate of 443). The
//     addresses are never port-scanned, unless one is itself a verified IP target that may be scanned now (the caller decides,
//     through exposure).
//
// Nothing else is sent: no exploit, no login, no path but "/", no redirect followed, no UDP. Every probe is written to the probe
// log (ProbeLog) before it goes out, and again with its answer.
//
// It is the Go standard library only: a TCP connect does what a port scan needs from the box's own network without raw sockets,
// pcap or cgo, so the ProjectDiscovery libraries planned in D-8 are not needed. It runs in core (the box's outgoing HTTPS is
// there already); the scan container stays for nmap and nuclei.
//
// Everything a target sends back is untrusted (SYS-6): reads are bounded in size and time, pages are matched as text, certificates
// are parsed by crypto/x509, names by a strict rule. Every probe goes to an address that Public accepted, checked again at the dial.
package surface

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/content/wordlist"
)

// Bounds of one scan (D-229). Nothing is cut: a domain has at most maxNames names (more is ErrTooManyNames), so at most
// 2 × maxNames HTTP checks, and the port scan covers only verified IP targets (exposure holds at most 20). The time cap is the
// sum of the phases at their worst, so it stops a scan only when something hangs.
const (
	maxPageBody     = 64 << 10 // bytes read of a page
	dialTimeout     = 1500 * time.Millisecond
	dialRate        = 300 // new connections a second, at most
	dialParallel    = 100
	pageTimeout     = 6 * time.Second
	pageParallel    = 32
	resolveTimeout  = 5 * time.Second
	resolveParallel = 32
	ctTimeout       = 45 * time.Second
	scanTimeout     = 5 * time.Minute
)

// ErrTooLong means the scan did not finish within scanTimeout; nothing of it is kept.
var ErrTooLong = errors.New("surface: the scan did not finish in time")

// ErrNotPublic means the target IP is not one the scan may probe.
var ErrNotPublic = errors.New("surface: the address is not a public address the box may scan")

// Resolver looks up addresses, CNAME, MX and NS records through the box's own resolver; *net.Resolver satisfies it. Tests pass a
// fake: no test sends a DNS query.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// Probe is one line of the probe log (LEGAL §3: target, time, what was sent), kept 90 days by the scan module (scan INV-7).
type Probe struct {
	ID       string     // unique, set by the scanner
	Addr     netip.Addr // where it went
	Label    string     // the name asked for, or the IP
	Kind     string     // "tcp", "http", "https", "tls", or "dns" (one row a domain scan for its lookups; Addr is then not set)
	Request  string     // what was sent: "TCP connect to 98 ports", "GET https://www.acme.example/"; after, the open ports too
	Answered bool       // false until something answered
}

// ProbeLog keeps the probe log. Record is called with the probes before they go out (Answered false) and again with the same
// IDs after; an error before stops the scan, so nothing is probed that is not logged.
type ProbeLog interface {
	Record(ctx context.Context, ps []Probe) error
}

// Config is what New needs. Public, Probes and Log are required.
type Config struct {
	// Public says whether an address may be probed (exposure.IsPublicIPv4: no private, loopback, link-local, CGNAT, multicast,
	// documentation or reserved address). A name that resolves to anything else is listed, never probed.
	Public func(netip.Addr) bool
	Probes ProbeLog
	// Dial opens every connection to a target (the port scan, the pages, the TLS handshakes); nil: a net.Dialer. Tests pass an
	// in-memory one.
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
	Resolver Resolver     // nil: net.DefaultResolver
	CT       *http.Client // the certificate-transparency search; nil: a client that verifies TLS and follows no redirect
	Log      *slog.Logger
}

// Scanner runs scans. It holds no state between them.
type Scanner struct {
	public  func(netip.Addr) bool
	probes  ProbeLog
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	resolve Resolver
	ct      *http.Client
	log     *slog.Logger
}

// New returns a Scanner.
func New(cfg Config) (*Scanner, error) {
	if cfg.Public == nil || cfg.Probes == nil || cfg.Log == nil {
		return nil, errors.New("surface: Public, Probes and Log are required")
	}
	s := &Scanner{public: cfg.Public, probes: cfg.Probes, dial: cfg.Dial, resolve: cfg.Resolver, ct: cfg.CT, log: cfg.Log}
	if s.dial == nil {
		s.dial = (&net.Dialer{}).DialContext
	}
	if s.resolve == nil {
		s.resolve = net.DefaultResolver
	}
	if s.ct == nil {
		s.ct = &http.Client{
			Timeout:       ctTimeout,
			Transport:     http.DefaultTransport.(*http.Transport).Clone(), //nolint:forcetypeassert // the standard library's own type
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return s, nil
}

// The result of a scan: what exposure stores as a snapshot (exposure.Content).
type (
	// Host is a name under the domain (D-567, exposure INV-27): where it was found, its final CNAME, its addresses with their kind,
	// and IP, the first of its IPv4 addresses (zero when it has none: an IPv6-only name, or a CNAME that leads nowhere).
	Host struct {
		Name   string
		IP     netip.Addr
		Source string
		CNAME  string
		Addrs  []Addr
	}
	// Port is an open TCP port. Product is what its page names (a fingerprint, else the Server header), or empty.
	Port struct {
		IP      netip.Addr
		Port    int
		Service string
		Product string
	}
	// Admin is an admin page that answered. Danger: close it now; otherwise restrict it by IP.
	Admin struct {
		URL     string
		Product string
		IP      netip.Addr
		Port    int
		Danger  bool
	}
	// Cert is the certificate a TLS port showed. Host is the name (or IP) asked for, with ":port" unless the port is 443.
	Cert struct {
		Host     string
		Issuer   string
		NotAfter time.Time
	}
	// Result is what one scan found. WordlistSkipped: a domain scan did not try the common names because the domain answers any
	// name (wildcard DNS).
	Result struct {
		Hosts           []Host
		Ports           []Port
		Admin           []Admin
		Certs           []Cert
		WordlistSkipped bool
	}
)

// Domain scans a verified domain (D-57 (7), D-567): its names from certificate transparency, the apex's MX and NS hosts under it
// and the common names that resolve (discover), each with its addresses, CNAME and class, listed; HTTP checks by name on 80 and 443
// for the names on a public IPv4 address; a port scan only of the addresses that mayScanPorts accepts (exposure: a verified IP
// target that may be scanned now), which are also the ones of kind "box". One probe-log row of kind "dns" is written before the
// lookups. ErrCT when the search gives no answer, ErrTooManyNames when the domain has more names than one scan reads, ErrTooLong
// past the time cap.
func (s *Scanner) Domain(ctx context.Context, domain string, mayScanPorts func(context.Context, netip.Addr) bool) (Result, error) {
	domain = strings.ToLower(domain)
	if !nameRE.MatchString(domain) {
		return Result{}, fmt.Errorf("surface: %q is not a domain name", domain)
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	ct, err := s.searchCT(ctx, domain)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	s.log.InfoContext(ctx, "exposure_scan_ct", "domain", domain, "names", len(ct))
	probe := []Probe{{ID: probeID(), Label: domain, Kind: "dns", Request: fmt.Sprintf(
		"DNS lookups via the box's resolver: A, AAAA, CNAME of %d names; MX, NS of %s; wildcard check; up to %d common names", len(ct), domain, len(wordlist.Labels()))}}
	if err := s.record(ctx, probe, false); err != nil {
		return Result{}, err
	}
	d, err := s.discover(ctx, domain, ct)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	probe[0].Answered = slices.ContainsFunc(d.names, func(n string) bool { return len(d.answers[n].addrs) > 0 })
	probe[0].Request += fmt.Sprintf("; %d names", len(d.names))
	if err := s.record(ctx, probe, true); err != nil {
		return Result{}, err
	}
	s.log.InfoContext(ctx, "exposure_scan_dns", "domain", domain, "names", len(d.names), "wordlist_skipped", d.skipped)
	res := Result{WordlistSkipped: d.skipped}
	var jobs []fetchJob
	var public []netip.Addr
	for _, n := range d.names {
		a := d.answers[n]
		if len(a.addrs) == 0 && a.cname == "" {
			continue // a name from an old certificate that no longer resolves
		}
		h := Host{Name: n, Source: d.source[n], CNAME: a.cname}
		if i := slices.IndexFunc(a.addrs, netip.Addr.Is4); i >= 0 {
			h.IP = a.addrs[i]
		}
		res.Hosts = append(res.Hosts, h)
		if i := slices.IndexFunc(a.addrs, s.public); i >= 0 { // the checks by name go to its first public address, the same every day
			at := hostAddr{host: n, ip: a.addrs[i]}
			jobs = append(jobs, fetchJob{hostAddr: at, port: portByNumber[80]}, fetchJob{hostAddr: at, port: portByNumber[443]})
		}
		for _, ip := range a.addrs {
			if s.public(ip) && !slices.Contains(public, ip) {
				public = append(public, ip)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	slices.SortFunc(public, netip.Addr.Compare)
	var ips []netip.Addr
	box := map[netip.Addr]bool{}
	for _, ip := range public {
		if mayScanPorts(ctx, ip) {
			ips = append(ips, ip)
			box[ip] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	for i := range res.Hosts {
		res.Hosts[i].Addrs = s.classify(d.answers[res.Hosts[i].Name].addrs, box)
	}
	open, err := s.scanPorts(ctx, ips)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	answers, err := s.fetchAll(ctx, jobs)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	return assemble(res, ips, open, jobs, answers), nil
}

// IP scans the box's own public address (a verified IP target): every port of commonPorts, then the pages and certificates of
// the open ones, with the IP as the host.
func (s *Scanner) IP(ctx context.Context, ip netip.Addr) (Result, error) {
	ip = ip.Unmap()
	if !s.public(ip) {
		return Result{}, fmt.Errorf("%w: %s", ErrNotPublic, ip)
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	open, err := s.scanPorts(ctx, []netip.Addr{ip})
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	var jobs []fetchJob
	for _, p := range open[ip] {
		if spec := portByNumber[p]; spec.kind != plain {
			jobs = append(jobs, fetchJob{hostAddr: hostAddr{host: ip.String(), ip: ip}, port: spec})
		}
	}
	answers, err := s.fetchAll(ctx, jobs)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	return assemble(Result{}, []netip.Addr{ip}, open, jobs, answers), nil
}

type hostAddr struct {
	host string // the name asked for (Host header, SNI), or the IP itself
	ip   netip.Addr
}

// stopped turns the end of the scan's own time cap into ErrTooLong; a caller that hung up gets its own error.
func (s *Scanner) stopped(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTooLong
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// assemble builds the result from the open ports and the answers of the pages. Ports are listed only for ips (the port scan).
func assemble(res Result, ips []netip.Addr, open map[netip.Addr][]int, jobs []fetchJob, answers []answer) Result {
	type key struct {
		ip   netip.Addr
		port int
	}
	product := map[key]string{}
	admins := map[string]bool{}
	for i, a := range answers {
		j := jobs[i]
		if a.cert != nil {
			res.Certs = append(res.Certs, certRow(j, a.cert))
		}
		if !a.ok {
			continue
		}
		k := key{j.ip, j.port.port}
		fp := identify(a.page)
		switch {
		case fp != nil:
			product[k] = fp.product
		case a.page.server != "" && product[k] == "":
			product[k] = a.serverRaw
		}
		if fp != nil && fp.admin && !admins[j.url()] {
			admins[j.url()] = true
			res.Admin = append(res.Admin, Admin{URL: j.url(), Product: fp.product, IP: j.ip, Port: j.port.port, Danger: fp.danger})
		}
	}
	for _, ip := range ips {
		for _, p := range open[ip] {
			res.Ports = append(res.Ports, Port{IP: ip, Port: p, Service: portByNumber[p].service, Product: product[key{ip, p}]})
		}
	}
	return res
}

func probeID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return "xp-" + hex.EncodeToString(b)
}

// record writes probes to the probe log. After the probes (done), the write must happen even if the scan was cancelled.
func (s *Scanner) record(ctx context.Context, ps []Probe, done bool) error {
	if len(ps) == 0 {
		return nil
	}
	if done {
		ctx = context.WithoutCancel(ctx)
	}
	if err := s.probes.Record(ctx, ps); err != nil {
		return fmt.Errorf("surface: writing the probe log: %w", err)
	}
	return nil
}

// scanPorts connects to every port of commonPorts on every address, at most dialRate new connections a second and dialParallel at
// once, and returns the ports that accepted, in order. A connection is closed as soon as it opens: nothing is sent. One probe-log
// line an address, written before and completed with the open ports after.
func (s *Scanner) scanPorts(ctx context.Context, ips []netip.Addr) (map[netip.Addr][]int, error) {
	probes := make([]Probe, len(ips))
	for i, ip := range ips {
		probes[i] = Probe{ID: probeID(), Addr: ip, Label: ip.String(), Kind: "tcp", Request: "TCP connect to " + strconv.Itoa(len(commonPorts)) + " ports"}
	}
	if err := s.record(ctx, probes, false); err != nil {
		return nil, err
	}
	open := map[netip.Addr][]int{}
	var mu sync.Mutex
	sem := make(chan struct{}, dialParallel)
	tick := time.NewTicker(time.Second / dialRate)
	defer tick.Stop()
	var wg sync.WaitGroup
loop:
	for _, ip := range ips {
		for _, spec := range commonPorts {
			select {
			case <-ctx.Done():
				break loop
			case <-tick.C:
			}
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				dctx, cancel := context.WithTimeout(ctx, dialTimeout)
				defer cancel()
				c, err := s.dialTarget(dctx, netip.AddrPortFrom(ip, uint16(spec.port))) //nolint:gosec // the ports of commonPorts fit in 16 bits
				if err != nil {
					return
				}
				_ = c.Close()
				mu.Lock()
				open[ip] = append(open[ip], spec.port)
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	for i, ip := range ips {
		slices.Sort(open[ip])
		list := make([]string, len(open[ip]))
		for k, p := range open[ip] {
			list[k] = strconv.Itoa(p)
		}
		probes[i].Answered = len(list) > 0
		probes[i].Request += "; open: " + cmp.Or(strings.Join(list, ", "), "none")
		s.log.InfoContext(ctx, "exposure_scan_ports", "ip", ip.String(), "tried", len(commonPorts), "open", open[ip])
	}
	return open, s.record(ctx, probes, true)
}

// dialTarget is the one way to a target: the address must be public (checked again here, whatever planned it).
func (s *Scanner) dialTarget(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if !s.public(ap.Addr()) {
		return nil, fmt.Errorf("%w: %s", ErrNotPublic, ap.Addr())
	}
	return s.dial(ctx, "tcp", ap.String())
}

type fetchJob struct {
	hostAddr
	port portSpec
}

// url is the page's address as people type it: the default port left out.
func (j fetchJob) url() string {
	scheme, def := "http", 80
	if j.port.kind == webTLS {
		scheme, def = "https", 443
	}
	host := j.host
	if j.port.port != def {
		host = net.JoinHostPort(j.host, strconv.Itoa(j.port.port))
	}
	return scheme + "://" + host
}

type answer struct {
	ok        bool // the page was read
	page      page
	serverRaw string
	cert      *x509.Certificate
}

// fetchAll runs the jobs a few at a time; answers[i] is the answer of jobs[i]. One probe-log line a job, written before and
// completed after.
func (s *Scanner) fetchAll(ctx context.Context, jobs []fetchJob) ([]answer, error) {
	probes := make([]Probe, len(jobs))
	for i, j := range jobs {
		kind, req := "tls", "TLS handshake with "+net.JoinHostPort(j.host, strconv.Itoa(j.port.port))
		if j.port.kind != tlsOnly {
			kind, req = strings.SplitN(j.url(), ":", 2)[0], "GET "+j.url()+"/"
		}
		probes[i] = Probe{ID: probeID(), Addr: j.ip, Label: j.host, Kind: kind, Request: req}
	}
	if err := s.record(ctx, probes, false); err != nil {
		return nil, err
	}
	answers := make([]answer, len(jobs))
	sem := make(chan struct{}, pageParallel)
	var wg sync.WaitGroup
	for i, j := range jobs {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			jctx, cancel := context.WithTimeout(ctx, pageTimeout)
			defer cancel()
			if j.port.kind == tlsOnly {
				answers[i].cert = s.handshake(jctx, j)
				return
			}
			answers[i] = s.fetch(jctx, j)
		})
	}
	wg.Wait()
	for i, a := range answers {
		probes[i].Answered = a.ok || a.cert != nil
	}
	return answers, s.record(ctx, probes, true)
}

// tlsConfig reads whatever certificate the target shows: it is reported, never trusted, so it is not verified.
func tlsConfig(host string) *tls.Config {
	c := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} //nolint:gosec // reads the page and the certificate only; nothing is sent that needs trust
	if _, err := netip.ParseAddr(host); err != nil {
		c.ServerName = host // SNI: the name, never an IP
	}
	return c
}

// handshake makes a TLS handshake to a TLS port and returns the leaf certificate, or nil.
func (s *Scanner) handshake(ctx context.Context, j fetchJob) *x509.Certificate {
	raw, err := s.dialTarget(ctx, netip.AddrPortFrom(j.ip, uint16(j.port.port))) //nolint:gosec // a port of commonPorts
	if err != nil {
		return nil
	}
	c := tls.Client(raw, tlsConfig(j.host))
	defer func() { _ = c.Close() }()
	if err := c.HandshakeContext(ctx); err != nil {
		return nil
	}
	if pc := c.ConnectionState().PeerCertificates; len(pc) > 0 {
		return pc[0]
	}
	return nil
}

// fetch reads "/" of a web port once, with the name in the Host header (and SNI), over a connection to the planned address only.
// A redirect is never followed: its Location is matched as a hint (an admin page often answers "/" with a redirect to its login).
func (s *Scanner) fetch(ctx context.Context, j fetchJob) answer {
	target := netip.AddrPortFrom(j.ip, uint16(j.port.port)) //nolint:gosec // a port of commonPorts
	tr := &http.Transport{
		Proxy:                  nil, // straight to the target: a proxy would scan from somewhere else
		DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dialTarget(ctx, target) },
		TLSClientConfig:        tlsConfig(j.host),
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
	}
	defer tr.CloseIdleConnections()
	start := j.url()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start+"/", nil)
	if err != nil {
		return answer{}
	}
	resp, err := client.Do(req)
	if err != nil {
		s.log.InfoContext(ctx, "exposure_scan_page", "url", start, "ip", j.ip.String(), "error", err.Error())
		return answer{}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPageBody))
	a := answer{ok: true, serverRaw: oneLine(resp.Header.Get("Server"), 100)}
	a.page = page{
		title: strings.ToLower(readTitle(string(body))), server: strings.ToLower(a.serverRaw), body: strings.ToLower(string(body)),
		location: strings.ToLower(resp.Header.Get("Location")), header: map[string]bool{},
	}
	for _, h := range []string{"X-Jenkins", "Kbn-Name"} {
		a.page.header[strings.ToLower(h)] = resp.Header.Get(h) != ""
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		a.cert = resp.TLS.PeerCertificates[0]
	}
	s.log.InfoContext(ctx, "exposure_scan_page", "url", start, "ip", j.ip.String(), "status", resp.StatusCode)
	return a
}

// oneLine keeps the printable ASCII of a header, at most n bytes.
func oneLine(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, v)
	return strings.TrimSpace(v[:min(len(v), n)])
}

// certRow is the row of a certificate. A certificate whose issuer is its subject is "Self-signed".
func certRow(j fetchJob, c *x509.Certificate) Cert {
	host := j.host
	if j.port.port != 443 {
		host = net.JoinHostPort(j.host, strconv.Itoa(j.port.port))
	}
	issuer := cmp.Or(c.Issuer.CommonName, strings.Join(c.Issuer.Organization, ", "), c.Issuer.String())
	if string(c.RawIssuer) == string(c.RawSubject) {
		issuer = "Self-signed"
	}
	return Cert{Host: host, Issuer: oneLine(issuer, 200), NotAfter: c.NotAfter.UTC()}
}
