// Package surface is the external-surface scan of the scan module (D-229), the exposure.Runner behind "Scan now" of External
// exposure (S-EXP-1). For a verified domain it lists the names under it in certificate-transparency logs (crt.sh) and resolves
// them; for the box's public IP it starts from that address. Then, on public addresses only, it connects to a fixed list of
// TCP ports (commonPorts), reads the first page of the open web ports once (admin pages, the Server header) and the
// certificate of the TLS ports. Nothing else is sent: no exploit, no login, no path but "/", no UDP.
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
	"crypto/tls"
	"crypto/x509"
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
)

// Bounds of one scan (D-229). The time cap is the sum of the phases at their worst, so it stops a scan only when something hangs.
const (
	maxIPs          = 32       // public addresses whose ports are scanned
	maxPages        = 64       // pages read and TLS handshakes made
	maxPageBody     = 64 << 10 // bytes read of a page
	dialTimeout     = 1500 * time.Millisecond
	dialRate        = 300 // new connections a second, at most
	dialParallel    = 100
	pageTimeout     = 8 * time.Second
	pageParallel    = 8
	resolveTimeout  = 5 * time.Second
	resolveParallel = 16
	ctTimeout       = 45 * time.Second
	scanTimeout     = 5 * time.Minute
	maxRedirects    = 3
)

// ErrTooLong means the scan did not finish within scanTimeout; nothing of it is kept.
var ErrTooLong = errors.New("surface: the scan did not finish in time")

// ErrNotPublic means the target IP is not one the scan may probe.
var ErrNotPublic = errors.New("surface: the address is not a public address the box may scan")

// Resolver looks up addresses; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config is what New needs. Public and Log are required.
type Config struct {
	// Public says whether an address may be probed (exposure.IsPublicIPv4: no private, loopback, link-local, CGNAT, multicast,
	// documentation or reserved address). A name that resolves to anything else is listed, never probed.
	Public func(netip.Addr) bool
	// Dial opens every connection to a target (the port scan, the pages, the TLS handshakes); nil: a net.Dialer. Tests pass an
	// in-memory one.
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
	Resolver Resolver     // nil: net.DefaultResolver
	CT       *http.Client // the certificate-transparency search; nil: a client that verifies TLS
	Log      *slog.Logger
}

// Scanner runs scans. It holds no state between them.
type Scanner struct {
	public  func(netip.Addr) bool
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	resolve Resolver
	ct      *http.Client
	log     *slog.Logger
}

// New returns a Scanner.
func New(cfg Config) (*Scanner, error) {
	if cfg.Public == nil || cfg.Log == nil {
		return nil, errors.New("surface: Public and Log are required")
	}
	s := &Scanner{public: cfg.Public, dial: cfg.Dial, resolve: cfg.Resolver, ct: cfg.CT, log: cfg.Log}
	if s.dial == nil {
		s.dial = (&net.Dialer{}).DialContext
	}
	if s.resolve == nil {
		s.resolve = net.DefaultResolver
	}
	if s.ct == nil {
		s.ct = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()} //nolint:forcetypeassert // the standard library's own type
	}
	return s, nil
}

// The result of a scan: what exposure stores as a snapshot (exposure.Content).
type (
	// Host is a name under the domain and the first of its IPv4 addresses.
	Host struct {
		Name string
		IP   netip.Addr
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
	// Result is what one scan found.
	Result struct {
		Hosts []Host
		Ports []Port
		Admin []Admin
		Certs []Cert
	}
)

// Domain scans a verified domain: its names from certificate transparency, their addresses, then the public ones (ErrCT when the
// search gives no answer, ErrTooLong past the time cap).
func (s *Scanner) Domain(ctx context.Context, domain string) (Result, error) {
	domain = strings.ToLower(domain)
	if !nameRE.MatchString(domain) {
		return Result{}, fmt.Errorf("surface: %q is not a domain name", domain)
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	names, err := s.searchCT(ctx, domain)
	if err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	s.log.InfoContext(ctx, "exposure_scan_ct", "domain", domain, "names", len(names))
	addrs := s.resolveAll(ctx, names)
	var res Result
	var targets []hostAddr // the names on the public addresses, in order, for the pages
	ips := []netip.Addr{}
	for _, n := range names {
		a := addrs[n]
		if len(a) == 0 {
			continue
		}
		res.Hosts = append(res.Hosts, Host{Name: n, IP: a[0]})
		for _, ip := range a {
			if !s.public(ip) {
				continue
			}
			if !slices.Contains(ips, ip) {
				if len(ips) >= maxIPs {
					continue
				}
				ips = append(ips, ip)
			}
			targets = append(targets, hostAddr{host: n, ip: ip})
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	return s.probe(ctx, res, ips, targets)
}

// IP scans the box's own public address.
func (s *Scanner) IP(ctx context.Context, ip netip.Addr) (Result, error) {
	ip = ip.Unmap()
	if !s.public(ip) {
		return Result{}, fmt.Errorf("%w: %s", ErrNotPublic, ip)
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	return s.probe(ctx, Result{}, []netip.Addr{ip}, []hostAddr{{host: ip.String(), ip: ip}})
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
	return err
}

// resolveAll looks up the IPv4 addresses of every name, a few at a time; a name that does not resolve is left out. Addresses are
// sorted so that the first one is stable from one scan to the next.
func (s *Scanner) resolveAll(ctx context.Context, names []string) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr, len(names))
	var mu sync.Mutex
	sem := make(chan struct{}, resolveParallel)
	var wg sync.WaitGroup
	for _, n := range names {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
			defer cancel()
			a, err := s.resolve.LookupNetIP(rctx, "ip4", n)
			if err != nil || len(a) == 0 {
				return
			}
			for i := range a {
				a[i] = a[i].Unmap()
			}
			slices.SortFunc(a, netip.Addr.Compare)
			mu.Lock()
			out[n] = slices.Compact(a)
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// probe scans the ports of ips, then reads the pages and certificates of the open ones, and fills res.
func (s *Scanner) probe(ctx context.Context, res Result, ips []netip.Addr, targets []hostAddr) (Result, error) {
	open := s.scanPorts(ctx, ips)
	if err := ctx.Err(); err != nil {
		return Result{}, s.stopped(ctx, err)
	}
	type key struct {
		ip   netip.Addr
		port int
	}
	product := map[key]string{}
	var jobs []fetchJob
	seen := map[string]bool{}
	for _, t := range targets {
		for _, p := range open[t.ip] {
			spec := portByNumber[p]
			id := t.host + ":" + strconv.Itoa(p)
			if spec.kind == plain || seen[id] || len(jobs) >= maxPages {
				continue
			}
			seen[id] = true
			jobs = append(jobs, fetchJob{hostAddr: t, port: spec})
		}
	}
	answers := s.fetchAll(ctx, jobs)
	if err := ctx.Err(); err != nil {
		return Result{}, s.stopped(ctx, err)
	}
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
	return res, nil
}

// scanPorts connects to every port of commonPorts on every address, at most dialRate new connections a second and dialParallel at
// once, and returns the ports that accepted, in order. A connection is closed as soon as it opens: nothing is sent.
func (s *Scanner) scanPorts(ctx context.Context, ips []netip.Addr) map[netip.Addr][]int {
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
	for _, ip := range ips {
		slices.Sort(open[ip])
		s.log.InfoContext(ctx, "exposure_scan_ports", "ip", ip.String(), "tried", len(commonPorts), "open", open[ip])
	}
	return open
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

// fetchAll runs the jobs a few at a time; answers[i] is the answer of jobs[i].
func (s *Scanner) fetchAll(ctx context.Context, jobs []fetchJob) []answer {
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
	return answers
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
// Redirects are followed only on the same scheme, host and port, at most maxRedirects; another is reported as its Location.
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
	client := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects || req.URL.Scheme+"://"+req.URL.Host != start {
			return http.ErrUseLastResponse
		}
		return nil
	}}
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
