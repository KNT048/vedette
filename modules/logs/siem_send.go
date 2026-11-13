package logs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// siemTimeout bounds a connection, a write and an HTTP call to the SIEM.
const siemTimeout = 10 * time.Second

var (
	errSiemForbidden  = errors.New("logs: the SIEM address is link-local, multicast, unspecified or a cloud metadata service")
	errSiemOwn        = errors.New("logs: the SIEM address is Vedette itself")
	errSiemBoxUnknown = errors.New("logs: the box's own addresses are not known yet")
	errSiemNotPrivate = errors.New("logs: plain http is only sent to an address on your own network")
	errSiemStatus     = errors.New("logs: the destination answered with an error status")
)

// statusError is an HTTP answer outside 2xx.
type statusError struct{ Code int }

func (e *statusError) Error() string { return errSiemStatus.Error() + ": HTTP " + strconv.Itoa(e.Code) }
func (e *statusError) Unwrap() error { return errSiemStatus }

// metadataAddrs are cloud instance-metadata endpoints that are not link-local.
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("fd20:ce::254"), netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("192.0.0.192")}

// addrForms is ip plus the IPv4 address that a transition form carries (NAT64, 6to4, IPv4-compatible): a connection to one of them
// reaches that IPv4 address through a translator, so both are judged (D-208 does the same for feeds).
func addrForms(ip netip.Addr) []netip.Addr {
	ip = ip.Unmap().WithZone("")
	out := []netip.Addr{ip}
	if !ip.Is6() {
		return out
	}
	b := ip.As16()
	var v4 [4]byte
	zeros := func(from, to int) bool {
		for _, x := range b[from:to] {
			if x != 0 {
				return false
			}
		}
		return true
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && zeros(4, 12):
		copy(v4[:], b[12:16])
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1:
		for _, x := range nat64Local(b) {
			out = append(out, netip.AddrFrom4(x))
		}
		return out
	case b[0] == 0x20 && b[1] == 0x02:
		copy(v4[:], b[2:6])
	case zeros(0, 12) && !ip.IsUnspecified() && ip != netip.IPv6Loopback():
		copy(v4[:], b[12:16])
	default:
		return out
	}
	return append(out, netip.AddrFrom4(v4))
}

// nat64Layouts are the RFC 6052 layouts a 64:ff9b:1::/48 sub-prefix can have (never /32 or /40): the prefix length and the byte
// offsets of the four IPv4 octets (byte 8 is the reserved u octet).
var nat64Layouts = []struct {
	bits int
	at   [4]int
}{{48, [4]int{6, 7, 9, 10}}, {56, [4]int{7, 9, 10, 11}}, {64, [4]int{9, 10, 11, 12}}, {96, [4]int{12, 13, 14, 15}}}

func nat64Embed(b [16]byte, at [4]int) [4]byte {
	return [4]byte{b[at[0]], b[at[1]], b[at[2]], b[at[3]]}
}

// nat64Always is what a guard never allows whatever the box's own addresses are (loopback, link-local, multicast, unspecified,
// broadcast, cloud metadata): a reading of such an address is judged in every layout, learned or not (D-442 (2)).
func nat64Always(a netip.Addr) bool {
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || slices.Contains(metadataAddrs, a)
}

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry. The operator's prefix is a sub-prefix of that /48
// and its length is not in the address. The address is read in each layout and every reading is judged, so a forbidden IPv4 address
// is never missed. When the network's own NAT64 prefix was learned (nat64Prefixes, RFC 7050) and covers the address, the learned
// layouts (all that cover it) are read for the checks that depend on the network (private ranges, the box's own addresses), and the
// other layouts only for nat64Always: DNS can narrow the first group, never switch off the second. A learned reading inside 0.0.0.0/8
// falls back to every layout. Otherwise a reading inside 0.0.0.0/8 is dropped: a translator never forwards to "this network", and it
// is what the zero suffix of a shorter prefix looks like in a longer layout. An operator prefix whose own bytes read as an
// always-refused address in a shorter layout (byte 6, or byte 7 for a /64 or /96, of 127 or 224-239, or the bytes a9fe) has every
// NAT64 destination refused (a known false positive: it fails closed).
func nat64Local(b [16]byte) [][4]byte {
	addr := netip.AddrFrom16(b)
	var out [][4]byte
	add := func(v4 [4]byte) {
		if v4[0] != 0 && !slices.Contains(out, v4) {
			out = append(out, v4)
		}
	}
	var bits []int
	for _, p := range nat64Prefixes() {
		if p.Contains(addr) {
			bits = append(bits, p.Bits())
		}
	}
	if len(bits) > 0 {
		learned := true
		for _, l := range nat64Layouts {
			if slices.Contains(bits, l.bits) {
				if v4 := nat64Embed(b, l.at); v4[0] == 0 {
					learned = false
				} else {
					add(v4)
				}
			}
		}
		if learned {
			for _, l := range nat64Layouts {
				if v4 := nat64Embed(b, l.at); nat64Always(netip.AddrFrom4(v4)) {
					add(v4)
				}
			}
			return out
		}
		out = nil
	}
	for _, l := range nat64Layouts {
		add(nat64Embed(b, l.at))
	}
	return out
}

// learnNAT64 reads the AAAA answers for ipv4only.arpa (RFC 7050, what Android, iOS and systemd-resolved do): an answer inside
// 64:ff9b:1::/48 that carries 192.0.0.170 or 192.0.0.171 in exactly one layout, with a zero u octet, gives the prefix and its length.
func learnNAT64(answers []netip.Addr) []netip.Prefix {
	local := netip.MustParsePrefix("64:ff9b:1::/48")
	var out []netip.Prefix
	for _, a := range answers {
		a = a.Unmap()
		if !a.Is6() || !local.Contains(a) {
			continue
		}
		b := a.As16()
		if b[8] != 0 {
			continue
		}
		bits := 0
		for _, l := range nat64Layouts {
			if v4 := nat64Embed(b, l.at); v4 == [4]byte{192, 0, 0, 170} || v4 == [4]byte{192, 0, 0, 171} {
				if bits != 0 {
					bits = -1
					break
				}
				bits = l.bits
			}
		}
		if bits > 0 {
			if p := netip.PrefixFrom(a, bits).Masked(); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// nat64Cache asks the system resolver for ipv4only.arpa only when a 64:ff9b:1::/48 address is judged, for at most 2 s, and keeps the
// answer 6 hours (10 minutes when nothing was learned or the lookup failed, so a missing DNS64 costs one lookup per 10 minutes).
// One lookup runs at a time and nobody waits for it: a caller that finds it running (or a fresh cache) gets what is known, which is
// nothing at first, and nothing means every layout. The query carries no customer data (D-442).
type nat64Cache struct {
	mu       sync.Mutex
	lookup   func(ctx context.Context) ([]netip.Addr, error)
	now      func() time.Time
	prefixes []netip.Prefix
	until    time.Time
	busy     bool
}

func (c *nat64Cache) get() []netip.Prefix {
	c.mu.Lock()
	if c.busy || c.now().Before(c.until) {
		defer c.mu.Unlock()
		return c.prefixes
	}
	c.busy = true
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answers, err := c.lookup(ctx)
	prefixes := learnNAT64(answers)
	ttl := 6 * time.Hour
	if err != nil || len(prefixes) == 0 {
		ttl = 10 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy, c.prefixes, c.until = false, prefixes, c.now().Add(ttl)
	return prefixes
}

// nat64Prefixes is the learned NAT64 prefixes of this network. Tests replace it.
var nat64Prefixes = (&nat64Cache{
	lookup: func(ctx context.Context) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	},
	now: time.Now,
}).get

// siemForbidden says whether the SIEM may never be at ip: link-local, multicast, unspecified, broadcast or a cloud metadata
// endpoint, in any of its transition forms. RFC 1918 addresses are fine: an internal SIEM is the normal case. Vedette itself is
// siemOwn's (D-446).
func siemForbidden(ip netip.Addr) bool {
	for _, f := range addrForms(ip) {
		switch {
		case f.IsUnspecified(), f.IsMulticast(), f.IsLinkLocalUnicast(), f.IsLinkLocalMulticast(), f == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			return true
		}
		for _, m := range metadataAddrs {
			if f == m {
				return true
			}
		}
	}
	return false
}

// vedettePorts are the ports Vedette itself answers on at the machine's addresses (D-446): the interface 8443, the sensor link 8444,
// MCP 8765, syslog 514 and syslog over TLS 6514 (install.sh preflight, the core unit's PublishPort lines, the container-only compose).
// Same list in feeds, notify and ai. A SIEM forward to 514 or 6514 of the machine would loop back into Vedette's own listener.
var vedettePorts = []uint16{514, 6514, 8443, 8444, 8765}

// siemOwn says whether ip at port is Vedette itself (D-446), in any transition form: loopback (unless allowLoopback, tests only), an
// address of core's own container (selfAddrs) on every port, or one of machine (the machine's addresses: vedette-host, the
// container's gateway) on a port of vedettePorts. A SIEM on the machine at its own port is a normal destination.
func siemOwn(ip netip.Addr, port uint16, machine []netip.Addr, allowLoopback bool) bool {
	self := selfAddrs()
	vport := slices.Contains(vedettePorts, port)
	for _, f := range addrForms(ip) {
		if f.IsLoopback() {
			if !allowLoopback {
				return true
			}
			continue
		}
		if slices.Contains(self, f) {
			return true
		}
		if vport {
			for _, m := range machine {
				if m.Unmap().WithZone("") == f {
					return true
				}
			}
		}
	}
	return false
}

// selfAddrs are the addresses of this process's own interfaces (in the shipped container: core itself), loopback left out.
func selfAddrs() []netip.Addr {
	var out []netip.Addr
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if p, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(p.IP); ok && !ip.Unmap().IsLoopback() {
					out = append(out, ip.Unmap().WithZone(""))
				}
			}
		}
	}
	return out
}

// ownText is the sentence for Vedette itself (D-446): the same in feeds, notify, logs and ai.
const ownText = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."

// siemControl runs on the socket just before connect, after name resolution, for TCP and UDP alike, so a name that resolves (or
// rebinds) to a forbidden address is refused where it counts. privateOnly is the rule of plain http: only an address on the
// customer's own network.
func (s *Service) siemControl(privateOnly bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return errSiemForbidden
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return errSiemForbidden
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return errSiemForbidden
		}
		box, known := s.boxAddrs()
		if !known {
			return errSiemBoxUnknown // fail closed: until vedette-host has answered, the box's own addresses cannot be excluded
		}
		if siemOwn(ip, uint16(n), box, s.allowLoopback) {
			return errSiemOwn
		}
		if siemForbidden(ip) {
			return errSiemForbidden
		}
		if privateOnly {
			a := ip.Unmap()
			if !a.IsPrivate() && (!a.IsLoopback() || !s.allowLoopback) {
				return errSiemNotPrivate
			}
		}
		return nil
	}
}

func (s *Service) dialer(privateOnly bool) *net.Dialer {
	return &net.Dialer{Timeout: siemTimeout, Control: s.siemControl(privateOnly)}
}

// sendOut is siemSend, or the test's replacement of it.
func (s *Service) sendOut(ctx context.Context, cfg siemRow, recs []siemRecord) (string, error) {
	if s.siemSendFn != nil {
		return s.siemSendFn(ctx, cfg, recs)
	}
	return s.siemSend(ctx, cfg, recs)
}

// siemSend writes records to the destination of cfg and returns a sentence for the test result. Sending never touches the database:
// the caller holds no writer while this runs.
func (s *Service) siemSend(ctx context.Context, cfg siemRow, recs []siemRecord) (string, error) {
	host := s.hostname(ctx)
	if cfg.Format == "json" {
		return s.sendWebhook(ctx, cfg, recs, host)
	}
	return s.sendSyslog(ctx, cfg, recs, host)
}

func (s *Service) sendSyslog(ctx context.Context, cfg siemRow, recs []siemRecord, host string) (string, error) {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := s.dialer(false)
	var conn net.Conn
	var err error
	switch cfg.Proto {
	case "udp":
		conn, err = d.DialContext(ctx, "udp", addr)
	case "tcp":
		conn, err = d.DialContext(ctx, "tcp", addr)
	case "tls":
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}}
		conn, err = td.DialContext(ctx, "tcp", addr)
	default:
		return "", errors.New("logs: unknown SIEM protocol")
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	for _, r := range recs {
		var line []byte
		if cfg.Format == "cef" {
			line = formatCEF(r, host)
		} else {
			line = formatSyslog(r, host)
		}
		if cfg.Proto != "udp" {
			line = octetFrame(line)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(siemTimeout))
		if _, err := conn.Write(line); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("Sent %d test record to %s:%d/%s.", len(recs), cfg.Host, cfg.Port, cfg.Proto), nil
}

func (s *Service) sendWebhook(ctx context.Context, cfg siemRow, recs []siemRecord, host string) (string, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Timeout:       2 * siemTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // a redirect is an answer, never followed
		Transport: &http.Transport{
			Proxy:                 nil, // never an environment proxy: it would see the signed body
			DialContext:           s.dialer(u.Scheme == "http").DialContext,
			TLSHandshakeTimeout:   siemTimeout,
			ResponseHeaderTimeout: siemTimeout,
			DisableKeepAlives:     true,
		},
	}
	code := 0
	for _, r := range recs {
		body := formatJSON(r, host)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		ts := strconv.FormatInt(s.now().Unix(), 10)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Vedette-logs")
		req.Header.Set(siemTimestampHeader, ts)
		req.Header.Set(siemSignatureHeader, siemSign(cfg.key.Reveal(), ts, body))
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		code = resp.StatusCode
		_ = resp.Body.Close()
		if code < 200 || code > 299 {
			return "", &statusError{Code: code}
		}
	}
	return fmt.Sprintf("The destination returned HTTP %d.", code), nil
}

// siemFailure turns a send error into a fixed sentence for the test result. The error text itself is never shown: a Go error of an
// HTTP call carries the whole URL (its path is a token), and the remote's own words could carry anything.
func siemFailure(err error, cfg siemRow) string {
	target := cfg.Host
	if cfg.Format == "json" {
		if u, e := url.Parse(cfg.URL); e == nil {
			target = u.Scheme + "://" + u.Host
		}
	}
	var dnsErr *net.DNSError
	var se *statusError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, errSiemBoxUnknown):
		return "The box does not know its own addresses yet, so it cannot check the destination. Try again in a minute."
	case errors.Is(err, errSiemOwn):
		return "Refused. " + ownText
	case errors.Is(err, errSiemForbidden):
		return "Refused: the destination is a link-local, multicast or unspecified address, or a cloud metadata service."
	case errors.Is(err, errSiemNotPrivate):
		return "Refused: plain http:// is only sent to an address on your own network. Use https:// for this destination."
	case errors.Is(err, errSiemStatus):
		errors.As(err, &se)
		return "The destination answered HTTP " + strconv.Itoa(se.Code) + ". Check the URL and the signing key on the receiving side."
	case errors.As(err, &dnsErr):
		return "Could not find " + target + ". Check the name."
	case errors.Is(err, context.DeadlineExceeded):
		return "Could not reach " + target + " in time. Check the name or IP address, the port and any firewall between the box and the SIEM."
	}
	if errors.As(err, &certErr) {
		return "The certificate of " + target + " is not trusted or does not match the name. Vedette checks it against the system's certificate authorities."
	}
	return "Could not connect to " + target + ". Check the name or IP address, the port and any firewall between the box and the SIEM."
}
