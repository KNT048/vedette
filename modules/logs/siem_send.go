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
	"strconv"
	"syscall"
	"time"
)

// siemTimeout bounds a connection, a write and an HTTP call to the SIEM.
const siemTimeout = 10 * time.Second

var (
	errSiemForbidden  = errors.New("logs: the SIEM address is this machine, link-local, multicast, unspecified or an address of this box")
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

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry. The operator's prefix is a sub-prefix of that /48,
// so its length is /48, /56, /64 or /96 (never /32 or /40) and is not known from the address: it is read in each of those RFC 6052 layouts
// (byte 8 is the reserved u octet) and every reading is judged. A reading inside 0.0.0.0/8 is dropped: a translator never forwards to
// "this network", and it is what the zero suffix of a shorter prefix looks like in a longer layout.
func nat64Local(b [16]byte) [][4]byte {
	var out [][4]byte
	for _, v4 := range [][4]byte{
		{b[6], b[7], b[9], b[10]},
		{b[7], b[9], b[10], b[11]},
		{b[9], b[10], b[11], b[12]},
		{b[12], b[13], b[14], b[15]},
	} {
		if v4[0] != 0 {
			out = append(out, v4)
		}
	}
	return out
}

// siemForbidden says whether the SIEM may never be at ip: loopback (the box's own services listen there), link-local, multicast,
// unspecified, broadcast, a cloud metadata endpoint, or one of the box's own addresses, in any of its transition forms. RFC 1918
// addresses are fine: an internal SIEM is the normal case. allowLoopback is set by tests only.
func siemForbidden(ip netip.Addr, box []netip.Addr, allowLoopback bool) bool {
	for _, f := range addrForms(ip) {
		switch {
		case f.IsUnspecified(), f.IsMulticast(), f.IsLinkLocalUnicast(), f.IsLinkLocalMulticast(), f == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			return true
		case f.IsLoopback():
			if !allowLoopback {
				return true
			}
			continue
		}
		for _, m := range metadataAddrs {
			if f == m {
				return true
			}
		}
		for _, b := range box {
			if b.Unmap().WithZone("") == f {
				return true
			}
		}
	}
	return false
}

// siemControl runs on the socket just before connect, after name resolution, for TCP and UDP alike, so a name that resolves (or
// rebinds) to a forbidden address is refused where it counts. privateOnly is the rule of plain http: only an address on the
// customer's own network.
func (s *Service) siemControl(privateOnly bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errSiemForbidden
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return errSiemForbidden
		}
		box, known := s.boxAddrs()
		if !known {
			return errSiemBoxUnknown // fail closed: until vedette-host has answered, the box's own addresses cannot be excluded
		}
		if siemForbidden(ip, box, s.allowLoopback) {
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
	case errors.Is(err, errSiemForbidden):
		return "Refused: the destination is this machine, a link-local, multicast or unspecified address, or an address of this box."
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
