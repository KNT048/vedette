package surface

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The tests run in a synctest bubble on an in-memory network (net.Pipe): no real address is ever dialed and no real clock is waited
// on (the rate limit and the timeouts run on the bubble's clock).

// testPublic stands for exposure.IsPublicIPv4 here: the documentation ranges are "public" so that the tests use them.
func testPublic(a netip.Addr) bool {
	return a.Is4() && !a.IsPrivate() && !a.IsLoopback() && !a.IsUnspecified()
}

type handler func(c net.Conn)

// fakeNet answers the dials of the scanner: an address with a handler accepts, every other one is refused.
type fakeNet struct {
	mu     sync.Mutex
	open   map[string]handler
	dialed []string
}

func (n *fakeNet) dial(_ context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	h := n.open[addr]
	n.mu.Unlock()
	if network != "tcp" || h == nil {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		h(server)
	}()
	return client, nil
}

func (n *fakeNet) dials(prefix string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, d := range n.dialed {
		if strings.HasPrefix(d, prefix) {
			c++
		}
	}
	return c
}

// serve answers one HTTP request; resp picks the answer from the request (its Host and path).
func serve(resp func(r *http.Request) string) handler {
	return func(c net.Conn) {
		r, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return // a port-scan connection: closed without a word
		}
		_, _ = io.WriteString(c, resp(r))
	}
}

// overTLS wraps a handler in a TLS server that shows cert.
func overTLS(cert tls.Certificate, h handler) handler {
	return func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return
		}
		h(tc)
	}
}

func silent(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

func htmlPage(title string) func(*http.Request) string {
	return func(*http.Request) string {
		body := "<html><head><title>" + title + "</title></head><body>hello</body></html>"
		return "HTTP/1.1 200 OK\r\nServer: nginx/1.22\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	}
}

var notAfter = time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)

// selfSigned makes a certificate for name whose issuer is itself, or one signed by a CA named issuer.
func selfSigned(t *testing.T, name, issuer string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter}
	parent, signer := tpl, key
	if issuer != "" {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parent, signer = &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: issuer}, IsCA: true, BasicConstraintsValid: true,
			NotBefore: tpl.NotBefore, NotAfter: notAfter}, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ctAnswer(status int, body string, asked *[]string) *http.Client {
	return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		*asked = append(*asked, r.URL.String())
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("only ip4 is asked")
	}
	if a, ok := f[host]; ok {
		return slices.Clone(a), nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, x := range s {
		out[i] = netip.MustParseAddr(x)
	}
	return out
}

func newScanner(t *testing.T, n *fakeNet, r Resolver, ct *http.Client) *Scanner {
	t.Helper()
	s, err := New(Config{Public: testPublic, Dial: n.dial, Resolver: r, CT: ct, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A domain: the names come from CT (only valid names under the domain), the public addresses are probed, a private one is listed
// and never dialed; pages, admin pages and certificates come from the open ports, with the name in Host and SNI.
func TestDomainScan(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		fortigate := selfSigned(t, "acme.example", "Example CA R1")
		mail := selfSigned(t, "mail.acme.example", "")
		var hosts []string
		var mu sync.Mutex
		login := func(r *http.Request) string {
			mu.Lock()
			hosts = append(hosts, r.Host)
			mu.Unlock()
			return htmlPage("FortiGate - Login")(r)
		}
		n := &fakeNet{open: map[string]handler{
			"203.0.113.10:22":  silent,
			"203.0.113.10:80":  serve(htmlPage("Welcome to Acme")),
			"203.0.113.10:443": overTLS(fortigate, serve(login)),
			"203.0.113.11:993": overTLS(mail, silent),
			"10.0.0.5:80":      serve(htmlPage("internal")),
		}}
		ct := `[{"common_name":"acme.example","name_value":"acme.example\nwww.acme.example\n*.acme.example"},
			{"common_name":"mail.acme.example","name_value":"MAIL.acme.example.\nfoo@acme.example\nevil.other.example\nxacme.example"},
			{"common_name":"internal.acme.example","name_value":"internal.acme.example\ngone.acme.example"}]`
		var asked []string
		res := fakeResolver{
			"acme.example": addrs("203.0.113.10"), "www.acme.example": addrs("203.0.113.10"), "mail.acme.example": addrs("203.0.113.11"),
			"internal.acme.example": addrs("10.0.0.5"),
		}
		got, err := newScanner(t, n, res, ctAnswer(200, ct, &asked)).Domain(t.Context(), "acme.example")
		if err != nil {
			t.Fatal(err)
		}
		if len(asked) != 1 || asked[0] != "https://crt.sh/?q=%25.acme.example&output=json" {
			t.Fatalf("CT asked %v", asked)
		}
		var names []string
		for _, h := range got.Hosts {
			names = append(names, h.Name+"="+h.IP.String())
		}
		if want := []string{"acme.example=203.0.113.10", "www.acme.example=203.0.113.10", "mail.acme.example=203.0.113.11", "internal.acme.example=10.0.0.5"}; !slices.Equal(names, want) {
			t.Fatalf("hosts %v, want %v", names, want)
		}
		if d := n.dials("10.0.0.5"); d != 0 {
			t.Fatalf("a private address was dialed %d times", d)
		}
		if d := n.dials("203.0.113.10:"); d < len(commonPorts) {
			t.Fatalf("%d dials to the public address, want every port of the list", d)
		}
		var ports []string
		for _, p := range got.Ports {
			ports = append(ports, fmt.Sprintf("%s:%d/%s/%s", p.IP, p.Port, p.Service, p.Product))
		}
		if want := []string{"203.0.113.10:22/ssh/", "203.0.113.10:80/http/nginx/1.22", "203.0.113.10:443/https/FortiGate", "203.0.113.11:993/imaps/"}; !slices.Equal(ports, want) {
			t.Fatalf("ports %v, want %v", ports, want)
		}
		if len(got.Admin) != 2 || got.Admin[0] != (Admin{URL: "https://acme.example", Product: "FortiGate", IP: netip.MustParseAddr("203.0.113.10"), Port: 443, Danger: true}) ||
			got.Admin[1].URL != "https://www.acme.example" {
			t.Fatalf("admin %+v", got.Admin)
		}
		slices.Sort(hosts)
		if !slices.Equal(hosts, []string{"acme.example", "www.acme.example"}) {
			t.Fatalf("Host headers %v", hosts)
		}
		var certs []string
		for _, c := range got.Certs {
			certs = append(certs, c.Host+"|"+c.Issuer+"|"+c.NotAfter.Format(time.RFC3339))
		}
		if want := []string{"acme.example|Example CA R1|2031-03-04T05:06:07Z", "www.acme.example|Example CA R1|2031-03-04T05:06:07Z", "mail.acme.example:993|Self-signed|2031-03-04T05:06:07Z"}; !slices.Equal(certs, want) {
			t.Fatalf("certs %v, want %v", certs, want)
		}
	})
}

// The box's own IP: its pages are read with the IP as the host; an address that is not public is refused before any dial.
func TestIPScan(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cert := selfSigned(t, "pfsense.localdomain", "")
		n := &fakeNet{open: map[string]handler{"203.0.113.7:8443": overTLS(cert, serve(htmlPage("pfSense - Login")))}}
		s := newScanner(t, n, fakeResolver{}, nil)
		got, err := s.IP(t.Context(), netip.MustParseAddr("203.0.113.7"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Hosts) != 0 || len(got.Ports) != 1 || got.Ports[0].Product != "pfSense" || got.Ports[0].Service != "https" {
			t.Fatalf("result %+v", got)
		}
		if len(got.Admin) != 1 || got.Admin[0].URL != "https://203.0.113.7:8443" || !got.Admin[0].Danger {
			t.Fatalf("admin %+v", got.Admin)
		}
		if len(got.Certs) != 1 || got.Certs[0].Host != "203.0.113.7:8443" || got.Certs[0].Issuer != "Self-signed" {
			t.Fatalf("certs %+v", got.Certs)
		}
		before := len(n.dialed)
		if _, err := s.IP(t.Context(), netip.MustParseAddr("192.168.1.1")); !errors.Is(err, ErrNotPublic) {
			t.Fatalf("private IP: %v", err)
		}
		if len(n.dialed) != before {
			t.Fatal("a private IP was dialed")
		}
	})
}

// No answer from CT stops the scan (a snapshot without the subdomains would say they are gone): asked twice, nothing dialed.
func TestCTDownStopsTheScan(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		for _, c := range []struct {
			status int
			body   string
		}{{502, "Bad Gateway"}, {200, "<html>busy</html>"}} {
			n := &fakeNet{open: map[string]handler{}}
			var asked []string
			_, err := newScanner(t, n, fakeResolver{"acme.example": addrs("203.0.113.10")}, ctAnswer(c.status, c.body, &asked)).Domain(t.Context(), "acme.example")
			if !errors.Is(err, ErrCT) || len(asked) != 2 || len(n.dialed) != 0 {
				t.Fatalf("%d: err %v, asked %d, dialed %d", c.status, err, len(asked), len(n.dialed))
			}
		}
	})
}

// A redirect to the same page origin is followed; one elsewhere is not (it is matched as its Location), and nothing but the
// planned address is ever dialed.
func TestRedirects(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		n := &fakeNet{open: map[string]handler{
			"203.0.113.7:80": serve(func(r *http.Request) string {
				if r.URL.Path == "/login" {
					return htmlPage("RouterOS router configuration page")(r)
				}
				return "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			}),
			"203.0.113.7:10443": overTLS(selfSigned(t, "vpn", ""), serve(func(*http.Request) string {
				return "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/remote/login?lang=en\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			})),
		}}
		got, err := newScanner(t, n, fakeResolver{}, nil).IP(t.Context(), netip.MustParseAddr("203.0.113.7"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Admin) != 1 || got.Admin[0].Product != "MikroTik RouterOS" || got.Admin[0].URL != "http://203.0.113.7" {
			t.Fatalf("admin %+v", got.Admin)
		}
		if len(got.Ports) != 2 || got.Ports[1].Product != "Fortinet SSL VPN" {
			t.Fatalf("ports %+v", got.Ports)
		}
		for _, d := range n.dialed {
			if !strings.HasPrefix(d, "203.0.113.7:") {
				t.Fatalf("dialed %s", d)
			}
		}
	})
}

func TestIdentify(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		p    page
		want string
	}{
		{page{title: "fortigate"}, "FortiGate"},
		{page{title: "synology diskstation - nas01"}, "Synology DSM"},
		{page{title: "dashboard [jenkins]"}, "Jenkins"},
		{page{header: map[string]bool{"x-jenkins": true}}, "Jenkins"},
		{page{title: "integrated lights-out 5"}, "HPE iLO"},
		{page{title: "ilo 5 login"}, "HPE iLO"},
		{page{title: "grafana"}, "Grafana"},
		{page{title: "asus router login"}, "ASUS router"},
		{page{title: "gpon home gateway"}, "GPON home gateway"},
		{page{body: `{"name":"x","tagline":"you know, for search"}`}, "Elasticsearch"},
		// ordinary sites are not admin pages
		{page{title: "acme store - asus laptops"}, ""},
		{page{title: "grain silo supplies"}, ""},
		{page{title: "our partners: cisco, fortinet", body: "we resell fortinet and pfsense"}, ""},
		{page{title: "welcome"}, ""},
	} {
		got := ""
		if fp := identify(c.p); fp != nil {
			got = fp.product
		}
		if got != c.want {
			t.Errorf("identify(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestParseCT(t *testing.T) {
	t.Parallel()
	if _, err := parseCT(strings.NewReader(`{"error":"busy"}`), "acme.example", maxCTBody); err == nil {
		t.Fatal("an object was taken for the list")
	}
	if _, err := parseCT(strings.NewReader(`[{"name_value":"a.acme.example"}, {"name_value":`), "acme.example", maxCTBody); err == nil {
		t.Fatal("a broken answer was taken")
	}
	// at most maxNames names, the domain first; the rest of a long answer is not read
	var b strings.Builder
	b.WriteString("[")
	for i := range 500 {
		fmt.Fprintf(&b, `{"name_value":"h%d.acme.example"},`, i)
	}
	b.WriteString(`"not an entry"]`)
	names, err := parseCT(strings.NewReader(b.String()), "acme.example", maxCTBody)
	if err != nil || len(names) != maxNames || names[0] != "acme.example" || names[1] != "h0.acme.example" {
		t.Fatalf("%d names, %v", len(names), err)
	}
	// an answer cut at the size limit keeps the whole entries before the cut
	big := `[{"name_value":"a.acme.example"},{"name_value":"` + strings.Repeat("x", 1000) + `"}]`
	if names, err := parseCT(strings.NewReader(big), "acme.example", 500); err != nil || !slices.Equal(names, []string{"acme.example", "a.acme.example"}) {
		t.Fatalf("cut answer: %v %v", names, err)
	}
}

// FuzzParseCT: whatever crt.sh sends, the parser does not panic and keeps only valid names under the domain.
func FuzzParseCT(f *testing.F) {
	f.Add(`[{"common_name":"a.acme.example","name_value":"b.acme.example\n*.acme.example"}]`)
	f.Add(`[{"name_value":"\u0000.acme.example"}]`)
	f.Add(`[`)
	f.Fuzz(func(t *testing.T, in string) {
		names, err := parseCT(strings.NewReader(in), "acme.example", maxCTBody)
		if err != nil {
			return
		}
		if len(names) == 0 || len(names) > maxNames || names[0] != "acme.example" {
			t.Fatalf("names %v", names)
		}
		for _, n := range names[1:] {
			if !nameRE.MatchString(n) || !strings.HasSuffix(n, ".acme.example") {
				t.Fatalf("kept %q", n)
			}
		}
	})
}

// The port list is fixed and documented (D-229): no port twice, about a hundred.
func TestPortList(t *testing.T) {
	t.Parallel()
	if len(portByNumber) != len(commonPorts) || len(commonPorts) < 80 || len(commonPorts) > 110 {
		t.Fatalf("%d ports, %d distinct", len(commonPorts), len(portByNumber))
	}
}
