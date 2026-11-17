package feeds

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// Supervisor, N100 2026-11-17: with www.cisa.gov pointed at 127.0.0.1, main's pull ended in the egress guard's error ("it is Vedette
// itself") and never asked the GitHub copy. With both copies asked at every check (D-91 as amended), cisa.gov failing at any level
// leaves the GitHub copy's list applied in that same check, with the right note and no alert. The real guarded client runs here
// (newClient with a test resolver); only the final connect is pointed at local test servers (Fetcher.dialOverride, after every check).
func TestG13_CISAFailingAtEveryLevelTheCopyIsAppliedInTheSameCheck(t *testing.T) {
	t.Parallel()
	addr := map[string]string{ // what each test name resolves to (none of them is this machine)
		"mirror.lan": "10.255.77.2", "refused.lan": "10.255.77.3", "badtls.lan": "10.255.77.4", "status.lan": "10.255.77.5",
		"slow.lan": "10.255.77.6", "own.lan": "127.0.0.1", // nxdomain.lan: not in the table
	}
	for name, c := range map[string]struct {
		primary string
		status  int // status.lan answers it
		why     string
	}{
		"DNS failure":        {"http://nxdomain.lan/kev.json", 0, "cisa.gov did not resolve on this box"},
		"connection refused": {"http://refused.lan/kev.json", 0, "cisa.gov refused the connection"},
		"TLS bad cert":       {"https://badtls.lan/kev.json", 0, "cisa.gov failed the secure connection (TLS certificate or handshake)"},
		"egress guard":       {"http://own.lan/kev.json", 0, "cisa.gov resolved to an address Vedette does not connect to"},
		"HTTP 403":           {"http://status.lan/kev.json", http.StatusForbidden, "cisa.gov refused this box (HTTP 403)"},
		"HTTP 503":           {"http://status.lan/kev.json", http.StatusServiceUnavailable, "cisa.gov answered HTTP 503"},
		"timeout":            {"http://slow.lan/kev.json", 0, "cisa.gov did not answer in time"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var e *env
			date := func(w http.ResponseWriter) { w.Header().Set("Date", e.clock().UTC().Format(http.TimeFormat)) }
			mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				date(w)
				_, _ = w.Write([]byte(testFile(t, "kev.json")))
			}))
			defer mirror.Close()
			status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { date(w); answer(w, c.status) }))
			defer status.Close()
			badTLS := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("a bad certificate was trusted") }))
			defer badTLS.Close()
			closed, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			closedAddr := closed.Addr().String()
			_ = closed.Close()
			to := map[string]string{"10.255.77.2": mirror.Listener.Addr().String(), "10.255.77.3": closedAddr, "10.255.77.4": badTLS.Listener.Addr().String(),
				"10.255.77.5": status.Listener.Addr().String()}
			res := func(_ context.Context, host string) ([]netip.Addr, error) {
				if a, ok := addr[host]; ok {
					return []netip.Addr{netip.MustParseAddr(a)}, nil
				}
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(address)
				if host == "10.255.77.6" {
					return nil, &net.OpError{Op: "dial", Net: network, Err: os.ErrDeadlineExceeded}
				}
				target, ok := to[host]
				if !ok {
					return nil, errors.New("no test server at " + address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}
			e = newEnvFetcher(t, Fetcher{Client: newClient(DefaultFetchTimeout, res), Version: "test", dialOverride: dial})
			a := &alerts{}
			e.svc.Alert = a.send
			e.only("cisa-kev")
			e.svc.KEVPrimary, e.svc.KEVFallback = c.primary, "http://mirror.lan/kev.json"
			e.mirror("cisa-kev", c.primary)

			e.tick(e.svc, 0) // one scheduled check
			f := e.feed("cisa-kev")
			if f.Status != "ok" || orEmpty(f.AnsweredBy) != AnsweredMirror || f.Error == nil || !strings.HasPrefix(*f.Error, c.why+"; the other copy answered.") {
				t.Fatalf("status %v, newest from %v, note %v", f.Status, orEmpty(f.AnsweredBy), orEmpty(f.Error))
			}
			if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Vendor != "Synology" {
				t.Error("the GitHub copy's list was not applied in the same check")
			}
			if got := a.list(); len(got) != 0 {
				t.Errorf("one copy failing alerted: %v", got)
			}
		})
	}
}
