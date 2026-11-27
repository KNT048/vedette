package ai

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// The box reads a possible CVE's reference pages itself, guarded: https only, a public address only (checked after the name is
// resolved), redirects to https only, a 2 MiB body, at most three pages read per CVE (a failed one leaves its place); each page says why
// it was not read.
func TestRefFetcher_Limits(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/advisory":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><p>Junos OS 15.1 versions before 15.1R7-S13 are affected.</p></body></html>"))
		case "/big":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strings.Repeat("a", refMaxBody+10)))
		case "/to-http":
			http.Redirect(w, r, "http://example.com/advisory", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "internal.example.com" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	connect := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	f := newRefFetcher(resolve, connect)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	f.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	pages := f.fetch(t.Context(), []string{
		"http://example.com/advisory",           // skipped: not https
		"https://internal.example.com/advisory", // refused: a private address
		"https://example.com/advisory",          // read
		"https://example.com/big",               // too large
		"https://example.com/to-http",           // a redirect to http is refused
		"https://example.com/advisory?2",        // read
		"https://example.com/advisory?3",        // read: three pages read
		"https://example.com/advisory?4",        // skipped
	})
	want := []struct{ status, note string }{
		{"skipped", "https"}, {"failed", "public internet address"}, {"ok", ""}, {"failed", "2 MiB"}, {"failed", "redirected"}, {"ok", ""}, {"ok", ""},
		{"skipped", "pages are read"},
	}
	if len(pages) != len(want) {
		t.Fatalf("%d pages, want %d: %+v", len(pages), len(want), pages)
	}
	for i, w := range want {
		if pages[i].Status != w.status || !strings.Contains(pages[i].Note, w.note) {
			t.Errorf("%s: %s %q, want %s with %q", pages[i].URL, pages[i].Status, pages[i].Note, w.status, w.note)
		}
	}
	if !strings.Contains(pages[2].Text, "15.1 versions before 15.1R7-S13") {
		t.Errorf("text of the page: %q", pages[2].Text)
	}
}

// A page that answers but carries no advisory text (a script-rendered portal's shell: "Loading", "Refresh", no CVE id and no version
// number) is not read: it is marked empty and leaves its place to the next page.
func TestRefFetcher_AScriptShellIsNotRead(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/shell":
			_, _ = w.Write([]byte(`<html><head><title>Example Community</title><script src="/app.js"></script></head><body><div>Loading</div>` +
				`<div>&times; Sorry to interrupt</div><div>CSS Error</div><a href="#">Refresh</a></body></html>`))
		default:
			_, _ = w.Write([]byte("<html><body><p>CVE-2099-0001: Example OS 15.1 versions before 15.1R7-S13 are affected.</p></body></html>"))
		}
	}))
	t.Cleanup(srv.Close)
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	connect := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	f := newRefFetcher(resolve, connect)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	f.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	pages := f.fetch(t.Context(), []string{"https://example.com/shell", "https://example.com/a1", "https://example.com/a2", "https://example.com/a3"})
	if len(pages) != 4 || pages[0].Status != "failed" || !pages[0].Empty || pages[0].Text != "" {
		t.Fatalf("the shell page: %+v, want failed, empty, no text", pages)
	}
	for _, p := range pages[1:] {
		if p.Status != "ok" || p.Empty {
			t.Errorf("%s: %s empty %v, want read (the shell leaves its place)", p.URL, p.Status, p.Empty)
		}
	}
}
