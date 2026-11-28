package ai

import (
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
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
			_, _ = w.Write([]byte("<html><body><p>Junos OS 15.1 versions before 15.1R7-S13 are affected.</p><p>Copy " + strconv.Itoa(len(r.URL.RawQuery)) + "</p></body></html>"))
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
		"https://example.com/advisory?33",
		"https://example.com/advisory?444",
		"https://example.com/advisory?5555",
		"https://example.com/advisory?66666",
		"https://example.com/advisory?777777",
		"https://example.com/advisory?8888888", // read: eight pages read
		"https://example.com/advisory?9",       // skipped
	})
	want := []struct{ status, note string }{
		{"skipped", "https"}, {"failed", "public internet address"}, {"ok", ""}, {"failed", "2 MiB"}, {"failed", "redirected"}, {"ok", ""}, {"ok", ""},
		{"ok", ""}, {"ok", ""}, {"ok", ""}, {"ok", ""}, {"ok", ""}, {"skipped", "pages are read"},
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
			_, _ = w.Write([]byte("<html><body><p>CVE-2099-0001: Example OS 15.1 versions before 15.1R7-S13 are affected (" + strconv.Itoa(len(r.URL.Path)) + ").</p></body></html>"))
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
	pages := f.fetch(t.Context(), []string{"https://example.com/shell", "https://example.com/a1", "https://example.com/a22", "https://example.com/a333"})
	if len(pages) != 4 || pages[0].Status != "failed" || !pages[0].Empty || pages[0].Text != "" {
		t.Fatalf("the shell page: %+v, want failed, empty, no text", pages)
	}
	for _, p := range pages[1:] {
		if p.Status != "ok" || p.Empty {
			t.Errorf("%s: %s empty %v, want read (the shell leaves its place)", p.URL, p.Status, p.Empty)
		}
	}
}

// The fetcher reads each page once: a reference that redirects to a page read already, or whose body is one read already, is skipped as
// the same page and leaves its place; a download (a ZIP) is refused by its Content-Type before its body is read; a page read once is
// kept, so another CVE citing it reads it without a request.
func TestRefFetcher_DuplicatesDownloadsAndTheCache(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/old-alert":
			http.Redirect(w, r, "https://example.com/alert", http.StatusMovedPermanently)
		case "/alert", "/mirror":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body><p>CVE-2099-0002 is fixed in Widget 4.2.1.</p></body></html>"))
		case "/portable.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(bytes.Repeat([]byte("PK"), 1<<20))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><p>CVE-2099-0002 notes for Widget 4.2 (" + strconv.Itoa(len(r.URL.Path)) + ").</p></body></html>"))
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
	pages := f.fetch(t.Context(), []string{"https://example.com/alert", "https://example.com/old-alert", "https://example.com/mirror",
		"https://example.com/portable.zip", "https://example.com/notes"})
	want := []struct{ status, note string }{{"ok", ""}, {"skipped", "same page"}, {"skipped", "same page"}, {"failed", "not a text page (application/zip)"}, {"ok", ""}}
	for i, w := range want {
		if pages[i].Status != w.status || !strings.Contains(pages[i].Note, w.note) {
			t.Errorf("%s: %s %q, want %s with %q", pages[i].URL, pages[i].Status, pages[i].Note, w.status, w.note)
		}
	}
	if pages[0].Bytes == 0 || len(pages[0].Blocks) == 0 {
		t.Errorf("the read page has no bytes or blocks: %+v", pages[0])
	}
	n := requests.Load()
	again := f.fetch(t.Context(), []string{"https://example.com/alert", "https://example.com/notes"})
	if requests.Load() != n || again[0].Status != "ok" || again[1].Status != "ok" {
		t.Errorf("a second CVE citing the pages made %d requests (%+v), want none", requests.Load()-n, again)
	}
}
