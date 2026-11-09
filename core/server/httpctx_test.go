package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/server"
)

func TestExchangeClientAddr(t *testing.T) {
	t.Parallel()
	for remote, want := range map[string]string{
		"192.0.2.1:5000": "192.0.2.1", "[2001:db8::1]:5000": "2001:db8::1", "[::ffff:192.0.2.9]:80": "192.0.2.9", "[fe80::1%eth0]:80": "fe80::1",
		"": "", "garbage": "", "192.0.2.1": "",
	} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		got := server.Exchange{R: r}.ClientAddr()
		if want == "" {
			if got.IsValid() {
				t.Errorf("%q gave %v", remote, got)
			}
			continue
		}
		if got != netip.MustParseAddr(want) {
			t.Errorf("%q gave %v, want %v", remote, got, want)
		}
	}
	// X-Forwarded-For is never read.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:1"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	r.Header.Set("X-Real-IP", "203.0.113.6")
	if got := (server.Exchange{R: r}).ClientAddr(); got.String() != "192.0.2.1" {
		t.Fatalf("ClientAddr = %v", got)
	}
	if _, ok := server.ExchangeFrom(context.Background()); ok {
		t.Fatal("an exchange out of nowhere")
	}
}
