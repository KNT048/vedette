package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"
)

func newNoiseForTest(t *testing.T) (*handshakeNoise, *bytes.Buffer, *time.Time) {
	t.Helper()
	var buf bytes.Buffer
	h := newHandshakeNoise(slog.NewTextHandler(&buf, nil))
	now := time.Unix(1_000_000, 0)
	h.st.now = func() time.Time { return now }
	return h, &buf, &now
}

func TestHandshakeNoiseWritesEachSourceAndReasonOncePerInterval(t *testing.T) {
	h, buf, now := newNoiseForTest(t)
	log := slog.NewLogLogger(h, slog.LevelWarn)
	unknown := "http: TLS handshake error from 192.0.2.2:5000: remote error: tls: unknown certificate"
	for i := range 5 {
		log.Print(strings.Replace(unknown, ":5000", fmt.Sprintf(":%d", 5000+i), 1)) // a new port per connection: still one source
	}
	log.Print("http: TLS handshake error from 192.0.2.2:5000: tls: first record does not look like a TLS handshake")
	log.Print("http: TLS handshake error from 192.0.2.2:5001: tls: first record does not look like a TLS handshake")
	log.Print("http: TLS handshake error from 192.0.2.3:5000: remote error: tls: unknown certificate") // another source: its own line
	log.Print("http: server closed idle connection")                                                   // not a handshake error: as it is
	out := buf.String()
	if n := strings.Count(out, "192.0.2.2:") - strings.Count(out, "does not look like"); n != 1 {
		t.Fatalf("unknown certificate lines of 192.0.2.2 in the first interval = %d, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "does not look like"); n != 1 {
		t.Fatalf("lines of another reason of the same source = %d, want 1 (its own line, once)", n)
	}
	if !strings.Contains(out, "192.0.2.3:5000") || !strings.Contains(out, "server closed idle connection") {
		t.Fatalf("another source and other lines must be written:\n%s", out)
	}
	*now = now.Add(handshakeInterval + time.Second)
	log.Print(unknown)
	if !strings.Contains(buf.String(), "and 4 more from this address") {
		t.Fatalf("the next line should say how many were held back:\n%s", buf.String())
	}
}

// A machine whose agent pins the CA of an earlier install fails every few seconds (osquery: bad record MAC). A day of it is at most one
// line per hour, and the line says what to do; before, every failure was a WARN line (about 2,400 a day per machine).
func TestHandshakeNoiseADayOfAStaleAgentIsOneLinePerHour(t *testing.T) {
	h, buf, now := newNoiseForTest(t)
	log := slog.NewLogLogger(h, slog.LevelWarn)
	const tries = 24 * 60 * 6 // every 10 s for a day
	for i := range tries {
		log.Printf("http: TLS handshake error from 198.51.100.7:%d: local error: tls: bad record MAC", 30000+i%20000)
		*now = now.Add(10 * time.Second)
	}
	lines := strings.Count(buf.String(), "\n")
	if lines > 24 {
		t.Fatalf("a day of a stale agent wrote %d lines, want at most 24 (one per hour)", lines)
	}
	if !strings.Contains(buf.String(), "run the install command on that machine again") {
		t.Fatalf("the line must say what to do:\n%s", buf.String())
	}
	t.Logf("handshake error lines for %d failures of one stale agent in a day: %d (before: %d)", tries, lines, tries)
	r := h.Refusals("198.51.100.7")
	if r.Count != tries || r.First.IsZero() || !r.Last.After(r.First) {
		t.Fatalf("refusals = %+v, want %d with first and last", r, tries)
	}
}

func TestHandshakeNoiseKeepsOnlyTrustRefusalsPerAddress(t *testing.T) {
	h, _, _ := newNoiseForTest(t)
	log := slog.NewLogLogger(h, slog.LevelWarn)
	log.Print("http: TLS handshake error from 192.0.2.10:1: remote error: tls: unknown certificate")               // a browser
	log.Print("http: TLS handshake error from 192.0.2.10:2: remote error: tls: bad certificate")                   // a browser
	log.Print("http: TLS handshake error from 192.0.2.10:3: tls: first record does not look like a TLS handshake") // a port scan
	log.Print("http: TLS handshake error from 192.0.2.11:4: remote error: tls: unknown certificate authority")     // an OpenSSL client pinning another CA
	log.Print("http: TLS handshake error from [::ffff:192.0.2.12]:5: local error: tls: bad record MAC")            // osquery, a v4-mapped source
	if r := h.Refusals("192.0.2.10"); r.Count != 0 {
		t.Fatalf("browser and scan errors counted as refusals: %+v", r)
	}
	if r := h.Refusals("192.0.2.11"); r.Count != 1 {
		t.Fatalf("unknown_ca refusals = %+v, want 1", r)
	}
	if r := h.Refusals("192.0.2.12"); r.Count != 1 {
		t.Fatalf("bad record MAC refusals of a v4-mapped source = %+v, want 1", r)
	}
	if r := h.Refusals("not an address"); r.Count != 0 {
		t.Fatalf("refusals of a non-address = %+v", r)
	}
}

func TestHandshakeNoiseTablesAreBounded(t *testing.T) {
	h, _, now := newNoiseForTest(t)
	log := slog.NewLogLogger(h, slog.LevelWarn)
	for i := range handshakeMaxKeys + 50 {
		log.Printf("http: TLS handshake error from 10.%d.%d.1:443: local error: tls: bad record MAC", i/256, i%256)
		*now = now.Add(time.Second)
	}
	if len(h.st.lines) > handshakeMaxKeys || len(h.st.refused) > handshakeMaxKeys {
		t.Fatalf("tables grew to %d lines and %d refusals, bound %d", len(h.st.lines), len(h.st.refused), handshakeMaxKeys)
	}
	if r := h.Refusals("10.0.0.1"); r.Count != 0 {
		t.Fatalf("the source heard from the longest ago should have made room: %+v", r)
	}
	last := handshakeMaxKeys + 49
	if r := h.Refusals(fmt.Sprintf("10.%d.%d.1", last/256, last%256)); r.Count != 1 {
		t.Fatalf("the newest source is missing: %+v", r)
	}
}

func testCAAt(t *testing.T, nb time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: nb, NotAfter: nb.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testCAPEMForAnchor(t *testing.T) string { return string(testCAAt(t, time.Now().Add(-time.Hour))) }

func TestCASinceReadsTheAnchorsNotBefore(t *testing.T) {
	nb := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	pemCA := testCAAt(t, nb)
	if got := caSince(func() ([]byte, error) { return pemCA, nil })(t.Context()); !got.Equal(nb) {
		t.Fatalf("caSince = %v, want %v", got, nb)
	}
	if got := caSince(func() ([]byte, error) { return nil, errors.New("busy") })(t.Context()); !got.IsZero() {
		t.Fatalf("caSince of an anchor that cannot be read = %v, want zero", got)
	}
	if got := caSince(func() ([]byte, error) { return []byte("not pem"), nil })(t.Context()); !got.IsZero() {
		t.Fatalf("caSince of a non-PEM anchor = %v, want zero", got)
	}
	if caSince(nil) != nil {
		t.Fatal("caSince(nil) must be nil (no anchor: not known)")
	}
}
