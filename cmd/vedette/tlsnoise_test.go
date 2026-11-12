package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestHandshakeNoiseKeepsOtherErrorsAndCountsTheUnknownCertificate(t *testing.T) {
	var buf bytes.Buffer
	h := newHandshakeNoise(slog.NewTextHandler(&buf, nil))
	now := time.Unix(1_000_000, 0)
	h.st.now = func() time.Time { return now }
	log := slog.NewLogLogger(h, slog.LevelWarn)
	unknown := "http: TLS handshake error from 10.0.0.2:5000: remote error: tls: unknown certificate"
	for range 5 {
		log.Print(unknown)
	}
	log.Print("http: TLS handshake error from 10.0.0.2:5000: tls: first record does not look like a TLS handshake")
	log.Print("http: TLS handshake error from 10.0.0.2:5000: tls: first record does not look like a TLS handshake")
	if n := strings.Count(buf.String(), "unknown certificate"); n != 1 {
		t.Fatalf("unknown certificate lines in the first interval = %d, want 1:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "does not look like"); n != 2 {
		t.Fatalf("other handshake errors written = %d, want 2", n)
	}
	now = now.Add(unknownCertInterval + time.Second)
	log.Print(unknown)
	if !strings.Contains(buf.String(), "and 4 more") {
		t.Fatalf("the next line should say how many were held back:\n%s", buf.String())
	}
}
