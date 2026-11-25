package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// The handshake errors of the 8443 server (http.Server.ErrorLog). Two clients repeat the same refusal forever:
//   - a browser that has not been told to trust the box's own certificate ("remote error: tls: unknown certificate"): an hour of use
//     wrote 1,662 WARN lines and hid the real warnings (S-CORE-9);
//   - an agent installed before the box made a new certificate authority (a reinstall or a data purge): it pins the old one and fails
//     every few seconds ("local error: tls: bad record MAC" from osquery), about 2,400 lines a day per machine.
//
// So every handshake error is written once per source address and reason per interval, with the count of those held back; the
// first one of a source is written at once. The refusals that mean "this client pins another certificate authority" are also kept
// per source address (in memory, since this start), so that a device's agent row can say that its agent no longer trusts the box.
const (
	handshakePrefix   = "http: TLS handshake error from "
	unknownCertMsg    = "remote error: tls: unknown certificate"
	handshakeInterval = time.Hour
	// handshakeMaxKeys bounds both tables: a scan of the whole network from many addresses cannot grow them. When full, the entry
	// heard from the longest ago makes room.
	handshakeMaxKeys = 1024
)

// trustRefusal reports whether a handshake error is a client that refuses the box's certificate authority itself: osquery that pins
// an earlier CA ends the handshake with a record the box cannot read (bad record MAC); an OpenSSL client (the Windows agent, the
// package reporter's curl on TLS 1.2) sends the alert unknown_ca. A browser's refusal of an untrusted certificate is another alert
// (unknown certificate, bad certificate) and a port scan's is not an alert at all, so neither counts.
func trustRefusal(reason string) bool {
	return strings.HasSuffix(reason, "tls: bad record MAC") || strings.HasSuffix(reason, "remote error: tls: unknown certificate authority")
}

// handshakeNoise wraps the handler behind http.Server.ErrorLog.
type handshakeNoise struct {
	slog.Handler
	st *handshakeState
}

type handshakeState struct {
	mu      sync.Mutex
	now     func() time.Time
	lines   map[string]*heldLine                // source address + reason
	refused map[netip.Addr]inventory.TLSRefusal // trust refusals by source address
}

type heldLine struct {
	next time.Time // when the next one is written
	held int       // how many were held back since the last one written
	last time.Time // when the last one came (eviction)
}

func newHandshakeNoise(h slog.Handler) *handshakeNoise {
	return &handshakeNoise{Handler: h, st: &handshakeState{now: time.Now, lines: map[string]*heldLine{}, refused: map[netip.Addr]inventory.TLSRefusal{}}}
}

// parseHandshake splits "http: TLS handshake error from <addr:port>: <reason>" (net/http's text); ok is false for any other line.
func parseHandshake(msg string) (netip.Addr, string, bool) {
	rest, ok := strings.CutPrefix(msg, handshakePrefix)
	if !ok {
		return netip.Addr{}, "", false
	}
	addr, reason, ok := strings.Cut(rest, ": ")
	if !ok {
		return netip.Addr{}, "", false
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return ap.Addr().Unmap(), reason, true
}

func (h *handshakeNoise) Handle(ctx context.Context, r slog.Record) error {
	ip, reason, ok := parseHandshake(r.Message)
	if !ok {
		return h.Handler.Handle(ctx, r)
	}
	s := h.st
	s.mu.Lock()
	now := s.now()
	trust := trustRefusal(reason)
	if trust {
		f, seen := s.refused[ip]
		if !seen {
			evictOldest(s.refused, func(v inventory.TLSRefusal) time.Time { return v.Last })
			f.First = now
		}
		f.Last, f.Count = now, f.Count+1
		s.refused[ip] = f
	}
	key := ip.String() + " " + reason
	l := s.lines[key]
	if l == nil {
		evictOldest(s.lines, func(v *heldLine) time.Time { return v.last })
		l = &heldLine{}
		s.lines[key] = l
	}
	l.last = now
	if now.Before(l.next) {
		l.held++
		s.mu.Unlock()
		return nil
	}
	held := l.held
	l.next, l.held = now.Add(handshakeInterval), 0
	s.mu.Unlock()
	if held > 0 {
		r.Message += fmt.Sprintf(" (and %d more from this address in the last %d minutes)", held, int(handshakeInterval/time.Minute))
	}
	switch {
	case trust:
		r.Message += "; a Vedette agent installed before the box's certificate changed (a reinstall or a data purge) does this: run the install command on that machine again"
	case reason == unknownCertMsg:
		r.Message += "; a browser that does not trust the box's own certificate does this on every connection"
	}
	return h.Handler.Handle(ctx, r)
}

// evictOldest makes room for one more entry when m is full: the one heard from the longest ago goes.
func evictOldest[K comparable, V any](m map[K]V, last func(V) time.Time) {
	if len(m) < handshakeMaxKeys {
		return
	}
	var oldest K
	var at time.Time
	first := true
	for k, v := range m {
		if t := last(v); first || t.Before(at) {
			oldest, at, first = k, t, false
		}
	}
	delete(m, oldest)
}

// Refusals is inventory.Config.TLSRefusals: the trust refusals heard from ip since this start (zero when none or ip is not an address).
func (h *handshakeNoise) Refusals(ip string) inventory.TLSRefusal {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return inventory.TLSRefusal{}
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	return h.st.refused[a.Unmap()]
}

func (h *handshakeNoise) WithAttrs(a []slog.Attr) slog.Handler {
	return &handshakeNoise{Handler: h.Handler.WithAttrs(a), st: h.st}
}

func (h *handshakeNoise) WithGroup(n string) slog.Handler {
	return &handshakeNoise{Handler: h.Handler.WithGroup(n), st: h.st}
}

// caSince is deps.BoxCASince: the NotBefore of the first certificate anchor gives (the box CA); zero when it cannot be read.
func caSince(anchor func() ([]byte, error)) func(context.Context) time.Time {
	if anchor == nil {
		return nil
	}
	return func(context.Context) time.Time {
		raw, err := anchor()
		if err != nil {
			return time.Time{}
		}
		b, _ := pem.Decode(raw)
		if b == nil || b.Type != "CERTIFICATE" {
			return time.Time{}
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return time.Time{}
		}
		return c.NotBefore
	}
}
