package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// The box serves its own certificate, which a browser that has not been told to trust it refuses on every connection
// ("remote error: tls: unknown certificate"): an hour of use wrote 1,662 WARN lines and hid the real warnings (S-CORE-9).
// That one refusal is written once per interval with the count of those held back; any other handshake error stays a WARN of its own.
const (
	unknownCertMsg      = "remote error: tls: unknown certificate"
	unknownCertInterval = 10 * time.Minute
)

// handshakeNoise wraps the handler behind http.Server.ErrorLog.
type handshakeNoise struct {
	slog.Handler
	st *handshakeState
}

type handshakeState struct {
	mu      sync.Mutex
	now     func() time.Time
	next    time.Time
	skipped int
}

func newHandshakeNoise(h slog.Handler) *handshakeNoise {
	return &handshakeNoise{Handler: h, st: &handshakeState{now: time.Now}}
}

func (h *handshakeNoise) Handle(ctx context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "http: TLS handshake error") && strings.HasSuffix(r.Message, unknownCertMsg) {
		s := h.st
		s.mu.Lock()
		now := s.now()
		if now.Before(s.next) {
			s.skipped++
			s.mu.Unlock()
			return nil
		}
		held := s.skipped
		s.next, s.skipped = now.Add(unknownCertInterval), 0
		s.mu.Unlock()
		if held > 0 {
			r.Message += fmt.Sprintf(" (and %d more in the last %d minutes; a browser that does not trust the box's own certificate does this on every connection)", held, int(unknownCertInterval/time.Minute))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h *handshakeNoise) WithAttrs(a []slog.Attr) slog.Handler {
	return &handshakeNoise{Handler: h.Handler.WithAttrs(a), st: h.st}
}

func (h *handshakeNoise) WithGroup(n string) slog.Handler {
	return &handshakeNoise{Handler: h.Handler.WithGroup(n), st: h.st}
}
