package logs

import (
	"log/slog"
	"testing"

	"github.com/knt048/vedette/core/events"
)

// The bad_conn record carries the severity of the hit, the same one notify gives the bad-address incident (Listing.Severity, normalised
// by badAddressEvent): critical for a command-and-control server, high from confidence 0.5, medium below. An event without a
// severity, or with one a bad-address incident never has, is medium, as badAddressEvent would make it.
func TestSiemBadConnCarriesTheSeverityOfTheHit(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	e.saveSiem(SiemInput{Enabled: true, Format: "cef", Host: "192.168.10.50", Port: 514, Proto: "udp", Events: []string{"bad_conn"}})
	e.svc.siemRunning.Store(true)
	row, _ := e.svc.loadSiem(t.Context(), e.cfg.Reader(), false)
	e.svc.siemCache.Store(&row)
	sevs := []any{"critical", "high", "medium", nil, "info", "urgent"}
	for _, sev := range sevs {
		hit := map[string]any{"id": "b-1", "src_ip": "192.168.10.9", "dest": "80.0.0.1", "dest_kind": "ip", "seen_via": "syslog:FW"}
		if sev != nil {
			hit["severity"] = sev
		}
		publish(t, bus, siemEventBadAddress, hit)
	}
	recs, _ := e.svc.siemQ.peek(10)
	if len(recs) != len(sevs) {
		t.Fatalf("%d records", len(recs))
	}
	for i, want := range []string{"critical", "high", "medium", "medium", "medium", "medium"} {
		if recs[i].Severity != want {
			t.Errorf("event severity %v: record severity %q, want %q", sevs[i], recs[i].Severity, want)
		}
	}
	// the incident path gives the same severity to the same hit
	for _, sev := range []string{"critical", "high", "medium"} {
		if got := badAddressEvent(IocHit{ID: "b-1", SrcIP: "192.168.10.9", Dest: "80.0.0.1", DestKind: "ip"}, sev).Severity; got != sev {
			t.Errorf("incident severity %q, want %q", got, sev)
		}
	}
}
