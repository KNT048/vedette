package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/exposure"
)

// A scan that opened ports makes one new_port event each in response. The first scan of a target is the baseline; nothing reaches
// response while exposure or response is off; one scan announces at most maxPortsPerScan.
func TestExposureScanOpensNewPorts(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	s.setModule("exposure", true)
	ctx := t.Context()
	scan := func(at string, first bool, ports ...string) {
		t.Helper()
		ev := exposure.ScanWrittenEvent{TargetID: "xt-1", RunID: "run-" + at, At: at + "T10:00:00.000Z", First: first}
		for _, p := range ports {
			ip, port, _ := strings.Cut(p, " ")
			n, _ := strconv.Atoi(port)
			ev.Opened = append(ev.Opened, exposure.OpenedService{TargetID: "xt-1", PortRow: exposure.PortRow{IP: ip, Port: n, Service: "svc-" + port}})
		}
		if err := s.d.Bus.Publish(ctx, events.Event{Name: exposure.EventScanWritten, Data: ev}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() []string {
		t.Helper()
		rows, err := s.d.DB.Reader().QueryContext(ctx, `SELECT id FROM resp_events WHERE trigger = 'new_port' ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		return out
	}
	want := func(step string, ids ...string) {
		t.Helper()
		if got := stored(); strings.Join(got, " ") != strings.Join(ids, " ") {
			t.Fatalf("%s: events %v, want %v", step, got, ids)
		}
	}

	scan("2026-11-10", true, "203.0.113.10 443")
	want("the first scan is the baseline")
	scan("2026-11-11", false, "203.0.113.10 8080", "2a01:4f8::5 22")
	want("two ports opened", "port:xt-1:2026-11-11:203.0.113.10:8080", "port:xt-1:2026-11-11:2a01:4f8::5:22")

	s.setModule("exposure", false)
	scan("2026-11-12", false, "203.0.113.10 21")
	s.setModule("exposure", true)
	s.setModule("response", false)
	scan("2026-11-13", false, "203.0.113.10 23")
	s.setModule("response", true)
	want("exposure or response off", "port:xt-1:2026-11-11:203.0.113.10:8080", "port:xt-1:2026-11-11:2a01:4f8::5:22")

	var many []string
	for p := 1000; p < 1000+maxPortsPerScan+5; p++ {
		many = append(many, fmt.Sprintf("203.0.113.10 %d", p))
	}
	scan("2026-11-14", false, many...)
	if n := len(stored()) - 2; n != maxPortsPerScan {
		t.Fatalf("one scan announced %d new ports, want the cap %d", n, maxPortsPerScan)
	}
}
