package sensoractive_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// INV-8: a device scan sends the ports nmap saw open, as one nmap list for the device (D-350); closed ports are not services.
func TestContract_INV8_OpenPortsFromTheScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	got, ok := e.sink.svc["192.168.10.20"]
	e.sink.mu.Unlock()
	if !ok {
		t.Fatal("no service list was sent for the device")
	}
	var lines []string
	for _, s := range got {
		if s.Confidence <= 0 || s.Confidence >= 1 {
			t.Errorf("%d/%s confidence %v is not in (0,1)", s.Port, s.Proto, s.Confidence)
		}
		lines = append(lines, fmt.Sprintf("%d/%s %s|%s|%s", s.Port, s.Proto, s.Name, s.Product, s.Version))
	}
	want := []string{"22/tcp ssh|OpenSSH|8.9p1", "80/tcp http|Apache httpd|2.4.52", "8080/tcp http-proxy|Squid http proxy|5.7"}
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Fatalf("services\n got %q\nwant %q", lines, want)
	}
}

// A host that did not answer changes nothing; a host that answered but hit the host timeout printed no port table, so its
// services and software are not replaced (an empty list would remove the ones of the last scan).
func TestNoServicesFromAHostThatDidNotAnswerOrTimedOut(t *testing.T) {
	t.Parallel()
	for _, fx := range []string{"down.xml", "timedout.xml"} {
		t.Run(fx, func(t *testing.T) {
			t.Parallel()
			p, err := filepath.Abs(filepath.Join("testdata", fx))
			if err != nil {
				t.Fatal(err)
			}
			e := newEnv(t, fakeOpts{always: p})
			if err := e.svc.ScanDevice(e.ctx(), "a-web", "discovered"); err != nil {
				t.Fatal(err)
			}
			e.sink.mu.Lock()
			defer e.sink.mu.Unlock()
			if _, ok := e.sink.svc["192.168.10.20"]; ok {
				t.Errorf("a service list was sent: %v", e.sink.svc)
			}
			if _, ok := e.sink.sw["192.168.10.20"]; ok {
				t.Errorf("a software list was sent: %v", e.sink.sw)
			}
			if fx == "timedout.xml" && !hasField(e.sink.obs, observe.Hostname, "web01.lan") {
				t.Errorf("the timed-out host's name was not recorded: %v", e.sink.obs)
			}
		})
	}
}

func hasField(obs []observe.Observation, f observe.Field, v string) bool {
	for _, o := range obs {
		if o.Field == f && o.Value == v {
			return true
		}
	}
	return false
}

// A normal scan replaces the device's nmap services; a later gentle scan (top 100 ports, no -sV) only adds what it saw and never
// wipes the normal scan's list or its product and version (D-350 (5)).
func TestGentleScanAfterANormalOneKeepsItsServices(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("testdata", "device.xml"))
	if err != nil {
		t.Fatal(err)
	}
	normal := filepath.Join(t.TempDir(), "device30.xml")                                                                         // the normal fixture, re-addressed to the printer
	if err := os.WriteFile(normal, []byte(strings.ReplaceAll(string(b), "192.168.10.20", "192.168.10.30")), 0o600); err != nil { //nolint:gosec // a path in t.TempDir()
		t.Fatal(err)
	}
	e := newEnv(t, fakeOpts{always: normal})
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); err != nil {
		t.Fatal(err)
	}
	gentle, err := filepath.Abs(filepath.Join("testdata", "fragile.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e.nm = writeFakeNmap(t, fakeOpts{always: gentle})
	e.build()
	e.inv.decision["a-printer"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true}
	if err := e.svc.ScanDevice(e.ctx(), "a-printer", "gentle"); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	if e.sink.adds != 1 {
		t.Fatalf("%d AddServices calls, want the gentle scan's one", e.sink.adds)
	}
	var lines []string
	for _, s := range e.sink.svc["192.168.10.30"] {
		lines = append(lines, fmt.Sprintf("%d/%s %s|%s", s.Port, s.Proto, s.Name, s.Product))
	}
	want := []string{"22/tcp ssh|OpenSSH", "80/tcp http|Apache httpd", "8080/tcp http-proxy|Squid http proxy", "9100/tcp jetdirect|"}
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Fatalf("services after normal then gentle\n got %q\nwant %q", lines, want)
	}
}

// D-511 (lead decision on #714): the one gentle scan of a device whose kind is unknown and that nobody made fragile also reads the
// page title and the certificate (http-title, ssl-cert, each capped by --script-timeout); a fragile device keeps the gentle command
// line exactly, with no script.
func TestGentleScanReadsTitlesOnlyOfUnknownNotFragile(t *testing.T) {
	t.Parallel()
	gentle, err := filepath.Abs(filepath.Join("testdata", "fragile.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		dec  sa.Decision
		want []string
	}{
		{"unknown, not fragile", sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true},
			[]string{"--privileged", "-sS", "--script", "http-title,ssl-cert", "--script-timeout", "20s", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}},
		{"unknown, fragile by a person", sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true, Fragile: true},
			[]string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}},
		{"fragile by its kind", sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Fragile: true},
			[]string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", "1", "--host-timeout", "15m", "--top-ports", "100", "-oX", "-", "192.168.10.30"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{})
			e.nm = writeFakeNmap(t, fakeOpts{always: gentle})
			e.build()
			e.inv.decision["a-printer"] = c.dec
			if err := e.svc.ScanDevice(e.ctx(), "a-printer", "discovered"); err != nil {
				t.Fatal(err)
			}
			calls := e.nm.calls(t)
			if len(calls) != 1 || !slices.Equal(calls[0], c.want) {
				t.Fatalf("nmap argv = %q\n          want %q", calls, c.want)
			}
		})
	}
}
