package surface

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// The deep-scan settings of a target reach the surface scan: a port it skips is never dialled (no connect, no page, no handshake),
// on the box's own IP and on the names of a domain alike, and the probe log says how many ports were tried. Gentle dials at a lower
// rate and fewer at a time.

func TestIPScanNeverDialsASkippedPort(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		n := &fakeNet{open: map[string]handler{
			"203.0.113.7:443":  serve(htmlPage("Router")),
			"203.0.113.7:22":   silent,
			"203.0.113.7:8080": serve(htmlPage("Admin")),
		}}
		log := &probeLog{}
		s := newScanner(t, n, fakeResolver{}, nil, log)
		got, err := s.IPWith(t.Context(), netip.MustParseAddr("203.0.113.7"), Options{SkipPorts: []int{22, 8080}})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range n.dialed {
			if strings.HasSuffix(d, ":22") || strings.HasSuffix(d, ":8080") {
				t.Fatalf("a skipped port was dialled: %s", d)
			}
		}
		if n.dials("203.0.113.7:443") == 0 {
			t.Fatal("a port that is not skipped was not dialled")
		}
		for _, p := range got.Ports {
			if p.Port == 22 || p.Port == 8080 {
				t.Fatalf("a skipped port is in the result: %+v", p)
			}
		}
		want := "TCP connect to " + strconv.Itoa(len(commonPorts)-2) + " ports (2 skipped by the target's settings)"
		if !slices.ContainsFunc(log.requests(), func(r string) bool { return strings.Contains(r, want) }) {
			t.Fatalf("the probe log does not say what was tried: %q", log.requests())
		}
		allLogged(t, n, log)
		// no ports to skip: every port of the list, as IP does
		n2 := &fakeNet{}
		if _, err := newScanner(t, n2, fakeResolver{}, nil, &probeLog{}).IPWith(t.Context(), netip.MustParseAddr("203.0.113.7"), Options{}); err != nil {
			t.Fatal(err)
		}
		if len(n2.dialed) != len(commonPorts) {
			t.Fatalf("%d dials without ports to skip, want %d", len(n2.dialed), len(commonPorts))
		}
	})
}

// A domain: the checks by name on 80 and 443 and the port scan of the box's addresses leave a skipped port alone.
func TestDomainScanNeverDialsASkippedPort(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		n := &fakeNet{open: map[string]handler{
			"203.0.113.10:80":  serve(htmlPage("Welcome")),
			"203.0.113.10:443": serve(htmlPage("Welcome")),
		}}
		ct := `[{"common_name":"acme.example","name_value":"acme.example\nwww.acme.example"}]`
		var asked []string
		res := fakeResolver{"acme.example": addrs("203.0.113.10"), "www.acme.example": addrs("203.0.113.10")}
		may := func(context.Context, netip.Addr) bool { return true }
		s := newScanner(t, n, res, ctAnswer(200, ct, &asked), &probeLog{})
		if _, err := s.DomainWith(t.Context(), "acme.example", Every, may, Options{SkipPorts: []int{80}}); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(n.dialed, "203.0.113.10:80") {
			t.Fatalf("the skipped port was dialled: %q", n.dialed)
		}
		if !slices.Contains(n.dialed, "203.0.113.10:443") {
			t.Fatal("port 443 was not checked")
		}
	})
}

// Gentle dials at gentleDialRate, gentleDialParallel at a time: on the bubble's clock, a gentle port scan of the list takes at least
// len(list)/gentleDialRate seconds. The pages stay as they are (one GET of / a web port), and the scan still fits scanTimeout.
func TestGentleDialsSlower(t *testing.T) {
	t.Parallel()
	if gentleDialRate >= dialRate || gentleDialParallel >= dialParallel || gentleDialRate < 1 {
		t.Fatal("gentle is not slower than normal")
	}
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		if _, err := newScanner(t, &fakeNet{}, fakeResolver{}, nil, &probeLog{}).IPWith(t.Context(), netip.MustParseAddr("203.0.113.7"), Options{Gentle: true}); err != nil {
			t.Fatal(err)
		}
		if took, least := time.Since(start), time.Duration(len(commonPorts)-1)*time.Second/gentleDialRate; took < least {
			t.Fatalf("a gentle port scan took %s, less than %s", took, least)
		}
	})
	if pace(Options{}) != (pacing{dialRate, dialParallel}) || pace(Options{Gentle: true}) != (pacing{gentleDialRate, gentleDialParallel}) {
		t.Fatal("pace")
	}
	// the scan's worst case at the gentle rate: the port scan of 20 addresses, the rest as at the normal rate (the comment of scanTimeout)
	if extra := time.Duration(20*len(commonPorts))*time.Second/gentleDialRate - time.Duration(20*len(commonPorts))*time.Second/dialRate; 271*time.Second+extra > scanTimeout {
		t.Fatalf("a gentle scan's worst case is over scanTimeout by %s", 271*time.Second+extra-scanTimeout)
	}
}
