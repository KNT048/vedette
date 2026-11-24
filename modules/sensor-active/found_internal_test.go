package sensoractive

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A check whose run over the extra ports did not finish covered nmap's top 1000 only: comparing it with a complete check (either
// way round) never says a port of the extra list opened or closed, and its OS guess (an NTLM answer may come from that run) is
// never compared. Ports outside the extra list are still compared.
func TestFoundComparesOnlyWhatBothChecksCovered(t *testing.T) {
	t.Parallel()
	const extraOnly = 22222 // an extra port outside nmap's usual lists
	if !slices.Contains(nmapargv.ExtraPortNumbers, extraOnly) {
		t.Fatalf("%d is not an extra port any more: pick another", extraOnly)
	}
	notExtra := 0
	for p := 40000; p < 65535; p++ {
		if !slices.Contains(nmapargv.ExtraPortNumbers, p) {
			notExtra = p
			break
		}
	}
	h := func(os string, ports ...int) host {
		// every port asked about that is not open refused the connection (host.answer: closed)
		all := []observe.PortRange{{From: 1, To: 65535}}
		x := host{addr: netip.MustParseAddr("192.168.10.20"), scanned: all, runs: []portRun{{scanned: all, extra: []string{"closed"}}}}
		for _, p := range ports {
			x.ports = append(x.ports, portInfo{number: p, proto: "tcp", name: "x"})
		}
		if os != "" {
			x.matches = []osMatch{{name: os, accuracy: 96}}
		}
		return x
	}
	full := foundOf(h("Linux 5.4 - 5.15", 22, extraOnly), nmapargv.Normal, false, nil)
	if full.Compared || full.ExtraFailed {
		t.Fatalf("first check: %+v", full)
	}
	// the extra run failed: 22222 not seen, and a new port outside the extra list opened; another OS guess
	part := foundOf(h("Windows 10", 22, notExtra), nmapargv.Normal, true, []DeviceFound{full})
	if !part.ExtraFailed || !part.Compared || !part.ComparedPart || len(part.Gone) != 0 || !slices.Equal(part.New, []int{notExtra}) || part.OSWas != "" {
		t.Fatalf("a check whose extra ports did not finish: %+v (want no 22222 gone, %d new, no OS change)", part, notExtra)
	}
	// the next complete check after it sees 22222 again: not "newly open"
	again := foundOf(h("Linux 5.4 - 5.15", 22, extraOnly, notExtra), nmapargv.Normal, false, []DeviceFound{part, full})
	if !again.Compared || !again.ComparedPart || len(again.New) != 0 || len(again.Gone) != 0 || again.OSWas != "" {
		t.Fatalf("a complete check after a partial one: %+v", again)
	}
	// two complete checks compare every port and the OS
	next := foundOf(h("Linux 6.1", 22), nmapargv.Normal, false, []DeviceFound{full})
	if next.ComparedPart || !slices.Equal(next.Gone, []int{extraOnly}) || next.OSWas != "Linux 5.4 - 5.15" {
		t.Fatalf("two complete checks: %+v", next)
	}
}
