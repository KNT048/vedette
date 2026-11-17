package sensoractive

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// The Extra run's open ports join the first run's host (SSH moved to 22222 is identified with the rest); a port both runs
// saw keeps the first run's answer; a first run that timed out keeps its meaning; a host only the Extra run saw is left out here.
func TestMergeExtra(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.168.10.20")
	first := []host{{addr: ip, ports: []portInfo{{number: 22, proto: "tcp", product: "OpenSSH", version: "8.9p1"}, {number: 80, proto: "tcp"}}}}
	extra := []host{{addr: ip, ports: []portInfo{{number: 22, proto: "tcp", product: "other"}, {number: 22222, proto: "tcp", name: "ssh", product: "OpenSSH", version: "9.6p1"}},
		scripts: []nseScript{{port: 22222, id: "x"}}, ntlm: ntlmInfo{version: "10.0.22631", port: 22222}}}
	got := mergeExtra(first, extra, ip)
	var ports []int
	for _, p := range got[0].ports {
		ports = append(ports, p.number)
	}
	if !slices.Equal(ports, []int{22, 80, 22222}) || got[0].ports[0].product != "OpenSSH" || len(got[0].scripts) != 1 || got[0].ntlm.version != "10.0.22631" {
		t.Fatalf("merged = %+v", got[0])
	}
	timedOut := []host{{addr: ip, timedOut: true}}
	if got := mergeExtra(timedOut, extra, ip); len(got[0].ports) != 0 {
		t.Fatalf("a timed-out first run took ports: %+v", got[0])
	}
	if got := mergeExtra(nil, extra, ip); len(got) != 0 { // review r1 M5: probeDevice records the Extra run alone then
		t.Fatalf("only the extra run saw it: %+v", got)
	}
	if sw := softwareOf(mergeExtra([]host{{addr: ip}}, extra, ip)[0]); !slices.ContainsFunc(sw, func(s observe.Software) bool { return s.Version == "9.6p1" }) {
		t.Fatalf("the extra port's product is not software: %+v", sw)
	}
}
