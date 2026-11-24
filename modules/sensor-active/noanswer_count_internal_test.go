package sensoractive

import (
	"encoding/xml"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// nmapTruth is what an nmap XML says about the TCP ports of each host, read here on its own (not by the parser under test): the
// state of each port it listed, the states it grouped in <extraports>, and the ports it asked about.
type nmapTruth struct {
	listed  map[int]string
	extra   []string
	scanned []observe.PortRange
}

// state is the port's state as the XML says it: "open", "closed", "filtered"-like, or "" when the XML does not say (grouped with
// ports of more than one state, or not asked about).
func (n nmapTruth) state(p int) string {
	if s, ok := n.listed[p]; ok {
		return s
	}
	if !inRanges(n.scanned, p) {
		return ""
	}
	if len(n.extra) == 1 {
		return n.extra[0]
	}
	return ""
}

func readTruth(t *testing.T, data []byte) map[netip.Addr]nmapTruth {
	t.Helper()
	var doc struct {
		ScanInfo []struct {
			Protocol string `xml:"protocol,attr"`
			Services string `xml:"services,attr"`
		} `xml:"scaninfo"`
		Hosts []struct {
			Addrs []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Extra []struct {
				State string `xml:"state,attr"`
			} `xml:"ports>extraports"`
			Ports []struct {
				Proto string `xml:"protocol,attr"`
				ID    int    `xml:"portid,attr"`
				State struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var scanned []observe.PortRange
	for _, si := range doc.ScanInfo {
		if si.Protocol == "tcp" {
			scanned = parsePortRanges(si.Services)
		}
	}
	out := map[netip.Addr]nmapTruth{}
	for _, h := range doc.Hosts {
		n := nmapTruth{listed: map[int]string{}, scanned: scanned}
		for _, e := range h.Extra {
			n.extra = append(n.extra, e.State)
		}
		for _, p := range h.Ports {
			if p.Proto == "tcp" {
				n.listed[p.ID] = p.State.State
			}
		}
		for _, a := range h.Addrs {
			if ip, err := netip.ParseAddr(a.Addr); err == nil && a.Type == "ipv4" {
				out[ip] = n
			}
		}
	}
	return out
}

// TestNoAnswerNeverReadsAsClosed is the count over every LAN fixture of this package: each host is checked again after a check that
// found its open ports plus 22 and 3389 open, and every port the new check calls "no longer open" (Gone) must be one nmap saw closed
// (it refused the connection). A port that sent nothing back (filtered, or grouped with such ports) may be a rate limit or a firewall
// dropping probes, never proof that it closed; a port no run asked about says nothing. Before the fix: 28 such ports in 21 of 24
// hosts (6 that nmap listed as filtered, 22 not asked about or grouped with filtered ports); after: 0.
func TestNoAnswerNeverReadsAsClosed(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("testdata/*.xml")
	if err != nil {
		t.Fatal(err)
	}
	bad, hostsBad, hostsSeen := 0, 0, 0
	for _, f := range files {
		name := filepath.Base(f)
		if strings.HasPrefix(name, "external") {
			continue // the public shapes are compared by exposure, not by a device check
		}
		data, err := os.ReadFile(f) //nolint:gosec // a fixture of this package
		if err != nil {
			t.Fatal(err)
		}
		hosts, err := parseNmapXML(data)
		if err != nil {
			continue // a fixture of a refused output
		}
		truth := readTruth(t, data)
		for _, h := range hosts {
			if h.timedOut {
				continue
			}
			hostsSeen++
			prev := DeviceFound{Reach: reachOf(nmapargv.Normal)}
			for _, p := range unionPorts(tcpPorts(h.ports), []int{22, 3389}) {
				prev.Ports = append(prev.Ports, FoundPort{Port: p, Proto: "tcp"})
			}
			prev.Open = len(prev.Ports)
			got := foundOf(h, nmapargv.Normal, false, []DeviceFound{prev})
			n := 0
			for _, p := range got.Gone {
				if st := truth[h.addr].state(p); st != "closed" {
					n++
					t.Logf("%s %s: port %d reads no longer open, but nmap saw it %q", name, h.addr, p, st)
				}
			}
			bad += n
			if n > 0 {
				hostsBad++
			}
		}
	}
	t.Logf("ports read as closed without a closed answer: %d, in %d of %d hosts", bad, hostsBad, hostsSeen)
	if bad != 0 {
		t.Errorf("%d ports that gave no answer read as no longer open (in %d hosts), want 0", bad, hostsBad)
	}
}
