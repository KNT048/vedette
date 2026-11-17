package agentintake

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/observe"
)

// Open services an agent reports (INV-22, kien 2026-11-17): the ports a machine listens on, from osquery's listening_ports (joined with
// processes for the program) and Wazuh's syscollector ports. A machine known only through its agent (a server outside the scan scope,
// a laptop off-site) otherwise had no Open services although its agent knows them; Defender, runZero and Lansweeper list an agent's
// listening ports the same way. The rows are the agent's own claim (SYS-6): only a port another machine can reach is kept (a socket
// bound to loopback is not), the program name is clean text cut to the inventory's limit, and the inventory checks the list again
// (INV-23).

const (
	maxServices = 1000 // the inventory's limit of one source's list on one device (inventory INV-23)
	maxSvcName  = 100  // the inventory's limit of a service name
)

// listening is one listening socket an agent reported: the port, "tcp" or "udp", the address it is bound to and the program.
type listening struct {
	port    int
	proto   string
	addr    string
	program string
}

// osqueryListening reads the rows of the listening_ports queries: protocol 6 is TCP, 17 UDP (IANA numbers, as osquery prints them).
func osqueryListening(rows []row) []listening {
	out := make([]listening, 0, len(rows))
	for _, r := range rows {
		port, err := strconv.Atoi(r["port"])
		if err != nil {
			continue
		}
		proto := ""
		switch r["protocol"] {
		case "6":
			proto = "tcp"
		case "17":
			proto = "udp"
		}
		out = append(out, listening{port: port, proto: proto, addr: r["address"], program: r["name"]})
	}
	return out
}

// mapServices turns listening sockets into the open services of the device: a port 1..65535 of TCP or UDP bound to an address that
// is not loopback (every address, 0.0.0.0 or ::, counts), one per port and protocol (the first named program wins), sorted, at most
// maxServices (the lowest ports). The program is the service's name, without product or version: a process name says what serves
// the port ("sshd", "nginx"), not which release, so it never reads as software.
func mapServices(rows []listening) []observe.Service {
	type key struct {
		port  int
		proto string
	}
	idx := map[key]int{}
	out := []observe.Service{}
	for _, r := range rows {
		if r.port < 1 || r.port > 65535 || (r.proto != "tcp" && r.proto != "udp") {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(r.addr))
		if err != nil || a.Unmap().IsLoopback() {
			continue
		}
		name, ok := cleanValue(r.program, maxValue)
		if !ok {
			name = ""
		}
		if rs := []rune(name); len(rs) > maxSvcName {
			name = strings.TrimSpace(string(rs[:maxSvcName]))
		}
		k := key{r.port, r.proto}
		if i, seen := idx[k]; seen {
			if out[i].Name == "" {
				out[i].Name = name
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, observe.Service{Port: r.port, Proto: r.proto, Name: name, Confidence: softwareConfidence})
	}
	slices.SortFunc(out, func(a, b observe.Service) int {
		return cmp.Or(cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port))
	})
	if len(out) > maxServices {
		out = out[:maxServices]
	}
	return out
}
