package capture

import (
	"bytes"
	"regexp"
	"strings"
)

const (
	maxSSDP      = 2048
	maxSSDPLines = 40
	// maxSSDPServer is the longest SERVER header read for a model; a longer one gives none.
	maxSSDPServer = 200
	maxSSDPModel  = 40
)

// The SERVER header is free text the sender writes (untrusted, INV-4): "<OS>/<version> UPnP/<version> <product>/<version>" by the
// UPnP spec, where the product is nearly always the UPnP software (MiniUPnPd, libupnp, Portable SDK, UPnP-Device-Host), not the
// device. So, as for the LLDP description (sysdesc.go, D-406), only a known layout that names the device gives a model, a short
// token; any other header gives nothing (D-411).
//
// ponytail: three layouts (AVM FRITZ!, Sonos, Philips Hue bridge); a new one is one more row here with a test.
var (
	// "FRITZ!Box 7590 UPnP/1.0 AVM FRITZ!Box 7590 154.07.57", "FRITZ!Box Fon WLAN 7390 UPnP/1.0 AVM FRITZ!Box Fon WLAN 7390 84.06.85":
	// the name is said twice, and only the same name twice counts.
	serverAVM = regexp.MustCompile(`^(FRITZ![A-Za-z]{2,10}(?: [A-Za-z0-9]{1,10}){1,4}) UPnP/1\.[01] AVM (FRITZ![A-Za-z]{2,10}(?: [A-Za-z0-9]{1,10}){1,4}) [0-9]{1,3}\.[0-9]{2}\.[0-9]{2}$`)
	// "Linux UPnP/1.0 Sonos/70.3-35220 (ZPS23)": the model code in brackets
	serverSonos = regexp.MustCompile(`^Linux UPnP/1\.0 Sonos/[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}-[0-9]{1,8} \(([A-Z]{1,4}[0-9]{1,4}[A-Z]?)\)$`)
	// "Hue/1.0 UPnP/1.0 IpBridge/1.48.0" (square bridge), "FreeRTOS/7.4.2 UPnP/1.0 IpBridge/1.15.0" (round bridge)
	serverHue = regexp.MustCompile(`^(?:Hue/1\.0|FreeRTOS/[0-9]{1,2}(?:\.[0-9]{1,3}){1,2}) UPnP/1\.0 IpBridge/[0-9]{1,2}(?:\.[0-9]{1,3}){1,2}$`)
)

// parseSSDPServer returns the model a known layout of an SSDP SERVER header states; "" for any other header.
func parseSSDPServer(server string) string {
	if len(server) > maxSSDPServer {
		return ""
	}
	model := ""
	if m := serverAVM.FindStringSubmatch(server); m != nil && m[1] == m[2] {
		model = m[1]
	} else if m := serverSonos.FindStringSubmatch(server); m != nil {
		model = "Sonos " + m[1]
	} else if serverHue.MatchString(server) {
		model = "Philips Hue Bridge"
	}
	if len(model) > maxSSDPModel {
		return ""
	}
	return model
}

// ssdpMessage holds the headers read from an SSDP NOTIFY or search response. LOCATION is parsed for display
// only: this module never fetches it (it is a URL chosen by whoever sent the packet, SYS-6).
type ssdpMessage struct {
	server   string // SERVER, e.g. "Linux/5.4 UPnP/1.0 MiniUPnPd/2.2"
	usn      string
	nt       string // NT of a NOTIFY or ST of a response
	location string
}

// parseSSDP reads a NOTIFY or a "200 OK" search response. Search requests (M-SEARCH) carry nothing about the
// sender and are ignored.
func parseSSDP(b []byte) (ssdpMessage, error) {
	if len(b) > maxSSDP {
		return ssdpMessage{}, malformed("ssdp: too long")
	}
	head, _, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	if len(lines) > maxSSDPLines {
		return ssdpMessage{}, malformed("ssdp: too many header lines")
	}
	start := strings.ToUpper(lines[0])
	if !strings.HasPrefix(start, "NOTIFY * HTTP/1.1") && !strings.HasPrefix(start, "HTTP/1.1 200") {
		if strings.HasPrefix(start, "M-SEARCH ") {
			return ssdpMessage{}, errIgnore
		}
		return ssdpMessage{}, malformed("ssdp: start line")
	}
	var m ssdpMessage
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return ssdpMessage{}, malformed("ssdp: header line")
		}
		v = strings.TrimSpace(v)
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "SERVER":
			m.server = v
		case "USN":
			m.usn = v
		case "NT", "ST":
			m.nt = v
		case "LOCATION":
			m.location = v
		}
	}
	return m, nil
}
