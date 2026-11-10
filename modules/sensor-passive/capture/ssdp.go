package capture

import (
	"bytes"
	"strings"
)

const (
	maxSSDP      = 2048
	maxSSDPLines = 40
)

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
