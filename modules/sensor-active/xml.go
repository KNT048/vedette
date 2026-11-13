package sensoractive

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the nmap XML parser (INV-7, SYS-6): the output is data from the network, so any structure
// beyond these fails the whole batch rather than being cut to fit.
const (
	maxXMLDepth     = 12
	maxXMLAttrs     = 24
	maxXMLTokens    = 400_000
	maxXMLHosts     = 256
	maxPortsPerHost = 1500
	maxOSMatches    = 8
	maxCPEs         = 8
	maxText         = 200 // longest stored string, in runes
	maxCPELen       = 300
)

var (
	errXMLTooBig  = errors.New("nmap output is larger than the limit")
	errXMLInvalid = errors.New("nmap output is not valid")
	macRE         = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)
)

// host is one live host of an nmap run.
type host struct {
	addr     netip.Addr
	mac      string // as nmap printed it; empty when none
	vendor   string // vendor of the MAC
	hostname string
	ports    []portInfo // open ports only
	matches  []osMatch
	timedOut bool // nmap gave up on the host (--host-timeout): it printed no port table, so ports says nothing
	// closed and filtered count the ports nmap found in those states (listed ports and <extraports>): with no open port they
	// say whether the device refused the probes (closed) or something dropped them (filtered), D-501.
	closed, filtered int
}

type portInfo struct {
	number                 int
	proto, name            string
	product, version, info string
	conf                   int // nmap's 1..10, 0 when absent
	cpes                   []string
}

type osMatch struct {
	name     string
	accuracy int // 0..100
	classes  []osClass
}

type osClass struct {
	typ, vendor, family, gen string
	accuracy                 int
	cpes                     []string
}

// unprintable is true for what a banner nmap copies must not carry into the inventory: control characters
// (C0, DEL and C1), format characters (bidi overrides and isolates, zero-width characters, the byte order mark,
// the soft hyphen, tag characters) and the line and paragraph separators. They reorder or hide text in the UI
// and in a CSV export (INV-7).
func unprintable(r rune) bool {
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

// text accepts a string from nmap only if it is printable UTF-8 of 1..maxText runes; otherwise it is "" (absent).
func text(s string) string {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxText || !utf8.ValidString(s) || strings.ContainsFunc(s, unprintable) {
		return ""
	}
	return s
}

// cpeText accepts a CPE 2.2 URI: printable ASCII starting with "cpe:/".
func cpeText(s string) string {
	if len(s) > maxCPELen || !strings.HasPrefix(s, "cpe:/") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

// countState adds n ports of a state nmap printed: "closed", or any state with "filtered" in it (filtered, open|filtered,
// closed|filtered). Open ports are in ports; the counts are capped so a forged count cannot overflow.
func (h *host) countState(state string, n int) {
	switch {
	case state == "closed":
		h.closed = min(h.closed+n, 1<<20)
	case strings.Contains(state, "filtered"):
		h.filtered = min(h.filtered+n, 1<<20)
	}
}

func attrs(el xml.StartElement) map[string]string {
	m := make(map[string]string, len(el.Attr))
	for _, a := range el.Attr {
		m[a.Name.Local] = a.Value
	}
	return m
}

func clamp(n, lo, hi int) int { return max(lo, min(hi, n)) }

func num(s string, hi int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return clamp(n, 0, hi)
}

// parseNmapXML reads the XML of one nmap run (INV-7). It streams with encoding/xml, fails closed on a size,
// depth, attribute, token, host or port limit, on a root other than nmaprun, on any directive but nmap's own
// DOCTYPE, and on a document that does not end properly (a cut-off run). Strings are kept only as text and
// only when printable. Hosts that are not up, or have no IPv4 address, are left out.
func parseNmapXML(data []byte) ([]host, error) {
	if int64(len(data)) > maxOutput {
		return nil, errXMLTooBig
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true // an unknown entity is an error; charsets other than UTF-8 are refused (no CharsetReader)
	var (
		path   []string
		hosts  []host
		cur    *host
		up     bool
		port   *portInfo
		portOK bool
		match  *osMatch
		class  *osClass
		cpeDst *[]string
		cpeBuf strings.Builder
		closed bool
	)
	for tokens := 0; ; tokens++ {
		if tokens > maxXMLTokens {
			return nil, fmt.Errorf("%w: too many tokens", errXMLInvalid)
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errXMLInvalid, err)
		}
		if closed {
			if _, ws := tok.(xml.CharData); !ws && !isComment(tok) {
				return nil, fmt.Errorf("%w: content after the end", errXMLInvalid)
			}
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(path) >= maxXMLDepth {
				return nil, fmt.Errorf("%w: too deep", errXMLInvalid)
			}
			if len(t.Attr) > maxXMLAttrs {
				return nil, fmt.Errorf("%w: too many attributes", errXMLInvalid)
			}
			for _, a := range t.Attr {
				if len(a.Value) > 4096 {
					return nil, fmt.Errorf("%w: attribute too long", errXMLInvalid)
				}
			}
			if len(path) == 0 && t.Name.Local != "nmaprun" {
				return nil, fmt.Errorf("%w: root is not nmaprun", errXMLInvalid)
			}
			path = append(path, t.Name.Local)
			a := attrs(t)
			switch strings.Join(path, "/") {
			case "nmaprun/host":
				if len(hosts) >= maxXMLHosts {
					return nil, fmt.Errorf("%w: too many hosts", errXMLInvalid)
				}
				cur, up = &host{timedOut: a["timedout"] == "true"}, false
			case "nmaprun/host/status":
				up = cur != nil && a["state"] == "up"
			case "nmaprun/host/address":
				if cur == nil {
					break
				}
				switch a["addrtype"] {
				case "ipv4":
					if ip, err := netip.ParseAddr(a["addr"]); err == nil && ip.Is4() {
						cur.addr = ip
					}
				case "mac":
					if macRE.MatchString(a["addr"]) {
						cur.mac, cur.vendor = a["addr"], text(a["vendor"])
					}
				}
			case "nmaprun/host/hostnames/hostname":
				if cur != nil && cur.hostname == "" {
					cur.hostname = text(a["name"])
				}
			case "nmaprun/host/ports/port":
				if cur == nil {
					break
				}
				if len(cur.ports) >= maxPortsPerHost {
					return nil, fmt.Errorf("%w: too many ports", errXMLInvalid)
				}
				port, portOK = &portInfo{number: num(a["portid"], 65535), proto: text(a["protocol"])}, false
			case "nmaprun/host/ports/extraports":
				if cur != nil {
					cur.countState(a["state"], num(a["count"], 65535))
				}
			case "nmaprun/host/ports/port/state":
				portOK = port != nil && a["state"] == "open"
				if cur != nil && port != nil {
					cur.countState(a["state"], 1)
				}
			case "nmaprun/host/ports/port/service":
				if port != nil {
					port.name, port.product, port.version, port.info = text(a["name"]), text(a["product"]), text(a["version"]), text(a["extrainfo"])
					port.conf = num(a["conf"], 10)
				}
			case "nmaprun/host/ports/port/service/cpe":
				if port != nil && len(port.cpes) < maxCPEs {
					cpeDst = &port.cpes
					cpeBuf.Reset()
				}
			case "nmaprun/host/os/osmatch":
				if cur != nil && len(cur.matches) < maxOSMatches {
					cur.matches = append(cur.matches, osMatch{name: text(a["name"]), accuracy: num(a["accuracy"], 100)})
					match = &cur.matches[len(cur.matches)-1]
				} else {
					match = nil
				}
			case "nmaprun/host/os/osmatch/osclass":
				if match != nil && len(match.classes) < maxOSMatches {
					match.classes = append(match.classes, osClass{typ: text(a["type"]), vendor: text(a["vendor"]), family: text(a["osfamily"]), gen: text(a["osgen"]), accuracy: num(a["accuracy"], 100)})
					class = &match.classes[len(match.classes)-1]
				} else {
					class = nil
				}
			case "nmaprun/host/os/osmatch/osclass/cpe":
				if class != nil && len(class.cpes) < maxCPEs {
					cpeDst = &class.cpes
					cpeBuf.Reset()
				}
			}
		case xml.CharData:
			if cpeDst != nil && cpeBuf.Len() <= maxCPELen {
				cpeBuf.Write(t)
			}
		case xml.EndElement:
			switch strings.Join(path, "/") {
			case "nmaprun":
				closed = true
			case "nmaprun/host":
				if cur != nil && up && cur.addr.IsValid() {
					hosts = append(hosts, *cur)
				}
				cur = nil
			case "nmaprun/host/ports/port":
				if cur != nil && port != nil && portOK {
					cur.ports = append(cur.ports, *port)
				}
				port = nil
			case "nmaprun/host/ports/port/service/cpe", "nmaprun/host/os/osmatch/osclass/cpe":
				if cpeDst != nil {
					if c := cpeText(strings.TrimSpace(cpeBuf.String())); c != "" {
						*cpeDst = append(*cpeDst, c)
					}
					cpeDst = nil
				}
			}
			path = path[:len(path)-1]
		case xml.Directive:
			if string(t) != "DOCTYPE nmaprun" {
				return nil, fmt.Errorf("%w: unexpected directive", errXMLInvalid)
			}
		case xml.ProcInst:
			if t.Target != "xml" && t.Target != "xml-stylesheet" {
				return nil, fmt.Errorf("%w: unexpected processing instruction", errXMLInvalid)
			}
		}
	}
	if !closed {
		return nil, fmt.Errorf("%w: the document is cut off", errXMLInvalid)
	}
	return hosts, nil
}

func isComment(t xml.Token) bool { _, ok := t.(xml.Comment); return ok }
