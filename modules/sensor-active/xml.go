package sensoractive

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// Limits of the nmap XML parser (INV-7, SYS-6): the output is data from the network, so any structure
// beyond these fails the whole batch rather than being cut to fit.
const (
	// maxXMLDepth: nmap's own elements nest 7 deep (nmaprun/host/os/osmatch/osclass/cpe); a script's structured output adds a
	// table per level under <script> (the vulns library: script/table/table/table/elem is 9 under a port).
	maxXMLDepth     = 16
	maxXMLAttrs     = 24
	maxXMLTokens    = 400_000
	maxXMLHosts     = 256
	maxPortsPerHost = 1500
	maxOSMatches    = 8
	maxCPEs         = 8
	maxText         = 200 // longest stored string, in runes
	maxCPELen       = 300
	maxElemLen      = 256      // longest <elem> text of an NTLM script that is read; a longer one is dropped
	maxScriptOutput = 64 << 10 // longest output attribute of a <script> that is read (ssl-cert prints the whole certificate); a longer one is ignored
	// The NSE results of a full external run. maxScriptsPerHost: a few dozen scripts answer on a web port and at most
	// commonports.MaxBelievableOpen ports are believed, so a real host prints far fewer; the cap (four per listed port) bounds a
	// hostile answer, and more fails the run like too many ports (the whole XML is bounded by MaxOutput anyway). It applies to
	// every shape, LAN ones included (their -sV can print version-category scripts too); a LAN host near it is not expected.
	// maxScriptText: a script's text is kept up to 2000 runes: the whole output of a
	// vulns-library finding (smb-vuln-ms17-010 prints about 700 characters with its references) and of the usual discovery
	// scripts fits; the long dumps (a certificate in PEM, every comment of a page) are cut, never dropped. maxScriptFindings and
	// maxScriptCVEs: a vulns-library script reports one or a few findings of one or a few CVEs each; 20 bounds a script that
	// reports a list.
	maxScriptsPerHost = 4 * maxPortsPerHost
	maxScriptText     = 2000
	maxScriptFindings = 20
	maxFindingTitle   = 120 // a finding's title, as exposure keeps it (maxProduct there)
	maxScriptCVEs     = 20
)

var (
	errXMLTooBig  = errors.New("nmap output is larger than the limit")
	errXMLInvalid = errors.New("nmap output is not valid")
	// errTooManyPorts is the errXMLInvalid of a host with more than maxPortsPerHost ports listed: on the weekly scan of every
	// port that is a device answering on every port (review r2 M1)
	errTooManyPorts = fmt.Errorf("%w: too many ports", errXMLInvalid)
	macRE           = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)
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
	// read are the ports the PortVersions follow-up of a weekly scan read with -sV, set by probeAllPorts; nil otherwise
	read []int
	// closed and filtered count the ports nmap found in those states (listed ports and <extraports>): with no open port they
	// say whether the device refused the probes (closed) or something dropped them (filtered).
	closed, filtered int
	// scanned are the TCP ports the run looked at (nmap's <scaninfo services>); nil when it printed none
	scanned []observe.PortRange
	// runs is what each nmap run merged into this host said about the ports it did not find open (one run, or a normal scan and
	// its Extra run): answer reads it
	runs    []portRun
	ntlm    ntlmInfo    // what the device said about itself in an NTLM challenge; zero when no script answered
	scripts []nseScript // every NSE script result of an open port or of the host (<hostscript>), read for the full shapes
	says    []selfSays  // what the device stated about itself to the scripts of selfScripts (a web page's version), no login involved
}

// portRun is what one nmap run said about the TCP ports of a host it did not find open: the ports it asked about (its <scaninfo>),
// the state of each port it listed one by one (at most maxPortsPerHost), and the states it grouped in <extraports> without naming
// the ports.
type portRun struct {
	scanned []observe.PortRange
	listed  map[int]string
	extra   []string
}

// maxExtraStates bounds the <extraports> states kept per run: nmap prints one per state (closed, filtered), so a longer list is not nmap's.
const maxExtraStates = 4

// portAnswer is what a check learned about one TCP port.
type portAnswer int

const (
	notAsked       portAnswer = iota // no run of the check asked about the port: the check says nothing about it
	noAnswer                         // asked, and nothing came back (nmap's "filtered"): see answer
	answeredClosed                   // the device refused the connection (nmap's "closed"): the port is closed
	answeredOpen                     // the port is open
)

// answer is what the check of h learned about a TCP port. It is the one rule by which a check's result turns into the state of a
// port: only an open port is open, and only a port that refused the connection is closed. A port nmap asked about that sent nothing
// back ("filtered", "closed|filtered", or grouped in <extraports> with such ports) is noAnswer: a firewall that drops the probes and a
// device or link that rate-limits or loses them look the same to nmap, so the check is incomplete for that port, never proof that it
// closed. A port inside <extraports> is closed only when the run grouped nothing but closed ports there.
func (h host) answer(port int) portAnswer {
	if slices.ContainsFunc(h.ports, func(p portInfo) bool { return p.proto == "tcp" && p.number == port }) {
		return answeredOpen
	}
	got := notAsked
	for _, r := range h.runs {
		st, listed := r.listed[port]
		switch {
		case listed && st == "closed":
			return answeredClosed
		case listed:
			got = noAnswer
		case !inRanges(r.scanned, port):
		case len(r.extra) == 1 && r.extra[0] == "closed":
			return answeredClosed
		default:
			got = noAnswer
		}
	}
	return got
}

// noPortAnswered says the device was up but no port it was asked about answered (every one "filtered", or most of them with none
// open): the whole check is incomplete, the same rule as answer's for one port (Identification WhyFiltered, the history's words).
func (h host) noPortAnswered() bool {
	return !h.timedOut && len(h.ports) == 0 && h.filtered > 0 && h.filtered >= h.closed
}

func inRanges(rs []observe.PortRange, p int) bool {
	return slices.ContainsFunc(rs, func(r observe.PortRange) bool { return p >= r.From && p <= r.To })
}

// nseScript is one NSE script result: the script's id, its text output (scriptText, or outputWithheld) and the findings
// of the vulns library in its structured output. Port is 0 for a host script.
type nseScript struct {
	port     int
	id       string
	output   string
	findings []nseFinding
}

// nseFinding is one finding of nmap's vulns library (https://nmap.org/nsedoc/lib/vulns.html), read only from the script's
// structured output (review r1 M1): a <table> directly under <script> with an <elem key="state">, its <elem key="title">, and the
// CVE ids of its key ("CVE-2017-0143") and of its <table key="ids"> ("CVE:CVE-2017-0143"). Free text a service controls (a page
// comment, a header, a banner) never makes a finding or names a CVE. State is per finding (L3).
type nseFinding struct {
	state string // findingVulnerable, findingLikely or findingNotVulnerable
	title string
	cves  []string
}

// The states of a finding: the vulns library prints "VULNERABLE", "VULNERABLE (Exploitable)", "VULNERABLE (DoS)", "LIKELY
// VULNERABLE" and "NOT VULNERABLE"; any other state is not kept.
const (
	findingVulnerable    = "vulnerable"
	findingLikely        = "likely"
	findingNotVulnerable = "not_vulnerable"
)

// outputWithheld replaces the text of a script that can print credentials or hashes (nmapargv.StoresOutput, review r1 M4).
const outputWithheld = "Output not stored: it can hold credentials."

var (
	scriptIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)     // nmap's script names: "smb-vuln-ms17-010", "http-title"
	cveKeyRE   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)       // the key of a finding's table (review r1 L2: anchored)
	cveIDRE    = regexp.MustCompile(`^CVE:(CVE-[0-9]{4}-[0-9]{4,7})$`) // an <elem> of its ids table
)

// findingState maps the state the vulns library printed to the kept ones; "" for any other.
func findingState(s string) string {
	switch s = strings.TrimSpace(s); {
	case strings.HasPrefix(s, "VULNERABLE"):
		return findingVulnerable
	case strings.HasPrefix(s, "LIKELY VULNERABLE"):
		return findingLikely
	case strings.HasPrefix(s, "NOT VULNERABLE"):
		return findingNotVulnerable
	}
	return ""
}

// addCVE keeps a CVE id once, at most maxScriptCVEs.
func (f *nseFinding) addCVE(c string) {
	if len(f.cves) < maxScriptCVEs && !slices.Contains(f.cves, c) {
		f.cves = append(f.cves, c)
	}
}

// scriptText is a script's output as kept: valid UTF-8, line breaks kept (the vulns library prints one field a line), tabs and
// carriage returns as spaces, every other unprintable rune (control, format, bidi, line and paragraph separators, INV-7)
// removed, trimmed and cut to maxScriptText runes.
func scriptText(s string) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t' || r == '\r':
			return ' '
		case unprintable(r):
			return -1
		}
		return r
	}, s)
	return clipRunes(strings.TrimSpace(s), maxScriptText)
}

// ntlmInfo is the part of an NTLM CHALLENGE that nmap's rdp-ntlm-info or http-ntlm-info printed (nmapargv.Scripts): the
// Windows version and build the device itself put in the challenge, and its computer name. Only values of the expected form are kept.
type ntlmInfo struct {
	version string // Product_Version, "10.0.22631": major.minor.build, without the monthly update revision
	port    int    // the port whose script gave version
	dnsName string // DNS_Computer_Name
	nbName  string // NetBIOS_Computer_Name
}

// name is the device's own name: its DNS name, else its NetBIOS name.
func (n ntlmInfo) name() string {
	if n.dnsName != "" {
		return n.dnsName
	}
	return n.nbName
}

// ntlmScripts are the scripts whose output is read; any other <script> is ignored.
var ntlmScripts = map[string]bool{"rdp-ntlm-info": true, "http-ntlm-info": true}

// selfScripts are the scripts that read what a device states about itself, without a login, in a page or an API it serves to
// anyone: the fields each one's structured output is read for (selfFields). A value longer than maxElemLen, or with a character that
// is not printable, is dropped.
var selfScripts = map[string]bool{"http-hp-ilo-info": true, "vmware-version": true}

// selfFields are the <elem> keys read from the output of each of selfScripts.
var selfFields = map[string]map[string]bool{
	"http-hp-ilo-info": {"ILOType": true, "ILOFirmware": true, "ServerType": true},
	"vmware-version":   {"Server version": true, "Build": true},
}

// selfSays is what one script of selfScripts read on one port.
type selfSays struct {
	port   int
	script string
	fields map[string]string
}

// field is the value of one key, "" when the device did not state it.
func (s selfSays) field(k string) string { return s.fields[k] }

var (
	ntlmVersionRE = regexp.MustCompile(`^(?:[1-9]|10)\.[0-9]{1,2}\.[0-9]{3,5}$`)
	ntlmNameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
)

// addSays keeps one field a self-statement script read: the first value of a key on a port wins.
func (h *host) addSays(port int, script, key, value string) {
	for i := range h.says {
		if h.says[i].port == port && h.says[i].script == script {
			if _, ok := h.says[i].fields[key]; !ok {
				h.says[i].fields[key] = value
			}
			return
		}
	}
	if len(h.says) < maxScriptsPerHost {
		h.says = append(h.says, selfSays{port: port, script: script, fields: map[string]string{key: value}})
	}
}

// setNTLM keeps one <elem> of an NTLM script: the first well-formed value of each field wins (a host with RDP and HTTP answers twice).
func (h *host) setNTLM(port int, key, value string) {
	switch key {
	case "Product_Version":
		if h.ntlm.version == "" && ntlmVersionRE.MatchString(value) {
			h.ntlm.version, h.ntlm.port = value, port
		}
	case "DNS_Computer_Name":
		if h.ntlm.dnsName == "" && ntlmNameRE.MatchString(value) {
			h.ntlm.dnsName = value
		}
	case "NetBIOS_Computer_Name":
		if h.ntlm.nbName == "" && ntlmNameRE.MatchString(value) {
			h.ntlm.nbName = value
		}
	}
}

type portInfo struct {
	number                 int
	proto, name            string
	product, version, info string
	// What the port said about the device besides product and version: nmap's device type of the service match, the page
	// title (http-title) and the certificate subject (ssl-cert). Evidence for identification, never software.
	devType, title, certSubject string
	conf                        int // nmap's 1..10, 0 when absent
	// method is how nmap named the service (M2-7): "probed" (a probe's answer matched), "table" (only nmap-services' name for the
	// port number: nothing was confirmed), "" when absent or any other word.
	method string
	cpes   []string
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

// clipRunes cuts s to at most n runes (whole runes; s is valid UTF-8 or text refuses it afterwards).
func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// Bounds of what a port says: a long certificate subject or title is shortened, never dropped whole.
const (
	maxTitle       = 80
	maxSubjectPart = 60
	maxSubject     = 140
)

// certSubject is the subject of ssl-cert's output ("Subject: commonName=FGT60F.../organizationName=Fortinet/..."), commonName first
// (it names the device: a FortiGate's serial, a host name), then the organisation, then the rest, each part cut to maxSubjectPart
// and the whole to maxSubject; "" when there is none or it is not printable.
func certSubject(out string) string {
	for line := range strings.Lines(out) {
		s, ok := strings.CutPrefix(strings.TrimSpace(line), "Subject: ")
		if !ok {
			continue
		}
		var first, org, rest []string
		for part := range strings.SplitSeq(strings.TrimSpace(s), "/") {
			if part = clipRunes(strings.TrimSpace(part), maxSubjectPart); part == "" {
				continue
			}
			switch {
			case strings.HasPrefix(part, "commonName="):
				first = append(first, part)
			case strings.HasPrefix(part, "organizationName="):
				org = append(org, part)
			default:
				rest = append(rest, part)
			}
		}
		return text(clipRunes(strings.Join(append(append(first, org...), rest...), "/"), maxSubject))
	}
	return ""
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

// serviceName is the name of a <service> as nmap's own text output prints it: nmap's XML keeps TLS apart, in
// tunnel="ssl", so an HTTPS admin page on 4443 is name="http" tunnel="ssl"; it becomes "ssl/http", which every consumer
// (scan endpoints, exposure schemeOf and ZAP) reads as TLS. Without it nuclei spoke plain HTTP to a TLS port and found nothing.
func serviceName(a map[string]string) string {
	if a["tunnel"] != "ssl" {
		return a["name"]
	}
	if a["name"] == "" {
		return "ssl"
	}
	return "ssl/" + a["name"]
}

func attrs(el xml.StartElement) map[string]string {
	m := make(map[string]string, len(el.Attr))
	for _, a := range el.Attr {
		m[a.Name.Local] = a.Value
	}
	return m
}

// readAttrs are the attributes the parser reads (the a["…"] keys of parseNmapXML and serviceName; TestReadAttrsAreTheParsersKeys
// keeps the two in step). Only they are capped at maxAttrLen, a script's output apart (maxScriptOutput). Every other attribute nmap
// prints is never read and bounded only by maxOutput: nmap echoes its whole command line in <nmaprun args> (the
// --script list of the full shapes alone is about 4.8 KB, 6.2 KB disruptive), the -p list in <scaninfo services>, and the fingerprint
// of a port it cannot identify in <service servicefp> (about 6 KB, from what the target answered). Capping them refused whole runs.
var readAttrs = map[string]bool{
	"accuracy": true, "addr": true, "addrtype": true, "conf": true, "count": true, "devicetype": true, "extrainfo": true, "id": true,
	"key": true, "method": true, "name": true, "osfamily": true, "osgen": true, "output": true, "portid": true, "product": true, "protocol": true,
	"state": true, "timedout": true, "tunnel": true, "type": true, "vendor": true, "version": true,
}

const maxAttrLen = 4096 // longest attribute that is read, a script's output apart

// scaninfoServices is the attribute of <scaninfo> that lists the ports a run looked at, as nmap's ranges ("1-1000,1002").
const scaninfoServices = "services"

// maxScanRanges bounds the ranges read from a <scaninfo>: nmap's top 1000 ports are about a hundred ranges.
const maxScanRanges = 2000

// parsePortRanges reads nmap's port list ("22,80-90"); nil when it is empty, over maxScanRanges ranges or not a list of ports.
func parsePortRanges(list string) []observe.PortRange {
	var out []observe.PortRange
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		from, err := strconv.Atoi(lo)
		to := from
		if err == nil && isRange {
			to, err = strconv.Atoi(hi)
		}
		if err != nil || from < 1 || to > 65535 || from > to || len(out) >= maxScanRanges {
			return nil
		}
		out = append(out, observe.PortRange{From: from, To: to})
	}
	return out
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
		path     []string
		hosts    []host
		cur      *host
		up       bool
		port     *portInfo
		portOK   bool
		match    *osMatch
		class    *osClass
		cpeDst   *[]string
		cpeBuf   strings.Builder
		closed   bool
		ntlm     bool   // inside the <script> of an NTLM script of an open port
		selfID   string // the id of the <script> being read when it is one of selfScripts, of an open port; "" otherwise
		title    bool   // inside the <script> of http-title
		elemKey  string // key of the <elem> being read; "" when none
		elemBuf  strings.Builder
		scr      *nseScript  // the <script> being read, of an open port or of the host; nil outside one
		scrDepth int         // len(path) of scr's <script>
		fnd      *nseFinding // a <table> directly under scr: a vulns-library finding when it has a state
		inIDs    bool        // inside fnd's <table key="ids">
		fKey     string      // the field of fnd an <elem> being read fills ("state", "title", "ids"); "" when none
		fBuf     strings.Builder
		scanned  []observe.PortRange // the TCP ports of the run's <scaninfo>; set on each host
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
				// A script's printed output (a certificate with many names, a long page title) may be longer than any other
				// attribute; it is bounded apart below, so a long one never refuses the whole run. Attributes the parser
				// never reads are not capped one by one (readAttrs; the whole document is bounded by maxOutput).
				if len(a.Value) > maxAttrLen && readAttrs[a.Name.Local] && (t.Name.Local != "script" || a.Name.Local != "output") {
					return nil, fmt.Errorf("%w: attribute too long", errXMLInvalid)
				}
			}
			if len(path) == 0 && t.Name.Local != "nmaprun" {
				return nil, fmt.Errorf("%w: root is not nmaprun", errXMLInvalid)
			}
			path = append(path, t.Name.Local)
			a := attrs(t)
			if t.Name.Local == "script" && len(a["output"]) > maxScriptOutput {
				delete(a, "output") // only that script's output is ignored; its port and the run are kept (#714 round 2, L3)
			}
			p, d := strings.Join(path, "/"), len(path)
			switch {
			case cur != nil && (p == "nmaprun/host/ports/port/script" && port != nil || p == "nmaprun/host/hostscript/script"):
				if len(cur.scripts) >= maxScriptsPerHost {
					return nil, fmt.Errorf("%w: too many script results", errXMLInvalid)
				}
				scr, scrDepth = &nseScript{id: a["id"], output: scriptText(a["output"])}, d
				if a["output"] != "" && !nmapargv.StoresOutput(a["id"]) { // review r1 M4: it can print credentials or hashes
					scr.output = outputWithheld
				}
				if port != nil {
					scr.port = port.number
				}
			case scr != nil && d == scrDepth+1 && t.Name.Local == "table":
				fnd = &nseFinding{}
				if cveKeyRE.MatchString(a["key"]) {
					fnd.addCVE(a["key"])
				}
			case fnd != nil && d == scrDepth+2 && t.Name.Local == "table" && a["key"] == "ids":
				inIDs = true
			case fnd != nil && t.Name.Local == "elem" && (d == scrDepth+2 && (a["key"] == "state" || a["key"] == "title") || inIDs && d == scrDepth+3):
				fKey = a["key"]
				if inIDs {
					fKey = "ids"
				}
				fBuf.Reset()
			}
			switch p {
			case "nmaprun/scaninfo":
				if a["protocol"] == "tcp" && scanned == nil {
					scanned = parsePortRanges(a[scaninfoServices]) // not a readAttrs key: the -p list may be long, and is only parsed
				}
			case "nmaprun/host":
				if len(hosts) >= maxXMLHosts {
					return nil, fmt.Errorf("%w: too many hosts", errXMLInvalid)
				}
				cur, up = &host{timedOut: a["timedout"] == "true", scanned: scanned, runs: []portRun{{scanned: scanned}}}, false
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
					return nil, errTooManyPorts
				}
				port, portOK = &portInfo{number: num(a["portid"], 65535), proto: text(a["protocol"])}, false
			case "nmaprun/host/ports/extraports":
				if cur != nil {
					cur.countState(a["state"], num(a["count"], 65535))
					if r := &cur.runs[0]; len(r.extra) < maxExtraStates {
						r.extra = append(r.extra, a["state"])
					}
				}
			case "nmaprun/host/ports/port/state":
				portOK = port != nil && a["state"] == "open"
				if cur != nil && port != nil {
					cur.countState(a["state"], 1)
					if r := &cur.runs[0]; a["state"] != "open" && port.proto == "tcp" && port.number > 0 && len(r.listed) < maxPortsPerHost {
						if r.listed == nil {
							r.listed = map[int]string{}
						}
						r.listed[port.number] = a["state"]
					}
				}
			case "nmaprun/host/ports/port/service":
				if port != nil {
					port.name, port.product, port.version, port.info = text(serviceName(a)), text(a["product"]), text(a["version"]), text(a["extrainfo"])
					port.devType = text(a["devicetype"])
					port.conf = num(a["conf"], 10)
					if m := a["method"]; m == "probed" || m == "table" {
						port.method = m
					}
				}
			case "nmaprun/host/ports/port/service/cpe":
				if port != nil && len(port.cpes) < maxCPEs {
					cpeDst = &port.cpes
					cpeBuf.Reset()
				}
			case "nmaprun/host/ports/port/script":
				ntlm = cur != nil && port != nil && ntlmScripts[a["id"]]
				title = cur != nil && port != nil && a["id"] == "http-title"
				selfID = ""
				if cur != nil && port != nil && selfScripts[a["id"]] {
					selfID = a["id"]
				}
				if cur != nil && port != nil && a["id"] == "ssl-cert" {
					port.certSubject = certSubject(a["output"])
				}
			case "nmaprun/host/ports/port/script/elem":
				if ntlm || (title && a["key"] == "title") || (selfID != "" && selfFields[selfID][a["key"]]) {
					elemKey = a["key"]
					elemBuf.Reset()
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
			if elemKey != "" && elemBuf.Len() <= maxElemLen {
				elemBuf.Write(t)
			}
			if fKey != "" && fBuf.Len() <= maxElemLen {
				fBuf.Write(t)
			}
		case xml.EndElement:
			p, d := strings.Join(path, "/"), len(path)
			switch {
			case fKey != "" && t.Name.Local == "elem":
				if v := strings.TrimSpace(fBuf.String()); fBuf.Len() <= maxElemLen { // a longer value is not read
					switch fKey {
					case "state":
						fnd.state = findingState(v)
					case "title":
						fnd.title = text(clipRunes(v, maxFindingTitle))
					case "ids":
						if m := cveIDRE.FindStringSubmatch(v); m != nil {
							fnd.addCVE(m[1])
						}
					}
				}
				fKey = ""
			case inIDs && d == scrDepth+2 && t.Name.Local == "table":
				inIDs = false
			case fnd != nil && d == scrDepth+1 && t.Name.Local == "table":
				if fnd.state != "" && len(scr.findings) < maxScriptFindings { // a table without a state is not a finding
					scr.findings = append(scr.findings, *fnd)
				}
				fnd = nil
			case scr != nil && (p == "nmaprun/host/ports/port/script" || p == "nmaprun/host/hostscript/script"):
				// A port script counts only on an open port (the state comes before the scripts in nmap's XML); a script whose id is
				// not of nmap's form is dropped.
				if cur != nil && (p == "nmaprun/host/hostscript/script" || portOK) && scriptIDRE.MatchString(scr.id) {
					cur.scripts = append(cur.scripts, *scr)
				}
				scr, fnd, inIDs, fKey = nil, nil, false, ""
			}
			switch p {
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
			case "nmaprun/host/ports/port/script":
				ntlm, title, selfID = false, false, ""
			case "nmaprun/host/ports/port/script/elem":
				// The challenge is read only from an open port; a value longer than maxElemLen or of another form is dropped.
				// A title longer than the buffer keeps its start (#714 review: shortened, not dropped).
				if elemKey != "" && cur != nil && portOK && (title || elemBuf.Len() <= maxElemLen) {
					v := text(clipRunes(strings.Join(strings.Fields(elemBuf.String()), " "), maxTitle))
					switch {
					case title:
						port.title = v
					case selfID != "":
						if v != "" && elemBuf.Len() <= maxElemLen {
							cur.addSays(port.number, selfID, elemKey, v)
						}
					default:
						cur.setNTLM(port.number, elemKey, text(strings.TrimSpace(elemBuf.String())))
					}
				}
				elemKey = ""
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
