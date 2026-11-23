package ids

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/logs/listen"
)

// Limits of what one IPS event can put in a row. A log line is untrusted input (SYS-6): every value is cut to these bounds and a
// line that does not have the shape of its vendor's IPS event gives no event at all (fail closed).
const (
	// MaxLineBytes is the longest line read; the logs module stores at most 2,048 bytes of a line, so this is only a guard.
	MaxLineBytes = 4096
	// MaxSignatureLen and MaxCategoryLen are the longest signature and category kept, in characters (the API's limits).
	MaxSignatureLen = 300
	MaxCategoryLen  = 120
	// MaxCVEs is how many CVE ids one event keeps (the lowest ones, sorted).
	MaxCVEs = 8
	// maxPairs is how many key=value pairs a line is read for; a line with more is not an event.
	maxPairs = 200
	// maxCSVFields is how many comma-separated fields a Palo Alto line is read for.
	maxCSVFields = 160
)

// cutMark is what the logs module appends to a line it cut: a cut line may have lost the end of a value, so it gives no event.
const cutMark = " ...[cut]"

// Event is one IPS or IDS event read from a log line: what fired, from where, at what.
type Event struct {
	Profile   string // the device profile that read it: fortigate, suricata, snort, suricata_eve, sophos, sonicwall, paloalto, meraki
	SID       int64  // the rule or signature number; -1 when the event gives none
	Signature string // the rule name as the event wrote it, never empty
	Category  string // the rule's class as the event wrote it; "" when it gives none
	Priority  int    // 1 (most urgent) .. 4
	Src, Dst  netip.Addr
	DstPort   int    // -1 when the event gives no port (ICMP)
	Proto     string // tcp, udp, icmp... lower case; "" when the event gives none
	CVEs      []string
}

// profileKinds is which log source kinds (the logs module's KIND_IDS) can carry which IPS event format. Suricata and Snort run on
// pfSense, OPNsense, UniFi gateways and plain Linux hosts; they are recognised by their syslog program name, so a line of another
// program on the same source is never read as one.
var profileKinds = map[string][]string{
	"fortigate":      {"fortigate"},
	"sophos":         {"sophos"},
	"sonicwall":      {"sonicwall"},
	"paloalto":       {"paloalto"},
	"meraki":         {"meraki"},
	"pfsense":        {"suricata"},
	"opnsense":       {"suricata"},
	"ubiquiti":       {"suricata"},
	"unifi":          {"suricata"},
	"suricata":       {"suricata"},
	"linux-rsyslog":  {"suricata"},
	"linux-journald": {"suricata"},
	"syslog-ng":      {"suricata"},
	"syslog-generic": {"suricata"},
}

// nativeIPS are the kinds of device that run an IPS themselves: a source of one of them is a source of IPS events. A plain Linux or
// generic syslog source is read too (Suricata or Snort may run there) but is not counted as one.
var nativeIPS = map[string]bool{"fortigate": true, "sophos": true, "sonicwall": true, "paloalto": true, "meraki": true, "pfsense": true, "opnsense": true,
	"ubiquiti": true, "unifi": true, "suricata": true}

// NativeIPS reports whether a log source of this kind is a device that writes IPS events.
func NativeIPS(kind string) bool { return nativeIPS[kind] }

// Reads reports whether lines of a source of this kind can carry IPS events.
func Reads(kind string) bool { return profileKinds[kind] != nil }

// Parse reads one stored log line of a source of the given kind. ok is false for every line that is not an IPS event of a format
// the kind can send, and for one that is but is malformed: a missing or doubled field, an address that is not an address, a cut line.
// Parse is total and bounded: no input makes it panic, allocate more than a few times the line, or run in more than linear time
// (Go's regexp is linear).
func Parse(kind, line string) (Event, bool) {
	formats := profileKinds[kind]
	if formats == nil || len(line) > MaxLineBytes || strings.HasSuffix(line, cutMark) || !utf8.ValidString(line) {
		return Event{}, false
	}
	env := listen.ParseSyslog(line)
	for _, f := range formats {
		var e Event
		var ok bool
		switch f {
		case "fortigate":
			e, ok = parseFortiGate(env.Msg)
		case "sophos":
			e, ok = parseSophos(env.Msg)
		case "sonicwall":
			e, ok = parseSonicWall(env.Msg)
		case "paloalto":
			e, ok = parsePaloAlto(env.Msg)
		case "meraki":
			e, ok = parseMeraki(line)
		case "suricata":
			e, ok = parseSuricataFamily(env)
		}
		if ok {
			return finish(e)
		}
	}
	return Event{}, false
}

// finish bounds the values and checks what every event must have.
func finish(e Event) (Event, bool) {
	e.Signature = clipText(e.Signature, MaxSignatureLen)
	e.Category = clipText(e.Category, MaxCategoryLen)
	e.Proto = strings.ToLower(e.Proto)
	if len(e.Proto) > 16 || strings.IndexFunc(e.Proto, notProtoRune) >= 0 {
		e.Proto = ""
	}
	if e.Signature == "" || !e.Src.IsValid() || !e.Dst.IsValid() || e.Priority < 1 || e.Priority > 4 || e.DstPort < -1 || e.DstPort > 65535 || e.SID < -1 {
		return Event{}, false
	}
	e.Src, e.Dst = e.Src.Unmap(), e.Dst.Unmap()
	e.CVEs = normCVEs(e.CVEs)
	return e, true
}

func notProtoRune(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' }

// clipText makes a display value of an untrusted one: control and format characters become spaces, runs of spaces one, and it is
// cut to n characters.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || r == 0x2028 || r == 0x2029 || r >= 0x200b && r <= 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r == 0xfeff {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return strings.TrimSpace(s)
}

var cveRE = regexp.MustCompile(`(?i)\bCVE[-_](\d{4})[-_](\d{4,7})\b`)

// cvesIn finds the CVE ids written in a text (CVE-2021-44228, and CVE_2021_44228 as Emerging Threats rules write them in their
// metadata), at most MaxCVEs*4 of them read.
func cvesIn(texts ...string) []string {
	var out []string
	for _, t := range texts {
		for _, m := range cveRE.FindAllStringSubmatch(t, MaxCVEs*4) {
			out = append(out, "CVE-"+m[1]+"-"+m[2])
		}
	}
	return out
}

// normCVEs sorts the ids (by year, then number), drops repeats and years that cannot be a CVE's, and keeps the first MaxCVEs.
func normCVEs(in []string) []string {
	type id struct {
		y, n int
		s    string
	}
	var ids []id
	for _, c := range in {
		m := cveRE.FindStringSubmatch(c)
		if m == nil || m[0] != c && "CVE-"+m[1]+"-"+m[2] != c {
			continue
		}
		y, _ := strconv.Atoi(m[1])
		n, _ := strconv.Atoi(m[2])
		if y < 1999 || y > 2100 {
			continue
		}
		ids = append(ids, id{y, n, "CVE-" + m[1] + "-" + m[2]})
	}
	slices.SortFunc(ids, func(a, b id) int {
		return cmp.Or(cmp.Compare(a.y, b.y), cmp.Compare(a.n, b.n), strings.Compare(a.s, b.s))
	})
	ids = slices.CompactFunc(ids, func(a, b id) bool { return a.s == b.s })
	out := make([]string, 0, min(len(ids), MaxCVEs))
	for _, i := range ids[:min(len(ids), MaxCVEs)] {
		out = append(out, i.s)
	}
	return out
}

// ---- key=value lines (FortiGate, Sophos, SonicWall, Meraki) ----

// fields reads the key=value pairs of a line (key=value and key="quoted value") and returns the wanted ones. ok is false when a
// wanted key is written twice, a quote is not closed or is glued to more text, or the line has more than maxPairs pairs: then no value
// of the line is trusted.
func fields(s string, want ...string) (map[string]string, bool) {
	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		wanted[w] = true
	}
	vals := map[string]string{}
	pairs := 0
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		j := i
		for j < len(s) && isKeyByte(s[j]) {
			j++
		}
		if j == i || j >= len(s) || s[j] != '=' { // a word, not a pair
			for j < len(s) && s[j] != ' ' && s[j] != '\t' {
				if s[j] == '"' {
					return nil, false
				}
				j++
			}
			i = max(j, i+1)
			continue
		}
		if pairs++; pairs > maxPairs {
			return nil, false
		}
		key := s[i:j]
		j++
		var val string
		if j < len(s) && s[j] == '"' {
			k := j + 1
			for k < len(s) && s[k] != '"' {
				if s[k] == '\\' {
					k++
				}
				k++
			}
			if k >= len(s) || k+1 < len(s) && s[k+1] != ' ' && s[k+1] != '\t' {
				return nil, false
			}
			val, j = s[j+1:k], k+1
		} else {
			k := j
			for k < len(s) && s[k] != ' ' && s[k] != '\t' {
				if s[k] == '"' {
					return nil, false
				}
				k++
			}
			val, j = s[j:k], k
		}
		if wanted[key] {
			if _, seen := vals[key]; seen {
				return nil, false
			}
			vals[key] = val
		}
		i = j
	}
	return vals, true
}

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// addr reads an address as an event writes it: canonical text, no zone.
func addr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// port reads a port; "" is no port.
func port(s string) (int, bool) {
	if s == "" {
		return -1, true
	}
	if len(s) > 5 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

// sid reads a rule number; "" is none.
func sid(s string) (int64, bool) {
	if s == "" {
		return -1, true
	}
	if len(s) > 12 {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ianaProto names the IP protocol numbers an IPS event writes.
func ianaProto(s string) string {
	switch s {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "ipv6-icmp"
	case "132":
		return "sctp"
	}
	return ""
}

// levelPriority maps a vendor's severity word to the 1..4 priority (critical 1, high 2, medium 3, low and informational 4).
func levelPriority(s string) (int, bool) {
	switch strings.ToLower(s) {
	case "critical":
		return 1, true
	case "high":
		return 2, true
	case "medium":
		return 3, true
	case "low", "info", "informational":
		return 4, true
	}
	return 0, false
}

// snortPriority reads a Snort-style priority: 1 is the most urgent; a larger number is the least urgent level, 4.
func snortPriority(s string) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return min(n, 4), true
}

var fortiGroup = regexp.MustCompile(`^([a-z0-9_]{1,40}): `)

// parseFortiGate reads a FortiOS IPS signature log (type=utm subtype=ips, log ids 0419016384 and its siblings): attack, attackid,
// severity, srcip, dstip, dstport, proto (a number) and, on FortiOS versions that write it, cve. The msg's group ("web_misc: ...")
// is the category.
func parseFortiGate(msg string) (Event, bool) {
	v, ok := fields(msg, "type", "subtype", "attack", "attackid", "severity", "srcip", "dstip", "dstport", "proto", "cve", "msg")
	if !ok || v["type"] != "utm" || v["subtype"] != "ips" {
		return Event{}, false
	}
	e := Event{Profile: "fortigate", Signature: v["attack"], Proto: ianaProto(v["proto"])}
	var okS, okD, okP, okI, okR bool
	e.Src, okS = addr(v["srcip"])
	e.Dst, okD = addr(v["dstip"])
	e.DstPort, okP = port(v["dstport"])
	e.SID, okI = sid(v["attackid"])
	e.Priority, okR = levelPriority(v["severity"])
	if !okS || !okD || !okP || !okI || !okR {
		return Event{}, false
	}
	if e.SID == 0 { // attack id 0 is FortiGuard's "unknown"
		e.SID = -1
	}
	if m := fortiGroup.FindStringSubmatch(v["msg"]); m != nil {
		e.Category = m[1]
	}
	if e.Proto == "icmp" || e.Proto == "ipv6-icmp" {
		e.DstPort = -1
	}
	e.CVEs = cvesIn(v["cve"], v["attack"], v["msg"])
	return e, true
}

// parseSophos reads a Sophos Firewall IPS event (log_type="IDP"): signature_id, signature_msg, classification, rule_priority, src_ip,
// dst_ip, protocol, dst_port.
func parseSophos(msg string) (Event, bool) {
	v, ok := fields(msg, "log_type", "signature_id", "signature_msg", "classification", "rule_priority", "src_ip", "dst_ip", "protocol", "dst_port")
	if !ok || v["log_type"] != "IDP" {
		return Event{}, false
	}
	e := Event{Profile: "sophos", Signature: v["signature_msg"], Category: v["classification"], Proto: v["protocol"]}
	var okS, okD, okP, okI, okR bool
	e.Src, okS = addr(v["src_ip"])
	e.Dst, okD = addr(v["dst_ip"])
	e.DstPort, okP = port(v["dst_port"])
	e.SID, okI = sid(v["signature_id"])
	e.Priority, okR = snortPriority(v["rule_priority"])
	if !okS || !okD || !okP || !okI || !okR {
		return Event{}, false
	}
	e.CVEs = cvesIn(v["signature_msg"])
	return e, true
}

// endpoint reads ip, ip:port and ip:port:interface (SonicWall) and the bracketed [v6]:port.
func endpoint(s string, withIface bool) (netip.Addr, int, bool) {
	if withIface { // SonicWall: 198.51.100.7:44312:X1 (IPv4 only; the interface is the last part)
		if i := strings.LastIndexByte(s, ':'); i > 0 && strings.Count(s, ":") == 2 {
			s = s[:i]
		}
	}
	if strings.HasPrefix(s, "[") {
		ap, err := netip.ParseAddrPort(s)
		if err != nil || ap.Addr().Zone() != "" {
			return netip.Addr{}, 0, false
		}
		return ap.Addr().Unmap(), int(ap.Port()), true
	}
	if a, ok := addr(s); ok && a.Is4() {
		return a, -1, true
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return netip.Addr{}, 0, false
	}
	a, ok := addr(s[:i])
	p, okP := port(s[i+1:])
	if !ok || !okP || p < 0 {
		return netip.Addr{}, 0, false
	}
	return a, p, true
}

// parseSonicWall reads a SonicOS IPS alert (m=608 IPS Detection Alert, m=609 IPS Prevention Alert): msg, sid, ipscat, ipspri, src and
// dst as ip:port:interface, proto as tcp/port.
func parseSonicWall(msg string) (Event, bool) {
	v, ok := fields(msg, "m", "msg", "sid", "ipscat", "ipspri", "src", "dst", "proto")
	if !ok || v["m"] != "608" && v["m"] != "609" {
		return Event{}, false
	}
	name := v["msg"]
	for _, p := range []string{"IPS Detection Alert: ", "IPS Prevention Alert: "} {
		if after, found := strings.CutPrefix(name, p); found {
			name = after
		}
	}
	if i := strings.Index(name, ", SID: "); i >= 0 { // SonicOS 7 adds ", SID: n, Priority: Low"
		name = name[:i]
	}
	e := Event{Profile: "sonicwall", Signature: name}
	if e.Signature == "" {
		e.Signature = v["ipscat"]
	} else if v["ipscat"] != name {
		e.Category = v["ipscat"]
	}
	var okS, okD, okI, okR bool
	e.Src, _, okS = endpoint(v["src"], true)
	e.Dst, e.DstPort, okD = endpoint(v["dst"], true)
	e.SID, okI = sid(v["sid"])
	e.Priority, okR = snortPriority(v["ipspri"])
	if !okS || !okD || !okI || !okR {
		return Event{}, false
	}
	if p, _, found := strings.Cut(v["proto"], "/"); found {
		e.Proto = p
	}
	e.CVEs = cvesIn(name)
	return e, true
}

// parseMeraki reads a Meraki MX IDS alert ("security_event ids_alerted" and the older "ids-alerts"): signature=gid:sid:rev,
// priority, protocol, src and dst as ip:port, and the rule name after "message: ".
func parseMeraki(line string) (Event, bool) {
	i := strings.Index(line, " security_event ids_alerted ")
	skip := len(" security_event ids_alerted ")
	if i < 0 {
		i, skip = strings.Index(line, " ids-alerts "), len(" ids-alerts ")
	}
	if i < 0 {
		return Event{}, false
	}
	rest := line[i+skip:]
	text := ""
	if j := strings.Index(rest, " message: "); j >= 0 {
		rest, text = rest[:j], strings.TrimSpace(rest[j+len(" message: "):])
	}
	v, ok := fields(rest, "signature", "priority", "protocol", "src", "dst")
	if !ok {
		return Event{}, false
	}
	parts := strings.Split(v["signature"], ":")
	if len(parts) != 3 {
		return Event{}, false
	}
	id, okI := sid(parts[1])
	if _, okG := sid(parts[0]); !okG || !okI || id < 0 {
		return Event{}, false
	}
	e := Event{Profile: "meraki", SID: id, Signature: text}
	if e.Signature == "" {
		e.Signature = "Rule " + v["signature"]
	}
	if p, _, found := strings.Cut(v["protocol"], "/"); found {
		e.Proto = p
	}
	var okS, okD, okR bool
	e.Src, _, okS = endpoint(v["src"], false)
	e.Dst, e.DstPort, okD = endpoint(v["dst"], false)
	e.Priority, okR = snortPriority(v["priority"])
	if !okS || !okD || !okR {
		return Event{}, false
	}
	e.CVEs = cvesIn(text)
	return e, true
}

// ---- Palo Alto THREAT (CSV) ----

// csvFields splits one CSV line (fields in double quotes may hold commas; "" is a quote). ok is false for an unclosed quote, a quote
// glued to more text, or more than maxCSVFields fields.
func csvFields(s string) ([]string, bool) {
	var out []string
	for i := 0; i <= len(s); {
		if len(out) == maxCSVFields {
			return nil, false
		}
		if i < len(s) && s[i] == '"' {
			var b strings.Builder
			j := i + 1
			for {
				if j >= len(s) {
					return nil, false
				}
				if s[j] == '"' {
					if j+1 < len(s) && s[j+1] == '"' {
						b.WriteByte('"')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, b.String())
			j++
			if j < len(s) && s[j] != ',' {
				return nil, false
			}
			i = j + 1
			continue
		}
		j := strings.IndexByte(s[i:], ',')
		if j < 0 {
			j = len(s) - i
		}
		f := s[i : i+j]
		if strings.IndexByte(f, '"') >= 0 {
			return nil, false
		}
		out = append(out, f)
		i += j + 1
	}
	return out, true
}

var panThreatID = regexp.MustCompile(`^(.{1,400}?)\s?\((\d{1,12})\)$`)

// parsePaloAlto reads a PAN-OS THREAT log of subtype vulnerability (exploit attempts) or spyware (command and control). Field positions
// (1-based) of the syslog format: 4 type, 5 subtype, 8 source, 9 destination, 26 destination port, 30 protocol, 33 threat
// name(id), 35 severity.
func parsePaloAlto(msg string) (Event, bool) {
	f, ok := csvFields(msg)
	if !ok || len(f) < 36 || f[3] != "THREAT" || f[4] != "vulnerability" && f[4] != "spyware" {
		return Event{}, false
	}
	e := Event{Profile: "paloalto", Category: f[4], Proto: f[29]}
	m := panThreatID.FindStringSubmatch(f[32])
	if m == nil {
		return Event{}, false
	}
	e.Signature = m[1]
	var okI, okS, okD, okP, okR bool
	e.SID, okI = sid(m[2])
	e.Src, okS = addr(f[7])
	e.Dst, okD = addr(f[8])
	e.DstPort, okP = port(f[25])
	e.Priority, okR = levelPriority(f[34])
	if !okI || !okS || !okD || !okP || !okR {
		return Event{}, false
	}
	e.CVEs = cvesIn(m[1])
	return e, true
}

// ---- Suricata and Snort ----

// snortLine is the alert line Suricata (alert-syslog, fast.log) and Snort write: an optional fast.log time and [Drop]/[wDrop] mark,
// [gid:sid:rev], the rule message, an optional classification, the priority, {PROTO} and source -> destination. Every part is bounded.
var snortLine = regexp.MustCompile(`^(?:\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{1,6} {1,2})?(?:\[w?Drop\] )?(?:\[\*\*\] )?\[(\d{1,10}):(\d{1,10}):(\d{1,10})\] (.{1,600}?) (?:\[\*\*\] )?(?:\[Classification: ([^\]]{0,160})\] )?\[Priority: (\d{1,3})\] \{([A-Za-z0-9-]{1,16})\} ([0-9A-Fa-f:.\[\]]{2,60}) -> ([0-9A-Fa-f:.\[\]]{2,60})$`)

// parseSuricataFamily reads the lines of the suricata and snort programs: the alert line, or (Suricata) an EVE JSON alert record.
func parseSuricataFamily(env listen.Envelope) (Event, bool) {
	app := strings.ToLower(env.App)
	if app != "suricata" && app != "snort" {
		return Event{}, false
	}
	msg := strings.TrimSpace(env.Msg)
	if app == "suricata" && strings.HasPrefix(msg, "{") {
		return parseEVE(msg)
	}
	m := snortLine.FindStringSubmatch(msg)
	if m == nil {
		return Event{}, false
	}
	e := Event{Profile: app, Signature: m[4], Category: m[5], Proto: strings.ToLower(m[7])}
	if e.Category == "(null)" {
		e.Category = ""
	}
	var okI, okR bool
	e.SID, okI = sid(m[2])
	e.Priority, okR = snortPriority(m[6])
	icmp := e.Proto == "icmp" || e.Proto == "ipv6-icmp"
	src, _, okS := suricataEndpoint(m[8], icmp, app)
	dst, dport, okD := suricataEndpoint(m[9], icmp, app)
	if !okI || !okR || !okS || !okD {
		return Event{}, false
	}
	e.Src, e.Dst, e.DstPort = src, dst, dport
	e.CVEs = cvesIn(m[4])
	return e, true
}

// suricataEndpoint reads an endpoint of the alert line. Suricata always writes address:port with the IPv6 address unbracketed (the ICMP
// type in the port's place); Snort writes ICMP endpoints without a port and may bracket IPv6. The port of an ICMP endpoint is no port.
func suricataEndpoint(s string, icmp bool, app string) (netip.Addr, int, bool) {
	if icmp && app == "snort" {
		if a, ok := addr(s); ok {
			return a, -1, true
		}
	}
	a, p, ok := endpoint(s, false)
	if !ok {
		return netip.Addr{}, 0, false
	}
	if icmp {
		p = -1
	} else if p < 0 { // TCP or UDP with no port: not the line's shape
		return netip.Addr{}, 0, false
	}
	return a, p, true
}

// eveAlert is the part of a Suricata EVE alert record that is read.
type eveAlert struct {
	EventType string          `json:"event_type"`
	SrcIP     string          `json:"src_ip"`
	DestIP    string          `json:"dest_ip"`
	DestPort  json.RawMessage `json:"dest_port"`
	Proto     string          `json:"proto"`
	Alert     *struct {
		SignatureID json.RawMessage `json:"signature_id"`
		Signature   string          `json:"signature"`
		Category    string          `json:"category"`
		Severity    json.RawMessage `json:"severity"`
		Metadata    struct {
			CVE []string `json:"cve"`
		} `json:"metadata"`
	} `json:"alert"`
}

// parseEVE reads a Suricata EVE JSON alert record sent over syslog (OPNsense, and Suricata's eve-log with filetype syslog).
func parseEVE(msg string) (Event, bool) {
	var r eveAlert
	if err := json.Unmarshal([]byte(msg), &r); err != nil || r.EventType != "alert" || r.Alert == nil {
		return Event{}, false
	}
	e := Event{Profile: "suricata_eve", Signature: r.Alert.Signature, Category: r.Alert.Category, Proto: strings.ToLower(r.Proto)}
	var okS, okD, okP, okI, okR bool
	e.Src, okS = addr(r.SrcIP)
	e.Dst, okD = addr(r.DestIP)
	e.DstPort, okP = port(string(r.DestPort))
	e.SID, okI = sid(string(r.Alert.SignatureID))
	e.Priority, okR = snortPriority(string(r.Alert.Severity))
	if !okS || !okD || !okP || !okI || !okR || len(r.Alert.Metadata.CVE) > MaxCVEs*4 {
		return Event{}, false
	}
	if e.Proto == "icmp" || e.Proto == "ipv6-icmp" {
		e.DstPort = -1
	}
	e.CVEs = cvesIn(append([]string{r.Alert.Signature}, r.Alert.Metadata.CVE...)...)
	return e, true
}
