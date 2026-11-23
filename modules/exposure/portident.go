package exposure

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// S-EXP-2: each open port says how its service was named, so the page never shows nmap's usual service of a port number
// as if a probe had read it, and a port nothing identified says so, with what its certificate, page title or Server header said.

// The values of PortRow.Ident.
const (
	IdentProbed = "probed" // a probe's answer named the service (or the surface scan's GET read a Server header)
	IdentPort   = "port"   // only the usual service of the port number (nmap's method="table"): not confirmed
	IdentNone   = "none"   // nothing identified: nmap's "unknown", a bare TLS layer, or a port that closed at once (tcpwrapped)
)

const (
	maxCertNames = 5
	maxCertName  = 100
	maxHint      = 120
	maxLocation  = 200
)

// serviceMethod keeps nmap's two method words; anything else is "" (not known).
func serviceMethod(m string) string {
	if m == "probed" || m == "table" {
		return m
	}
	return ""
}

// baseService is a service name without the TLS layer: "ssl/http" → "http", "ssl" → "".
func baseService(name string) string {
	if name == "ssl" {
		return ""
	}
	return strings.TrimPrefix(name, "ssl/")
}

// serviceFamily is what two names have to share to name the same service: "https", "ssl/http" and "http" are one family.
func serviceFamily(name string) string {
	b := baseService(name)
	if b == "https" {
		return "http"
	}
	return b
}

// unnamed: nmap read no service on the port.
func unnamed(name string) bool {
	b := baseService(name)
	return b == "" || b == "unknown" || b == "tcpwrapped"
}

// identOf is how one service row named its service. A row of a snapshot from an older release has no method: "" unless it names nothing.
func identOf(r ServiceRow) string {
	switch {
	case unnamed(r.Name):
		return IdentNone
	case r.Method == "probed":
		return IdentProbed
	case r.Method == "table":
		return IdentPort
	}
	return ""
}

// identifyPorts sets Ident and the script hints on every row of ip that service identification read. The surface scan's own
// answer counts: a row whose GET read a product stays identified whatever nmap's table says. A name a probe read replaces the
// surface's port-list name when the two are not the same service, and a port nothing identified takes nmap's name ("unknown",
// "ssl/unknown", "tcpwrapped"), so the page does not keep the port list's guess.
func identifyPorts(ports []PortRow, services []ServiceRow, scripts []ScriptRow, ip string) []PortRow {
	svc := map[int]ServiceRow{}
	for _, r := range services {
		if r.IP == ip {
			svc[r.Port] = r
		}
	}
	hints := scriptHints(scripts, ip)
	for i, p := range ports {
		if ipKey(p.IP) != ip {
			continue
		}
		if h, ok := hints[p.Port]; ok {
			ports[i].CertNames, ports[i].Title, ports[i].Server, ports[i].Location = h.CertNames, h.Title, h.Server, h.Location
		}
		r, ok := svc[p.Port]
		if !ok {
			continue
		}
		id := identOf(r)
		switch {
		case p.Product != "" && r.Product == "" && (id == IdentPort || id == IdentNone):
			id = IdentProbed // the surface scan's GET read who answers; nmap's table name adds nothing
		case id == IdentNone:
			ports[i].Service = r.Name
		case id == IdentProbed && serviceFamily(r.Name) != serviceFamily(p.Service):
			ports[i].Service = r.Name
			if p.Product == "" { // the product follows the service the probe named, as on a row addServicePorts adds
				ports[i].Product = strings.TrimSpace(r.Product + " " + r.Version)
			}
		}
		if id == "" { // nmap gave no method word: the intake's mark (a port-number guess, or a product the GET read) stays
			id = p.Ident
		}
		ports[i].Ident = id
	}
	return ports
}

// portHints is what the scripts of a deep scan read on one port.
type portHints struct {
	CertNames []string
	Title     string
	Server    string
	Location  string // the redirect http-title did not follow
}

var (
	certCN  = regexp.MustCompile(`(?m)^Subject: .*?commonName=([^/\n]+)`)
	certSAN = regexp.MustCompile(`(?m)^Subject Alternative Name: (.+)$`)
)

// scriptHints reads ssl-cert (the subject's common name and the DNS names of the alternative names), http-title (the first line,
// unless nmap says the page has none; where it redirects when nmap did not follow it) and http-server-header (the first line) on the ports of ip.
func scriptHints(scripts []ScriptRow, ip string) map[int]portHints {
	out := map[int]portHints{}
	for _, s := range scripts {
		if s.IP != ip || s.Port < 1 {
			continue
		}
		h := out[s.Port]
		o := nmapText(s.Output)
		switch s.ID {
		case "ssl-cert":
			h.CertNames = certNames(o)
		case "http-title":
			t := firstLine(o)
			if to, ok := strings.CutPrefix(t, "Did not follow redirect to "); ok {
				h.Location = field(to, maxLocation)
			} else if !strings.HasPrefix(t, "Site doesn't have a title") {
				h.Title = field(t, maxHint)
			}
		case "http-server-header":
			h.Server = field(firstLine(o), maxHint)
		default:
			continue
		}
		out[s.Port] = h
	}
	return out
}

// nmapEscape is a byte nmap's script output escaped: it prints every byte outside printable ASCII as \xNN (a GitLab page
// title "Sign in \xC2\xB7 GitLab").
var nmapEscape = regexp.MustCompile(`(?:\\x[89A-Fa-f][0-9A-Fa-f])+`)

// nmapText decodes the \xNN runs of a script's output (bytes 0x80 and up: nmap prints the others as they are, so a literal "\x0A" in a
// title stays text) back to the UTF-8 the service sent; a byte that is not part of UTF-8 stays as nmap printed it. field still
// refuses control characters.
func nmapText(s string) string {
	return nmapEscape.ReplaceAllStringFunc(s, func(run string) string {
		b := make([]byte, 0, len(run)/4)
		for i := 0; i+4 <= len(run); i += 4 {
			v, _ := strconv.ParseUint(run[i+2:i+4], 16, 8)
			b = append(b, byte(v))
		}
		var out strings.Builder
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r == utf8.RuneError && n == 1 {
				fmt.Fprintf(&out, `\x%02X`, b[0])
			} else {
				out.WriteRune(r)
			}
			b = b[n:]
		}
		return out.String()
	})
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(s)
}

// certNames is the subject's common name, then the DNS names of the subject alternative names, each once, at most maxCertNames.
func certNames(out string) []string {
	var names []string
	add := func(n string) {
		if n = field(n, maxCertName); n != "" && !slices.Contains(names, n) && len(names) < maxCertNames {
			names = append(names, n)
		}
	}
	if m := certCN.FindStringSubmatch(out); m != nil {
		add(m[1])
	}
	if m := certSAN.FindStringSubmatch(out); m != nil {
		for _, part := range strings.Split(m[1], ",") {
			if n, ok := strings.CutPrefix(strings.TrimSpace(part), "DNS:"); ok {
				add(n)
			}
		}
	}
	return names
}

// sanitizePortIdent copies the identification fields of p onto the sanitized row: a known Ident only, printable hints within their limits.
func sanitizePortIdent(row, p PortRow) PortRow {
	switch p.Ident {
	case IdentProbed, IdentPort, IdentNone:
		row.Ident = p.Ident
	}
	for _, n := range p.CertNames {
		if n = field(n, maxCertName); n != "" && len(row.CertNames) < maxCertNames {
			row.CertNames = append(row.CertNames, n)
		}
	}
	row.Title, row.Server, row.Location = field(p.Title, maxHint), field(p.Server, maxHint), field(p.Location, maxLocation)
	return row
}

// serviceNames is a person's name for nmap's or the port list's service names. It is the same table as LABEL in
// web/src/features/exposure/services.ts (TestServiceNamesMatchThePage holds them together), so the alert and the page say one name.
var serviceNames = map[string]string{
	"microsoft-ds": "SMB", "netbios-ssn": "NetBIOS", "ms-sql": "SQL Server", "ms-sql-s": "SQL Server", "domain": "DNS", "postgresql": "PostgreSQL", "mysql": "MySQL",
	"mongodb": "MongoDB", "redis": "Redis", "winrm-https": "WinRM", "http-proxy": "HTTP proxy", "teamviewer": "TeamViewer", "radmin": "Radmin",
	"mikrotik-api": "MikroTik API", "mikrotik-api-ssl": "MikroTik API", "winbox": "Winbox", "jetdirect": "Printer", "dvr": "Camera recorder (DVR)",
	"cisco-sccp": "Cisco SCCP (IP phones)", "ms-wbt-server": "Remote Desktop (RDP)", "msrpc": "Windows RPC", "http-alt": "HTTP", "https-alt": "HTTPS",
	"ssl/http": "HTTPS", "ssl/https": "HTTPS", "ssl/http-alt": "HTTPS", "ssl/imap": "IMAPS", "ssl/pop3": "POP3S", "ssl/smtp": "SMTPS", "ssl/sip": "SIP over TLS",
	"ssl/ldap": "LDAPS", "vnc-http": "VNC web viewer", "upnp": "UPnP", "ipp": "Printer (IPP)", "rtsp": "RTSP (cameras)", "openvpn": "OpenVPN",
	"pptp": "PPTP VPN", "isakmp": "IPsec VPN", "bgp": "BGP",
}

// serviceName is the page's serviceName (services.ts): the table, else a short acronym upper-cased, "… over TLS" for a TLS layer.
func serviceName(service string) string {
	if n, ok := serviceNames[service]; ok {
		return n
	}
	base := strings.TrimPrefix(service, "ssl/")
	name, ok := serviceNames[base]
	if !ok {
		name = base
		if n := len(base); n >= 2 && n <= 6 && !strings.ContainsFunc(base, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
			name = strings.ToUpper(base)
		}
	}
	if base != service {
		name += " over TLS"
	}
	return name
}

// ServiceLabel is the port's service as a person reads it (the "New open port" alert's summary and the day comparison):
// "SIP", "HTTPS", "probably SIP" when only the port number names it, "service not identified" (or "TLS, service not identified")
// when nothing does.
func ServiceLabel(p PortRow) string {
	if p.Ident == IdentNone || unnamed(p.Service) {
		if p.Service == "ssl" || strings.HasPrefix(p.Service, "ssl/") || p.Service == "https" {
			return "TLS, service not identified"
		}
		return "service not identified"
	}
	if p.Ident == IdentPort {
		return "probably " + serviceName(p.Service)
	}
	return serviceName(p.Service)
}

// identifiedCounts is how many of the rows a probe named, how many only the port number named, how many nothing named, and how
// many were named without a product by a scan that did not record how (a row with no method word: a snapshot from an older release,
// or an older scanner). Such a row with a product, version or CPE was named by a probe (nmap's port table gives only the service
// name); one with a service name alone may be either, so it is counted apart and never as identified.
func identifiedCounts(rows []ServiceRow) (probed, port, none, unsure int) {
	for _, r := range rows {
		switch identOf(r) {
		case IdentPort:
			port++
		case IdentNone:
			none++
		case IdentProbed:
			probed++
		default:
			if r.Product != "" || r.Version != "" || r.CPE != "" {
				probed++
			} else {
				unsure++
			}
		}
	}
	return probed, port, none, unsure
}

// servicesRead is the count part of the "Service identification" line: "2 services identified, 2 named by port number only,
// 2 not identified".
func servicesRead(rows []ServiceRow) string {
	probed, guess, none, unsure := identifiedCounts(rows)
	read := plural(probed, "service") + " identified"
	if guess > 0 {
		read += fmt.Sprintf(", %d named by port number only", guess)
	}
	if unsure > 0 {
		read += fmt.Sprintf(", %d named without a product (the scan did not record whether by a probe or by the port number)", unsure)
	}
	if none > 0 {
		read += fmt.Sprintf(", %d not identified", none)
	}
	return read
}

// servicesLineRE is a stored "Service identification" line that has counts: an IP target's (the default scan's says "Port scan
// (nmap) of N TCP ports, then service identification (nmap -sV) of the open ones: "), or one address's of a domain's deep
// scan ("203.0.113.7 (www.example.com): " in front). Group 1 is the address of that prefix, group 2 the line up to the counts, group
// 4 what follows them (the deep scan's script results).
var servicesLineRE = regexp.MustCompile(`^(?:(\d{1,3}(?:\.\d{1,3}){3}) \([^)]*\): )?(Service identification \(nmap -sV\)(?: on \d+ TCP ports?)?: |Port scan \(nmap\) of \d+ TCP ports?, then service identification \(nmap -sV\) of the open ones: )(\d+ services? identified[^.]*)\.((?: nmap's scripts: .*)?)$`)

// keptServices is the "ip:port" of each service row an earlier scan kept (its port has LastSeen, INV-22): this scan did not read it.
func keptServices(snap Snapshot) map[string]bool {
	ports := map[string]bool{}
	for _, p := range snap.Ports {
		if p.LastSeen != "" {
			ports[fmt.Sprintf("%s:%d", ipKey(p.IP), p.Port)] = true
		}
	}
	kept := map[string]bool{}
	for _, r := range snap.Services {
		if k := fmt.Sprintf("%s:%d", ipKey(r.IP), r.Port); ports[k] {
			kept[k] = true
		}
	}
	return kept
}

// recountServices says the counts of each stored "Service identification" line again from the snapshot's stored rows, with today's
// classification (servicesRead): a snapshot stored before a port named by its number alone was told apart said "6 services
// identified" next to a comparison line that counts the same rows today, and the two must never disagree. Only the rows that
// step read count: of the line's address, without the rows an earlier scan kept (their port has LastSeen, INV-22).
func recountServices(snap *Snapshot) {
	kept := keptServices(*snap)
	for i, c := range snap.Checks {
		if c.Kind != "services" {
			continue
		}
		m := servicesLineRE.FindStringSubmatchIndex(c.Text)
		if m == nil {
			continue
		}
		ip := ""
		if m[2] >= 0 {
			ip = c.Text[m[2]:m[3]]
		}
		rows := []ServiceRow{}
		for _, r := range snap.Services {
			if (ip == "" || ipKey(r.IP) == ip) && !kept[fmt.Sprintf("%s:%d", ipKey(r.IP), r.Port)] {
				rows = append(rows, r)
			}
		}
		snap.Checks[i].Text = c.Text[:m[6]] + servicesRead(rows) + c.Text[m[7]:]
	}
}
