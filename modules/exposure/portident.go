package exposure

import (
	"regexp"
	"slices"
	"strings"
)

// M2-7 (J6, S-EXP-2): each open port says how its service was named, so the page never shows nmap's usual service of a port number
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

// identOf is how one service row named its service. A row of a snapshot from before M2-7 has no method: "" unless it names nothing.
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
			ports[i].CertNames, ports[i].Title, ports[i].Server = h.CertNames, h.Title, h.Server
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
}

var (
	certCN  = regexp.MustCompile(`(?m)^Subject: .*?commonName=([^/\n]+)`)
	certSAN = regexp.MustCompile(`(?m)^Subject Alternative Name: (.+)$`)
)

// scriptHints reads ssl-cert (the subject's common name and the DNS names of the alternative names), http-title (the first line,
// unless nmap says the page has none or it did not follow a redirect) and http-server-header (the first line) on the ports of ip.
func scriptHints(scripts []ScriptRow, ip string) map[int]portHints {
	out := map[int]portHints{}
	for _, s := range scripts {
		if s.IP != ip || s.Port < 1 {
			continue
		}
		h := out[s.Port]
		switch s.ID {
		case "ssl-cert":
			h.CertNames = certNames(s.Output)
		case "http-title":
			if t := firstLine(s.Output); !strings.HasPrefix(t, "Site doesn't have a title") && !strings.HasPrefix(t, "Did not follow redirect") {
				h.Title = field(t, maxHint)
			}
		case "http-server-header":
			h.Server = field(firstLine(s.Output), maxHint)
		default:
			continue
		}
		out[s.Port] = h
	}
	return out
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

// sanitizePortIdent copies the M2-7 fields of p onto the sanitized row: a known Ident only, printable hints within their limits.
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
	row.Title, row.Server = field(p.Title, maxHint), field(p.Server, maxHint)
	return row
}
