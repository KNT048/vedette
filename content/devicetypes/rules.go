package devicetypes

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

//go:embed rules.json
var rulesJSON []byte

// Facts is what Vedette already holds about a device, the input of Identify. Everything in it came from the network: untrusted text,
// only matched and quoted, never run or parsed further.
type Facts struct {
	IP             string // dotted IPv4, "" when unknown
	MAC            string // lower case aa:bb:cc:dd:ee:ff, "" when unknown
	Vendor         string // the folded make: a network card maker from the OUI table or nmap, or the make an agent or person gave
	VendorFromCard bool   // Vendor is the network card maker (passive or nmap), not the device's make
	Hostname       string
	Model          string
	OS             string
	Gateway        bool // the box's default gateway is this device's IP
	Services       []Service
}

// Service is one open port of the device and what it said.
type Service struct {
	Port    int
	Proto   string // tcp or udp; only tcp ports count for ports rules
	Name    string // nmap's service name ("ssh", "rtsp")
	Product string
	Detail  string // nmap extra info, its device type, the page title, the certificate subject (D-511)
}

// Guess is what a rule concluded: a type a person may confirm. It is never a kind (D-511): it changes no behaviour.
type Guess struct {
	Type       string  `json:"kind"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`        // one sentence: what matched and what that most likely means
	Model      string  `json:"model,omitempty"` // a model a certificate or page title states ("FortiGate 60F")
	// Alternatives are the other types the same signals fit (a Fortinet card: an access point or a switch), offered next to the
	// guess so confirming it is a choice, not a default (#714 review: a fragile access point is not silently made a firewall).
	Alternatives []string `json:"alternatives,omitempty"`
	Rule         string   `json:"-"`
}

type rule struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Confidence float64  `json:"confidence"`
	Vendor     []string `json:"vendor"`     // lower-case pieces of the make; any one
	MACPrefix  []string `json:"mac_prefix"` // aa:bb:cc; any one
	PortsAny   []int    `json:"ports_any"`  // open tcp ports; any one
	PortsAll   []int    `json:"ports_all"`  // open tcp ports; every one
	Text       string   `json:"text"`       // regexp over what one service said (product, detail)
	Hostname   string   `json:"hostname"`   // regexp
	Model      string   `json:"model"`      // regexp over the model
	OS         string   `json:"os"`         // regexp
	Gateway    bool     `json:"gateway"`
	LastOctet  []int    `json:"last_octet"`
	ModelFrom  *struct {
		Re     string `json:"re"`     // regexp with one group over what a service said
		Format string `json:"format"` // "{1}" is the group
	} `json:"model_from"`
	Says         string   `json:"says"`
	Alternatives []string `json:"alternatives"`

	text, hostname, model, os, modelFrom *regexp.Regexp
}

var rules []rule

func init() {
	var list []rule
	if err := json.Unmarshal(rulesJSON, &list); err != nil {
		panic("devicetypes: rules.json: " + err.Error()) // our own file, checked by a test
	}
	for i := range list {
		r := &list[i]
		var err error
		compile := func(dst **regexp.Regexp, src string) {
			if src != "" && err == nil {
				*dst, err = regexp.Compile(src)
			}
		}
		compile(&r.text, r.Text)
		compile(&r.hostname, r.Hostname)
		compile(&r.model, r.Model)
		compile(&r.os, r.OS)
		if r.ModelFrom != nil {
			compile(&r.modelFrom, r.ModelFrom.Re)
		}
		if err != nil {
			panic(fmt.Sprintf("devicetypes: rule %s: %v", r.ID, err))
		}
	}
	rules = list
}

// Identify applies the rules in order and returns the first that matches (D-511). ok is false when none does: Vedette then says
// nothing rather than guess from too little.
func Identify(f Facts) (Guess, bool) {
	open := map[int]string{}
	for _, s := range f.Services {
		if s.Proto == "tcp" {
			open[s.Port] = s.Name
		}
	}
	for i := range rules {
		if g, ok := rules[i].apply(f, open); ok {
			return g, true
		}
	}
	return Guess{}, false
}

func (r *rule) apply(f Facts, open map[int]string) (Guess, bool) {
	var why []string
	if r.Gateway {
		if !f.Gateway {
			return Guess{}, false
		}
		why = append(why, "it is the box's default gateway")
	}
	if len(r.Vendor) > 0 {
		v := strings.ToLower(f.Vendor)
		if v == "" || !slices.ContainsFunc(r.Vendor, func(p string) bool { return strings.Contains(v, p) }) {
			return Guess{}, false
		}
		if f.VendorFromCard {
			why = append(why, shortVendor(f.Vendor)+" network card")
		} else {
			why = append(why, "made by "+shortVendor(f.Vendor))
		}
	}
	if len(r.MACPrefix) > 0 {
		i := slices.IndexFunc(r.MACPrefix, func(p string) bool { return f.MAC != "" && strings.HasPrefix(f.MAC, p) })
		if i < 0 {
			return Guess{}, false
		}
		why = append(why, "MAC address starting "+r.MACPrefix[i])
	}
	var ports []int
	if len(r.PortsAny) > 0 {
		for _, p := range r.PortsAny {
			if _, ok := open[p]; ok {
				ports = append(ports, p)
			}
		}
		if len(ports) == 0 {
			return Guess{}, false
		}
	}
	for _, p := range r.PortsAll {
		if _, ok := open[p]; !ok {
			return Guess{}, false
		}
		if !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	if len(ports) > 0 {
		slices.Sort(ports)
		why = append(why, portWords(ports, open))
	}
	if r.text != nil {
		port, hit := 0, ""
		for _, s := range f.Services {
			if m := r.text.FindString(s.Product + " " + s.Detail); m != "" {
				port, hit = s.Port, m
				break
			}
		}
		if hit == "" {
			return Guess{}, false
		}
		why = append(why, fmt.Sprintf("port %d says %q", port, clip(strings.TrimSpace(hit), 60)))
	}
	for _, c := range []struct {
		re         *regexp.Regexp
		val, words string
	}{{r.hostname, f.Hostname, "host name"}, {r.model, f.Model, "model"}, {r.os, f.OS, "operating system"}} {
		if c.re == nil {
			continue
		}
		if c.val == "" || !c.re.MatchString(c.val) {
			return Guess{}, false
		}
		why = append(why, fmt.Sprintf("%s %q", c.words, clip(c.val, 60)))
	}
	if len(r.LastOctet) > 0 {
		dot := strings.LastIndexByte(f.IP, '.')
		n, err := strconv.Atoi(f.IP[dot+1:])
		if dot < 0 || err != nil || !slices.Contains(r.LastOctet, n) {
			return Guess{}, false
		}
		why = append(why, "address ending in ."+strconv.Itoa(n))
	}
	if len(why) == 0 { // a rule with no condition would match everything; the file test refuses one, this is the second guard
		return Guess{}, false
	}
	g := Guess{Type: r.Type, Confidence: r.Confidence, Rule: r.ID, Evidence: sentence(why) + ": " + r.Says + ".", Alternatives: r.Alternatives}
	if r.modelFrom != nil {
		for _, s := range f.Services {
			if m := r.modelFrom.FindStringSubmatch(s.Product + " " + s.Detail); len(m) > 1 && m[1] != "" {
				g.Model = strings.ReplaceAll(r.ModelFrom.Format, "{1}", m[1])
				break
			}
		}
	}
	return g, true
}

// portWords says "port 22 (ssh)" or "ports 554 (rtsp) and 8000 (http-alt)".
func portWords(ports []int, open map[int]string) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
		if n := open[p]; n != "" {
			parts[i] += " (" + clip(n, 20) + ")"
		}
	}
	if len(parts) == 1 {
		return "port " + parts[0]
	}
	return "ports " + sentence(parts)
}

// sentence joins "a", "b", "c" as "a, b and c", the first letter in upper case.
func sentence(parts []string) string {
	s := parts[0]
	if len(parts) > 1 {
		s = strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
	r, n := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r)) + s[n:]
}

// shortVendor drops the company form: "Fortinet, Inc." -> "Fortinet", "Sichuan AI-Link Technology Co., Ltd." -> "Sichuan AI-Link
// Technology".
func shortVendor(v string) string {
	v, _, _ = strings.Cut(v, ",")
	for _, s := range []string{" Co.", " Inc.", " Ltd.", " Corp.", " Corporation", " Inc"} {
		v = strings.TrimSuffix(v, s)
	}
	return clip(strings.TrimSpace(v), 40)
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
