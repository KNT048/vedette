// Package adminpages is the one table of admin and VPN pages Vedette recognises on the Internet (S-EXP-1): the network
// appliances that are attacked first (firewalls, VPN gateways, routers), and the admin pages of storage, servers and tools. The
// scan module's surface scan applies it to the page its GET of / read (title, Server header, body, redirect, a few headers, the
// certificate), and exposure applies it to what a deep scan read on any port (certificate names, page title, Server header,
// redirect, the product and CPE of service identification). Knowledge about products is data: adminpages.json, each row with its
// source. Everything it reads came from the target: untrusted text, only matched (RE2, linear time), never run.
package adminpages

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed adminpages.json
var data []byte

// The kinds of evidence a page states about itself, strongest first.
const (
	EvCert     = "certificate" // a name of its TLS certificate, matched whole
	EvTitle    = "title"       // its page title
	EvServer   = "server"      // its HTTP Server header
	EvRedirect = "redirect"    // where its first page sends the browser
	EvBody     = "body"        // a marker of its page (surface scan only)
	EvHeader   = "header"      // a header only that product sends (surface scan only)
	EvProduct  = "product"     // the product, CPE or extra information service identification read, or the name a scan gave it
)

// Family is an appliance family: the inventory devices that are one (Device over their vendor, model and OS; KevKeys, the KEV
// vendor|product pairs of its own operating system, never one a client of the same vendor shares). SharedVPN: one certificate,
// Server header or product name serves both its admin page and its VPN portal.
type Family struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Vendor    string   `json:"vendor"`
	SharedVPN bool     `json:"shared_vpn"`
	KevKeys   []string `json:"kev_keys"`
	DeviceRe  string   `json:"device"`
	// Kinds are the device types a device of the family can be (a firewall, a router, a VPN gateway; a switch for Juniper): a
	// switch, an access point or a NAS of the same vendor is not the family's appliance.
	Kinds []string `json:"kinds"`
	// NotWebPorts are ports where the family's certificate answers a protocol that is no web page (FortiGate's FGFM on 541).
	NotWebPorts  []int  `json:"not_web_ports"`
	NotWebSource string `json:"not_web_source"`
	Device       *regexp.Regexp
}

// Fingerprint is one product's page. Admin false is a VPN portal: it faces the Internet by design, it names the port but is not an
// admin page. Danger: close it now; otherwise restrict it by address.
type Fingerprint struct {
	Product  string   `json:"product"`
	FamilyID string   `json:"family"`
	Admin    bool     `json:"admin"`
	Danger   bool     `json:"danger"`
	TitleRe  string   `json:"title"`       // a title only that product has: enough by itself
	TitleLog string   `json:"title_login"` // a word that names the product only on a sign-in page (the title also has a sign-in word)
	BrandRe  string   `json:"brand"`       // an appliance word an ordinary site also uses: counts only on its sign-in page or a title that is little more than it
	ServerRe string   `json:"server"`      // over the Server header
	BodyRe   string   `json:"body"`        // over the first page
	LocRe    string   `json:"location"`    // over the redirect target
	Headers  []string `json:"header"`      // a header only that product sends (lower case)
	CertRe   string   `json:"cert"`        // over one whole certificate name
	ProdRe   string   `json:"product_re"`  // over a product, CPE or extra information
	Source   string   `json:"source"`
	Family   *Family

	title, titleLog, brand, server, body, loc, cert, prod *regexp.Regexp
}

// Page is what a scan read on one port. Any field may be empty.
type Page struct {
	Title, Server, Body, Location string
	Headers                       map[string]bool // lower-case names of the headers that were present
	CertNames                     []string        // subject common name and DNS alternative names
	Products                      []string        // service identification's product, CPE and extra information, or a scan's product name
}

// Match is the fingerprint a page matched and the evidence that did.
type Match struct {
	*Fingerprint
	Evidence string
}

var (
	families     []Family
	fingerprints []Fingerprint
	loadErr      error
)

func init() { families, fingerprints, loadErr = load(data) }

func load(b []byte) ([]Family, []Fingerprint, error) {
	var f struct {
		Families     []Family      `json:"families"`
		Fingerprints []Fingerprint `json:"fingerprints"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("adminpages.json: %w", err)
	}
	byID := map[string]*Family{}
	for i := range f.Families {
		fam := &f.Families[i]
		re, err := regexp.Compile("(?i)" + fam.DeviceRe)
		if err != nil {
			return nil, nil, fmt.Errorf("adminpages.json: family %q: device pattern: %w", fam.ID, err)
		}
		if fam.ID == "" || fam.Name == "" || byID[fam.ID] != nil {
			return nil, nil, fmt.Errorf("adminpages.json: family %q: no id or name, or the id twice", fam.ID)
		}
		fam.Device = re
		byID[fam.ID] = fam
	}
	for i := range f.Fingerprints {
		fp := &f.Fingerprints[i]
		var err error
		compile := func(dst **regexp.Regexp, src string) {
			if src != "" && err == nil {
				*dst, err = regexp.Compile(src)
			}
		}
		compile(&fp.title, fp.TitleRe)
		compile(&fp.titleLog, fp.TitleLog)
		compile(&fp.brand, fp.BrandRe)
		compile(&fp.server, fp.ServerRe)
		compile(&fp.body, fp.BodyRe)
		compile(&fp.loc, fp.LocRe)
		compile(&fp.cert, fp.CertRe)
		compile(&fp.prod, fp.ProdRe)
		if err != nil {
			return nil, nil, fmt.Errorf("adminpages.json: %s: %w", fp.Product, err)
		}
		if fp.Product == "" || fp.Source == "" {
			return nil, nil, fmt.Errorf("adminpages.json: a fingerprint has no product or no source")
		}
		if fp.FamilyID != "" {
			if fp.Family = byID[fp.FamilyID]; fp.Family == nil {
				return nil, nil, fmt.Errorf("adminpages.json: %s: unknown family %q", fp.Product, fp.FamilyID)
			}
		}
	}
	return f.Families, f.Fingerprints, nil
}

// Err is the error of reading the table; TestTable fails on it (the table is ours).
func Err() error { return loadErr }

// Families lists the appliance families.
func Families() []Family { return families }

// Fingerprints lists the fingerprints in the order they are tried.
func Fingerprints() []Fingerprint { return fingerprints }

// ByProduct is the fingerprint a scan named a port with ("FortiGate", "Fortinet SSL VPN"), or nil.
func ByProduct(name string) *Fingerprint {
	for i := range fingerprints {
		if strings.EqualFold(fingerprints[i].Product, name) {
			return &fingerprints[i]
		}
	}
	return nil
}

// Identify returns the first fingerprint that the page matches, with the evidence. The VPN portals come first in the table, so a
// port that states it is a family's VPN portal by any of its statements (its redirect to /remote/login) is that portal even when its
// certificate names the family.
func Identify(p Page) (Match, bool) {
	p = lower(p)
	for i := range fingerprints {
		if ev := fingerprints[i].match(p); ev != "" {
			return Match{Fingerprint: &fingerprints[i], Evidence: ev}, true
		}
	}
	return Match{}, false
}

func lower(p Page) Page {
	p.Title = strings.Join(strings.Fields(strings.ToLower(p.Title)), " ")
	p.Server, p.Body, p.Location = strings.ToLower(p.Server), strings.ToLower(p.Body), strings.ToLower(p.Location)
	names := make([]string, 0, len(p.CertNames))
	for _, n := range p.CertNames {
		names = append(names, strings.ToLower(strings.TrimSpace(n)))
	}
	p.CertNames = names
	prods := make([]string, 0, len(p.Products))
	for _, n := range p.Products {
		prods = append(prods, strings.ToLower(strings.TrimSpace(n)))
	}
	p.Products = prods
	return p
}

func (f *Fingerprint) match(p Page) string {
	if f.cert != nil {
		for _, n := range p.CertNames {
			if f.cert.MatchString(n) {
				return EvCert
			}
		}
	}
	if p.Title != "" && (f.title != nil && f.title.MatchString(p.Title) || f.titleLog != nil && f.titleLog.MatchString(p.Title) && Loginish(p.Title) ||
		f.brand != nil && f.brandTitle(p.Title)) {
		return EvTitle
	}
	if f.server != nil && p.Server != "" && f.server.MatchString(p.Server) {
		return EvServer
	}
	if f.loc != nil && p.Location != "" && f.loc.MatchString(p.Location) {
		return EvRedirect
	}
	if f.body != nil && p.Body != "" && f.body.MatchString(p.Body) {
		return EvBody
	}
	for _, h := range f.Headers {
		if p.Headers[h] {
			return EvHeader
		}
	}
	for _, s := range p.Products {
		if s != "" && (strings.EqualFold(s, f.Product) || f.prod != nil && f.prod.MatchString(s)) {
			return EvProduct
		}
	}
	return ""
}

// brandTitle: the title carries the appliance word and is its sign-in page, or has nothing else than host names, models or versions
// beside it ("fw01 - FortiGate"), so a shop, a review or a post that names the product ("FortiGate 60F price | Example Shop", "Best
// FortiGate", "How to install GlobalProtect") is not one.
func (f *Fingerprint) brandTitle(title string) bool {
	if !f.brand.MatchString(title) {
		return false
	}
	rest := f.brand.ReplaceAllString(title, " ")
	if signIn.MatchString(rest) {
		return true
	}
	for _, w := range wordRe.FindAllString(rest, -1) {
		if !strings.ContainsAny(w, "0123456789.-_") {
			return false
		}
	}
	return true
}

var (
	// loginWords are the surface scan's words of a page about signing in to a device (any part of the title, as it always matched).
	loginWords = []string{"login", "log in", "sign in", "router", "modem", "gateway", "wireless", "web management"}
	// signIn are the words of a sign-in page beside an appliance word: never one an appliance's own name or a shop uses ("gateway",
	// "router", "wireless").
	signIn = regexp.MustCompile(`\b(login|log in|logon|log on|sign in|signin|authentication|administration|portal)\b`)
	wordRe = regexp.MustCompile(`[a-z0-9][a-z0-9._-]+`)
)

// Loginish says whether a lower-case title is about signing in to a device.
func Loginish(t string) bool {
	for _, w := range loginWords {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}
