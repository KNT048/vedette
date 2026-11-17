package surface

import (
	"html"
	"regexp"
	"strings"

	"github.com/knt048/vedette/content/adminpages"
)

// page is what one GET of / returned, lower-cased for matching. All of it came from the target: untrusted (SYS-6).
type page struct {
	title    string // the <title>, unescaped, spaces collapsed
	server   string // the Server header
	body     string // the first maxPageBody bytes
	location string // the Location header of a redirect that was not followed
	header   map[string]bool
	// certNames are the subject common name and DNS names of the certificate the port showed (FortiGate's default certificate is
	// issued to "FortiGate" or its serial number).
	certNames []string
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// readTitle returns the title of an HTML page: unescaped, spaces collapsed, at most 200 characters.
func readTitle(body string) string {
	m := titleRE.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(m[1])), " ")
	if r := []rune(t); len(r) > 200 {
		t = string(r[:200])
	}
	return t
}

// identify names a product from its first page and its certificate through the shared table of admin and VPN pages
// (content/adminpages, which exposure applies to what a deep scan reads on any port too), or nil. A product whose fingerprint is
// not an admin page (a VPN portal) names the port but is not listed as one.
func identify(p page) *adminpages.Fingerprint {
	m, ok := adminpages.Identify(adminpages.Page{Title: p.title, Server: p.server, Body: p.body, Location: p.location, Headers: p.header, CertNames: p.certNames})
	if !ok {
		return nil
	}
	return m.Fingerprint
}
