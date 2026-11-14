package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/core/store"
)

// Passive web scan of the web ports of a verified target with the ZAP baseline (S-EXP-2, CONTRACT INV-24, D-562, plan
// exposure-real-vulns §5 slice c). ZAP runs in its own one-shot container with the spider and the passive rules only: no form is
// posted, no AJAX spider, no active scan. The container and its network are the host's (vedette-host op zap.baseline); exposure
// decides what to ask for (the web ports of a target that passed this run's gate), reads the report as untrusted data, and keeps
// the alerts apart from the exploited CVEs (a passive alert is something ZAP noticed, not a known exploited vulnerability).

// WebScanner runs ZAP's baseline scan against one URL and returns its JSON report (zap-baseline.py -J, at most MaxWebReport
// bytes). The scan calls it only for a web port of a target that passed the gate of that run (INV-1, INV-13): the IP target's own
// IP, or a name under a verified domain; url is that page, and t the target. The implementation keeps its own fences (the host
// checks again that the address is the box's own egress, or that the domain's TXT token is there) and writes every request to the
// probe log before it is sent (LEGAL §3). The report is untrusted. A step that could not run for a reason the page may show (not
// set up, busy, the image is not pulled) returns *Unavailable.
type WebScanner interface {
	Baseline(ctx context.Context, t ScanTarget, url string) (WebScan, error)
}

// WebScan is what one baseline run produced: ZAP's JSON report as it was written.
type WebScan struct {
	Report []byte
}

// Limits of the passive web scan (INV-24).
const (
	MaxWebReport = 4 << 20 // bytes of a ZAP report that are read; a bigger one is refused
	// MaxWebScans bounds the pages one scan hands to ZAP (each run takes up to 1 GiB and minutes: ponytail: four, then "not scanned"
	// lines; upgrade: a setting once the N100 measurement says how many fit).
	MaxWebScans    = 4
	WebScanTimeout = 8 * time.Minute // one page: the spider runs 1 minute and the passive rules wait at most 5 (-m 1 -T 5)

	maxWebFindings = 200 // rows kept per snapshot
	maxZapAlerts   = 500 // alerts one report may hold before it is refused
	maxWebURLs     = 3   // sample URLs kept per alert
	maxWebURL      = 300 // characters of a sample URL; longer is dropped
	maxWebName     = 120
	maxWebText     = 400
)

// The lines of the passive web scan under "Not checked" (INV-24).
const (
	// notSetUpWeb is the line of every scan while no WebScanner is wired (the ZAP container is not set up on this box).
	notSetUpWeb  = "Passive web scan (ZAP) is not set up on this box yet." //nolint:gosec // a sentence about the passive web scan, not a credential
	notWebNone   = "Passive web scan (ZAP): no web port was identified, so no page was scanned."
	notWebFail   = "Passive web scan (ZAP) failed, so the page was not checked. The box log has the error."
	notWebSlow   = "Passive web scan (ZAP) did not finish within 8 minutes, so the page was not checked."
	notWebUnread = "Passive web scan (ZAP) returned a report that could not be read, so the page was not checked."
	notWebNoPage = "ZAP reported no page at this address (no answer, a different protocol or a blocked request), so nothing was checked there."
)

// WebFindingRow is one ZAP alert on one scanned page (contract.ts WebFinding): a passive rule matched something in the responses.
// Risk is high, medium, low or info; Confidence is low, medium, high or confirmed (ZAP's own words). CWE is 0 when ZAP names none.
// URLs are at most maxWebURLs sample pages of the scanned site that showed it; Count is how many pages did.
type WebFindingRow struct {
	Site        string   `json:"site"`
	PluginID    string   `json:"plugin_id"`
	Name        string   `json:"name"`
	Risk        string   `json:"risk"`
	Confidence  string   `json:"confidence"`
	CWE         int      `json:"cwe"`
	Description string   `json:"description"`
	Solution    string   `json:"solution"`
	URLs        []string `json:"urls"`
	Count       int      `json:"count"`
}

var (
	zapRisks       = []string{"info", "low", "medium", "high"}                        // ZAP riskcode 0..3
	zapConfidences = []string{"false_positive", "low", "medium", "high", "confirmed"} // ZAP confidence 0..4
)

// ErrBadReport says the report is not one this parser reads. The scan says it could not read it; it never reads as "no alerts".
var ErrBadReport = errors.New("exposure: unreadable ZAP report")

// ErrNoPage says the report has no entry for the scanned address, so ZAP saw no page there.
var ErrNoPage = errors.New("exposure: ZAP reported no page at the scanned address")

// zapNum is a number as ZAP prints it: a JSON string of digits ("2") or a JSON number. Anything else (a float, null, text) is refused.
type zapNum int

func (n *zapNum) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		var err error
		if s, err = strconv.Unquote(s); err != nil {
			return ErrBadReport
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < -1 || v > 1<<30 {
		return ErrBadReport
	}
	*n = zapNum(v)
	return nil
}

type zapReport struct {
	Site *[]struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID   *zapNum `json:"pluginid"`
			Alert      string  `json:"alert"`
			Name       string  `json:"name"`
			RiskCode   *zapNum `json:"riskcode"`
			Confidence *zapNum `json:"confidence"`
			CWE        zapNum  `json:"cweid"`
			Desc       string  `json:"desc"`
			Solution   string  `json:"solution"`
			Instances  []struct {
				URI string `json:"uri"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// ParseZAPReport reads a ZAP baseline JSON report (zap-baseline.py -J) of a scan of page. The report is untrusted (rules/security.md):
// a bigger one than MaxWebReport, one that is not JSON of the expected shape, a risk or confidence that is not ZAP's, or more than
// maxZapAlerts alerts is refused as ErrBadReport, never read as "no alerts". Unknown fields are ignored. Only the site entry of the
// scanned address counts (ZAP lists every host it saw); a report without one is ErrNoPage. Text is stripped of markup, printable
// only and clipped; a sample URL that is not http(s) on the scanned host is dropped.
func ParseZAPReport(raw []byte, page string) ([]WebFindingRow, error) {
	if len(raw) == 0 || len(raw) > MaxWebReport {
		return nil, fmt.Errorf("%w: %d bytes", ErrBadReport, len(raw))
	}
	var rep zapReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadReport, err)
	}
	if rep.Site == nil {
		return nil, fmt.Errorf("%w: no site list", ErrBadReport)
	}
	want, ok := pageKey(page)
	if !ok {
		return nil, fmt.Errorf("%w: scanned address %q", ErrBadReport, page)
	}
	rows, alerts, matched := []WebFindingRow{}, 0, false
	for _, site := range *rep.Site {
		if k, ok := pageKey(site.Name); !ok || k != want {
			continue
		}
		matched = true
		for _, a := range site.Alerts {
			if alerts++; alerts > maxZapAlerts {
				return nil, fmt.Errorf("%w: more than %d alerts", ErrBadReport, maxZapAlerts)
			}
			if a.PluginID == nil || a.RiskCode == nil || a.Confidence == nil || *a.RiskCode < 0 || int(*a.RiskCode) >= len(zapRisks) || *a.PluginID < 0 ||
				*a.Confidence < 0 || int(*a.Confidence) >= len(zapConfidences) {
				return nil, fmt.Errorf("%w: an alert without a plugin id, or with a risk or confidence that is not ZAP's", ErrBadReport)
			}
			if *a.Confidence == 0 { // ZAP's "false positive": the rule itself says it is not a finding
				continue
			}
			name := a.Name
			if name == "" {
				name = a.Alert
			}
			urls, seen := []string{}, map[string]bool{}
			for _, in := range a.Instances {
				if u, ok := sampleURL(in.URI, want); ok && !seen[u] {
					seen[u] = true
					if len(urls) < maxWebURLs {
						urls = append(urls, u)
					}
				}
			}
			cwe := int(a.CWE)
			if cwe < 0 {
				cwe = 0
			}
			row, ok := cleanWebRow(WebFindingRow{Site: page, PluginID: strconv.Itoa(int(*a.PluginID)), Name: plainText(name, maxWebName), Risk: zapRisks[*a.RiskCode],
				Confidence: zapConfidences[*a.Confidence], CWE: cwe, Description: plainText(a.Desc, maxWebText), Solution: plainText(a.Solution, maxWebText),
				URLs: urls, Count: len(a.Instances)})
			if !ok {
				return nil, fmt.Errorf("%w: an alert without a name", ErrBadReport)
			}
			rows = append(rows, row)
		}
	}
	if !matched {
		return nil, ErrNoPage
	}
	return rows, nil
}

// pageKey is scheme, lower-case host and effective port of an http(s) address: two spellings of the same page are equal.
func pageKey(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, true
}

// sampleURL keeps an instance address only when it is an http(s) page of the scanned site, printable and not longer than maxWebURL.
func sampleURL(raw, site string) (string, bool) {
	if utf8.RuneCountInString(raw) > maxWebURL || field(raw, maxWebURL) != raw {
		return "", false
	}
	if k, ok := pageKey(raw); !ok || k != site {
		return "", false
	}
	return raw, true
}

// plainText turns the HTML ZAP writes into text that cannot carry markup: tags removed, anything not printable replaced by a space,
// spaces collapsed, at most n characters (a cut text ends in an ellipsis).
func plainText(s string, n int) string {
	var b strings.Builder
	inTag := false
	for _, r := range strings.ToValidUTF8(s, "") {
		switch {
		case r == '<':
			inTag = true
			b.WriteByte(' ')
		case r == '>':
			inTag = false
			b.WriteByte(' ')
		case inTag:
		case unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(out); len(r) > n {
		out = strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return out
}

// cleanWebRow is the one check a web finding passes before it is stored (INV-10, INV-24); ok is false for a row that is not one.
func cleanWebRow(r WebFindingRow) (WebFindingRow, bool) {
	r.Name, r.PluginID = plainText(r.Name, maxWebName), field(r.PluginID, 12)
	r.Description, r.Solution = plainText(r.Description, maxWebText), plainText(r.Solution, maxWebText)
	if r.Name == "" || r.PluginID == "" || !slices.Contains(zapRisks, r.Risk) || !slices.Contains(zapConfidences[1:], r.Confidence) {
		return WebFindingRow{}, false
	}
	if _, ok := pageKey(r.Site); !ok || utf8.RuneCountInString(r.Site) > maxWebURL || field(r.Site, maxWebURL) != r.Site {
		return WebFindingRow{}, false
	}
	if r.CWE < 0 || r.CWE > 1<<20 {
		r.CWE = 0
	}
	site, _ := pageKey(r.Site)
	urls := []string{}
	for _, u := range r.URLs {
		if u, ok := sampleURL(u, site); ok && len(urls) < maxWebURLs && !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	r.URLs = urls
	r.Count = max(r.Count, len(urls))
	return r, true
}

// sanitizeWeb keeps the rows that pass cleanWebRow, the highest risk first, at most maxWebFindings.
func sanitizeWeb(in []WebFindingRow) []WebFindingRow {
	out := []WebFindingRow{}
	for _, r := range in {
		if r, ok := cleanWebRow(r); ok {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b WebFindingRow) int { return slices.Index(zapRisks, b.Risk) - slices.Index(zapRisks, a.Risk) })
	if len(out) > maxWebFindings {
		out = out[:maxWebFindings]
	}
	return out
}

// isWebService says nmap named a web service on the port (http, https, ssl/http, http-alt, https-alt; not an HTTP proxy).
func isWebService(name string) bool {
	n := strings.TrimPrefix(strings.ToLower(name), "ssl/")
	return strings.HasPrefix(n, "http") && n != "http-proxy"
}

// webURLs lists the pages of this scan's target a passive web scan may ask for, at most MaxWebScans, and how many it left out. Only
// the target of this run: an IP target's own IP on the web ports service identification read (INV-19), and, for a domain, its names
// (the domain itself or a name under it, pointing at a public address) on the ports 80 and 443 the surface scan found open. An
// address or name that is not one of these is never in the list, so a hostile report from the runner cannot widen it.
func webURLs(st ScanTarget, c Content) (urls []string, left int) {
	var all []string
	switch st.Kind {
	case KindIP:
		ip, err := netip.ParseAddr(st.Value)
		if err != nil {
			return nil, 0
		}
		rows := slices.Clone(c.Services)
		slices.SortStableFunc(rows, func(a, b ServiceRow) int { return a.Port - b.Port })
		for _, r := range rows {
			if a, err := netip.ParseAddr(r.IP); err == nil && a == ip && isWebService(r.Name) {
				all = append(all, pageURL(isTLSService(r), ip.String(), r.Port))
			}
		}
	case KindDomain:
		open := map[string]bool{}
		for _, p := range c.Ports {
			open[fmt.Sprintf("%s:%d", ipKey(p.IP), p.Port)] = true
		}
		for _, h := range c.Hosts {
			a, err := netip.ParseAddr(h.IP)
			name := strings.ToLower(h.Name)
			if err != nil || !egressip.IsPublicIPv4(a.Unmap()) || !domainRE.MatchString(name) || (name != st.Value && !strings.HasSuffix(name, "."+st.Value)) {
				continue
			}
			for _, port := range []int{443, 80} {
				if open[fmt.Sprintf("%s:%d", ipKey(h.IP), port)] {
					all = append(all, pageURL(port == 443, name, port))
				}
			}
		}
	}
	all = slices.Compact(all)
	if len(all) > MaxWebScans {
		return all[:MaxWebScans], len(all) - MaxWebScans
	}
	return all, 0
}

// isTLSService: nmap's "ssl/http" or "https" names, or the usual TLS web ports when the name does not say.
func isTLSService(r ServiceRow) bool {
	n := strings.ToLower(r.Name)
	return strings.HasPrefix(n, "ssl/") || strings.HasPrefix(n, "https") || r.Port == 443 || r.Port == 8443
}

func pageURL(tls bool, host string, port int) string {
	scheme, def := "http", 80
	if tls {
		scheme, def = "https", 443
	}
	if port == def {
		return scheme + "://" + host + "/"
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, port)
}

// webPassive is the web step of a scan (INV-24), after service identification and before the snapshot is stored: ZAP's baseline on
// each page webURLs lists, one after the other. Without a WebScanner the scan records notSetUpWeb. Like identify it ends the scan
// only when the run is stopped: a page that failed, was unavailable or whose report could not be read is a "Not checked" line, and
// the rest is kept. A report that could not be read is never "no alerts".
func (s *Service) webPassive(ctx context.Context, st ScanTarget, c Content) (Content, error) {
	if s.cfg.Web == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notSetUpWeb})
		return c, nil
	}
	urls, left := webURLs(st, c)
	if len(urls) == 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notWebNone})
		return c, nil
	}
	var scanned []string
	alerts := 0
	for _, page := range urls {
		wctx, cancel := context.WithTimeout(ctx, WebScanTimeout)
		res, err := s.cfg.Web.Baseline(wctx, st, page)
		slow := wctx.Err() != nil
		cancel()
		var un *Unavailable
		if err == nil {
			var rows []WebFindingRow
			switch rows, err = ParseZAPReport(res.Report, page); {
			case err == nil:
				c.WebFindings = append(c.WebFindings, rows...)
				scanned, alerts = append(scanned, page), alerts+len(rows)
				continue
			case errors.Is(err, ErrNoPage):
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page+": "+notWebNoPage, maxLineText)})
				continue
			default:
				s.cfg.Log.ErrorContext(ctx, "exposure: unreadable ZAP report", "target", st.Value, "page", page, "error", err)
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page+": "+notWebUnread, maxLineText)})
				continue
			}
		}
		switch {
		case ctx.Err() != nil: // the run was stopped: nothing is stored
			return c, err
		case errors.As(err, &un):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText("Passive web scan (ZAP) did not run: "+un.Reason, maxLineText)})
			return c, nil // the same reason holds for the other pages: one line
		case slow:
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page+": "+notWebSlow, maxLineText)})
		default:
			s.cfg.Log.ErrorContext(ctx, "exposure: passive web scan failed", "target", st.Value, "page", page, "error", err)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page+": "+notWebFail, maxLineText)})
		}
	}
	if left > 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: fmt.Sprintf("Passive web scan (ZAP): %s not scanned; at most %d pages are scanned in one scan.", plural(left, "more web port"), MaxWebScans)})
	}
	if len(scanned) > 0 {
		c.Checks = append(c.Checks, CheckRow{Kind: "web", At: store.FormatTS(s.clock()), Text: clipText(fmt.Sprintf(
			"Passive web scan (ZAP baseline: spider and passive rules, no form sent) of %s: %s. %s.", plural(len(scanned), "page"), strings.Join(scanned, ", "), plural(alerts, "alert")), maxLineText)})
	}
	return c, nil
}
