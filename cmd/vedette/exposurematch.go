package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
)

// exposureMatcher is exposure's Matcher (S-EXP-2, exposure INV-20, D-553): the services nmap -sV identified on the box's own public
// IP, matched by findings.MatchAsset against the CISA KEV list with the NVD version ranges the feeds keep, so exploited CVEs only.
// Nothing is stored: exposure calls it each time a snapshot is read, so a new KEV entry shows without a rescan. A service counts as
// compared only when the list has exploited CVEs under its CPE's vendor and product; otherwise it is Unlisted (nginx is
// "igor_sysoev:nginx" to nmap and "f5:nginx" to NVD today).
//
// A service is looked up by the CPE nmap printed. Its KEV keys come from the NVD configurations of the KEV entries themselves (a
// KEV entry whose NVD data names cpe:2.3:a:apache:http_server gives that CPE the key "apache|http server"), plus catalog when it
// is set: inventory's curated CPE to KEV keys (inventory.Service.KevKeysByCPE). Catalog keys count only when some entry of the list carries them, so a service is never "compared" against a product the list does not have (INV-20).
type exposureMatcher struct {
	vulns   func(ctx context.Context) ([]findings.Vuln, error)
	catalog func(ctx context.Context) func(cpe string) []string // inventory.Service.KevKeysByCPE, read once per Match; nil: the list's own CPEs only
	now     func() time.Time
}

// exposureVulns reads the list for exposureMatcher through the cached reader findings uses (findingsFeeds). The feeds module off is
// a reason the page shows; the list is then not read.
func exposureVulns(d deps) func(context.Context) ([]findings.Vuln, error) {
	cache := &vulnCache{}
	return func(ctx context.Context) ([]findings.Vuln, error) {
		if d.Reg != nil && !d.Reg.Enabled("feeds") {
			return nil, &exposure.Unavailable{Reason: "the Feeds module is off, so the list of exploited vulnerabilities is not kept. An admin can turn it on in Settings, Modules."}
		}
		svc, err := feedsService(d)
		if err != nil {
			return nil, err
		}
		return findingsFeeds{st: svc.Store(), cache: cache}.Vulns(ctx)
	}
}

func (m exposureMatcher) Match(ctx context.Context, svcs []exposure.ServiceRow) (exposure.Matches, error) {
	vulns, err := m.vulns(ctx)
	if err != nil {
		return exposure.Matches{}, err
	}
	byCPE := kevKeysByCPE(vulns)
	var lookup func(cpe string) []string
	var listed map[string]bool // the vendor|product keys the list carries
	if m.catalog != nil {
		lookup, listed = m.catalog(ctx), map[string]bool{}
		for _, v := range vulns {
			listed[findings.KevKey(v.Vendor, v.Product)] = true
		}
	}
	out := exposure.Matches{Vulns: []exposure.VulnRow{}, Gaps: []exposure.GapRow{}, Listed: len(vulns)}
	assets := map[string]*findings.Asset{} // one asset per IP, named by the IP: the sentence says "<ip> runs Apache httpd 2.4.49"
	var order []string
	where := map[string]exposure.ServiceRow{} // software id -> its service
	for _, s := range svcs {
		cpe := cpe23(s.CPE)
		if cpe == "" {
			continue
		}
		base := cpeBase(cpe)
		keys := byCPE[base]
		if lookup != nil {
			extra := slices.DeleteFunc(slices.Clone(lookup(s.CPE)), func(k string) bool { return !listed[k] }) // a new slice: byCPE's lists are shared
			keys = slices.Concat(keys, extra)
		}
		display := s.Product
		if display == "" {
			display = s.Name
		}
		if len(keys) == 0 { // no exploited CVE is listed under this name: nothing was compared, and the page says so
			out.Unlisted = append(out.Unlisted, fmt.Sprintf("%s (%s)", display, strings.SplitN(base, ":", 2)[1]))
			continue
		}
		out.Compared++
		a := assets[s.IP]
		if a == nil {
			a = &findings.Asset{ID: exposure.ScanIDPrefix + s.IP, Name: s.IP}
			assets[s.IP] = a
			order = append(order, s.IP)
		}
		id := fmt.Sprintf("%s:%d", s.IP, s.Port)
		where[id] = s
		a.Software = append(a.Software, findings.Software{ID: id, Display: display, Version: s.Version, CPE: cpe, KevKeys: keys})
	}
	if len(order) == 0 {
		return out, nil
	}
	byCVE := make(map[string]*findings.Vuln, len(vulns))
	for i := range vulns {
		byCVE[vulns[i].CVE] = &vulns[i]
	}
	now := m.now()
	for _, ip := range order {
		res := findings.MatchAsset(*assets[ip], vulns, nil, now)
		for _, x := range res.New {
			s, v := where[x.SoftwareID], byCVE[x.CVE]
			row := exposure.VulnRow{IP: s.IP, Port: s.Port, CVE: x.CVE, Basis: string(x.Basis), Summary: x.Evidence.Summary}
			if v != nil {
				row.Name, row.Ransomware = v.Name, v.Ransomware
				if !v.DateAdded.IsZero() {
					d := v.DateAdded.Format(time.DateOnly)
					row.DateAdded = &d
				}
			}
			out.Vulns = append(out.Vulns, row)
		}
		for _, n := range res.NeedVersion {
			s := where[n.SoftwareID]
			out.Gaps = append(out.Gaps, exposure.GapRow{IP: s.IP, Port: s.Port, Software: n.Software, CVEs: n.CVEs})
		}
	}
	return out, nil
}

// kevKeysByCPE maps "part:vendor:product" of every CPE an NVD configuration of a KEV entry names to the KEV keys of those entries.
func kevKeysByCPE(vulns []findings.Vuln) map[string][]string {
	out := map[string][]string{}
	for _, v := range vulns {
		key := findings.KevKey(v.Vendor, v.Product)
		for _, a := range v.Affected {
			base := cpeBase(a.CPE)
			if base == "" {
				continue
			}
			if l := out[base]; len(l) == 0 || l[len(l)-1] != key {
				out[base] = append(l, key)
			}
		}
	}
	return out
}

// cpeBase is "part:vendor:product" of a CPE 2.3 string ("cpe:2.3:a:apache:http_server:2.4.49:…" -> "a:apache:http_server").
func cpeBase(cpe string) string {
	f := strings.SplitN(cpe, ":", 6)
	if len(f) < 5 || f[0] != "cpe" || f[1] != "2.3" {
		return ""
	}
	return f[2] + ":" + f[3] + ":" + f[4]
}

// cpe23 turns the CPE 2.2 URI nmap prints ("cpe:/a:apache:http_server:2.4.49") into a CPE 2.3 string with the other attributes
// "*". Only plain URIs are taken (letters, digits, '.', '_', '-'); a percent-encoded or packed one gives "" (not compared).
func cpe23(uri string) string {
	rest, ok := strings.CutPrefix(strings.ToLower(uri), "cpe:/")
	if !ok {
		return ""
	}
	f := strings.Split(rest, ":")
	if len(f) < 3 || len(f) > 7 {
		return ""
	}
	attrs := []string{"*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*"}
	for i, v := range f {
		for _, r := range v {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
				return ""
			}
		}
		if v != "" {
			attrs[i] = v
		}
	}
	if (attrs[0] != "a" && attrs[0] != "o" && attrs[0] != "h") || attrs[1] == "*" || attrs[2] == "*" {
		return ""
	}
	return "cpe:2.3:" + strings.Join(attrs, ":")
}
