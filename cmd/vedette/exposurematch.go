package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
)

// exposureMatcher is exposure's Matcher (S-EXP-2, exposure INV-20): the services nmap -sV identified on the box's own public
// IP, compared with the same catalogue the devices are (findings' Feeds.MatchSet: the exploited lists and every other CVE naming the
// product, with the ranges the catalogue's precedence gives), so a service gets the CVEs and the fix (findings.FixOf) a device
// running that software gets. Only what findings announces is shown (findings.Announced): a catalogue CVE on no exploited list stays
// silent here as it does in the alerts. Nothing is stored: exposure calls it each time a snapshot is read, so a new KEV entry shows
// without a rescan. A service counts as
// compared only when the list has exploited CVEs under its CPE's vendor and product; otherwise it is Unlisted (nginx is
// "igor_sysoev:nginx" to nmap and "f5:nginx" to NVD today).
//
// A service is looked up by the CPE nmap printed. Its KEV keys come from the NVD configurations of the KEV entries themselves (a
// KEV entry whose NVD data names cpe:2.3:a:apache:http_server gives that CPE the key "apache|http server"), plus catalog when it
// is set: inventory's curated CPE to KEV keys (inventory.Service.KevKeysByCPE). Catalog keys count only when some entry of the list carries them, so a service is never "compared" against a product the list does not have (INV-20).
type exposureMatcher struct {
	vulns func(ctx context.Context) ([]findings.Vuln, error)
	// catalogue is findings' Feeds.MatchSet: what the services are compared with. nil: the exploited list (vulns) alone. It is read
	// through memo, under the feeds' match stamp (stamp), so a page read costs what it did before the catalogue was read.
	catalogue func(ctx context.Context, scope findings.MatchScope) ([]findings.Vuln, error)
	stamp     func(ctx context.Context) (string, error)
	memo      *catalogueMemo                                      // nil: read every time
	catalog   func(ctx context.Context) func(cpe string) []string // inventory.Service.KevKeysByCPE, read once per Match; nil: the list's own CPEs only
	now       func() time.Time
}

// catalogueMemo keeps the catalogue sets read under the current match stamp, by the products they were read for: an exposure read
// (a snapshot, a comparison of two) asks again and again for the same services, and the set changes only when a feed does.
type catalogueMemo struct {
	mu    sync.Mutex
	stamp string
	sets  map[string][]findings.Vuln // read only once stored: the matcher never changes it
}

// get returns the set stored for products under stamp, else the one read gives (and keeps it).
func (c *catalogueMemo) get(stamp, products string, read func() ([]findings.Vuln, error)) ([]findings.Vuln, error) {
	c.mu.Lock()
	if c.stamp == stamp {
		if v, ok := c.sets[products]; ok {
			c.mu.Unlock()
			return v, nil
		}
	}
	c.mu.Unlock()
	v, err := read()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.stamp != stamp || c.sets == nil {
		c.stamp, c.sets = stamp, map[string][]findings.Vuln{}
	}
	c.sets[products] = v
	c.mu.Unlock()
	return v, nil
}

// exposureFeeds reads the exploited list (exposureMatcher.vulns) and the catalogue (exposureMatcher.catalogue) through the cached
// reader findings uses (findingsFeeds). The feeds module off is a reason the page shows; nothing is then read.
func exposureFeeds(d deps) (vulns func(context.Context) ([]findings.Vuln, error), catalogue func(context.Context, findings.MatchScope) ([]findings.Vuln, error), stamp func(context.Context) (string, error)) {
	cache := &vulnCache{}
	feedsOf := func() (findingsFeeds, error) {
		if d.Reg != nil && !d.Reg.Enabled("feeds") {
			return findingsFeeds{}, &exposure.Unavailable{Reason: "the Feeds module is off, so the list of exploited vulnerabilities is not kept. An admin can turn it on in Settings, Modules."}
		}
		svc, err := feedsService(d)
		if err != nil {
			return findingsFeeds{}, err
		}
		return findingsFeeds{st: svc.Store(), cache: cache}, nil
	}
	vulns = func(ctx context.Context) ([]findings.Vuln, error) {
		f, err := feedsOf()
		if err != nil {
			return nil, err
		}
		return f.Vulns(ctx)
	}
	catalogue = func(ctx context.Context, scope findings.MatchScope) ([]findings.Vuln, error) {
		f, err := feedsOf()
		if err != nil {
			return nil, err
		}
		return f.MatchSet(ctx, scope)
	}
	stamp = func(ctx context.Context) (string, error) {
		f, err := feedsOf()
		if err != nil {
			return "", err
		}
		return f.st.MatchStamp(ctx)
	}
	return vulns, catalogue, stamp
}

func (m exposureMatcher) Match(ctx context.Context, svcs []exposure.ServiceRow) (exposure.Matches, error) {
	out, _, err := m.match(ctx, svcs)
	return out, err
}

// announced says findings tells people about v: the urgency a finding of v starts with (findings' Vuln.StartUrgency) through the one
// rule, findings.Announced.
func announced(v findings.Vuln) bool {
	return findings.Announced(findings.Finding{Urgency: v.StartUrgency()})
}

// fixOf is the fix findings.FixOf gives a CVE shown on a service, asked for only by the one that shows it (exposure's rows carry no
// fix yet): nothing is computed for the reads that do not.
type fixOf func(s exposure.ServiceRow, cve string) findings.Fix

// match is Match and the fix of each CVE it shows.
func (m exposureMatcher) match(ctx context.Context, svcs []exposure.ServiceRow) (exposure.Matches, fixOf, error) {
	vulns, err := m.vulns(ctx)
	if err != nil {
		return exposure.Matches{}, nil, err
	}
	byCPE := kevKeysByCPE(vulns)
	var lookup func(cpe string) []string
	var listed map[string]bool // the vendor|product keys the list carries
	if m.catalog != nil {
		lookup, listed = m.catalog(ctx), map[string]bool{}
		for _, v := range vulns {
			listed[productid.Key(v.Vendor, v.Product)] = true
		}
	}
	out := exposure.Matches{Vulns: []exposure.VulnRow{}, Gaps: []exposure.GapRow{}, Listed: len(vulns)}
	assets := map[string]*findings.Asset{} // one asset per IP, named by the IP: the sentence says "<ip> runs Apache httpd 2.4.49"
	var order []string
	where := map[string]exposure.ServiceRow{} // software id -> its service
	sw := map[string]findings.Software{}      // software id -> its line
	for _, s := range svcs {
		cpe := cpe23(s.CPE)
		if cpe == "" {
			continue
		}
		base := cpeBase(cpe)
		keys := byCPE[base]
		for _, alt := range productid.NmapAliases(base) { // nmap's old vendor name (igor_sysoev:nginx) for the product NVD lists (f5:nginx)
			if len(keys) > 0 {
				break
			}
			if keys = byCPE[alt]; len(keys) > 0 {
				base, cpe = alt, "cpe:2.3:"+alt+cpe[len("cpe:2.3:")+len(cpeBase(cpe)):] // the version compares against the ranges NVD keeps under alt
			}
		}
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
		line := findings.Software{ID: id, Display: display, Version: s.Version, Banner: s.Extra, CPE: cpe, KevKeys: keys, Source: "scan"}
		a.Software = append(a.Software, line)
		sw[id] = line
	}
	none := func(exposure.ServiceRow, string) findings.Fix { return findings.Fix{Kind: findings.FixUnknown} }
	if len(order) == 0 {
		return out, none, nil
	}
	list := vulns
	if m.catalogue != nil {
		all := make([]findings.Asset, 0, len(order))
		for _, ip := range order {
			all = append(all, *assets[ip])
		}
		read := func() ([]findings.Vuln, error) { return m.catalogue(ctx, findings.NewMatchScope(all, nil)) }
		if m.memo == nil || m.stamp == nil {
			list, err = read()
		} else {
			var stamp string
			if stamp, err = m.stamp(ctx); err == nil {
				list, err = m.memo.get(stamp, productsOf(all), read)
			}
		}
		if err != nil {
			return exposure.Matches{}, nil, err
		}
		// a CVE outside the reporting window is set aside here as findings' matcher sets it aside on a device
		list = slices.DeleteFunc(slices.Clone(list), func(v findings.Vuln) bool { return v.OutsideWindow })
	}
	byCVE := make(map[string]*findings.Vuln, len(list))
	for i := range list {
		byCVE[list[i].CVE] = &list[i]
	}
	shown := func(cve string) *findings.Vuln { // a CVE findings announces; the others of the catalogue are not this page's
		if v := byCVE[cve]; v != nil && announced(*v) {
			return v
		}
		return nil
	}
	now := m.now()
	for _, ip := range order {
		a := *assets[ip]
		res := findings.MatchAsset(a, list, nil, now)
		for _, x := range res.New {
			s, v := where[x.SoftwareID], shown(x.CVE)
			if v == nil {
				continue
			}
			row := exposure.VulnRow{IP: s.IP, Port: s.Port, CVE: x.CVE, Basis: string(x.Basis), Summary: x.Evidence.Summary}
			kevRow(&row, *v)
			out.Vulns = append(out.Vulns, row)
		}
		for _, x := range res.OtherPlatform { // The banner names another platform than the one the CVE affects
			s := where[x.SoftwareID]
			if shown(x.CVE) == nil {
				continue
			}
			out.RuledOut = append(out.RuledOut, exposure.RuledOutRow{IP: s.IP, Port: s.Port, CVE: x.CVE, Reason: x.Evidence.Summary})
		}
		for _, x := range res.Aged { // An exploited CVE published over 12 months ago needs a version compared or a scan hit
			s, v := where[x.SoftwareID], shown(x.CVE)
			if v == nil {
				continue
			}
			out.RuledOut = append(out.RuledOut, exposure.RuledOutRow{IP: s.IP, Port: s.Port, CVE: x.CVE,
				Reason: fmt.Sprintf("Published on %s, more than 12 months ago, and only the product name matches: the banner gives no version Vedette can compare. For an old CVE Vedette needs a version or a hit of this page's scans.", orgtime.CalendarDay(v.Published))})
		}
		for _, x := range res.NameOnly { // Only the product name matches, whatever the CVE's age
			s := where[x.SoftwareID]
			if shown(x.CVE) == nil {
				continue
			}
			out.RuledOut = append(out.RuledOut, exposure.RuledOutRow{IP: s.IP, Port: s.Port, CVE: x.CVE,
				Reason: fmt.Sprintf("Only the product name matches: %s. Vedette lists an exploited CVE when it can compare a version or this page's scans find it.", x.Gap())})
		}
		for _, x := range res.Asked { // A platform-limited CVE whose platform the banner does not name is not listed, with why
			s := where[x.SoftwareID]
			if shown(x.CVE) == nil {
				continue
			}
			out.RuledOut = append(out.RuledOut, exposure.RuledOutRow{IP: s.IP, Port: s.Port, CVE: x.CVE,
				Reason: x.AskedWhy() + ". This page cannot tell; if the port is a device you watch, answer the question in its Could not be checked list."})
		}
		for _, n := range res.NeedVersion {
			s := where[n.SoftwareID]
			cves := slices.DeleteFunc(slices.Clone(n.CVEs), func(c string) bool { return shown(c) == nil })
			if len(cves) == 0 {
				continue
			}
			out.Gaps = append(out.Gaps, exposure.GapRow{IP: s.IP, Port: s.Port, Software: n.Software, CVEs: cves})
		}
	}
	return out, func(s exposure.ServiceRow, cve string) findings.Fix {
		v := byCVE[cve]
		l, ok := sw[fmt.Sprintf("%s:%d", s.IP, s.Port)]
		if v == nil || !ok {
			return findings.Fix{Kind: findings.FixUnknown}
		}
		return findings.FixOf(*assets[s.IP], l, *v)
	}, nil
}

// productsOf names the products of the assets' software (CPE vendor and product, the version left out), sorted: what a catalogue set
// is kept under.
func productsOf(assets []findings.Asset) string {
	var l []string
	for _, a := range assets {
		for _, s := range a.Software {
			l = append(l, cpeBase(s.CPE))
		}
	}
	slices.Sort(l)
	return strings.Join(slices.Compact(l), ",")
}

// Exploited is exposure's ExploitedLookup: the CVE ids among cves that today's list carries, with their name, date and
// ransomware flag (the CVEs Retire.js names for a JavaScript library ZAP saw on a page, and those Greenbone names).
func (m exposureMatcher) Exploited(ctx context.Context, cves []string) (map[string]exposure.KEVEntry, error) {
	vulns, err := m.vulns(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]exposure.KEVEntry{}
	for _, v := range vulns {
		if slices.Contains(cves, v.CVE) {
			row := exposure.VulnRow{CVE: v.CVE}
			kevRow(&row, v)
			out[v.CVE] = exposure.KEVEntry{Name: row.Name, DateAdded: row.DateAdded, Ransomware: row.Ransomware}
		}
	}
	return out, nil
}

// kevRow fills the name, ransomware flag and date CISA listed it of a row from its list entry.
func kevRow(row *exposure.VulnRow, v findings.Vuln) {
	row.Name, row.Ransomware = v.Name, v.Ransomware
	if !v.DateAdded.IsZero() {
		d := v.DateAdded.Format(time.DateOnly)
		row.DateAdded = &d
	}
}

// kevKeysByCPE maps "part:vendor:product" of every CPE an NVD configuration of a KEV entry names to the KEV keys of those entries.
func kevKeysByCPE(vulns []findings.Vuln) map[string][]string {
	out := map[string][]string{}
	for _, v := range vulns {
		key := productid.Key(v.Vendor, v.Product)
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
