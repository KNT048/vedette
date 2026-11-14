package exposure

// FULL-5 slice 3 (D-571, INV-27 depth): the deep scan of each address of a verified domain's names, at the domain's terms depth.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	deepToken = "0123456789abcdef0123456789abcdef"
	ipPriv    = "10.0.0.5"
	ipV6      = "2606:4700::1"
)

// deepDNS answers TXT like fakeResolver and A records from a, so the core-side re-check of a name can be steered (no real DNS).
type deepDNS struct {
	*fakeResolver
	mu  sync.Mutex
	a   map[string][]string
	err error
}

func (d *deepDNS) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	var out []netip.Addr
	for _, v := range d.a[host] {
		out = append(out, netip.MustParseAddr(v))
	}
	return out, nil
}

func (d *deepDNS) point(name string, ips ...string) { d.mu.Lock(); d.a[name] = ips; d.mu.Unlock() }

// deepCall is one seam call of a deep step: the address and the ScanTarget it was handed.
type deepCall struct {
	ip string
	st ScanTarget
}

// deepSeams are the ServiceScanner, TemplateScanner and WebScanner of these tests: they record each call, refuse an address that is
// not a public IPv4 (it must never get there) and answer one web service on 443 for each address.
type deepSeams struct {
	mu        sync.Mutex
	services  []deepCall
	templates []deepCall
	pages     []WebPage
	webST     []ScanTarget
	bad       []string
	onService func(ctx context.Context) error // runs inside ScanServices when set
}

func (f *deepSeams) ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	f.mu.Lock()
	if !IsPublicIPv4(ip) {
		f.bad = append(f.bad, ip.String())
	}
	f.services = append(f.services, deepCall{ip.String(), t})
	hook := f.onService
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return ServiceScan{}, err
		}
	}
	return ServiceScan{Ports: 65535, Services: []ServiceRow{{IP: ip.String(), Port: 443, Name: "https", Product: "nginx", Version: "1.24.0"}}}, nil
}

func (f *deepSeams) ScanTemplates(_ context.Context, t ScanTarget, ip netip.Addr, jobs []TemplateJob) (TemplateScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.templates = append(f.templates, deepCall{ip.String(), t})
	var sent []string
	for range jobs {
		sent = append(sent, "tech-detect")
	}
	return TemplateScan{Sent: sent}, nil
}

func (f *deepSeams) Baseline(_ context.Context, t ScanTarget, p WebPage) (WebScan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages, f.webST = append(f.pages, p), append(f.webST, t)
	return WebScan{Report: []byte(`{"site":[{"@name":"` + strings.TrimSuffix(p.URL, "/") + `","alerts":[]}]}`)}, nil
}

func (f *deepSeams) serviceIPs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.services {
		out = append(out, c.ip)
	}
	return out
}

func (f *deepSeams) call(ip string) (ScanTarget, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.services {
		if c.ip == ip {
			return c.st, true
		}
	}
	return ScanTarget{}, false
}

type deepLog struct {
	mu  sync.Mutex
	tpl []TemplateProbe
	web []WebProbe
}

func (l *deepLog) RecordTemplateProbes(_ context.Context, p []TemplateProbe) error {
	l.mu.Lock()
	l.tpl = append(l.tpl, p...)
	l.mu.Unlock()
	return nil
}

func (l *deepLog) RecordWebProbe(_ context.Context, p WebProbe) error {
	l.mu.Lock()
	l.web = append(l.web, p)
	l.mu.Unlock()
	return nil
}

type fakeFence struct {
	mu    sync.Mutex
	asked []string
}

func (f *fakeFence) Token(_ context.Context, domain string) (string, error) {
	f.mu.Lock()
	f.asked = append(f.asked, domain)
	f.mu.Unlock()
	return deepToken, nil
}

type deepEnv struct {
	*env
	dns   *deepDNS
	seams *deepSeams
	log   *deepLog
	dom   TargetView
	run   *fakeRunner
}

// newDeepEnv: acme.example verified and committed; ipA is the box's own verified, committed IP (the prober sees it); the seams and a
// matcher are wired. The runner lists acme.example on ipA (box), www and api on ipB, cdn on ipC, intra on a private address and
// v6 on IPv6 only; DNS agrees with it.
func newDeepEnv(t *testing.T) *deepEnv {
	t.Helper()
	e := newEnv(t)
	d := &deepEnv{env: e, dns: &deepDNS{fakeResolver: e.dns, a: map[string][]string{}}, seams: &deepSeams{}, log: &deepLog{}}
	e.svc.cfg.Resolver = d.dns
	e.svc.cfg.Services, e.svc.cfg.Templates, e.svc.cfg.Web, e.svc.cfg.Probes = d.seams, d.seams, d.seams, d.log
	e.svc.cfg.Matcher = &fakeMatcher{}
	box := e.detect(ipA)
	if _, err := e.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	d.dom = e.committedDomain()
	hosts := []HostRow{
		{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassBox, Contacted: true}}},
		{Name: "www.acme.example", IP: ipB, Source: "ct", IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic, Contacted: true}}},
		{Name: "api.acme.example", IP: ipB, Source: "ct", IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic, Contacted: true}}},
		{Name: "cdn.acme.example", IP: ipC, Source: "ct", CNAME: "acme.example.cdn.cloudflare.net", IPs: []HostIP{{IP: ipC, Family: "ipv4", Class: ClassPublic, Contacted: true, Deep: DeepScanned, LastDeep: "2099-01-01T00:00:00.000Z"}}},
		{Name: "intra.acme.example", IP: ipPriv, Source: "ct", IPs: []HostIP{{IP: ipPriv, Family: "ipv4", Class: ClassPrivate}}},
		{Name: "v6.acme.example", Source: "wordlist", IPs: []HostIP{{IP: ipV6, Family: "ipv6", Class: ClassPublic}}},
	}
	for _, h := range hosts {
		for _, a := range h.IPs {
			d.dns.point(h.Name, append(d.dns.a[h.Name], a.IP)...)
		}
	}
	d.run = &fakeRunner{content: Content{Hosts: hosts, Ports: []PortRow{{IP: ipB, Port: 443, Service: "https"}, {IP: ipA, Port: 443, Service: "https"}}}}
	e.svc.SetRunner(d.run)
	return d
}

func (d *deepEnv) scan() Snapshot {
	d.t.Helper()
	snap, err := d.svc.Scan(d.ctx(), "admin@acme.example", d.dom.ID)
	if err != nil {
		d.t.Fatal(err)
	}
	got, err := d.svc.SnapshotOf(d.ctx(), d.dom.ID, snap.Date)
	if err != nil {
		d.t.Fatal(err)
	}
	return got
}

func deepOf(s Snapshot, ip string) HostIP {
	for _, h := range s.Hosts {
		for _, a := range h.IPs {
			if a.IP == ip {
				return a
			}
		}
	}
	return HostIP{}
}

func hasLine(s Snapshot, sub string) bool {
	return slices.ContainsFunc(s.NotChecked, func(n NotCheckedRow) bool { return strings.Contains(n.Text, sub) })
}

// D-571: without accepted terms nothing new goes to any address: no deep seam is called (not even for the box's own IP, which is a
// domain's name here), the fence is not asked, the by-name passive pass is in the K-4 scope, and the lines are the K-4 lines.
func TestContract_INV27_Deep_WithoutTermsNothingNewIsSent(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	fence := &fakeFence{}
	d.svc.cfg.DomainFence = fence
	s := d.scan()
	if len(d.seams.services) != 0 || len(d.seams.templates) != 0 || len(fence.asked) != 0 || len(d.log.tpl) != 0 {
		t.Fatalf("services %v, templates %v, fence %v", d.seams.services, d.seams.templates, fence.asked)
	}
	for _, st := range d.seams.webST { // only the by-name passive pages on 80/443, in the K-4 scope
		if st.Mode.Full || st.Domain != nil {
			t.Fatalf("passive page with %+v", st)
		}
	}
	for _, p := range d.log.web {
		if p.Tool != webTool {
			t.Fatalf("probe %+v", p)
		}
	}
	for _, want := range []string{notOtherPortsDom, notServicesDom, notTemplatesDom, notGBDomain, "checked by name on ports 80 and 443 only; accept this domain's testing terms"} {
		if !hasLine(s, want) {
			t.Errorf("missing %q in %q", want, notChecked(s))
		}
	}
	if slices.ContainsFunc(s.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "deep" }) || len(s.Services) != 0 {
		t.Fatalf("deep lines or services without terms: %q", notChecked(s))
	}
	if a := deepOf(s, ipC); a.Deep != "" || a.LastDeep != "" { // the runner's own claims are dropped
		t.Fatalf("cdn = %+v", a)
	}
}

// D-571: with the terms but no domain fence on this box, only the box's own IP gets the deep scan (its own pipeline, no scope); every
// other public address gets the "needs the fence" line and nothing more than the by-name checks.
func TestContract_INV27_Deep_NoFenceOnlyTheBoxIP(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.acceptTerms(d.dom.ID, false)
	s := d.scan()
	if got := d.seams.serviceIPs(); !slices.Equal(got, []string{ipA}) {
		t.Fatalf("services asked for %v", got)
	}
	st, _ := d.seams.call(ipA)
	if !st.Mode.Full || st.Mode.Disruptive || st.Domain != nil || st.ID != d.dom.ID {
		t.Fatalf("box step = %+v", st)
	}
	if !hasLine(s, "not scanned at depth: this box needs the Vedette host's domain fence (update the box)") || !hasLine(s, ipB) {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if deepOf(s, ipB).Deep != DeepFence || deepOf(s, ipC).Deep != DeepFence || deepOf(s, ipA).Deep != DeepScanned || deepOf(s, ipA).LastDeep == "" {
		t.Fatalf("hosts %+v", s.Hosts)
	}
	for _, p := range d.seams.pages {
		if a, _ := netip.ParseAddr(p.IP.String()); a.String() != ipA && p.Port != 443 && p.Port != 80 {
			t.Fatalf("page %+v", p)
		}
	}
}

// D-571: with the terms and a domain fence, each public address gets the deep seams once (however many names point at it), with the
// run's mode and the domain's scope {domain, name, token}; the box's own IP takes its pipeline without a scope; private and IPv6
// addresses are never dialed and have their lines; the web scan by name goes to the names of the deep addresses, re-checked.
func TestContract_INV27_Deep_WithFenceEveryAddressOnce(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	s := d.scan()
	got := d.seams.serviceIPs()
	slices.Sort(got)
	if want := []string{ipB, ipA, ipC}; !slices.Equal(got, []string{ipB, ipA, ipC}) {
		t.Fatalf("services asked for %v, want each of %v once", got, want)
	}
	if len(d.seams.bad) != 0 {
		t.Fatalf("dialed %v", d.seams.bad)
	}
	st, _ := d.seams.call(ipB)
	if !st.Mode.Full || !st.Mode.Disruptive || st.Domain == nil || *st.Domain != (DomainScope{Domain: "acme.example", Name: "api.acme.example", Token: deepToken}) {
		t.Fatalf("ipB step = %+v %+v", st, st.Domain)
	}
	if st, _ := d.seams.call(ipA); st.Domain != nil {
		t.Fatalf("box step has a scope: %+v", st.Domain)
	}
	for _, c := range d.seams.templates {
		if !c.st.Mode.Full || (c.ip != ipA) != (c.st.Domain != nil) {
			t.Fatalf("templates %+v", c)
		}
	}
	if len(d.seams.templates) != 3 {
		t.Fatalf("templates %+v", d.seams.templates)
	}
	if !hasLine(s, "Private addresses (1 address): listed, never contacted.") || !hasLine(s, "IPv6 addresses (1 listed): IPv6 is not scanned yet.") {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if len(s.Services) != 3 || !slices.ContainsFunc(s.Ports, func(p PortRow) bool { return p.IP == ipC && p.Port == 443 }) {
		t.Fatalf("services %+v ports %+v", s.Services, s.Ports)
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return strings.HasPrefix(c.Text, ipB+" (api.acme.example, www.acme.example): deep scan at the testing terms depth (through the domain fence, name api.acme.example)")
	}) {
		t.Fatalf("checks %+v", s.Checks)
	}
	// web by name at depth: at most MaxDeepWebPages pages, each by name and with the scope of its own name
	deepPages := 0
	for i, p := range d.seams.pages {
		if d.seams.webST[i].Mode.Full {
			deepPages++
			if p.IP.String() != ipA && (d.seams.webST[i].Domain == nil || d.seams.webST[i].Domain.Name != p.Host) {
				t.Fatalf("deep page %+v with %+v", p, d.seams.webST[i].Domain)
			}
		}
	}
	if deepPages != MaxDeepWebPages || !hasLine(s, "Web scan by name at the testing terms depth: 2 pages not scanned this run") {
		t.Fatalf("%d deep pages; not checked %q", deepPages, notChecked(s))
	}
	if deepOf(s, ipB).Deep != DeepScanned || deepOf(s, ipPriv).Deep != "" || deepOf(s, ipV6).Deep != "" {
		t.Fatalf("hosts %+v", s.Hosts)
	}
}

// D-571: a name that no longer resolves to the address at the core-side re-check gets no call and a line; a DNS failure is its own line.
func TestContract_INV27_Deep_NameMovedOrNoAnswer(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.dns.point("cdn.acme.example", ipD)
	s := d.scan()
	if _, called := d.seams.call(ipC); called {
		t.Fatal("ipC was scanned")
	}
	if deepOf(s, ipC).Deep != DeepRefused || !hasLine(s, ipC+" (cdn.acme.example): not scanned at depth: "+deepMoved) {
		t.Fatalf("not checked %q", notChecked(s))
	}
	d.advance(ScanEvery + time.Minute)
	d.dns.mu.Lock()
	d.dns.err = errors.New("no answer")
	d.dns.mu.Unlock()
	d.seams.services = nil
	s = d.scan()
	if got := d.seams.serviceIPs(); !slices.Equal(got, []string{ipA}) || !hasLine(s, deepNoAnswer) {
		t.Fatalf("services %v; not checked %q", got, notChecked(s))
	}
}

// D-571 (plan §4): with 5 addresses and MaxDeepIPs 3, three are scanned and two get "not scanned this run … next in line" lines; the
// next run takes the two left first (never scanned), then the least recently scanned.
func TestContract_INV27_Deep_CapAndRotation(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	ips := []string{"9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4", "9.9.9.5"}
	var hosts []HostRow
	for i, ip := range ips {
		name := fmt.Sprintf("h%d.acme.example", i+1)
		hosts = append(hosts, HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}})
		d.dns.point(name, ip)
	}
	d.run.content = Content{Hosts: hosts, Ports: []PortRow{}}
	s := d.scan()
	if got := d.seams.serviceIPs(); !slices.Equal(got, ips[:3]) {
		t.Fatalf("first run scanned %v", got)
	}
	for i, ip := range ips[3:] {
		if a := deepOf(s, ip); a.Deep != DeepWaiting || a.NextInLine != i+1 {
			t.Fatalf("%s = %+v", ip, a)
		}
		if !hasLine(s, fmt.Sprintf("%s (h%d.acme.example): not scanned this run (at most 3 addresses get the deep scan in one run), never scanned at depth; next in line (%d).", ip, i+4, i+1)) {
			t.Fatalf("not checked %q", notChecked(s))
		}
	}
	first := deepOf(s, ips[0]).LastDeep
	d.advance(ScanEvery + time.Minute)
	d.seams.services = nil
	s = d.scan()
	if got := d.seams.serviceIPs(); !slices.Equal(got, []string{ips[3], ips[4], ips[0]}) {
		t.Fatalf("second run scanned %v", got)
	}
	if a := deepOf(s, ips[1]); a.Deep != DeepWaiting || a.LastDeep != first || !hasLine(s, "last scanned at depth") {
		t.Fatalf("%s = %+v; %q", ips[1], a, notChecked(s))
	}
}

// D-571: withdrawing the domain's terms while a deep step runs stops the run (FULL-1's mechanism), and no further address is scanned.
func TestContract_INV27_Deep_WithdrawStopsTheDeepStep(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.seams.onService = func(ctx context.Context) error {
		if _, err := d.svc.RevokeTerms(context.WithoutCancel(ctx), "admin@acme.example", d.dom.ID); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	_, err := d.svc.Scan(d.ctx(), "admin@acme.example", d.dom.ID)
	if err == nil {
		t.Fatal("the scan was not stopped")
	}
	if r := d.svc.CurrentScan(); r == nil || r.Status != RunStopped || r.StopReason == nil {
		t.Fatalf("run = %+v", r)
	}
	if got := d.seams.serviceIPs(); len(got) != 1 {
		t.Fatalf("services asked for %v", got)
	}
}

// D-571 (LEGAL-2): a domain's terms say the scan reaches third-party hosting, CDN and proxies, name the IP-level tools and the
// customer's responsibility; an IP's text is unchanged; the version is 2026-11-14c.
func TestContract_INV27_Deep_DomainTermsText(t *testing.T) {
	t.Parallel()
	if TermsVersion != "2026-11-14c" {
		t.Fatalf("version %s", TermsVersion)
	}
	dom := termsFor(KindDomain, "acme.example").Text
	for _, want := range []string{
		"Every name under acme.example that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN.",
		"Cloudflare and AWS forbid denial-of-service tests",
		"Vedette sends all ports, OpenVAS, nuclei and the active web scan (ZAP) to each address a name under acme.example resolves to.",
		// TERMS.md (D-544) word for word, so the two texts never disagree
		"Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission. Vedette does not check who owns those addresses.",
	} {
		if !strings.Contains(dom, want) {
			t.Errorf("domain terms lack %q", want)
		}
	}
	if strings.Contains(dom, "yours alone") {
		t.Error("the domain terms still say yours alone")
	}
	ip := termsFor(KindIP, ipA).Text
	if !strings.Contains(ip, "Accept only if "+ipA+" is yours alone") || strings.Contains(ip, "Verifying a name") {
		t.Errorf("IP terms = %q", ip)
	}
	e := newEnv(t)
	v := e.addVerifiedDomain()
	if got := e.target(v.ID).TermsNotice; got.Version != TermsVersion || got.Text != dom {
		t.Fatalf("notice = %+v", got)
	}
	// the audit row of an acceptance stays within core/audit's 2000 characters and says it was cut; the row keeps the whole text
	acc := e.acceptTerms(v.ID, true)
	for _, a := range e.audits() {
		if a.Action == "exposure.terms_accept" && (len([]rune(a.Detail)) > auditDetailMax || !strings.HasSuffix(a.Detail, termsClipNote)) {
			t.Fatalf("audit detail of %d characters: %q", len([]rune(a.Detail)), a.Detail[len(a.Detail)-120:])
		}
	}
	if acc.Terms == nil || acc.Terms.Text != dom+"\n"+termsDisruptive {
		t.Fatalf("stored terms = %+v", acc.Terms)
	}
}

// D-571: OpenVAS, when it is on, runs on the addresses a domain's deep scan reached: the box's own IP in its pipeline; an address that
// is not the box's only through a host that checks the domain fence for OpenVAS (GreenboneFence), else a line and nothing sent.
func TestContract_INV27_Deep_OpenVASOnTheDeepAddresses(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.terms = nil
	e.enable()
	dns := &deepDNS{fakeResolver: e.dns, a: map[string][]string{"www.acme.example": {ipB}}}
	e.svc.cfg.Resolver, e.svc.cfg.DomainFence, e.svc.cfg.Services = dns, &fakeFence{}, &deepSeams{}
	box := e.detect(ipA)
	if _, err := e.commit(box[0].ID); err != nil {
		t.Fatal(err)
	}
	dom := e.committedDomain()
	e.acceptTerms(dom.ID, false)
	e.svc.SetRunner(&fakeRunner{content: Content{Hosts: []HostRow{
		{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassBox}}},
		{Name: "www.acme.example", IP: ipB, Source: "ct", IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic}}},
	}, Ports: []PortRow{}}})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.svc.SnapshotOf(e.ctx(), dom.ID, snap.Date)
	if err != nil {
		t.Fatal(err)
	}
	logged := map[string]bool{}
	for _, p := range h.gvm.log.rows {
		logged[p.IP] = true
	}
	if !logged[ipA] || logged[ipB] {
		t.Fatalf("OpenVAS probe log %+v", h.gvm.log.rows)
	}
	if !hasLine(s, ipB+" (www.acme.example): "+notGBNoFence) || hasLine(s, notGBDomain) {
		t.Fatalf("not checked %q", notChecked(s))
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "OpenVAS scanned "+ipA)
	}) {
		t.Fatalf("checks %+v", s.Checks)
	}
}
