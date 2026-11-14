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
	mu       sync.Mutex
	a        map[string][]string
	err      error
	cnameErr error // LookupCNAME answers it when set; otherwise the name itself (no CNAME)
}

func (d *deepDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cnameErr != nil {
		return "", d.cnameErr
	}
	return host + ".", nil
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
	svcErr    error                           // ScanServices answers it when set (after recording the call)
	extra     []ServiceRow                    // more services ScanServices answers, for their own address
	errFor    map[string]error                // ScanServices answers it for that address when set
}

func (f *deepSeams) ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	f.mu.Lock()
	if !IsPublicIPv4(ip) {
		f.bad = append(f.bad, ip.String())
	}
	f.services = append(f.services, deepCall{ip.String(), t})
	hook, svcErr, extra := f.onService, f.svcErr, f.extra
	if e := f.errFor[ip.String()]; e != nil {
		svcErr = e
	}
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return ServiceScan{}, err
		}
	}
	if svcErr != nil {
		return ServiceScan{}, svcErr
	}
	rows := []ServiceRow{{IP: ip.String(), Port: 443, Name: "https", Product: "nginx", Version: "1.24.0"}}
	for _, r := range extra {
		if r.IP == ip.String() {
			rows = append(rows, r)
		}
	}
	return ServiceScan{Ports: 65535, Services: rows}, nil
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
func TestContract_INV28_Deep_WithoutTermsNothingNewIsSent(t *testing.T) {
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
func TestContract_INV28_Deep_NoFenceOnlyTheBoxIP(t *testing.T) {
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
func TestContract_INV28_Deep_WithFenceEveryAddressOnce(t *testing.T) {
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
	// review r1 M4: ipC is reached only through cdn.acme.example's CNAME outside the domain: never the disruptive checks
	if st, _ := d.seams.call(ipC); !st.Mode.Full || st.Mode.Disruptive {
		t.Fatalf("ipC step = %+v", st.Mode)
	}
	if !hasLine(s, ipC+" (cdn.acme.example): reached only through a name that points (CNAME) outside this domain, so the disruptive checks were not run there.") {
		t.Fatalf("not checked %q", notChecked(s))
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
	// review r1 M1: no web scan at depth until the active ZAP scan exists: every page is the by-name passive pass, logged as such
	for i, st := range d.seams.webST {
		if st.Mode.Full || st.Domain != nil {
			t.Fatalf("page %+v sent at depth with %+v", d.seams.pages[i], st)
		}
	}
	for _, p := range d.log.web {
		if p.Tool != webTool {
			t.Fatalf("probe-log tool %q is not what the adapter runs", p.Tool)
		}
	}
	if deepOf(s, ipB).Deep != DeepScanned || deepOf(s, ipPriv).Deep != "" || deepOf(s, ipV6).Deep != "" {
		t.Fatalf("hosts %+v", s.Hosts)
	}
}

// D-571: a name that no longer resolves to the address at the core-side re-check gets no call and a line; a DNS failure is its own line.
func TestContract_INV28_Deep_NameMovedOrNoAnswer(t *testing.T) {
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
func TestContract_INV28_Deep_CapAndRotation(t *testing.T) {
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
func TestContract_INV28_Deep_WithdrawStopsTheDeepStep(t *testing.T) {
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

// D-571 (LEGAL-2, reviews r1 H1 and r2): a domain's terms say the scan reaches third-party hosting, CDN and proxies, name the IP-level
// tools, the customer's responsibility and the CNAME rule; an IP keeps its "yours alone" sentence; both say what runs without the tick
// and what the tick adds; the version is 2026-11-14e.
func TestContract_INV28_Deep_DomainTermsText(t *testing.T) {
	t.Parallel()
	if TermsVersion != "2026-11-14e" {
		t.Fatalf("version %s", TermsVersion)
	}
	dom := termsFor(KindDomain, "acme.example").Text
	for _, want := range []string{
		"Every name under acme.example that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN.",
		"Cloudflare and AWS forbid denial-of-service tests",
		"Vedette's tools reach each address a name under acme.example resolves to, including a third-party hosting provider, CDN or proxy in front of your names: the scan of all ports, OpenVAS, nuclei and the web scan (ZAP).",
		// review r1 M4
		"A name that points (CNAME) to a name outside acme.example is scanned at whatever address the owner of that other name sets, so the disruptive checks never run on an address reached only that way.",
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
	// review r1 H1: the texts say what the deep scan sends without the tick (D-526, D-527, OpenVAS deep config), and what waits for it
	for _, text := range []string{dom, ip} {
		for _, want := range []string{
			"including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command)",
			"through a known authentication bypass",
			"Some checks, OpenVAS's in particular, may write a harmless test file or record to confirm a flaw and then try to remove it.",
			"Checks that can crash a service, guess passwords or sign in with default passwords, and the exploit checks of nuclei and nmap that send more than a harmless read, run only with the disruptive checks below.",
			"including the public anonymous login a service may offer (for example anonymous FTP)",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("terms lack %q", want)
			}
		}
		if strings.Contains(text, "exploiting it run only with") {
			t.Errorf("terms say exploit checks run only with the tick: %q", text)
		}
	}
	if d := termsFor(KindDomain, "acme.example").Disruptive; !strings.Contains(d, "exploit checks that send more than a harmless read, such as nuclei's POST exploit requests that may create or change data and nmap's SQL injection probes") {
		t.Errorf("disruptive tick = %q", d)
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
func TestContract_INV28_Deep_OpenVASOnTheDeepAddresses(t *testing.T) {
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

// review r1 L7: only public IPv4 addresses of names under the domain are candidates; mapped, private, CGNAT, link-local, multicast and
// unspecified addresses, IPv6, and names that only look like the domain are not.
func TestContract_INV28_Deep_Candidates(t *testing.T) {
	t.Parallel()
	row := func(name, ip string) HostRow {
		return HostRow{Name: name, IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}}
	}
	hosts := []HostRow{
		row("a.acme.example", "::ffff:10.0.0.1"), row("b.acme.example", "100.64.1.1"), row("c.acme.example", "169.254.1.1"),
		row("d.acme.example", "224.0.0.1"), row("e.acme.example", "0.0.0.0"), row("f.acme.example", ipV6),
		row("acme.example.evil.com", ipB), row("xacme.example", ipB), row("www.acme.example", ipC),
		{Name: "cdn.acme.example", CNAME: "x.cdn.example.net", IPs: []HostIP{{IP: ipD, Family: "ipv4", Class: ClassPublic}}},
	}
	got, private := deepCandidates(hosts, "acme.example", nil, nil)
	in := map[string]bool{}
	for _, a := range got {
		in[a.ip.String()] = a.inZone
	}
	if len(got) != 2 || !in[ipC] || in[ipD] || private == 0 {
		t.Fatalf("candidates %+v, private %d", got, private)
	}
	if _, ok := in[ipD]; !ok {
		t.Fatalf("candidates %+v", got)
	}
}

// review r1 L7: the runner's "box" claim on an address that is not the box's, with no domain fence, sends nothing: the re-check refuses it.
func TestContract_INV28_Deep_RunnerBoxClaimIsChecked(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.acceptTerms(d.dom.ID, false)
	d.run.content.Hosts[1].IPs[0].Class = ClassBox // www on ipB, which is not the box's
	s := d.scan()
	if _, called := d.seams.call(ipB); called {
		t.Fatal("ipB was scanned")
	}
	if deepOf(s, ipB).Deep != DeepRefused || !hasLine(s, ipB+" (api.acme.example, www.acme.example): not scanned at depth: "+deepNoFence) {
		t.Fatalf("ipB = %+v; not checked %q", deepOf(s, ipB), notChecked(s))
	}
}

// review r1 M2: an address whose service identification did not run is not "scanned": no new LastDeep, and the ports an earlier run
// found there are kept unchecked rather than closed after two such runs.
func TestContract_INV28_Deep_NmapDidNotRunKeepsPorts(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.seams.extra = []ServiceRow{{IP: ipB, Port: 8443, Name: "https", Product: "nginx"}}
	s := d.scan()
	first := deepOf(s, ipB).LastDeep
	if deepOf(s, ipB).Deep != DeepScanned || first == "" {
		t.Fatalf("ipB = %+v", deepOf(s, ipB))
	}
	d.seams.mu.Lock()
	d.seams.svcErr = &Unavailable{Reason: "the scan module is busy"}
	d.seams.mu.Unlock()
	for range 2 {
		d.advance(ScanEvery + time.Minute)
		s = d.scan()
	}
	if a := deepOf(s, ipB); a.Deep != DeepIncomplete || a.LastDeep != first || a.LastTried == first {
		t.Fatalf("ipB = %+v", a)
	}
	if !slices.ContainsFunc(s.Ports, func(p PortRow) bool { return p.IP == ipB && p.Port == 8443 }) {
		t.Fatalf("the port nmap found before was dropped: %+v", s.Ports)
	}
	if !hasLine(s, deepNoNmap) {
		t.Fatalf("not checked %q", notChecked(s))
	}
}

// review r1 M3: an address the re-check refuses takes no place: with 3 always-refused addresses before 3 others, the 3 others are
// scanned in each run.
func TestContract_INV28_Deep_RefusedTakesNoPlace(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	ips := []string{"9.9.9.1", "9.9.9.2", "9.9.9.3", "9.9.9.4", "9.9.9.5", "9.9.9.6"}
	var hosts []HostRow
	for i, ip := range ips {
		name := fmt.Sprintf("h%d.acme.example", i+1)
		hosts = append(hosts, HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}})
		if i < 3 {
			d.dns.point(name, ipD) // moved: refused at the re-check
		} else {
			d.dns.point(name, ip)
		}
	}
	d.run.content = Content{Hosts: hosts, Ports: []PortRow{}}
	for run := range 2 {
		if run > 0 {
			d.advance(ScanEvery + time.Minute)
			d.seams.mu.Lock()
			d.seams.services = nil
			d.seams.mu.Unlock()
		}
		s := d.scan()
		if got := d.seams.serviceIPs(); !slices.Equal(got, ips[3:]) {
			t.Fatalf("run %d scanned %v", run, got)
		}
		for _, ip := range ips[:3] {
			if a := deepOf(s, ip); a.Deep != DeepRefused || a.LastTried == "" {
				t.Fatalf("run %d: %s = %+v", run, ip, a)
			}
		}
	}
}

// review r2 M1: the CNAME rule fails closed: with the tick on, a name whose CNAME cannot be looked up right before the step (here every
// CNAME lookup fails, and the runner's row has no CNAME) gets no disruptive checks, and a line says why.
func TestContract_INV28_Deep_CNAMELookupFailsClosed(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	d.dns.mu.Lock()
	d.dns.cnameErr = errors.New("timeout")
	d.dns.mu.Unlock()
	s := d.scan()
	st, called := d.seams.call(ipB)
	if !called || !st.Mode.Full || st.Mode.Disruptive {
		t.Fatalf("ipB step = %+v (called %v)", st.Mode, called)
	}
	for _, c := range d.seams.templates {
		if c.st.Mode.Disruptive {
			t.Fatalf("templates with the disruptive checks: %+v", c)
		}
	}
	if !hasLine(s, ipB+" (api.acme.example, www.acme.example): the box could not confirm right before the scan that its name stays inside this domain (CNAME lookup)") {
		t.Fatalf("not checked %q", notChecked(s))
	}
}

// review r2 N1: the "did not probe every port" keep-rule is per address. ipC's deep nmap does not finish (its "ports" Not checked
// line), so its port 10022, found by an earlier deep scan, is kept unchecked; ipB's deep nmap finished, so its closed 10022 is missed
// by one scan and closed by the next, as INV-22 says.
func TestContract_INV28_Deep_KeepRuleIsPerAddress(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, false)
	d.seams.extra = []ServiceRow{{IP: ipB, Port: 10022, Name: "ssh", Product: "OpenSSH"}, {IP: ipC, Port: 10022, Name: "ssh", Product: "OpenSSH"}}
	s := d.scan()
	port := func(s Snapshot, ip string) (PortRow, bool) {
		i := slices.IndexFunc(s.Ports, func(p PortRow) bool { return p.IP == ip && p.Port == 10022 })
		if i < 0 {
			return PortRow{}, false
		}
		return s.Ports[i], true
	}
	if _, ok := port(s, ipB); !ok {
		t.Fatalf("first scan ports %+v", s.Ports)
	}
	if _, ok := port(s, ipC); !ok {
		t.Fatalf("first scan ports %+v", s.Ports)
	}
	d.seams.mu.Lock()
	d.seams.extra = nil // ipB closed 10022
	d.seams.errFor = map[string]error{ipC: ErrServicesTimedOut}
	d.seams.mu.Unlock()
	d.advance(ScanEvery + time.Minute)
	s = d.scan()
	if b, ok := port(s, ipB); !ok || b.Misses != 1 || b.Unchecked {
		t.Fatalf("ipB after one miss: %+v %v", b, ok)
	}
	if c, ok := port(s, ipC); !ok || c.Misses != 0 || !c.Unchecked {
		t.Fatalf("ipC (nmap did not finish): %+v %v", c, ok)
	}
	d.advance(ScanEvery + time.Minute)
	s = d.scan()
	if b, ok := port(s, ipB); ok {
		t.Fatalf("ipB's closed port is still listed: %+v", b)
	}
	if c, ok := port(s, ipC); !ok || !c.Unchecked {
		t.Fatalf("ipC: %+v %v", c, ok)
	}
}
