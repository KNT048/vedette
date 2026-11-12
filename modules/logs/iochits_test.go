package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

// fakeFeeds is the Feeds port of the tests: a fixed list, a count of the lookups and the failures to answer with.
type fakeFeeds struct {
	mu     sync.Mutex
	listed map[string]Listing // by "kind:value"
	calls  []string
	err    error
	hook   func(ctx context.Context) // runs inside every lookup
	noSub  bool                      // no switched-on feed lists subdomains (Subdomains says false)
	subs   int                       // calls of Subdomains
}

func (f *fakeFeeds) Lookup(ctx context.Context, kind, value string) (Listing, bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, kind+":"+value)
	err, hook := f.err, f.hook
	l, ok := f.listed[kind+":"+value]
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	if err != nil {
		return Listing{}, false, err
	}
	return l, ok, nil
}

func (f *fakeFeeds) On() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !errors.Is(f.err, ErrFeedsOff)
}

func (f *fakeFeeds) Listed(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.listed) > 0, nil
}

func (f *fakeFeeds) Subdomains(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs++
	return !f.noSub, nil
}

func (f *fakeFeeds) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeFeeds) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// iocPubs records both events of a hit, in the order they were published.
type iocPubs struct {
	mu    sync.Mutex
	order []string
	hits  []IocHit
	bad   []BadAddressEvent
	// onPublish, when set, runs for every event with its name and the id of the hit (before it is recorded here).
	onPublish func(ctx context.Context, name, id string)
}

func (p *iocPubs) Publish(ctx context.Context, e events.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch e.Name {
	case EventIocHit:
		p.hits = append(p.hits, e.Data.(IocHit))
		if p.onPublish != nil {
			p.onPublish(ctx, e.Name, e.Data.(IocHit).ID)
		}
	case EventBadAddress:
		p.bad = append(p.bad, e.Data.(BadAddressEvent))
		if p.onPublish != nil {
			p.onPublish(ctx, e.Name, e.Data.(BadAddressEvent).ID)
		}
	default:
		return fmt.Errorf("unexpected event %s", e.Name)
	}
	p.order = append(p.order, e.Name)
	return nil
}

func (p *iocPubs) counts() (hit, bad int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.hits), len(p.bad)
}

const (
	badIP     = "185.220.101.47"
	badDomain = "bad.example.net"
	lanDevice = "192.168.10.1" // the device of fakeInv: a-fw "FW-HQ"
)

// iocEnv is an environment with the feed list, the events and a FortiGate source at the address of the known device.
func iocEnv(t *testing.T) (*env, Source, *fakeFeeds, *iocPubs) {
	t.Helper()
	e := newEnv(t)
	ff := &fakeFeeds{listed: map[string]Listing{
		"ip:" + badIP:         {Feeds: []string{"Feodo", "Blocklist"}, Confidence: 0.9},
		"domain:" + badDomain: {Feeds: []string{"URLhaus"}, Confidence: 0.6},
	}}
	p := &iocPubs{}
	e.svc.cfg.Feeds, e.svc.cfg.Events = ff, p
	return e, e.add("FW-HQ", "192.168.10.200"), ff, p
}

func traffic(local, dst string) string {
	return fmt.Sprintf(`date=2026-11-09 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=%s srcport=51234 dstip=%s dstport=443 action="accept" policyid=5`, local, dst)
}

func dnsLine(local, name string) string {
	return fmt.Sprintf(`date=2026-11-09 time=10:22:00 logid="1501054802" type="utm" subtype="dns" level="notice" srcip=%s dstip=192.168.10.1 qname="%s" qtype="A" action="pass"`, local, name)
}

func hitCount(t *testing.T, e *env) int { return count(t, e.vol, `SELECT count(*) FROM logs_ioc_hits`) }

// POST-2: a known-bad address in a firewall line is one hit, one logs.ioc_hit.detected and one logs.bad_address.detected, in this order,
// with the device resolved and the line stored as before.
func TestContract_POST2_AKnownBadAddressIsOneHitAndTwoEvents(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if n := count(t, e.vol, `SELECT count(*) FROM logs_events`); n != 1 {
		t.Fatalf("%d lines stored", n)
	}
	if n := hitCount(t, e); n != 1 {
		t.Fatalf("%d hits", n)
	}
	if h, b := p.counts(); h != 1 || b != 1 || p.order[0] != EventIocHit || p.order[1] != EventBadAddress {
		t.Fatalf("events %v", p.order)
	}
	h := p.hits[0]
	if h.SrcIP != lanDevice || h.Dest != badIP || h.DestKind != "ip" || h.SeenVia != "syslog:FW-HQ" || h.Confidence != 0.9 || strings.Join(h.Feeds, ",") != "Blocklist,Feodo" ||
		h.AssetID == nil || *h.AssetID != "a-fw" || *h.AssetName != "FW-HQ" || h.ID == "" || !h.TS.Equal(t0) {
		t.Errorf("ioc hit %+v", h)
	}
	b := p.bad[0]
	if b.Source != "logs" || b.Target != "ioc:"+badIP || b.ID != h.ID || b.SrcIP != lanDevice || b.Dest != badIP || b.DestKind != "ip" || b.SeenVia != "syslog:FW-HQ" ||
		b.AssetID == nil || *b.AssetID != "a-fw" || len(b.Devices) != 1 || b.Devices[0].ID != "a-fw" || b.Severity != "high" ||
		len([]rune(b.Title)) > MaxEventTitle || !strings.Contains(b.Title, badIP) || !strings.Contains(b.What, "Blocklist, Feodo") || b.Action == "" {
		t.Errorf("bad address %+v", b)
	}
	if got := ff.lookups(); len(got) != 1 || got[0] != "ip:"+badIP {
		t.Errorf("lookups %v", got)
	}
	// What notify and the SIEM forwarder decode out of the payload.
	raw, _ := json.Marshal(b)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"source", "target", "title", "what", "action", "severity", "devices", "id", "src_ip", "dest", "dest_kind", "seen_via", "asset_id"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the payload has no %q", k)
		}
	}
}

// A domain in a DNS line and in a web filter line is a domain hit; the web filter line also looks up the address.
func TestIOCDomainHits(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	e.feedAll(src, []string{dnsLine(lanDevice, "Bad.Example.NET.")})
	if h, _ := p.counts(); h != 1 || p.hits[0].Dest != badDomain || p.hits[0].DestKind != "domain" || p.hits[0].Confidence != 0.6 {
		t.Fatalf("%+v", p.hits)
	}
	if got := ff.lookups(); len(got) != 1 || got[0] != "domain:"+badDomain { // the resolver (a private address) is not looked up
		t.Errorf("lookups %v", got)
	}
	web := `logid="0316013056" type="utm" subtype="webfilter" srcip=192.168.10.77 dstip=` + badIP + ` hostname="bad.example.net" action="blocked"`
	e.feedAll(src, []string{web})
	if n := hitCount(t, e); n != 3 { // one more for the address and one for the name of another device
		t.Fatalf("%d hits", n)
	}
	if d := e.digest(); len(d.BadConnections) != 3 {
		t.Fatalf("digest %d", len(d.BadConnections))
	}
}

// D-228: a feed that lists a name with all of its subdomains (hagezi TIF) makes a subdomain the device asked for a hit; the hit keeps the
// name asked for and the listed name (listed_as, D-425), the incident says which name is listed and is keyed on it, and the parents that
// names of a batch share are looked up once. Another device asking for a subdomain of the same name is its own hit.
func TestIOCSubdomainOfANameListedWithItsSubdomains(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	ff.listed["domain:tif-listed.net"] = Listing{Feeds: []string{"hagezi TIF"}, Confidence: 0.8, SubFeeds: []string{"hagezi TIF"}, SubConfidence: 0.8}
	e.feedAll(src, []string{dnsLine(lanDevice, "A.B.Tif-Listed.NET."), dnsLine("192.168.10.106", "c.tif-listed.net")})
	if h, b := p.counts(); h != 2 || b != 2 {
		t.Fatalf("%d hits %d events", h, b)
	}
	for i, want := range []string{"a.b.tif-listed.net", "c.tif-listed.net"} {
		h, b := p.hits[i], p.bad[i]
		if h.Dest != want || h.DestKind != "domain" || h.Confidence != 0.8 || strings.Join(h.Feeds, ",") != "hagezi TIF" || h.ListedAs == nil || *h.ListedAs != "tif-listed.net" || b.Dest != want ||
			b.Target != "ioc:tif-listed.net" || !strings.Contains(b.What, "(listed as tif-listed.net, with all of its subdomains)") || !strings.Contains(b.Title, want) {
			t.Errorf("hit %d %+v %+v", i, h, b)
		}
	}
	got := strings.Join(ff.lookups(), " ")
	if got != "domain:a.b.tif-listed.net domain:b.tif-listed.net domain:tif-listed.net domain:c.tif-listed.net" {
		t.Errorf("lookups %s", got)
	}
	d := e.digest()
	if len(d.BadConnections) != 2 || d.BadConnections[0].ListedAs == nil || *d.BadConnections[0].ListedAs != "tif-listed.net" {
		t.Fatalf("digest %+v", d.BadConnections)
	}
	if h, ok, err := e.svc.IocHit(t.Context(), p.hits[0].ID); err != nil || !ok || h.ListedAs == nil || *h.ListedAs != "tif-listed.net" {
		t.Errorf("IocHit %+v %v %v", h, ok, err)
	}
}

// D-425: the random subdomains of one listed name that a device asks for are one hit in 24 hours (dedupe on (device, listed name)), in
// one batch and across batches, and so is the listed name itself; a hit on a name listed for itself keeps listed_as null.
func TestIOCSubdomainsOfOneListedNameAreOneHit(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	ff.listed["domain:tif-listed.net"] = Listing{Feeds: []string{"hagezi TIF"}, Confidence: 0.8, SubFeeds: []string{"hagezi TIF"}, SubConfidence: 0.8}
	e.feedAll(src, []string{dnsLine(lanDevice, "x1q9.tif-listed.net"), dnsLine(lanDevice, "k2v7.tif-listed.net"), dnsLine(lanDevice, badDomain)})
	e.advance(time.Hour)
	e.feedAll(src, []string{dnsLine(lanDevice, "z8w3.tif-listed.net"), dnsLine(lanDevice, "tif-listed.net")})
	if h, b := p.counts(); h != 2 || b != 2 || hitCount(t, e) != 2 {
		t.Fatalf("%d hits %d events %d rows", h, b, hitCount(t, e))
	}
	if p.hits[0].Dest != badDomain || p.hits[0].ListedAs != nil || p.hits[1].Dest != "k2v7.tif-listed.net" || p.hits[1].ListedAs == nil { // a batch's pairs go by name
		t.Errorf("hits %+v", p.hits)
	}
}

// D-425: without a switched-on feed that lists subdomains the parents of an unlisted name are not looked up; the question is asked once a batch.
func TestIOCNoParentWalkWithoutASubdomainFeed(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	ff.noSub = true
	ff.listed["domain:tif-listed.net"] = Listing{Feeds: []string{"hagezi TIF"}, Confidence: 0.8, SubFeeds: []string{"hagezi TIF"}, SubConfidence: 0.8}
	e.feedAll(src, []string{dnsLine(lanDevice, "a.tif-listed.net"), dnsLine(lanDevice, "b.tif-listed.net")})
	if h, _ := p.counts(); h != 0 {
		t.Fatalf("hits %+v", p.hits)
	}
	if got := strings.Join(ff.lookups(), " "); got != "domain:a.tif-listed.net domain:b.tif-listed.net" || ff.subs != 1 {
		t.Errorf("lookups %s, %d questions", got, ff.subs)
	}
}

// D-228: a feed that lists names exactly (no SubFeeds: a custom feed, URLhaus) never makes a subdomain a hit, and a top-level domain
// is never looked up, even if a feed listed it.
func TestIOCSubdomainOfAnExactListingOrATopLevelDomainIsNoHit(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	ff.listed["domain:net"] = Listing{Feeds: []string{"x"}, Confidence: 1, SubFeeds: []string{"x"}, SubConfidence: 1}
	e.feedAll(src, []string{dnsLine(lanDevice, "www."+badDomain), dnsLine(lanDevice, "fine.net")})
	if h, _ := p.counts(); h != 0 || hitCount(t, e) != 0 {
		t.Fatalf("hits %+v", p.hits)
	}
	got := strings.Join(ff.lookups(), " ")
	if got != "domain:fine.net domain:www."+badDomain+" domain:"+badDomain+" domain:example.net" { // in the order of the batch's pairs; never "domain:net"
		t.Errorf("lookups %s", got)
	}
}

// The walk keeps the shortest maxIocParents parents of a long name, nearest first, and never a single label.
func TestParentDomains(t *testing.T) {
	t.Parallel()
	if got := parentDomains("a.b.bad.example"); strings.Join(got, " ") != "b.bad.example bad.example" {
		t.Errorf("%v", got)
	}
	for _, n := range []string{"bad.example", "example", "", "a..example", ".a.example"} {
		if got := parentDomains(n); len(got) != 0 {
			t.Errorf("%q: %v", n, got)
		}
	}
	long := strings.Repeat("x.", 125) + "bad.example" // 127 labels
	got := parentDomains(long)
	if len(got) != maxIocParents || got[len(got)-1] != "bad.example" || got[0] != strings.Repeat("x.", 9)+"bad.example" {
		t.Errorf("%d parents, %q … %q", len(got), got[0], got[len(got)-1])
	}
}

// Private and special destinations are never looked up, and neither is a connection that is not from a LAN device.
func TestIOCOnlyPublicDestinationsFromLANDevices(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	ff.listed["ip:10.1.1.1"], ff.listed["ip:203.0.113.9"], ff.listed["ip:8.8.8.8"] = Listing{Feeds: []string{"x"}, Confidence: 1}, Listing{Feeds: []string{"x"}, Confidence: 1}, Listing{Feeds: []string{"x"}, Confidence: 1}
	var texts []string
	for _, d := range []string{"10.1.1.1", "192.168.1.1", "127.0.0.1", "169.254.9.9", "224.0.0.251", "100.64.1.1", "203.0.113.9", "198.51.100.5", "255.255.255.255", "0.0.0.0", "fc00::1", "::1"} {
		texts = append(texts, traffic(lanDevice, d))
	}
	for _, s := range []string{"8.8.8.8", "100.64.1.1", "127.0.0.1", "fd00::1", "-"} { // not a LAN device
		texts = append(texts, traffic(s, badIP))
	}
	e.feedAll(src, texts)
	if got := ff.lookups(); len(got) != 0 {
		t.Fatalf("lookups %v", got)
	}
	if hitCount(t, e) != 0 {
		t.Fatal("a hit")
	}
	if h, b := p.counts(); h+b != 0 {
		t.Fatal("an event")
	}
	// A device of another kind has no profile: its lines are never read for a destination.
	other, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "linux-rsyslog", Name: "box", SenderIP: "192.168.10.201", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	e.feedAll(other, []string{traffic(lanDevice, badIP), "kernel: IN=eth0 SRC=192.168.10.5 DST=" + badIP})
	if len(ff.lookups()) != 0 || hitCount(t, e) != 0 {
		t.Fatal("a device without a profile made a hit")
	}
}

// The box itself, its gateway and a decoy are not a device that made a connection (the NeverCount set of D-210).
func TestIOCNeverFromTheBox(t *testing.T) {
	t.Parallel()
	e, src, ff, _ := iocEnv(t)
	e.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.10.2")}, nil
	}
	e.feedAll(src, []string{traffic("192.168.10.2", badIP)})
	if len(ff.lookups()) != 0 || hitCount(t, e) != 0 {
		t.Fatal("the box made a hit")
	}
}

// D-213, the anti-framing rule: a field written twice, a user-controlled field that injects a field, or an odd quote is no connection.
func TestIOCAmbiguousLinesMakeNoHit(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	base := traffic(lanDevice, "8.8.4.4")
	e.feedAll(src, []string{
		strings.Replace(base, "dstport=443", "dstip="+badIP+" dstport=443", 1),                  // a second dstip
		strings.Replace(base, `devname="FW-HQ"`, `devname=FW-HQ dstip=`+badIP, 1),               // injected by a field the device did not quote
		strings.Replace(base, `devname="FW-HQ"`, `devname="a" "dstip=`+badIP+`"`, 1),            // a quoted word that holds a field
		strings.Replace(base, `devname="FW-HQ"`, `devname=a"b`, 1) + " dstip=" + badIP,          // an odd quote
		dnsLine(lanDevice, badDomain) + ` qname="other.example.org"`,                            // two names
		strings.Replace(base, "srcip="+lanDevice, "srcip="+lanDevice+" srcip=192.168.10.99", 1), // two devices
		strings.Replace(base, "dstip=8.8.4.4", "dstip="+badIP+" dstip="+badIP, 1),               // the same twice
	})
	if hitCount(t, e) != 0 {
		t.Fatalf("hits %v", p.hits)
	}
	if got := ff.lookups(); len(got) != 0 {
		t.Fatalf("lookups %v", got)
	}
	// Text inside a quoted value is not a field: the real one still counts, once.
	e.feedAll(src, []string{strings.Replace(traffic(lanDevice, badIP), `devname="FW-HQ"`, `devname="x dstip=8.8.8.8 srcip=10.9.9.9"`, 1)})
	if h, _ := p.counts(); h != 1 || p.hits[0].Dest != badIP || p.hits[0].SrcIP != lanDevice {
		t.Fatalf("%+v", p.hits)
	}
}

// The same device and destination are one hit and one pair of events for 24 hours, in a batch and across batches; after 24 hours it is new.
func TestIOCDedupe(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	e.feedAll(src, repeat(traffic(lanDevice, badIP), 5))
	e.advance(time.Hour)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	e.advance(22 * time.Hour) // 23 hours after the first
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, b := p.counts(); hitCount(t, e) != 1 || h != 1 || b != 1 {
		t.Fatalf("rows %d events %d %d", hitCount(t, e), h, b)
	}
	e.feedAll(src, []string{traffic("192.168.10.33", badIP)}) // another device is another hit
	if hitCount(t, e) != 2 {
		t.Fatal("another device made no hit")
	}
	e.advance(2 * time.Hour) // 25 hours after the first
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, _ := p.counts(); hitCount(t, e) != 3 || h != 3 {
		t.Fatalf("rows %d events %d", hitCount(t, e), h)
	}
	if d := e.digest(); len(d.BadConnections) != 2 { // the first is 25 hours old: not in the digest
		t.Fatalf("digest %d", len(d.BadConnections))
	}
}

// PRE-3: with the feeds off the lines are stored, nothing is announced, the digest has no bad connections, and nothing is warned about.
// QA walk a: the digest says when no connection can be matched (no switched-on feed lists an indicator, the feeds module off, no port),
// so an empty list is not read as "none of your devices connected to a listed address".
func TestDigestSaysWhetherConnectionsCanBeMatched(t *testing.T) {
	t.Parallel()
	e, _, ff, _ := iocEnv(t)
	if !e.digest().IOCMatching {
		t.Fatal("indicators listed, digest says nothing can be matched")
	}
	ff.mu.Lock()
	listed := ff.listed
	ff.listed = nil
	ff.mu.Unlock()
	if e.digest().IOCMatching {
		t.Fatal("nothing listed, digest says it can match")
	}
	ff.mu.Lock()
	ff.listed = listed
	ff.mu.Unlock()
	ff.setErr(ErrFeedsOff)
	if e.digest().IOCMatching {
		t.Fatal("feeds off, digest says it can match")
	}
	e.svc.cfg.Feeds = nil
	if e.digest().IOCMatching {
		t.Fatal("no feeds port, digest says it can match")
	}
}

func TestContract_PRE3_FeedsOffMakeNoHits(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	logs := &logCapture{}
	e.svc.cfg.Log = slog.New(logs)
	ff.setErr(ErrFeedsOff)
	for range 3 {
		e.feedAll(src, []string{traffic(lanDevice, badIP), traffic(lanDevice, "9.9.9.9")})
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_events`); n != 6 {
		t.Fatalf("%d lines", n)
	}
	if got := ff.lookups(); len(got) != 3 { // the first lookup of a batch says it, the others of the batch are not made
		t.Errorf("lookups %v", got)
	}
	if hitCount(t, e) != 0 || len(e.digest().BadConnections) != 0 {
		t.Fatal("a hit with the feeds off")
	}
	if h, _ := p.counts(); h != 0 || logs.count("threat feeds") != 0 {
		t.Fatal("an event or a warning with the feeds off")
	}
	// Hits stored while the feeds were on are kept, and not shown while they are off (PRE-3).
	ff.setErr(nil)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if len(e.digest().BadConnections) != 1 {
		t.Fatal("no hit with the feeds on")
	}
	ff.setErr(ErrFeedsOff)
	if len(e.digest().BadConnections) != 0 || hitCount(t, e) != 1 {
		t.Fatal("the digest shows hits with the feeds off, or the rows were dropped")
	}
	// No port at all is the same.
	e.svc.cfg.Feeds = nil
	e.feedAll(src, []string{traffic("192.168.10.9", badIP)})
	if hitCount(t, e) != 1 {
		t.Fatal("a hit with no feeds")
	}
}

// A feed that cannot be read never blocks the ingest or drops a line; the failure is logged once, and again after a lookup worked.
func TestIOCLookupFailureNeverBlocksIngest(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	logs := &logCapture{}
	e.svc.cfg.Log = slog.New(logs)
	ff.setErr(errors.New("database is locked"))
	for range 4 {
		res, err := e.svc.Ingest(t.Context(), lines(src.ID, e.svc.now(), traffic(lanDevice, badIP), traffic("192.168.10.9", badIP)))
		if err != nil || res.Stored != 2 {
			t.Fatalf("%+v %v", res, err)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_events`); n != 8 {
		t.Fatalf("%d lines", n)
	}
	if n := logs.count("threat feeds"); n != 1 {
		t.Fatalf("%d warnings for one failure", n)
	}
	if hitCount(t, e) != 0 {
		t.Fatal("a hit from a failed lookup")
	}
	ff.setErr(nil) // recovery: the next batch matches, and a new failure is news again
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, _ := p.counts(); h != 1 {
		t.Fatalf("%d events after recovery", h)
	}
	ff.setErr(errors.New("database is locked"))
	e.feedAll(src, []string{traffic("192.168.10.5", badIP)})
	if n := logs.count("threat feeds"); n != 2 {
		t.Fatalf("%d warnings", n)
	}
}

// The lookups run before the transaction of the batch: a lookup that needs the writer of logs.db is not blocked by Ingest.
func TestIOCLookupRunsOutsideTheWriteTransaction(t *testing.T) {
	t.Parallel()
	e, src, ff, _ := iocEnv(t)
	var wrote error
	ff.hook = func(ctx context.Context) {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		wrote = e.vol.Write(cctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(cctx, `UPDATE logs_volume SET line_bytes = line_bytes WHERE id = 1`)
			return err
		})
	}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if wrote != nil {
		t.Fatalf("a lookup waited for the writer: %v", wrote)
	}
}

// A flood is bounded: a batch stores at most MaxIocHitsPerBatch new hits, an hour announces at most IocEventsPerHour, and the table
// holds at most MaxIocRows.
func TestIOCFloodIsBounded(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	var texts []string
	for i := range MaxBatch {
		d := fmt.Sprintf("45.%d.%d.9", i/200+1, i%200+1)
		ff.listed["ip:"+d] = Listing{Feeds: []string{"flood"}, Confidence: 0.5}
		texts = append(texts, traffic(lanDevice, d))
	}
	e.feedAll(src, texts)
	if n := hitCount(t, e); n != MaxIocHitsPerBatch {
		t.Fatalf("%d rows from one batch", n)
	}
	if h, b := p.counts(); h != MaxIocHitsPerBatch || b != MaxIocHitsPerBatch {
		t.Fatalf("%d %d events", h, b)
	}
	// the next batches: more rows, but the hour's budget of announcements runs out
	for k := 1; k <= 3; k++ {
		var more []string
		for i := range MaxIocHitsPerBatch {
			d := fmt.Sprintf("46.%d.%d.9", k, i+1)
			ff.listed["ip:"+d] = Listing{Feeds: []string{"flood"}, Confidence: 0.5}
			more = append(more, traffic(lanDevice, d))
		}
		e.feedAll(src, more)
	}
	if h, b := p.counts(); h != IocEventsPerHour || b != IocEventsPerHour {
		t.Fatalf("%d %d events in an hour", h, b)
	}
	if n := hitCount(t, e); n != 4*MaxIocHitsPerBatch {
		t.Fatalf("%d rows: a hit past the budget must still be stored", n)
	}
	e.advance(time.Hour) // the next clock hour: the budget is new
	ff.listed["ip:47.0.0.9"] = Listing{Feeds: []string{"flood"}, Confidence: 0.5}
	e.feedAll(src, []string{traffic(lanDevice, "47.0.0.9")})
	if h, _ := p.counts(); h != IocEventsPerHour+1 {
		t.Fatalf("%d events", h)
	}
}

func TestIOCRowCapKeepsTheNewest(t *testing.T) {
	t.Parallel()
	e, src, _, _ := iocEnv(t)
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
			INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id)
			SELECT 'old-' || i, strftime('%Y-%m-%dT%H:%M:%fZ', '2026-11-08 00:00:00', '+' || i || ' seconds'), '192.168.10.9', 'x' || i || '.example.org', 'domain', 'syslog:x', '[]', 0.5, 'ls-x' FROM n`, MaxIocRows)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if n := hitCount(t, e); n != MaxIocRows {
		t.Fatalf("%d rows", n)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_ioc_hits WHERE dest = ?`, badIP) != 1 || count(t, e.vol, `SELECT count(*) FROM logs_ioc_hits WHERE id = 'old-1'`) != 0 {
		t.Fatal("the cap did not drop the oldest and keep the newest")
	}
}

// INV-7: the device is looked up when the hit is read, not stored: a device that is renamed shows its new name, and an unknown address has none.
func TestContract_INV7_TheDeviceIsResolvedAtRead(t *testing.T) {
	t.Parallel()
	e, src, _, _ := iocEnv(t)
	inv := fakeInv{byIP: map[string]Device{lanDevice: {ID: "a-1", Name: "Reception PC"}}}
	e.svc.cfg.Inventory = inv
	e.feedAll(src, []string{traffic(lanDevice, badIP), traffic("192.168.10.77", badIP)})
	if count(t, e.vol, `SELECT count(*) FROM pragma_table_info('logs_ioc_hits') WHERE name LIKE 'asset%'`) != 0 {
		t.Fatal("the device is stored")
	}
	byIP := func() map[string]IocHit {
		out := map[string]IocHit{}
		for _, h := range e.digest().BadConnections {
			out[h.SrcIP] = h
		}
		return out
	}
	got := byIP()
	if h := got[lanDevice]; h.AssetID == nil || *h.AssetID != "a-1" || *h.AssetName != "Reception PC" {
		t.Fatalf("%+v", h)
	}
	if h := got["192.168.10.77"]; h.AssetID != nil || h.AssetName != nil {
		t.Fatalf("an unknown address has a device: %+v", h)
	}
	inv.byIP[lanDevice] = Device{ID: "a-1", Name: "Front desk\u202e"}
	inv.byIP["192.168.10.77"] = Device{ID: "a-2", Name: "Printer"}
	got = byIP()
	if h := got[lanDevice]; *h.AssetName != "Front desk" {
		t.Errorf("the new name is not shown, or is not plain text: %q", *h.AssetName)
	}
	if h := got["192.168.10.77"]; h.AssetID == nil || *h.AssetID != "a-2" {
		t.Errorf("a device added later is not found: %+v", h)
	}
	delete(inv.byIP, lanDevice)
	if h := byIP()[lanDevice]; h.AssetID != nil {
		t.Errorf("a deleted device is still shown: %+v", h)
	}
}

// The digest shows a hit at once, also after an earlier digest (the hits are not part of the cached reading of the counters).
func TestIOCDigestShowsANewHitAtOnce(t *testing.T) {
	t.Parallel()
	e, src, _, _ := iocEnv(t)
	if d := e.digest(); len(d.BadConnections) != 0 {
		t.Fatal("a hit on a clean box")
	}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	d, err := e.svc.Digest(t.Context()) // no dropSnapshot: the stored reading is still current
	if err != nil || len(d.BadConnections) != 1 {
		t.Fatalf("%v %+v", err, d.BadConnections)
	}
	raw, _ := json.Marshal(d)
	if !strings.Contains(string(raw), `"bad_connections":[{`) {
		t.Fatalf("%s", raw)
	}
	clean, _ := json.Marshal(Digest{BadConnections: []IocHit{}})
	if !strings.Contains(string(clean), `"bad_connections":[]`) {
		t.Fatalf("%s", clean)
	}
	for i := range 30 { // the digest lists at most DigestMax, the newest first
		e.advance(time.Second)
		dst := fmt.Sprintf("60.0.0.%d", i+1)
		e.svc.cfg.Feeds.(*fakeFeeds).listed["ip:"+dst] = Listing{Feeds: []string{"f"}, Confidence: 0.5}
		e.feedAll(src, []string{traffic(lanDevice, dst)})
	}
	d = e.digest()
	if len(d.BadConnections) != DigestMax || d.BadConnections[0].Dest != "60.0.0.30" {
		t.Fatalf("%d, first %s", len(d.BadConnections), d.BadConnections[0].Dest)
	}
}

// Confidence is the highest of the feeds, kept in [0,1]; the feed names are plain, sorted and bounded.
func TestIOCConfidenceAndFeedNames(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	long := strings.Repeat("n", 100)
	ff.listed["ip:70.0.0.1"] = Listing{Feeds: []string{"b", "a", "b", "c\nd", long, "", "1", "2", "3", "4", "5", "6"}, Confidence: 7}
	ff.listed["ip:70.0.0.2"] = Listing{Feeds: []string{"x"}, Confidence: -1}
	e.feedAll(src, []string{traffic(lanDevice, "70.0.0.1"), traffic(lanDevice, "70.0.0.2")})
	byDest := map[string]IocHit{}
	for _, h := range p.hits {
		byDest[h.Dest] = h
	}
	if h := byDest["70.0.0.1"]; h.Confidence != 1 || len(h.Feeds) != MaxIocFeeds || strings.ContainsAny(strings.Join(h.Feeds, ""), "\n") || h.Feeds[len(h.Feeds)-1] == "" {
		t.Errorf("%+v", h)
	}
	if h := byDest["70.0.0.2"]; h.Confidence != 0 {
		t.Errorf("%+v", h)
	}
	for _, f := range byDest["70.0.0.1"].Feeds {
		if len([]rune(f)) > 64 {
			t.Errorf("a feed name of %d characters", len([]rune(f)))
		}
	}
	// A destination that no feed lists any more (a listing with no feed) is no hit.
	ff.listed["ip:70.0.0.3"] = Listing{Confidence: 1}
	e.feedAll(src, []string{traffic(lanDevice, "70.0.0.3")})
	if hitCount(t, e) != 2 {
		t.Fatalf("%d hits", hitCount(t, e))
	}
}

// The read ports return what the digest shows (response's evidence lookup and ioc_connection trigger).
func TestIOCReadPortsAgreeWithTheDigest(t *testing.T) {
	t.Parallel()
	e, src, _, _ := iocEnv(t)
	e.feedAll(src, []string{traffic(lanDevice, badIP), dnsLine("192.168.10.9", badDomain)})
	d := e.digest()
	if len(d.BadConnections) != 2 {
		t.Fatalf("%d", len(d.BadConnections))
	}
	for _, want := range d.BadConnections {
		got, ok, err := e.svc.IocHit(t.Context(), want.ID)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if err != nil || !ok || string(g) != string(w) {
			t.Fatalf("IocHit(%s) = %s %v %v, the digest shows %s", want.ID, g, ok, err, w)
		}
	}
	for _, id := range []string{"", "ih-nope", strings.Repeat("x", 65), "' OR 1=1 --"} {
		if _, ok, err := e.svc.IocHit(t.Context(), id); ok || err != nil {
			t.Errorf("IocHit(%q) = %v %v", id, ok, err)
		}
	}
	all, err := e.svc.IocHits(t.Context(), t0.Add(-time.Hour), 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("%v %d", err, len(all))
	}
	high, err := e.svc.IocHits(t.Context(), t0.Add(-time.Hour), 0.8)
	if err != nil || len(high) != 1 || high[0].Dest != badIP {
		t.Fatalf("%v %+v", err, high)
	}
	if none, _ := e.svc.IocHits(t.Context(), t0.Add(time.Hour), 0); len(none) != 0 {
		t.Fatal("a hit from the future")
	}
}

// INV-4 and SYS-5: the purge drops hits older than the retention and announces nothing; no new job was added and only the purge is housekeeping.
func TestIOCPurgeFollowsTheRetentionAndIsSilent(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 7); err != nil {
		t.Fatal(err)
	}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	e.advance(6 * 24 * time.Hour)
	e.feedAll(src, []string{traffic("192.168.10.5", badIP)})
	h0, b0 := p.counts()
	e.advance(2 * 24 * time.Hour) // the first hit is 8 days old, the second 2
	if err := e.svc.dropStale(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := hitCount(t, e); n != 1 {
		t.Fatalf("%d hits after the purge", n)
	}
	if h, b := p.counts(); h != h0 || b != b0 {
		t.Fatal("the purge announced something")
	}
	var names []string
	for _, j := range Jobs(e.svc) {
		names = append(names, j.Name)
		if j.Housekeeping != (j.Name == "purge") {
			t.Errorf("job %s housekeeping %v", j.Name, j.Housekeeping)
		}
	}
	if len(names) != 4 {
		t.Errorf("jobs %v", names)
	}
}

// The text of a hit that a person reads is one line of plain text, cut to what notify takes, whatever a device or an operator named things.
func TestIOCEventTextIsPlainAndBounded(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	e.svc.cfg.Inventory = fakeInv{byIP: map[string]Device{lanDevice: {ID: "a-1", Name: "PC\n<script>" + strings.Repeat("é", 400) + "\u202e\x00"}}}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	b := p.bad[0]
	for _, s := range []string{b.Title, b.What, b.Action, b.Target, b.Devices[0].Name, b.Source} {
		if strings.ContainsAny(s, "\n\r\x00\u202e") {
			t.Errorf("control character in %q", s)
		}
	}
	if len([]rune(b.Title)) > MaxEventTitle || len([]rune(b.What)) > MaxEventText || len([]rune(b.Target)) > MaxEventKey || len([]rune(b.Devices[0].Name)) > MaxDeviceName {
		t.Errorf("too long: %d %d %d", len([]rune(b.Title)), len([]rune(b.What)), len([]rune(b.Devices[0].Name)))
	}
	if b.Severity != "high" {
		t.Errorf("severity %s", b.Severity)
	}
	// A weak listing is a medium incident.
	e.svc.cfg.Feeds.(*fakeFeeds).listed["ip:71.0.0.1"] = Listing{Feeds: []string{"f"}, Confidence: 0.3}
	e.feedAll(src, []string{traffic("192.168.10.88", "71.0.0.1")})
	if got := p.bad[len(p.bad)-1]; got.Severity != "medium" || len(got.Devices) != 0 || !strings.Contains(got.Title, "192.168.10.88") {
		t.Errorf("%+v", got)
	}
}

// A bus that fails to take an event does not fail the batch or lose the hit.
func TestIOCPublishFailureKeepsTheHit(t *testing.T) {
	t.Parallel()
	e, src, _, _ := iocEnv(t)
	e.svc.cfg.Events = failingPublisher{}
	res, err := e.svc.Ingest(t.Context(), lines(src.ID, e.svc.now(), traffic(lanDevice, badIP)))
	if err != nil || res.Stored != 1 || hitCount(t, e) != 1 {
		t.Fatalf("%+v %v %d", res, err, hitCount(t, e))
	}
	e.svc.cfg.Events = nil // no bus: nothing is sent and nothing fails
	e.feedAll(src, []string{traffic("192.168.10.9", badIP)})
	if hitCount(t, e) != 2 {
		t.Fatal("no bus lost a hit")
	}
}

type failingPublisher struct{}

func (failingPublisher) Publish(context.Context, events.Event) error {
	return errors.New("bus is down")
}

// The SIEM forwarder sends a bad connection once: with both "alerts" and "bad_conn" the incident that notify opens from the same connection is
// left out of the alerts, and the other incidents are not.
func TestSiemSendsABadConnectionOnce(t *testing.T) {
	e := newSiemEnv(t)
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	e.svc.Subscribe(bus)
	queued := func() []siemRecord { r, _ := e.svc.siemQ.peek(100); return r }
	arm := func(evs ...string) {
		e.saveSiem(SiemInput{Enabled: true, Format: "syslog", Host: "192.168.10.50", Port: 514, Proto: "udp", Events: evs})
		e.svc.siemRunning.Store(true)
		row, err := e.svc.loadSiem(t.Context(), e.cfg.Reader(), false)
		if err != nil {
			t.Fatal(err)
		}
		e.svc.siemCache.Store(&row)
		e.svc.siemQ.clear()
	}
	both := func() {
		publish(t, bus, siemEventBadAddress, map[string]any{"id": "ih-1", "src_ip": "10.0.0.9", "dest": "bad.example", "dest_kind": "domain"})
		publish(t, bus, siemEventIncident, map[string]any{"id": "i-1", "kind": "bad_address", "severity": "high"})
		publish(t, bus, siemEventIncident, map[string]any{"id": "i-2", "kind": "trap", "severity": "high"})
	}
	arm("alerts", "bad_conn")
	both()
	var names []string
	for _, r := range queued() {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "ioc.hit,incident.created" || queued()[1].Fields[0].Val != "i-2" {
		t.Fatalf("alerts and bad_conn: %v", names)
	}
	arm("alerts") // without bad_conn the incident is the only record of the connection: it is sent
	both()
	if r := queued(); len(r) != 2 || r[0].Fields[0].Val != "i-1" || r[1].Fields[0].Val != "i-2" {
		t.Fatalf("alerts only: %+v", r)
	}
	arm("bad_conn")
	both()
	if r := queued(); len(r) != 1 || r[0].Name != "ioc.hit" {
		t.Fatalf("bad_conn only: %+v", r)
	}
}

// M1: a chatty device that meets listed addresses it already has hits for does not use the cap of the batch: another device's first hit is stored.
func TestIOCChattyDeviceDoesNotHideAnotherDevicesFirstHit(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	var chatty []string
	for i := range MaxIocHitsPerBatch {
		d := fmt.Sprintf("48.0.0.%d", i+1)
		ff.listed["ip:"+d] = Listing{Feeds: []string{"f"}, Confidence: 0.5}
		chatty = append(chatty, traffic(lanDevice, d))
	}
	e.feedAll(src, chatty)
	if hitCount(t, e) != MaxIocHitsPerBatch {
		t.Fatalf("%d rows", hitCount(t, e))
	}
	for range 3 { // the same 50 pairs every batch, and another device that meets one of the addresses for the first time
		e.feedAll(src, append(append([]string(nil), chatty...), traffic("192.168.10.77", "48.0.0.1")))
		if n := hitCount(t, e); n != MaxIocHitsPerBatch+1 {
			t.Fatalf("%d rows: a repeated pair was stored again or the new one is missing", n)
		}
		if count(t, e.vol, `SELECT count(*) FROM logs_ioc_hits WHERE src_ip = '192.168.10.77'`) != 1 {
			t.Fatal("the first hit of another device is hidden")
		}
	}
	if h, _ := p.counts(); h != MaxIocHitsPerBatch+1 {
		t.Fatalf("%d events", h)
	}
}

// M5: the events are published after the commit: a subscriber that asks for the hit by its id finds it.
func TestIOCEventsAreAfterTheCommit(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	var found, asked int
	p.onPublish = func(ctx context.Context, _, id string) {
		asked++
		if _, ok, err := e.svc.IocHit(ctx, id); err == nil && ok {
			found++
		}
	}
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if asked != 2 || found != 2 {
		t.Fatalf("asked %d, found %d: an event was published before its hit was committed", asked, found)
	}
}

// A context that is cancelled right after the commit (a listener that is stopping) does not stop the announcement.
func TestIOCAnnouncesEvenIfTheIngestContextIsCancelled(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	e.svc.cfg.Events = cancelAfterCommit{p, cancel}
	if _, err := e.svc.Ingest(ctx, lines(src.ID, e.svc.now(), traffic(lanDevice, badIP))); err != nil {
		t.Fatal(err)
	}
	if h, b := p.counts(); h != 1 || b != 1 {
		t.Fatalf("%d %d events", h, b)
	}
}

type cancelAfterCommit struct {
	*iocPubs
	cancel context.CancelFunc
}

func (c cancelAfterCommit) Publish(ctx context.Context, e events.Event) error {
	c.cancel() // the caller's context is gone before the first event; the publisher must have its own
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return c.iocPubs.Publish(ctx, e)
}

// A hit past the hourly budget is said once per hour in the log.
func TestIOCBudgetRunningOutIsLoggedOncePerHour(t *testing.T) {
	t.Parallel()
	e, src, ff, _ := iocEnv(t)
	logs := &logCapture{}
	e.svc.cfg.Log = slog.New(logs)
	for k := 0; k < 4; k++ {
		var more []string
		for i := range MaxIocHitsPerBatch {
			d := fmt.Sprintf("49.%d.%d.9", k, i+1)
			ff.listed["ip:"+d] = Listing{Feeds: []string{"f"}, Confidence: 0.5}
			more = append(more, traffic(lanDevice, d))
		}
		e.feedAll(src, more)
	}
	if n := logs.count("hourly limit"); n != 1 {
		t.Fatalf("%d warnings in one hour", n)
	}
	e.advance(time.Hour)
	ff.listed["ip:49.9.9.9"], ff.listed["ip:49.9.9.8"] = Listing{Feeds: []string{"f"}, Confidence: 0.5}, Listing{Feeds: []string{"f"}, Confidence: 0.5}
	for k := 0; k < 3; k++ {
		var more []string
		for i := range MaxIocHitsPerBatch {
			d := fmt.Sprintf("50.%d.%d.9", k, i+1)
			ff.listed["ip:"+d] = Listing{Feeds: []string{"f"}, Confidence: 0.5}
			more = append(more, traffic(lanDevice, d))
		}
		e.feedAll(src, more)
	}
	if n := logs.count("hourly limit"); n != 2 {
		t.Fatalf("%d warnings in two hours", n)
	}
}

// M6 through Ingest: an event line with an injected srcip and dstip makes no hit.
func TestIOCEventLinesMakeNoHit(t *testing.T) {
	t.Parallel()
	e, src, ff, _ := iocEnv(t)
	e.feedAll(src, []string{`date=2026-11-09 logid="0101039426" type="event" subtype="vpn" level="alert" user="x" srcip=192.168.10.66 dstip=` + badIP + ` a="" action="ssl-login-fail"`})
	if hitCount(t, e) != 0 || len(ff.lookups()) != 0 {
		t.Fatal("an event line made a hit")
	}
}

// D-227: a line the device blocked (FortiGate action deny/blocked/…) is said as an attempt, "tried to reach … (blocked by <source>)", and
// kept as blocked for the page; a line that went through says "connected to"; a blocked attempt does not hide, for 24 hours, the
// connection of the same pair that follows it.
func TestIOCBlockedLineIsAnAttempt(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	e.feedAll(src, []string{strings.Replace(traffic(lanDevice, badIP), `action="accept"`, `action="deny"`, 1)})
	if h, b := p.counts(); h != 1 || b != 1 || !p.hits[0].Blocked {
		t.Fatalf("events %d %d %+v", h, b, p.hits)
	}
	if b := p.bad[0]; !strings.Contains(b.Title, "tried to reach "+badIP+" (blocked by FW-HQ)") || !strings.Contains(b.What, "tried to reach "+badIP) ||
		strings.Contains(b.Title+b.What, "connected to") {
		t.Errorf("blocked: %q / %q", b.Title, b.What)
	}
	if d := e.digest(); len(d.BadConnections) != 1 || !d.BadConnections[0].Blocked {
		t.Fatalf("digest %+v", d.BadConnections)
	}
	e.advance(time.Hour)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, _ := p.counts(); h != 2 || p.hits[1].Blocked {
		t.Fatalf("the connection after the attempt: %d %+v", h, p.hits)
	}
	if b := p.bad[1]; !strings.Contains(b.Title, "connected to "+badIP) || strings.Contains(b.Title+b.What, "tried to reach") {
		t.Errorf("allowed: %q / %q", b.Title, b.What)
	}
}
