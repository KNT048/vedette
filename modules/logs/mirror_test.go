package logs

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// mirrorEnv is an environment with a feed list (one listed name, one name listed with its subdomains, the listed address of the
// other tests) and the events; no log source is declared: mirror-port matching needs none.
func mirrorEnv(t *testing.T) (*env, *fakeFeeds, *iocPubs) {
	t.Helper()
	e := newEnv(t)
	ff := &fakeFeeds{listed: map[string]Listing{
		"domain:bad.example.com":     {Feeds: []string{"URLhaus"}, Confidence: 0.9},
		"domain:tracker.example.com": {Feeds: []string{"hagezi TIF"}, Confidence: 0.7, SubFeeds: []string{"hagezi TIF"}, SubConfidence: 0.7},
		"ip:" + badIP:                {Feeds: []string{"Feodo"}, Confidence: 0.8},
	}}
	p := &iocPubs{}
	e.svc.cfg.Feeds, e.svc.cfg.Events = ff, p
	return e, ff, p
}

func mi(kind, src, dest string) MirrorItem {
	return MirrorItem{Kind: kind, At: t0.Add(-time.Minute), Src: netip.MustParseAddr(src), Dest: dest}
}

// rowCounts is the number of rows of every table of logs.db but logs_ioc_hits: mirror-port matching must leave them all as they were.
func rowCounts(t *testing.T, e *env) map[string]int {
	t.Helper()
	rows, err := e.vol.Reader().QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'logs_%' AND name <> 'logs_ioc_hits'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	out := map[string]int{}
	for _, n := range names {
		out[n] = count(t, e.vol, `SELECT count(*) FROM `+n)
	}
	return out
}

// The mirror port's metadata of a device is matched against the feeds like a firewall line: a DNS query for a listed name, the server
// name of a TLS connection under a name listed with its subdomains and a flow to a listed address are hits, each a stored row and
// two events with the mirror port named; a clean name, a documentation address, a source that is not a LAN device and an unknown
// kind are not. Nothing but the hits is stored: no line, no counter, no name that matched nothing.
func TestMirrorMetadataMatchesTheFeedsAndStoresOnlyHits(t *testing.T) {
	t.Parallel()
	e, ff, p := mirrorEnv(t)
	before := rowCounts(t, e)
	items := []MirrorItem{
		mi("dns", "10.0.0.5", "bad.example.com"),
		mi("dns", "10.0.0.5", "bad.example.com"), // the same query twice in one batch: one lookup, one hit
		mi("dns", "10.0.0.5", "www.example.com"), // clean
		mi("sni", "10.0.0.6", "x7.tracker.example.com"),
		mi("flow", "10.0.0.7", badIP),
		mi("flow", "10.0.0.5", "198.51.100.7"),     // a documentation address: no feed can list it, never looked up
		mi("http", "10.0.0.5", "192.0.2.10"),       // an address is not a name
		mi("dns", "192.0.2.10", "bad.example.com"), // not a LAN device
		mi("smtp", "10.0.0.5", "bad.example.com"),  // not a kind of the mirror port
	}
	if err := e.svc.MatchMirror(t.Context(), items); err != nil {
		t.Fatal(err)
	}
	if n := hitCount(t, e); n != 3 {
		t.Fatalf("%d hits, want 3", n)
	}
	if after := rowCounts(t, e); !mapsEqual(before, after) {
		t.Errorf("tables other than the hits changed: %v -> %v", before, after)
	}
	for _, l := range ff.lookups() {
		if strings.Contains(l, "198.51.100.7") || strings.Contains(l, "192.0.2.10") {
			t.Errorf("looked up %s", l)
		}
	}
	if n := strings.Count(strings.Join(ff.lookups(), " "), "domain:bad.example.com"); n != 1 {
		t.Errorf("bad.example.com looked up %d times", n)
	}
	hits, err := e.svc.IocHits(t.Context(), t0.Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	via := map[string]IocHit{}
	for _, h := range hits {
		via[h.SeenVia] = h
	}
	if h := via["span_dns"]; h.SrcIP != "10.0.0.5" || h.Dest != "bad.example.com" || h.DestKind != "domain" || h.Blocked || !h.TS.Equal(t0.Add(-time.Minute)) {
		t.Errorf("dns hit %+v", h)
	}
	if h := via["span_sni"]; h.Dest != "x7.tracker.example.com" || h.ListedAs == nil || *h.ListedAs != "tracker.example.com" {
		t.Errorf("sni hit %+v", h)
	}
	if h := via["span_flow"]; h.SrcIP != "10.0.0.7" || h.Dest != badIP || h.DestKind != "ip" {
		t.Errorf("flow hit %+v", h)
	}
	if h, b := p.counts(); h != 3 || b != 3 {
		t.Fatalf("%d hit events, %d bad-address events", h, b)
	}
	for _, b := range p.bad {
		if !strings.Contains(b.What, "Seen on the mirror port") || strings.Contains(b.What, "in the log of") || b.Target == "" {
			t.Errorf("bad-address event %+v", b)
		}
		if b.SeenVia == "span_dns" && !strings.Contains(b.Title, "10.0.0.5 looked up bad.example.com") {
			t.Errorf("dns title %q", b.Title)
		}
	}
	var src string
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT DISTINCT source_id FROM logs_ioc_hits`).Scan(&src); err != nil || src != MirrorSourceID {
		t.Errorf("source_id %q %v", src, err)
	}

	// The same metadata again is the same story: no new hit, no new event.
	if err := e.svc.MatchMirror(t.Context(), items); err != nil {
		t.Fatal(err)
	}
	if n := hitCount(t, e); n != 3 {
		t.Errorf("%d hits after a repeat", n)
	}
	if h, _ := p.counts(); h != 3 {
		t.Errorf("%d hit events after a repeat", h)
	}
}

// The time of an item is when the sensor saw it; one in the future or older than an hour is a wrong clock and is dated now.
func TestMirrorMetadataTimeIsBounded(t *testing.T) {
	t.Parallel()
	e, _, _ := mirrorEnv(t)
	future, old := mi("dns", "10.0.0.5", "bad.example.com"), mi("flow", "10.0.0.5", badIP)
	future.At, old.At = t0.Add(time.Hour), t0.Add(-48*time.Hour)
	if err := e.svc.MatchMirror(t.Context(), []MirrorItem{future, old}); err != nil {
		t.Fatal(err)
	}
	hits, err := e.svc.IocHits(t.Context(), t0.Add(-72*time.Hour), 0)
	if err != nil || len(hits) != 2 {
		t.Fatalf("%+v %v", hits, err)
	}
	for _, h := range hits {
		if !h.TS.Equal(t0) {
			t.Errorf("%s dated %v, want now", h.Dest, h.TS)
		}
	}
}

// The box, its gateway and a decoy are not a device (NeverCount); with the feeds module off nothing is looked up; a batch over the
// cap is refused whole.
func TestMirrorMetadataLimits(t *testing.T) {
	t.Parallel()
	e, ff, p := mirrorEnv(t)
	e.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil }
	if err := e.svc.MatchMirror(t.Context(), []MirrorItem{mi("dns", "10.0.0.1", "bad.example.com")}); err != nil {
		t.Fatal(err)
	}
	if len(ff.lookups()) != 0 || hitCount(t, e) != 0 {
		t.Fatal("the gateway's query made a lookup or a hit")
	}
	ff.setErr(ErrFeedsOff)
	if err := e.svc.MatchMirror(t.Context(), []MirrorItem{mi("dns", "10.0.0.5", "bad.example.com")}); err != nil {
		t.Fatal(err)
	}
	if hitCount(t, e) != 0 {
		t.Fatal("a hit with the feeds module off")
	}
	ff.setErr(nil)
	big := slices.Repeat([]MirrorItem{mi("dns", "10.0.0.5", "bad.example.com")}, MaxMirrorBatch+1)
	if err := e.svc.MatchMirror(t.Context(), big); !errors.Is(err, ErrMirrorBatchTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
	if hitCount(t, e) != 0 {
		t.Fatal("a refused batch made a hit")
	}
	if h, b := p.counts(); h+b != 0 {
		t.Fatal("an event")
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
