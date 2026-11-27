package domainfence

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeDNS answers from maps; a name in fail errors with a server failure. It counts the lookups (the cache test reads them).
type fakeDNS struct {
	mu    sync.Mutex
	txt   map[string][]string
	a     map[string][]netip.Addr
	cname map[string]string
	fail  map[string]bool
	wild  map[string][]string // zone -> the TXT a wildcard "*.zone" answers for every name under it with no record of its own
	n     int
}

func (f *fakeDNS) look(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.fail[name] {
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return nil
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".") // Owned asks rooted names
	if err := f.look(name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	for zone, v := range f.wild {
		if strings.HasSuffix(name, "."+zone) {
			return v, nil
		}
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupNetIP(_ context.Context, _, name string) ([]netip.Addr, error) {
	if err := f.look(name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.a[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	if err := f.look("cname:" + name); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.cname[name]; ok {
		return v + ".", nil
	}
	return name + ".", nil
}

func (f *fakeDNS) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

var (
	key1 = []byte(strings.Repeat("k", KeySize))
	key2 = []byte(strings.Repeat("o", KeySize))
	ip   = netip.MustParseAddr("34.117.59.81")
)

// world is acme.example with this box's token in its TXT record and www pointing at ip.
func world() *fakeDNS {
	return &fakeDNS{
		txt:   map[string][]string{"acme.example": {"v=spf1 -all", "vedette-verify=" + Token(key1, "acme.example")}},
		a:     map[string][]netip.Addr{"www.acme.example": {netip.MustParseAddr("34.117.59.80"), ip}, "cdn.acme.example": {ip}},
		cname: map[string]string{"cdn.acme.example": "acme.edge.example.net"},
		fail:  map[string]bool{},
	}
}

func job() Job {
	return Job{Domain: "acme.example", Name: "www.acme.example", IP: ip, Token: Token(key1, "acme.example")}
}

func newFence(t *testing.T, r Resolver, now func() time.Time) *Fence {
	t.Helper()
	f, err := New(key1, r, func(d string) bool { return d == "acme.example" }, now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTokenIsTheHMACOfTheDomain(t *testing.T) {
	t.Parallel()
	a, b := Token(key1, "acme.example"), Token(key2, "acme.example")
	if len(a) != TokenLen || a == b || a == Token(key1, "other.example") || !tokenRE.MatchString(a) {
		t.Fatalf("tokens %q %q: want 16 hex, bound to the key and the domain", a, b)
	}
}

func TestCheckRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*Job, *fakeDNS)
		want string
	}{
		{"yes", func(*Job, *fakeDNS) {}, ""},
		{"bad domain", func(j *Job, _ *fakeDNS) { j.Domain = "Acme..example" }, InvalidJob},
		{"name outside the domain", func(j *Job, _ *fakeDNS) { j.Name = "www.evil.example" }, InvalidJob},
		{"private address", func(j *Job, _ *fakeDNS) { j.IP = netip.MustParseAddr("192.168.1.10") }, InvalidJob},
		{"short token", func(j *Job, _ *fakeDNS) { j.Token = "abc" }, InvalidJob},
		{"another box's token", func(j *Job, d *fakeDNS) {
			j.Token = Token(key2, "acme.example")
			d.txt["acme.example"] = []string{"vedette-verify=" + j.Token} // the domain really carries it: still not this box's
		}, TokenForeign},
		{"a domain the host never issued a token for", func(j *Job, d *fakeDNS) {
			j.Domain, j.Name, j.Token = "other.example", "www.other.example", Token(key1, "other.example")
			d.txt["other.example"] = []string{"vedette-verify=" + j.Token}
			d.a["www.other.example"] = []netip.Addr{ip}
		}, TokenForeign},
		{"TXT gone", func(_ *Job, d *fakeDNS) { delete(d.txt, "acme.example") }, NotOwned},
		{"TXT holds another value", func(_ *Job, d *fakeDNS) { d.txt["acme.example"] = []string{"vedette-verify=0000"} }, NotOwned},
		{"name moved", func(_ *Job, d *fakeDNS) { d.a["www.acme.example"] = []netip.Addr{netip.MustParseAddr("34.117.59.80")} }, NameMoved},
		{"name gone", func(_ *Job, d *fakeDNS) { delete(d.a, "www.acme.example") }, NameMoved},
		{"TXT lookup fails", func(_ *Job, d *fakeDNS) { d.fail["acme.example"] = true }, Unchecked},
		{"TXT on _vedette-verify.<domain> (the domain is a CNAME)", func(_ *Job, d *fakeDNS) {
			d.txt["_vedette-verify.acme.example"], d.txt["acme.example"] = d.txt["acme.example"], nil
		}, ""},
		{"another box's token on _vedette-verify.<domain>", func(_ *Job, d *fakeDNS) {
			d.txt["_vedette-verify.acme.example"], d.txt["acme.example"] = []string{"vedette-verify=" + Token(key2, "acme.example")}, nil
		}, NotOwned},
		{"r1 High of #941: a wildcard TXT answers _vedette-verify.<domain> and any random name beside it", func(_ *Job, d *fakeDNS) {
			d.wild = map[string][]string{"acme.example": d.txt["acme.example"]}
			d.txt["acme.example"] = nil
		}, NotOwned},
		{"r1 High of #941: a wildcard CNAME makes _vedette-verify.<domain> a CNAME to the attacker's name", func(_ *Job, d *fakeDNS) {
			d.txt["_vedette-verify.acme.example"], d.txt["acme.example"] = d.txt["acme.example"], nil // what the CNAME's target answers
			d.cname["_vedette-verify.acme.example"] = "lb.lapsed-vendor.example"
		}, NotOwned},
		{"r1 Low of #941: the domain itself is a CNAME: the TXT reached through it is the target's", func(_ *Job, d *fakeDNS) {
			d.cname["acme.example"] = "tenant.vendor.example"
		}, NotOwned},
		{"the CNAME check of the record's name fails", func(_ *Job, d *fakeDNS) { d.fail["cname:acme.example"] = true }, Unchecked},
		{"the _vedette-verify lookup fails", func(_ *Job, d *fakeDNS) { delete(d.txt, "acme.example"); d.fail["_vedette-verify.acme.example"] = true }, Unchecked},
		{"A lookup fails", func(_ *Job, d *fakeDNS) { d.fail["www.acme.example"] = true }, Unchecked},
		{"CNAME lookup fails", func(_ *Job, d *fakeDNS) { d.fail["cname:www.acme.example"] = true }, Unchecked},
		{"disruptive, CNAME outside", func(j *Job, _ *fakeDNS) { j.Name, j.Disruptive = "cdn.acme.example", true }, CNAMEOutside},
		{"not disruptive, CNAME outside", func(j *Job, _ *fakeDNS) { j.Name = "cdn.acme.example" }, ""},
		{"disruptive, CNAME inside", func(j *Job, d *fakeDNS) { j.Disruptive = true; d.cname["www.acme.example"] = "web.acme.example" }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d, j := world(), job()
			c.edit(&j, d)
			o := newFence(t, d, nil).Check(t.Context(), j, true)
			if o.Reason != c.want {
				t.Fatalf("reason %q (%s), want %q", o.Reason, o.Detail, c.want)
			}
		})
	}
}

func TestChainNamesTheCanonicalName(t *testing.T) {
	t.Parallel()
	j := job()
	j.Name = "cdn.acme.example"
	o := newFence(t, world(), nil).Check(t.Context(), j, true)
	if o.Reason != "" || o.ChainText() != "cdn.acme.example -> acme.edge.example.net" {
		t.Fatalf("outcome %+v", o)
	}
}

func TestCacheHoldsFiveMinutes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	d := world()
	f := newFence(t, d, func() time.Time { return now })
	if o := f.Check(t.Context(), job(), true); o.Reason != "" || o.Cached {
		t.Fatalf("first check %+v", o)
	}
	n := d.count()
	now = now.Add(CacheFor - time.Second)
	if o := f.Check(t.Context(), job(), true); o.Reason != "" || !o.Cached || d.count() != n {
		t.Fatalf("within 5 minutes: %+v, lookups %d -> %d", o, n, d.count())
	}
	delete(d.txt, "acme.example")
	now = now.Add(2 * time.Second)
	if o := f.Check(t.Context(), job(), true); o.Reason != NotOwned || o.Cached {
		t.Fatalf("after 5 minutes: %+v, want a fresh check that sees the TXT gone", o)
	}
}

func TestCacheNeverExcusesTheToken(t *testing.T) {
	t.Parallel()
	f := newFence(t, world(), nil)
	_ = f.Check(t.Context(), job(), true)
	j := job()
	j.Token = Token(key2, "acme.example")
	if o := f.Check(t.Context(), j, true); o.Reason != TokenForeign {
		t.Fatalf("a cached yes let another token through: %+v", o)
	}
}

// The send of a tick returns when Watch takes it, before its re-check has read DNS: synctest.Wait lets that re-check finish before the
// TXT is deleted (otherwise the first re-check could see it gone, stop, and leave the second tick with no reader: the CI hang of PR
// #798). In the bubble a watch that never reads a tick again is a deadlock synctest reports at once, not a hang.
func TestWatchStopsTheToolWhenTheTXTGoes(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		d := world()
		f := newFence(t, d, nil)
		ticks := make(chan time.Time)
		stopped := make(chan struct{})
		got := make(chan Outcome, 1)
		go func() { got <- f.Watch(t.Context(), job(), ticks, func() { close(stopped) }) }()
		isStopped := func() bool {
			select {
			case <-stopped:
				return true
			default:
				return false
			}
		}
		ticks <- time.Time{}
		synctest.Wait() // the re-check is done and the watch waits for the next tick
		if isStopped() {
			t.Fatalf("the watch stopped the tool while the domain was still owned: %+v", <-got)
		}
		d.mu.Lock()
		delete(d.txt, "acme.example")
		d.mu.Unlock()
		ticks <- time.Time{}
		synctest.Wait()
		if !isStopped() {
			t.Fatal("the TXT record is gone and the watch did not stop the tool")
		}
		if o := <-got; o.Reason != NotOwned {
			t.Fatalf("watch ended with %+v, want target_not_owned", o)
		}
	})
}

func TestWatchEndsQuietlyWithItsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	o := newFence(t, world(), nil).Watch(ctx, job(), make(chan time.Time), func() { t.Error("stopped a tool that ended by itself") })
	if o.Reason != "" {
		t.Fatalf("%+v", o)
	}
}

func TestLoadKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "fence.key")
	if err := writeFile(good, NewKey()); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadKey(good); err != nil || len(k) != KeySize {
		t.Fatalf("LoadKey: %v", err)
	}
	short := filepath.Join(dir, "short.key")
	_ = writeFile(short, []byte("abc"))
	if _, err := LoadKey(short); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := New([]byte("abc"), world(), nil, nil); err == nil {
		t.Fatal("New accepted a short key")
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); !errors.Is(err, errNotExist()) {
		t.Fatalf("missing key: %v", err)
	}
}

// The sensor binary links this package: its non-test files import the standard library, core/localnet, its sibling leaf proofat and
// golang.org/x/net/dns/dnsmessage (standard library only) only.
func TestIsALeaf(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.Contains(p, ".") && p != "github.com/knt048/vedette/core/localnet" && p != "github.com/knt048/vedette/core/domainfence/proofat" &&
				p != "golang.org/x/net/dns/dnsmessage" {
				t.Errorf("%s imports %q: only the standard library, core/localnet, core/domainfence/proofat and dnsmessage", f, p)
			}
		}
	}
}

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func errNotExist() error { return fs.ErrNotExist }

func TestDomainList(t *testing.T) {
	t.Parallel()
	l, err := ParseList(ListText(map[string]bool{"b.example": true, "a.example": true}))
	if err != nil || len(l) != 2 || !l["a.example"] {
		t.Fatalf("%v %v", l, err)
	}
	if l, err := ParseList(nil); err != nil || len(l) != 0 {
		t.Fatalf("empty: %v %v", l, err)
	}
	if _, err := ParseList([]byte("a.example\nrm -rf /\n")); err == nil {
		t.Fatal("a line that is not a domain was accepted")
	}
	p := filepath.Join(t.TempDir(), "domains")
	listed := fileList(p, ParseList, func() {})
	if listed("a.example") {
		t.Fatal("a missing list listed a domain")
	}
	_ = writeFile(p, []byte("a.example\n"))
	if !listed("a.example") || listed("b.example") {
		t.Fatal("the file list does not say what the file holds")
	}
	if f, _ := New(key1, world(), nil, nil); f.Check(t.Context(), job(), false).Reason != TokenForeign {
		t.Fatal("a fence without a list let a domain through")
	}
}

// Review r2 L-2: a copy that cannot be read at a check (the host's rename, an instant) is read once more after the wait before the
// domain is refused, so a re-check of a running scan is not killed by it.
func TestFileListReadsAMissingCopyAgain(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "domains")
	waited := 0
	listed := fileList(p, ParseList, func() { waited++; _ = writeFile(p, []byte("acme.example\n")) })
	if !listed("acme.example") || waited != 1 {
		t.Fatalf("waited %d", waited)
	}
	if listed("other.example") || waited != 1 {
		t.Fatalf("a readable list that lacks the domain waited (%d)", waited)
	}
}

// rootedDNS records the names asked.
type rootedDNS struct {
	mu    sync.Mutex
	names []string
}

func (r *rootedDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	if name == "acme.example." {
		return []string{"vedette-verify=" + Token(key1, "acme.example")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r *rootedDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, "cname:"+name)
	return name, nil
}

// Review r2 L3 of #941: Owned asks every name rooted (a trailing dot), so the resolver's search domains never apply.
func TestOwnedAsksRootedNames(t *testing.T) {
	t.Parallel()
	r := &rootedDNS{}
	if p := Owned(t.Context(), r, "acme.example", Token(key1, "acme.example"), time.Second); p.At != "acme.example" {
		t.Fatalf("%+v", p)
	}
	r2 := &rootedDNS{}
	Owned(t.Context(), r2, "other.example", "0123456789abcdef", time.Second)
	for _, n := range append(r.names, r2.names...) {
		if !strings.HasSuffix(n, ".") {
			t.Fatalf("asked %q, not rooted (all: %v %v)", n, r.names, r2.names)
		}
	}
}

// A job may say its domain's own record sits on a parent name (ProofAt, the zone apex): the fence looks for the domain's own
// token there, with the same rules; never on a name that is not a parent of the domain.
func TestCheckProofAtAParentName(t *testing.T) {
	t.Parallel()
	d := world()
	tok := Token(key1, "git.acme.example")
	d.txt["acme.example"] = append(d.txt["acme.example"], "vedette-verify="+tok)
	d.a["git.acme.example"] = []netip.Addr{ip}
	f, err := New(key1, d, func(dom string) bool { return dom == "git.acme.example" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := Job{Domain: "git.acme.example", Name: "git.acme.example", IP: ip, Token: tok, ProofAt: "acme.example"}
	if o := f.Check(t.Context(), j, false); o.Reason != "" {
		t.Fatalf("own token on the apex: %+v", o)
	}
	j.ProofAt = ""
	if o := f.Check(t.Context(), j, false); o.Reason != NotOwned {
		t.Fatalf("no record on the domain itself: %+v", o)
	}
	for _, bad := range []string{"git.acme.example", "other.example", "example", "x.git.acme.example"} {
		j.ProofAt = bad
		if o := f.Check(t.Context(), j, false); o.Reason != InvalidJob {
			t.Fatalf("ProofAt %q: %+v", bad, o)
		}
	}
	d.cname["acme.example"] = "lb.vendor.example" // the apex answers through a CNAME: not the domain's record
	j.ProofAt = "acme.example"
	if o := f.Check(t.Context(), j, false); o.Reason != NotOwned {
		t.Fatalf("apex through a CNAME: %+v", o)
	}
}

// A proof name above both the domain and the name covers the name although it is not under the domain: the record of a sibling target
// (git.acme.example's token on acme.example) lets the fence scan www.acme.example, bounded by ProofAt, never beyond it, never
// across a public suffix, and never with another box's token.
func TestCheckNameUnderProofAtOutsideTheDomain(t *testing.T) {
	t.Parallel()
	d := world()
	tok := Token(key1, "git.acme.example")
	d.txt["acme.example"] = append(d.txt["acme.example"], "vedette-verify="+tok)
	d.a["acme.example"] = []netip.Addr{ip}
	d.a["x.other.example"] = []netip.Addr{ip}
	d.a["acme.example.evil.net"] = []netip.Addr{ip}
	d.cname["www.acme.example"] = "www.acme.example"
	f, err := New(key1, d, func(dom string) bool { return dom == "git.acme.example" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := Job{Domain: "git.acme.example", Name: "www.acme.example", IP: ip, Token: tok, ProofAt: "acme.example"}
	for _, name := range []string{"www.acme.example", "acme.example"} {
		j.Name = name
		if o := f.Check(t.Context(), j, false); o.Reason != "" {
			t.Fatalf("%s under the proof name: %+v", name, o)
		}
	}
	j.Name = "www.acme.example"
	for name, bad := range map[string]Job{
		"a name outside the proof name":   {Domain: j.Domain, Name: "x.other.example", IP: ip, Token: tok, ProofAt: "acme.example"},
		"a name that only ends the same":  {Domain: j.Domain, Name: "acme.example.evil.net", IP: ip, Token: tok, ProofAt: "acme.example"},
		"no proof name: the domain bound": {Domain: j.Domain, Name: "www.acme.example", IP: ip, Token: tok},
		"a public suffix as proof name":   {Domain: "a.b.ddns.net", Name: "c.ddns.net", IP: ip, Token: tok, ProofAt: "ddns.net"},
		"the proof name above the domain": {Domain: "acme.example", Name: "www.acme.example", IP: ip, Token: Token(key1, "acme.example"), ProofAt: "git.acme.example"},
	} {
		if o := f.Check(t.Context(), bad, false); o.Reason != InvalidJob && o.Reason != NotOwned {
			t.Errorf("%s: %+v", name, o)
		}
	}
	other := j
	other.Token = Token(key2, "git.acme.example") // another box's token
	if o := f.Check(t.Context(), other, false); o.Reason != TokenForeign {
		t.Fatalf("a foreign token: %+v", o)
	}
	// a disruptive job whose CNAME leaves the proof name is refused, one that stays inside it is not
	j.Disruptive = true
	d.cname["www.acme.example"] = "edge.other.example"
	if o := f.Check(t.Context(), j, false); o.Reason != CNAMEOutside {
		t.Fatalf("CNAME outside the proof name: %+v", o)
	}
	d.cname["www.acme.example"] = "shop.acme.example"
	if o := f.Check(t.Context(), j, false); o.Reason != "" {
		t.Fatalf("CNAME inside the proof name: %+v", o)
	}
}

// A record of the token that does not count (reached through a CNAME, answered by a wildcard) is told apart by a field, not by the
// words of Detail: the Ownership tab shows it as "Not counted".
func TestOwnedSaysARecordWasRefused(t *testing.T) {
	t.Parallel()
	tok := Token(key1, "acme.example")
	rec := []string{"vedette-verify=" + tok}
	for name, c := range map[string]struct {
		dns                *fakeDNS
		refused, unchecked bool
	}{
		"through a CNAME":    {dns: &fakeDNS{txt: map[string][]string{"acme.example": rec}, cname: map[string]string{"acme.example": "tenant.vendor.example"}}, refused: true},
		"through a wildcard": {dns: &fakeDNS{wild: map[string][]string{"acme.example": rec}}, refused: true},
		"no record":          {dns: &fakeDNS{}},
		"a lookup fails":     {dns: &fakeDNS{fail: map[string]bool{"acme.example": true}}, unchecked: true},
	} {
		p := Owned(t.Context(), c.dns, "acme.example", tok, time.Second)
		if p.At != "" || p.Refused != c.refused || p.Unchecked != c.unchecked || p.Detail == "" {
			t.Errorf("%s: %+v, want refused %v, unchecked %v", name, p, c.refused, c.unchecked)
		}
	}
}
