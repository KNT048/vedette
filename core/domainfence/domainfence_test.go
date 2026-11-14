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
	"time"
)

// fakeDNS answers from maps; a name in fail errors with a server failure. It counts the lookups (the cache test reads them).
type fakeDNS struct {
	mu    sync.Mutex
	txt   map[string][]string
	a     map[string][]netip.Addr
	cname map[string]string
	fail  map[string]bool
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
	if err := f.look(name); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.txt[name]; ok {
		return v, nil
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
	f, err := New(key1, r, now)
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
		{"TXT gone", func(_ *Job, d *fakeDNS) { delete(d.txt, "acme.example") }, NotOwned},
		{"TXT holds another value", func(_ *Job, d *fakeDNS) { d.txt["acme.example"] = []string{"vedette-verify=0000"} }, NotOwned},
		{"name moved", func(_ *Job, d *fakeDNS) { d.a["www.acme.example"] = []netip.Addr{netip.MustParseAddr("34.117.59.80")} }, NameMoved},
		{"name gone", func(_ *Job, d *fakeDNS) { delete(d.a, "www.acme.example") }, NameMoved},
		{"TXT lookup fails", func(_ *Job, d *fakeDNS) { d.fail["acme.example"] = true }, Unchecked},
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

func TestWatchStopsTheToolWhenTheTXTGoes(t *testing.T) {
	t.Parallel()
	d := world()
	f := newFence(t, d, nil)
	ticks := make(chan time.Time)
	stopped := make(chan struct{})
	got := make(chan Outcome, 1)
	go func() { got <- f.Watch(t.Context(), job(), ticks, func() { close(stopped) }) }()
	ticks <- time.Time{} // still owned: the watch goes on
	d.mu.Lock()
	delete(d.txt, "acme.example")
	d.mu.Unlock()
	ticks <- time.Time{}
	<-stopped
	if o := <-got; o.Reason != NotOwned {
		t.Fatalf("watch ended with %+v, want target_not_owned", o)
	}
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
	if _, err := New([]byte("abc"), world(), nil); err == nil {
		t.Fatal("New accepted a short key")
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); !errors.Is(err, errNotExist()) {
		t.Fatalf("missing key: %v", err)
	}
}

// The sensor binary links this package: its non-test files import the standard library and core/localnet only.
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
			if strings.Contains(p, ".") && p != "github.com/knt048/vedette/core/localnet" {
				t.Errorf("%s imports %q: only the standard library and core/localnet", f, p)
			}
		}
	}
}

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func errNotExist() error { return fs.ErrNotExist }
