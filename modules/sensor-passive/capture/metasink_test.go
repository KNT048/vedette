package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// fakePoster records the batches and when they came; answer, when set, says what core answers to the n-th request (from 0).
type fakePoster struct {
	mu      sync.Mutex
	batches [][]sensorlink.MetadataItem
	at      []time.Time
	answer  func(n int) error
}

func (f *fakePoster) PostMetadata(_ context.Context, r *sensorlink.MetadataRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.at)
	f.at = append(f.at, time.Now())
	if f.answer != nil {
		if err := f.answer(n); err != nil {
			return err
		}
	}
	f.batches = append(f.batches, append([]sensorlink.MetadataItem(nil), r.Items...))
	return nil
}

func (f *fakePoster) items() []sensorlink.MetadataItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sensorlink.MetadataItem
	for _, b := range f.batches {
		out = append(out, b...)
	}
	return out
}

func (f *fakePoster) times() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.at...)
}

var metaT0 = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

func dnsItem(src, name string) MetaItem {
	return MetaItem{Kind: MetaDNS, At: metaT0, SrcMAC: "aa:bb:cc:00:00:01", SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr("10.0.0.1"), Name: name, QType: 1}
}

func flowItem(dst string) MetaItem {
	return MetaItem{Kind: MetaFlow, At: metaT0, SrcIP: netip.MustParseAddr("10.0.0.5"), DstIP: netip.MustParseAddr(dst), Proto: 6, SrcPort: 50000, DstPort: 443, Packets: 9, Bytes: 900, First: metaT0}
}

func names(n int, src, prefix string) []MetaItem {
	out := make([]MetaItem, 0, n)
	for i := range n {
		out = append(out, dnsItem(src, fmt.Sprintf("%s%d.example.com", prefix, i)))
	}
	return out
}

// Only what the matching needs goes to core: the source address, the name or the flow's public destination, the kind and the time.
// A name is lower case without its trailing dot; a flow to a private, shared or broadcast address and a source that is not IPv4 go
// nowhere; the same (kind, source, destination) is sent once in metaRepeat.
func TestLinkMetadataSendsOnlyWhatMatchingNeeds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{}
		l := NewLinkMetadata(p, nil)
		go func() { _ = l.Run(t.Context()) }()
		in := []MetaItem{
			dnsItem("10.0.0.5", "Bad.Example.com."),
			dnsItem("10.0.0.5", "bad.example.com"),
			{Kind: MetaSNI, At: metaT0, SrcIP: netip.MustParseAddr("10.0.0.5"), DstIP: netip.MustParseAddr("198.51.100.7"), Name: "api.example.com"},
			{Kind: MetaHTTP, At: metaT0, SrcIP: netip.MustParseAddr("10.0.0.6"), DstIP: netip.MustParseAddr("198.51.100.8"), Name: "www.example.com"},
			flowItem("198.51.100.7"),
			flowItem("10.0.0.9"),        // private
			flowItem("100.64.1.1"),      // shared
			flowItem("255.255.255.255"), // broadcast
			flowItem("224.0.0.251"),     // multicast
			{Kind: MetaDNS, At: metaT0, SrcIP: netip.MustParseAddr("fd00::1"), Name: "bad.example.com"},
			{Kind: MetaDNS, At: metaT0, SrcIP: netip.MustParseAddr("10.0.0.5"), Name: "a..example.com"},
		}
		if err := l.Metadata(t.Context(), 1, in); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		want := []sensorlink.MetadataItem{
			{Kind: "dns", At: metaT0, Src: "10.0.0.5", Dest: "bad.example.com"},
			{Kind: "sni", At: metaT0, Src: "10.0.0.5", Dest: "api.example.com"},
			{Kind: "http", At: metaT0, Src: "10.0.0.6", Dest: "www.example.com"},
			{Kind: "flow", At: metaT0, Src: "10.0.0.5", Dest: "198.51.100.7"},
		}
		got := p.items()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("sent %v\nwant %v", got, want)
		}
		for _, it := range got {
			if !sensorlink.ValidMetadataItem(it) {
				t.Errorf("sent an item core refuses: %+v", it)
			}
		}
		// within metaRepeat the same items are not sent again; after it they are
		<-time.After(metaRepeat - time.Second)
		if err := l.Metadata(t.Context(), 2, in); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n := len(p.items()); n != len(want) {
			t.Fatalf("a repeat was sent: %d items", n)
		}
		<-time.After(2 * time.Second)
		if err := l.Metadata(t.Context(), 3, in); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n := len(p.items()); n != 2*len(want) {
			t.Fatalf("after the repeat window: %d items", n)
		}
	})
}

// Requests are paced by time, not by how often the capture flushes: a flood of distinct names (a random-subdomain storm) handed
// over in many small calls still makes at most one request per metaPostEvery, and Metadata never waits for the network.
func TestLinkMetadataPacesItsRequestsByTime(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{}
		l := NewLinkMetadata(p, nil)
		go func() { _ = l.Run(t.Context()) }()
		for i := range 50 { // fifty flushes in quick succession, each with new names
			if err := l.Metadata(t.Context(), uint64(i), names(200, "10.0.0.5", fmt.Sprintf("f%d-", i))); err != nil {
				t.Fatal(err)
			}
			<-time.After(100 * time.Millisecond)
		}
		synctest.Wait()
		at := p.times()
		for i := 1; i < len(at); i++ {
			if d := at[i].Sub(at[i-1]); d < metaPostEvery {
				t.Fatalf("request %d came %v after the one before, want at least %v", i, d, metaPostEvery)
			}
		}
		<-time.After(time.Minute)
		synctest.Wait()
		if n := len(p.items()); n != 50*200 || l.Pending() != 0 {
			t.Fatalf("%d items delivered of %d, %d pending", n, 50*200, l.Pending())
		}
	})
}

// What core cannot take now waits as long as core asks (Retry-After) and goes out later; a store_busy batch is offered maxMetaTries
// times, then dropped; what core refuses for good is dropped; a module that is off drops everything; a full queue drops new items.
// Every loss is reported by the next Metadata call.
func TestLinkMetadataFailures(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		limited := sensorlink.NewError(sensorlink.CodeRateLimited)
		limited.RetryAfter = 20 * time.Second
		p := &fakePoster{answer: func(n int) error {
			if n == 0 {
				return limited
			}
			return nil
		}}
		l := NewLinkMetadata(p, nil)
		go func() { _ = l.Run(t.Context()) }()
		start := time.Now()
		if err := l.Metadata(t.Context(), 1, []MetaItem{dnsItem("10.0.0.5", "bad.example.com")}); err != nil {
			t.Fatal(err)
		}
		<-time.After(time.Minute)
		synctest.Wait()
		if at := p.times(); len(at) != 2 || at[1].Sub(start) < 20*time.Second || len(p.items()) != 1 {
			t.Fatalf("after a 429 with Retry-After 20 s: requests at %v, items %v", at, p.items())
		}
	})
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answer: func(int) error { return errors.New("connection refused") }}
		l := NewLinkMetadata(p, nil)
		go func() { _ = l.Run(t.Context()) }()
		if err := l.Metadata(t.Context(), 1, []MetaItem{dnsItem("10.0.0.5", "bad.example.com")}); err != nil {
			t.Fatal(err)
		}
		<-time.After(2 * time.Minute)
		synctest.Wait()
		if n := len(p.times()); n > 8 || l.Pending() != 1 {
			t.Fatalf("core unreachable for 2 minutes: %d requests (backing off: few), %d pending (kept)", n, l.Pending())
		}
	})
	synctest.Test(t, func(t *testing.T) {
		p := &fakePoster{answer: func(int) error { return sensorlink.StoreBusy(time.Second) }}
		l := NewLinkMetadata(p, nil)
		go func() { _ = l.Run(t.Context()) }()
		_ = l.Metadata(t.Context(), 1, []MetaItem{dnsItem("10.0.0.5", "bad.example.com")})
		<-time.After(time.Minute)
		synctest.Wait()
		if n := len(p.times()); n != maxMetaTries || l.Pending() != 0 {
			t.Fatalf("store_busy: %d requests, %d pending", n, l.Pending())
		}
		if err := l.Metadata(t.Context(), 2, nil); !errors.Is(err, errMetaLost) {
			t.Fatalf("the loss is not reported: %v", err)
		}
		if err := l.Metadata(t.Context(), 3, nil); err != nil {
			t.Fatalf("a loss is reported twice: %v", err)
		}
	})
	for _, code := range []string{sensorlink.CodeInvalidRequest, sensorlink.CodeForbiddenRoute, sensorlink.CodeModuleOff} {
		synctest.Test(t, func(t *testing.T) {
			p := &fakePoster{answer: func(int) error { return sensorlink.NewError(code) }}
			l := NewLinkMetadata(p, nil)
			go func() { _ = l.Run(t.Context()) }()
			_ = l.Metadata(t.Context(), 1, names(3, "10.0.0.5", "r"))
			<-time.After(time.Minute)
			synctest.Wait()
			err := l.Metadata(t.Context(), 2, nil)
			if len(p.times()) != 1 || l.Pending() != 0 || (code == sensorlink.CodeModuleOff) == errors.Is(err, errMetaLost) {
				t.Fatalf("%s: %d requests, %d pending, %v", code, len(p.times()), l.Pending(), err)
			}
		})
	}
	// a full queue: no Run, nothing is sent
	l := NewLinkMetadata(&fakePoster{}, nil)
	if err := l.Metadata(t.Context(), 1, names(maxMetaPending+5, "10.0.0.8", "q")); !errors.Is(err, errMetaLost) {
		t.Fatalf("over the queue: %v", err)
	}
	if n := l.Pending(); n != maxMetaPending {
		t.Fatalf("%d pending", n)
	}
}
