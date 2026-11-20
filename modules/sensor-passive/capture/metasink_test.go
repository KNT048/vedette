package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

type fakePoster struct {
	batches [][]sensorlink.MetadataItem
	err     error
}

func (f *fakePoster) PostMetadata(_ context.Context, r *sensorlink.MetadataRequest) error {
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, append([]sensorlink.MetadataItem(nil), r.Items...))
	return nil
}

func (f *fakePoster) items() []sensorlink.MetadataItem {
	var out []sensorlink.MetadataItem
	for _, b := range f.batches {
		out = append(out, b...)
	}
	return out
}

var metaT0 = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

func dnsItem(src, name string) MetaItem {
	return MetaItem{Kind: MetaDNS, At: metaT0, SrcMAC: "aa:bb:cc:00:00:01", SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr("10.0.0.1"), Name: name, QType: 1}
}

func flowItem(dst string) MetaItem {
	return MetaItem{Kind: MetaFlow, At: metaT0, SrcIP: netip.MustParseAddr("10.0.0.5"), DstIP: netip.MustParseAddr(dst), Proto: 6, SrcPort: 50000, DstPort: 443, Packets: 9, Bytes: 900, First: metaT0}
}

// Only what the matching needs goes to core: the source address, the name or the flow's public destination, the kind and the time.
// A name is lower case without its trailing dot; a flow to a private, shared or broadcast address and a source that is not IPv4 go
// nowhere; the same (kind, source, destination) is sent once.
func TestLinkMetadataSendsOnlyWhatMatchingNeeds(t *testing.T) {
	t.Parallel()
	p := &fakePoster{}
	now := metaT0
	l := NewLinkMetadata(p, func() time.Time { return now })
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
	now = now.Add(metaRepeat - time.Second)
	if err := l.Metadata(t.Context(), 2, in); err != nil || len(p.batches) != 1 {
		t.Fatalf("repeat sent: %v %d batches", err, len(p.batches))
	}
	now = now.Add(2 * time.Second)
	if err := l.Metadata(t.Context(), 3, in); err != nil || len(p.items()) != 2*len(want) {
		t.Fatalf("after the repeat window: %v %d items", err, len(p.items()))
	}
}

// One flush makes at most MetadataPostsPerFlush requests of at most MaxMetadataItems items; the rest waits for the next flush,
// and the sink says it holds items so the Runner calls it even when nothing new came.
func TestLinkMetadataPacesItsRequests(t *testing.T) {
	t.Parallel()
	p := &fakePoster{}
	l := NewLinkMetadata(p, func() time.Time { return metaT0 })
	total := sensorlink.MaxMetadataItems*sensorlink.MetadataPostsPerFlush + 10
	in := make([]MetaItem, 0, total)
	for i := range total {
		in = append(in, dnsItem("10.0.0.5", fmt.Sprintf("n%d.example.com", i)))
	}
	if err := l.Metadata(t.Context(), 1, in); err != nil {
		t.Fatal(err)
	}
	if len(p.batches) != sensorlink.MetadataPostsPerFlush || len(p.batches[0]) != sensorlink.MaxMetadataItems || !l.Pending() {
		t.Fatalf("%d batches, pending %v", len(p.batches), l.Pending())
	}
	if err := l.Metadata(t.Context(), 2, nil); err != nil {
		t.Fatal(err)
	}
	if len(p.items()) != total || l.Pending() {
		t.Fatalf("%d items sent of %d, pending %v", len(p.items()), total, l.Pending())
	}
}

// What core cannot take now (rate limited, busy, unreachable) waits and goes out later; what core refuses for good is dropped; a
// module that is off drops everything; a full queue drops new items and says so.
func TestLinkMetadataFailures(t *testing.T) {
	t.Parallel()
	p := &fakePoster{err: sensorlink.NewError(sensorlink.CodeRateLimited)}
	l := NewLinkMetadata(p, func() time.Time { return metaT0 })
	if err := l.Metadata(t.Context(), 1, []MetaItem{dnsItem("10.0.0.5", "bad.example.com")}); err == nil || !l.Pending() {
		t.Fatalf("rate limited: %v, pending %v", err, l.Pending())
	}
	p.err = errors.New("connection refused")
	if err := l.Metadata(t.Context(), 2, nil); err == nil || !l.Pending() {
		t.Fatalf("unreachable: %v, pending %v", err, l.Pending())
	}
	p.err = nil
	if err := l.Metadata(t.Context(), 3, nil); err != nil || len(p.items()) != 1 || l.Pending() {
		t.Fatalf("later: %v %v", err, p.items())
	}

	p.err = sensorlink.NewError(sensorlink.CodeInvalidRequest)
	if err := l.Metadata(t.Context(), 4, []MetaItem{dnsItem("10.0.0.6", "bad.example.com")}); err == nil || l.Pending() {
		t.Fatalf("refused: %v, pending %v", err, l.Pending())
	}
	p.err = sensorlink.NewError(sensorlink.CodeModuleOff)
	if err := l.Metadata(t.Context(), 5, []MetaItem{dnsItem("10.0.0.7", "bad.example.com")}); err == nil || l.Pending() {
		t.Fatalf("module off: %v, pending %v", err, l.Pending())
	}

	p.err = sensorlink.NewError(sensorlink.CodeStoreBusy)
	in := make([]MetaItem, 0, maxMetaPending+5)
	for i := range maxMetaPending + 5 {
		in = append(in, dnsItem("10.0.0.8", fmt.Sprintf("q%d.example.com", i)))
	}
	if err := l.Metadata(t.Context(), 6, in); !errors.Is(err, errMetaOverflow) {
		t.Fatalf("over the queue: %v", err)
	}
	if n := len(l.pending); n != maxMetaPending {
		t.Fatalf("%d pending", n)
	}
}
