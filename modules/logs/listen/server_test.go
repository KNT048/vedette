package listen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var lo = netip.MustParseAddr("127.0.0.1")

// Network helpers with a context, as the linter wants (loopback only).
func dialCtx(network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func listenPacket(network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, addr)
}

// rig is a Server on loopback with a Sink that keeps what it gets.
type rig struct {
	t    *testing.T
	srv  *Server
	stop context.CancelFunc
	done chan error

	mu      sync.Mutex
	batches [][]Line
	sinkErr error
}

func (r *rig) sink(_ context.Context, lines []Line) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, append([]Line(nil), lines...))
	return r.sinkErr
}

func (r *rig) lines() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Line
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

func (r *rig) texts() []string {
	var out []string
	for _, l := range r.lines() {
		out = append(out, l.Text)
	}
	return out
}

// newRig starts a server; sources default to 127.0.0.1 as "src-1" over both protocols' first use (set by the caller).
func newRig(t *testing.T, lim Limits, now func() time.Time, ports ...int) *rig {
	t.Helper()
	if len(ports) == 0 {
		ports = []int{0}
	}
	r := &rig{t: t, done: make(chan error, 1)}
	srv, err := New(Config{Host: "127.0.0.1", Ports: ports, Sink: r.sink, Log: slog.New(slog.DiscardHandler), Now: now, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	return r
}

func (r *rig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.stop = cancel
	go func() { r.done <- r.srv.Run(ctx) }()
	r.t.Cleanup(func() { r.shutdown() })
}

func (r *rig) shutdown() {
	r.stop()
	select {
	case err := <-r.done:
		_ = err
	case <-time.After(10 * time.Second):
		r.t.Error("Run did not return after cancel")
	}
	r.done <- nil // a second shutdown (cleanup after the test did it) must not block
}

func (r *rig) set(proto string) {
	r.t.Helper()
	if err := r.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: proto}}); err != nil {
		r.t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// waitAddr waits for Run to have opened the socket.
func (r *rig) udpAddr() string {
	r.t.Helper()
	var a net.Addr
	waitFor(r.t, "the UDP socket", func() bool { a, _ = r.srv.Addrs(); return a != nil })
	return a.String()
}

func (r *rig) tcpAddr() string {
	r.t.Helper()
	var a net.Addr
	waitFor(r.t, "the TCP socket", func() bool { _, a = r.srv.Addrs(); return a != nil })
	return a.String()
}

func sendUDP(t *testing.T, addr, msg string) {
	t.Helper()
	c, err := dialCtx("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := dialCtx("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedByPeer says whether the server closed c within the wait.
func closedByPeer(c net.Conn, wait time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	_, err := c.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || (err != nil && !isTimeout(err))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestUDPLinesReachTheSinkWithTheirSourceAndEnvelope(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond}, nil)
	r.set("udp")
	r.start()
	addr := r.udpAddr()
	sendUDP(t, addr, "<34>Nov 11 08:30:15 gw sshd[1]: hello\n")
	sendUDP(t, addr, `<165>1 - h a - - - five`)
	sendUDP(t, addr, "no priority at all")
	sendUDP(t, addr, "\n") // empty: nothing
	waitFor(t, "three lines", func() bool { return len(r.lines()) == 3 })
	got := map[string]Line{}
	for _, l := range r.lines() {
		got[l.Text] = l
		if l.SourceID != "src-1" || l.At.IsZero() {
			t.Errorf("line %+v", l)
		}
	}
	if l := got["<34>Nov 11 08:30:15 gw sshd[1]: hello"]; l.Env.Format != FormatRFC3164 || l.Env.App != "sshd" {
		t.Errorf("3164 line %+v", l)
	}
	if got[`<165>1 - h a - - - five`].Env.Format != FormatRFC5424 || got["no priority at all"].Env.Format != FormatRaw {
		t.Errorf("formats %+v", got)
	}
	st := r.srv.Stats()
	if st.Received != 3 || st.Formats[FormatRaw] != 1 || st.Formats[FormatRFC5424] != 1 || st.Formats[FormatRFC3164] != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestTCPBothFramings(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond}, nil)
	r.set("tcp")
	r.start()
	c := dialTCP(t, r.tcpAddr())
	if _, err := io.WriteString(c, "<34>one\n5 <34>2<34>three\r\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "three lines", func() bool { return len(r.lines()) == 3 })
	if got := strings.Join(r.texts(), "|"); got != "<34>one|<34>2|<34>three" {
		t.Errorf("lines = %q", got)
	}
}

func TestHostileInputIsKeptBoundedAndNeverStopsTheStream(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond, MaxLine: 100, MaxFrame: 1000}, nil)
	r.set("tcp")
	r.start()
	c := dialTCP(t, r.tcpAddr())
	huge := "<34>" + strings.Repeat("A", 900)
	if _, err := io.WriteString(c, "<34>a\x00b\x1b[31m\n"+huge+"\n<34>after\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "three lines", func() bool { return len(r.lines()) == 3 })
	texts := r.texts()
	if texts[0] != "<34>a\x00b\x1b[31m" { // NUL and escapes are data here; Ingest cleans them
		t.Errorf("first = %q", texts[0])
	}
	if len(texts[1]) != 100 || texts[2] != "<34>after" {
		t.Errorf("huge line kept as %d bytes, next = %q", len(texts[1]), texts[2])
	}
	if st := r.srv.Stats(); st.Truncated != 1 {
		t.Errorf("truncated = %d", st.Truncated)
	}
}

func TestAHugeDatagramIsCutAndCounted(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond, MaxLine: 50}, nil)
	r.set("udp")
	r.start()
	// 8,000 bytes: far over MaxLine, and under macOS's default UDP datagram limit (net.inet.udp.maxdgram = 9216),
	// which refuses a bigger send with EMSGSIZE ("message too long") before it reaches the listener.
	sendUDP(t, r.udpAddr(), "<34>"+strings.Repeat("z", 8000))
	waitFor(t, "a line", func() bool { return len(r.lines()) == 1 })
	if n := len(r.lines()[0].Text); n != 50 {
		t.Errorf("kept %d bytes", n)
	}
	if r.srv.Stats().Truncated != 1 {
		t.Error("not counted as truncated")
	}
}

func TestABadOctetCountClosesTheConnection(t *testing.T) {
	for name, payload := range map[string]string{
		"count over the frame limit":  "999999 <34>x",
		"stream ends inside a frame":  "50 <34>short",
		"no newline within the limit": strings.Repeat("n", 2000),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, Limits{BatchWait: 20 * time.Millisecond, MaxFrame: 1000}, nil)
			r.set("tcp")
			r.start()
			c := dialTCP(t, r.tcpAddr())
			if _, err := io.WriteString(c, payload); err != nil {
				t.Fatal(err)
			}
			if name == "stream ends inside a frame" {
				_ = c.(*net.TCPConn).CloseWrite()
			}
			if !closedByPeer(c, 5*time.Second) {
				t.Fatal("the connection stayed open")
			}
			waitFor(t, "the bad frame to be counted", func() bool { return r.srv.Stats().BadFrames == 1 })
			if len(r.lines()) != 0 {
				t.Errorf("a bad frame produced lines: %q", r.texts())
			}
		})
	}
}

func TestSlowLorisIsClosed(t *testing.T) {
	r := newRig(t, Limits{FrameTimeout: 100 * time.Millisecond, Idle: 150 * time.Millisecond, BatchWait: 20 * time.Millisecond}, nil)
	r.set("tcp")
	r.start()
	addr := r.tcpAddr()

	trickle := dialTCP(t, addr) // starts a frame and never finishes it
	if _, err := io.WriteString(trickle, "<34>half a li"); err != nil {
		t.Fatal(err)
	}
	if !closedByPeer(trickle, 5*time.Second) {
		t.Error("a frame that never ends held its connection")
	}
	silent := dialTCP(t, addr) // sends nothing
	if !closedByPeer(silent, 5*time.Second) {
		t.Error("a silent connection was not closed")
	}
	count := dialTCP(t, addr) // promises 60,000 bytes and sends three
	if _, err := io.WriteString(count, "60000 <34>ab"); err != nil {
		t.Fatal(err)
	}
	if !closedByPeer(count, 5*time.Second) {
		t.Error("an unfinished octet-counted frame held its connection")
	}
	if len(r.lines()) != 0 {
		t.Errorf("unfinished frames made lines: %q", r.texts())
	}
	ok := dialTCP(t, addr) // an honest sender is not hurt
	if _, err := io.WriteString(ok, "<34>fine\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the honest line", func() bool { return len(r.lines()) == 1 })
}

func TestConnectionsAreBounded(t *testing.T) {
	r := newRig(t, Limits{MaxConns: 3, MaxConnsIP: 2, BatchWait: 20 * time.Millisecond}, nil)
	other := netip.MustParseAddr("127.0.0.2")
	if err := r.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tcp"}, other: {ID: "src-2", Proto: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	r.start()
	addr := r.tcpAddr()
	var keep []net.Conn
	for range 2 {
		keep = append(keep, dialTCP(t, addr))
	}
	over := dialTCP(t, addr) // a third from the same sender
	if !closedByPeer(over, 5*time.Second) {
		t.Fatal("a connection over the per-sender limit stayed open")
	}
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c2, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Skipf("no second loopback address here: %v", err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	waitFor(t, "four connections seen", func() bool { return r.srv.Stats().ConnRejected >= 1 })
	// total = 3 now (2 + 1): the next one from the second sender is over the total
	c3, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c3.Close() })
	if !closedByPeer(c3, 5*time.Second) {
		t.Fatal("a connection over the total limit stayed open")
	}
	_ = keep
	// a closed connection frees its place
	_ = keep[0].Close()
	waitFor(t, "a place to be free", func() bool {
		c, err := dialCtx("tcp4", addr)
		if err != nil {
			return false
		}
		defer func() { _ = c.Close() }()
		return !closedByPeer(c, 100*time.Millisecond)
	})
}

func TestUnknownSendersAreDroppedAndCountedInABoundedTable(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond, UnknownKept: 4}, nil)
	if err := r.srv.SetSources(map[netip.Addr]Source{netip.MustParseAddr("10.9.9.9"): {ID: "src-9", Proto: "udp"}, lo: {ID: "src-1", Proto: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	r.start()
	sendUDP(t, r.udpAddr(), "<34>from nobody I know") // UDP socket is open for 10.9.9.9; the sender is 127.0.0.1, declared for TCP only
	waitFor(t, "the datagram to be counted", func() bool { return r.srv.Stats().Unknown == 1 })
	// TCP from a sender declared for UDP only is refused too: use the second address when the host has it
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	for range 3 {
		if c, err := d.Dial("tcp4", r.tcpAddr()); err == nil {
			_ = c.Close()
		}
	}
	if len(r.lines()) != 0 {
		t.Errorf("an unknown sender made lines: %q", r.texts())
	}
	st := r.srv.Stats()
	if len(st.UnknownSender) == 0 || st.UnknownSender[len(st.UnknownSender)-1].IP != lo && st.UnknownSender[0].IP != lo {
		t.Errorf("unknown senders %+v", st.UnknownSender)
	}
}

func TestTheUnknownSenderTableHoldsTheMostRecentOnly(t *testing.T) {
	l := newLRU(256)
	base := time.Unix(0, 0)
	for i := range 1000 {
		l.touch(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i)}), base.Add(time.Duration(i)))
	}
	got := l.list()
	if len(got) != 256 {
		t.Fatalf("holds %d senders", len(got))
	}
	if got[0].IP != netip.AddrFrom4([4]byte{10, 0, 3, 231}) { // i = 999
		t.Errorf("most recent = %v", got[0].IP)
	}
	l.touch(got[255].IP, base)
	if l.list()[0].IP != got[255].IP || l.list()[0].Count != 2 {
		t.Error("a repeat sender is not moved to the front and counted")
	}
}

func TestAFloodFromOneSourceIsRateLimitedAndCounted(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	r := newRig(t, Limits{Rate: 10, Burst: 5, BatchWait: 20 * time.Millisecond}, func() time.Time { return clock })
	r.set("udp")
	r.start()
	addr := r.udpAddr()
	for i := range 40 {
		sendUDP(t, addr, fmt.Sprintf("<34>flood %d", i))
	}
	waitFor(t, "every datagram to be handled", func() bool { s := r.srv.Stats(); return s.Received+s.RateDropped == 40 })
	st := r.srv.Stats()
	if st.Received != 5 || st.RateDropped != 35 {
		t.Errorf("received %d, dropped %d: want 5 and 35 (burst 5, clock stopped)", st.Received, st.RateDropped)
	}
}

func TestOneSourceFloodingDoesNotCostAnotherItsShare(t *testing.T) {
	r := newRig(t, Limits{Rate: 1, Burst: 3}, func() time.Time { return time.Unix(1_800_000_000, 0) })
	for range 10 {
		r.srv.allow("a")
	}
	if !r.srv.allow("b") {
		t.Error("source b was refused because a flooded")
	}
}

func TestBatchesAreBoundedByLinesBytesAndTime(t *testing.T) {
	r := newRig(t, Limits{BatchLines: 500, BatchBytes: 1 << 20, BatchWait: 60 * time.Millisecond, Rate: 1e6, Burst: 1e6}, nil)
	r.set("tcp")
	r.start()
	c := dialTCP(t, r.tcpAddr())
	var b strings.Builder
	for i := range 1201 {
		fmt.Fprintf(&b, "<34>line %d\n", i)
	}
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "all lines", func() bool { return len(r.lines()) == 1201 })
	r.mu.Lock()
	sizes := []int{}
	for _, b := range r.batches {
		sizes = append(sizes, len(b))
		if len(b) > 500 {
			t.Errorf("a batch of %d lines", len(b))
		}
	}
	r.mu.Unlock()
	if len(sizes) < 3 {
		t.Errorf("batch sizes %v: want at least 3 for 1201 lines", sizes)
	}
	// time: one line alone is delivered by the timer
	n := len(r.lines())
	if _, err := io.WriteString(c, "<34>lonely\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lonely line", func() bool { return len(r.lines()) == n+1 })

	// bytes: 6 lines of 200 KiB cannot share a 1 MiB batch (the line limit is raised so that the byte limit decides)
	r2 := newRig(t, Limits{BatchBytes: 1 << 20, MaxLine: 300 << 10, MaxFrame: 400 << 10, BatchWait: time.Hour}, nil)
	r2.set("tcp")
	r2.start()
	c2 := dialTCP(t, r2.tcpAddr())
	big := strings.Repeat("b", 200<<10)
	if _, err := io.WriteString(c2, strings.Repeat("<34>"+big+"\n", 6)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a batch by size", func() bool { r2.mu.Lock(); defer r2.mu.Unlock(); return len(r2.batches) >= 1 })
	r2.mu.Lock()
	for _, b := range r2.batches {
		total := 0
		for _, l := range b {
			total += len(l.Text)
		}
		if total > 1<<20 {
			t.Errorf("a batch of %d bytes", total)
		}
	}
	r2.mu.Unlock()
}

func TestAFailingSinkLosesOnlyItsBatchAndIsCounted(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 10 * time.Millisecond}, nil)
	r.sinkErr = errors.New("disk full")
	r.set("udp")
	r.start()
	sendUDP(t, r.udpAddr(), "<34>one")
	waitFor(t, "the loss to be counted", func() bool { return r.srv.Stats().SinkLost == 1 })
	r.mu.Lock()
	r.sinkErr = nil
	r.mu.Unlock()
	sendUDP(t, r.udpAddr(), "<34>two")
	waitFor(t, "the next line to arrive", func() bool { return len(r.lines()) == 2 })
}

func TestSocketsFollowTheSources(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 10 * time.Millisecond}, nil)
	r.start()
	waitFor(t, "Run to be up", func() bool { r.srv.mu.Lock(); defer r.srv.mu.Unlock(); return r.srv.running })
	if u, tc := r.srv.Addrs(); u != nil || tc != nil {
		t.Fatalf("a server with no sources listens: %v %v", u, tc)
	}
	r.set("udp")
	if u, tc := r.srv.Addrs(); u == nil || tc != nil {
		t.Fatalf("one UDP source: udp=%v tcp=%v", u, tc)
	}
	sendUDP(t, r.udpAddr(), "<34>added")
	waitFor(t, "the line of the added source", func() bool { return len(r.lines()) == 1 })

	r.set("tcp") // the same sender changes protocol
	if u, tc := r.srv.Addrs(); u != nil || tc == nil {
		t.Fatalf("one TCP source: udp=%v tcp=%v", u, tc)
	}
	c := dialTCP(t, r.tcpAddr())
	if _, err := io.WriteString(c, "<34>over tcp\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the tcp line", func() bool { return len(r.lines()) == 2 })

	if err := r.srv.SetSources(nil); err != nil { // the last source is deleted: no socket, and the open connection is closed
		t.Fatal(err)
	}
	if u, tc := r.srv.Addrs(); u != nil || tc != nil {
		t.Fatalf("no sources: udp=%v tcp=%v", u, tc)
	}
	if !closedByPeer(c, 5*time.Second) {
		t.Error("the connection of a deleted source stayed open")
	}
}

func TestTurningTheServerOffClosesEverythingAndFlushes(t *testing.T) {
	r := newRig(t, Limits{BatchWait: time.Hour}, nil)
	r.set("tcp")
	r.start()
	addr := r.tcpAddr()
	c := dialTCP(t, addr)
	if _, err := io.WriteString(c, "<34>last words\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the line to be queued", func() bool { return r.srv.Stats().Received == 1 })
	r.shutdown()
	if got := r.texts(); len(got) != 1 || got[0] != "<34>last words" {
		t.Errorf("flushed %q", got)
	}
	if _, err := dialCtx("tcp4", addr); err == nil {
		t.Error("the port still accepts connections after shutdown")
	}
	if !closedByPeer(c, 2*time.Second) {
		t.Error("an open connection survived the shutdown")
	}
}

func TestTheFallbackPortIsUsedOnlyWhenThePreferredOneIsNotPermitted(t *testing.T) {
	var lc net.ListenConfig
	probe, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:1")
	if err == nil {
		_ = probe.Close()
		t.Skip("this process may bind port 1")
	}
	r := newRig(t, Limits{BatchWait: 10 * time.Millisecond}, nil, 1, 0)
	r.set("udp")
	r.start()
	sendUDP(t, r.udpAddr(), "<34>on the fallback")
	waitFor(t, "the line", func() bool { return len(r.lines()) == 1 })
	if st := r.srv.Status(); !st.FellBack || st.Preferred != 1 || !st.UDP || st.TCP {
		t.Errorf("status %+v", st)
	}
}

func TestEndToEndWithManySendersAtOnce(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 20 * time.Millisecond, Rate: 1e6, Burst: 1e6}, nil)
	r.set("tcp")
	r.start()
	addr := r.tcpAddr()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialCtx("tcp4", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = c.Close() }()
			for i := range 100 {
				_, _ = fmt.Fprintf(c, "<34>g%d n%d\n", g, i)
			}
		}()
	}
	wg.Wait()
	waitFor(t, "800 lines", func() bool { return len(r.lines()) == 800 })
}

// Review finding 1: a blank line, or the LF after an octet-counted frame, must not turn the idle wait (5 min) into the frame
// wait (30 s): a quiet sender is not a slow one.
func TestAQuietSenderKeepsItsConnectionAfterABlankLineOrTheLFOfAFrame(t *testing.T) {
	for name, payload := range map[string]string{"LF after an octet frame": "5 <34>a\n", "blank line": "<34>b\n\n", "CRLF pairs": "<34>c\r\n\r\n"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, Limits{FrameTimeout: 100 * time.Millisecond, Idle: 5 * time.Second, BatchWait: 10 * time.Millisecond}, nil)
			r.set("tcp")
			r.start()
			c := dialTCP(t, r.tcpAddr())
			if _, err := io.WriteString(c, payload); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the first line", func() bool { return len(r.lines()) == 1 })
			if closedByPeer(c, 400*time.Millisecond) { // longer than FrameTimeout, far shorter than Idle
				t.Fatal("a quiet sender was closed after the frame timeout")
			}
			if _, err := io.WriteString(c, "<34>next\n"); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the next line", func() bool { return len(r.lines()) == 2 })
		})
	}
}

// Review finding 2: a bind that fails costs that protocol only, is reported, and is retried without ending anything.
func TestAFailedTCPBindKeepsUDPAndIsReportedAndRetried(t *testing.T) {
	hold, err := listenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := hold.LocalAddr().(*net.UDPAddr).Port
	_ = hold.Close()
	var lc net.ListenConfig
	busy, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("the port is taken: %v", err)
	}
	r := newRig(t, Limits{BatchWait: 10 * time.Millisecond}, nil, port)
	other := netip.MustParseAddr("127.0.0.2")
	if err := r.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "udp"}}); err != nil {
		t.Fatal(err)
	}
	r.start()
	waitFor(t, "UDP up", func() bool { return r.srv.Status().UDP })
	err = r.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "udp"}, other: {ID: "src-2", Proto: "tcp"}})
	if err == nil {
		t.Fatal("a busy TCP port gave no error")
	}
	st := r.srv.Status()
	if !st.UDP || st.TCP || st.TCPErr == "" || st.UDPErr != "" {
		t.Fatalf("status %+v: UDP must stay up and TCP must say why it is down", st)
	}
	sendUDP(t, r.udpAddr(), "<34>still here")
	waitFor(t, "a UDP line while TCP is down", func() bool { return len(r.lines()) == 1 })
	_ = busy.Close()
	if err := r.srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "udp"}, other: {ID: "src-2", Proto: "tcp"}}); err != nil { // the retry
		t.Fatalf("the retry failed: %v", err)
	}
	if st := r.srv.Status(); !st.UDP || !st.TCP || st.TCPErr != "" {
		t.Fatalf("status after the retry %+v", st)
	}
}

func TestABindFailureAtStartDoesNotEndRun(t *testing.T) {
	hold, err := listenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	r := newRig(t, Limits{}, nil, hold.LocalAddr().(*net.UDPAddr).Port)
	r.set("udp")
	r.start()
	waitFor(t, "the failure to be reported", func() bool { return r.srv.Status().UDPErr != "" })
	select {
	case err := <-r.done:
		t.Fatalf("Run ended with %v", err)
	default:
	}
}

// Review finding 4: what the producers queued is stored when the server stops.

// Review finding 6: queue full and backpressure.
type slowSink struct {
	gate chan struct{}
	mu   sync.Mutex
	got  int
	// entered counts the calls that have started (and wait for the gate).
	entered atomic.Int32
}

func (s *slowSink) sink(_ context.Context, lines []Line) error {
	s.entered.Add(1)
	<-s.gate
	s.mu.Lock()
	s.got += len(lines)
	s.mu.Unlock()
	return nil
}

func (s *slowSink) stored() int { s.mu.Lock(); defer s.mu.Unlock(); return s.got }

func newBlockedRig(t *testing.T, proto string) (*Server, *slowSink) {
	t.Helper()
	ss := &slowSink{gate: make(chan struct{})}
	srv, err := New(Config{Host: "127.0.0.1", Ports: []int{0}, Sink: ss.sink, Log: slog.New(slog.DiscardHandler), Limits: Limits{Queue: 1, BatchLines: 1, BatchWait: time.Millisecond, Rate: 1e6, Burst: 1e6}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: proto}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(done) }()
	t.Cleanup(func() {
		select {
		case <-ss.gate:
		default:
			close(ss.gate)
		}
		cancel()
		<-done
	})
	return srv, ss
}

func TestAFullQueueDropsDatagramsAndCountsThem(t *testing.T) {
	srv, ss := newBlockedRig(t, "udp")
	var a net.Addr
	waitFor(t, "the socket", func() bool { a, _ = srv.Addrs(); return a != nil })
	c, err := dialCtx("udp4", a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for i := range 100 {
		_, _ = fmt.Fprintf(c, "<34>d%d", i)
	}
	waitFor(t, "the drops to be counted", func() bool { s := srv.Stats(); return s.QueueDropped > 0 && s.Received+s.QueueDropped == 100 })
	close(ss.gate)
	waitFor(t, "what was accepted to be stored", func() bool { return int64(ss.stored()) == srv.Stats().Received })
}

func TestATCPSenderIsHeldBackNotDroppedWhenTheQueueIsFull(t *testing.T) {
	srv, ss := newBlockedRig(t, "tcp")
	var a net.Addr
	waitFor(t, "the socket", func() bool { _, a = srv.Addrs(); return a != nil })
	c := dialTCP(t, a.String())
	var b strings.Builder
	for i := range 50 {
		fmt.Fprintf(&b, "<34>t%d\n", i)
	}
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatal(err)
	}
	// The Sink holds the first line, the queue (one place) holds the second: the reader is blocked on the third, which is not counted.
	waitFor(t, "the Sink to be held and the queue full", func() bool { return ss.entered.Load() >= 1 && len(srv.queue) == cap(srv.queue) })
	if st := srv.Stats(); st.Received != 2 || st.QueueDropped != 0 {
		t.Fatalf("the reader did not stop: received %d, dropped %d", st.Received, st.QueueDropped)
	}
	close(ss.gate)
	waitFor(t, "all 50 lines", func() bool { return ss.stored() == 50 })
	if srv.Stats().QueueDropped != 0 {
		t.Error("a TCP line was dropped")
	}
}

func TestAnUnknownTCPSenderIsClosedBeforeAnyReadAndCounted(t *testing.T) {
	r := newRig(t, Limits{BatchWait: 10 * time.Millisecond}, nil)
	if err := r.srv.SetSources(map[netip.Addr]Source{netip.MustParseAddr("10.9.9.9"): {ID: "src-9", Proto: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	r.start()
	c := dialTCP(t, r.tcpAddr())
	if !closedByPeer(c, 5*time.Second) { // nothing was sent: only a close at accept can explain it
		t.Fatal("the connection of an unknown sender stayed open")
	}
	waitFor(t, "the count", func() bool { return r.srv.Stats().Unknown == 1 })
	if st := r.srv.Stats(); st.Received != 0 || len(r.lines()) != 0 {
		t.Errorf("stats %+v", st)
	}
}

// A real slow-loris: one byte at a time, each in time for a per-read deadline, is still bounded by the absolute frame deadline.
func TestATrickleOfSingleBytesIsBoundedByTheFrameDeadline(t *testing.T) {
	r := newRig(t, Limits{FrameTimeout: 300 * time.Millisecond, Idle: 5 * time.Second}, nil)
	r.set("tcp")
	r.start()
	c := dialTCP(t, r.tcpAddr())
	start := time.Now()
	for time.Since(start) < 5*time.Second {
		if _, err := c.Write([]byte("a")); err != nil {
			break
		}
		if closedByPeer(c, 30*time.Millisecond) { // the read is the pacing: it returns early when the server closes
			break
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a trickle held the connection for %v with a frame deadline of 300 ms", d)
	}
}

// Review finding 5: a connection accepted while the sources change is not kept for a sender that is gone, even when the TCP
// listener itself stays open (another TCP source remains).
func TestRegisterRefusesASenderThatIsNoLongerATCPSource(t *testing.T) {
	r := newRig(t, Limits{MaxConns: 1}, nil)
	other := netip.MustParseAddr("127.0.0.2")
	both := map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tcp"}, other: {ID: "src-2", Proto: "tcp"}}
	if err := r.srv.SetSources(both); err != nil {
		t.Fatal(err)
	}
	r.start()
	r.tcpAddr()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	r.srv.mu.Lock()
	l := r.srv.tcp
	r.srv.mu.Unlock()
	if got := r.srv.register(l, c1, lo); got != regOK {
		t.Fatalf("a declared TCP sender: %d", got)
	}
	if got := r.srv.register(l, c2, other); got != regOverLimit {
		t.Errorf("over the total limit: %d", got)
	}
	r.srv.unregister(c1, lo)
	if err := r.srv.SetSources(map[netip.Addr]Source{other: {ID: "src-2", Proto: "tcp"}}); err != nil { // lo is gone, the listener stays
		t.Fatal(err)
	}
	if !r.srv.Status().TCP {
		t.Fatal("the TCP listener closed, so this test would not reach the sender check")
	}
	if got := r.srv.register(l, c1, lo); got != regStale {
		t.Errorf("a sender that was removed while its listener stays open: %d, want regStale", got)
	}
	if err := r.srv.SetSources(map[netip.Addr]Source{other: {ID: "src-2", Proto: "udp"}}); err != nil { // the listener closes
		t.Fatal(err)
	}
	if got := r.srv.register(l, c1, other); got != regGone {
		t.Errorf("a listener that is gone: %d, want regGone", got)
	}
	if got := r.srv.register(nil, c1, other); got != regGone {
		t.Errorf("no listener: %d", got)
	}
}

// A refusal because the sources changed is not counted as a connection over a limit.
func TestAConnectionRefusedForStaleSourcesIsNotCountedAsOverTheLimit(t *testing.T) {
	r := newRig(t, Limits{}, nil)
	r.set("tcp")
	r.start()
	r.tcpAddr()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	r.srv.mu.Lock()
	l := r.srv.tcp
	r.srv.mu.Unlock()
	_ = r.srv.SetSources(map[netip.Addr]Source{netip.MustParseAddr("10.1.1.1"): {ID: "src-9", Proto: "tcp"}})
	if got := r.srv.register(l, c1, lo); got != regStale || r.srv.Stats().ConnRejected != 0 {
		t.Errorf("register %d, ConnRejected %d", got, r.srv.Stats().ConnRejected)
	}
}

// Review (round 2) 1: a batch that is being stored when the server stops is not cancelled with it.
func TestABatchBeingStoredAtShutdownIsNotCancelled(t *testing.T) {
	var mu sync.Mutex
	stored, cancelled := 0, 0
	entered := make(chan struct{}, 1)
	sink := func(ctx context.Context, lines []Line) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-time.After(300 * time.Millisecond) // a slow store
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			cancelled += len(lines)
			return err
		}
		stored += len(lines)
		return nil
	}
	srv, err := New(Config{Host: "127.0.0.1", Ports: []int{0}, Sink: sink, Log: slog.New(slog.DiscardHandler), Limits: Limits{BatchLines: 5, BatchWait: time.Hour, Rate: 1e6, Burst: 1e6}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	var a net.Addr
	waitFor(t, "the socket", func() bool { _, a = srv.Addrs(); return a != nil })
	c := dialTCP(t, a.String())
	if _, err := io.WriteString(c, "<34>1\n<34>2\n<34>3\n<34>4\n<34>5\n<34>6\n"); err != nil { // one full batch, one line left over
		t.Fatal(err)
	}
	<-entered // the first batch is in the Sink
	waitFor(t, "all six lines to be accepted", func() bool { return srv.Stats().Received == 6 })
	cancel()
	err = <-done // context.Canceled
	_ = err
	mu.Lock()
	defer mu.Unlock()
	if stored != 6 || cancelled != 0 || srv.Stats().SinkLost != 0 {
		t.Errorf("stored %d, cancelled %d, lost %d: want 6, 0, 0", stored, cancelled, srv.Stats().SinkLost)
	}
}

// A Sink that never returns cannot hold the shutdown longer than FlushOnClose.
func TestAHungSinkIsBoundedAtShutdown(t *testing.T) {
	entered := make(chan struct{}, 1)
	sink := func(ctx context.Context, _ []Line) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	srv, err := New(Config{Host: "127.0.0.1", Ports: []int{0}, Sink: sink, Log: slog.New(slog.DiscardHandler), Limits: Limits{BatchLines: 1, FlushOnClose: 200 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetSources(map[netip.Addr]Source{lo: {ID: "src-1", Proto: "udp"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	var a net.Addr
	waitFor(t, "the socket", func() bool { a, _ = srv.Addrs(); return a != nil })
	sendUDP(t, a.String(), "<34>x")
	<-entered
	cancel()
	select {
	case err := <-done:
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("a hung Sink held the shutdown")
	}
}

// Review (round 2) 2: a stream of line ends only is a gap, and the gap is bounded by the idle deadline.
func TestAnEndlessStreamOfLineEndsDoesNotHoldAConnectionPastIdle(t *testing.T) {
	r := newRig(t, Limits{Idle: 250 * time.Millisecond, FrameTimeout: 5 * time.Second}, nil)
	r.set("tcp")
	r.start()
	c := dialTCP(t, r.tcpAddr())
	start := time.Now()
	for time.Since(start) < 4*time.Second {
		if _, err := c.Write([]byte("\r\n")); err != nil {
			break
		}
		if closedByPeer(c, 20*time.Millisecond) {
			break
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a stream of CR and LF held the connection for %v with an idle limit of 250 ms", d)
	}
}
