package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sshFail is a line of a daemon that the profiles do not read (the miner does): the remote peer is the address after "from".
func sshFail(ip string) string {
	return fmt.Sprintf("<38>Nov  9 10:00:00 gw sshd[812]: Failed password for invalid user admin from %s port 51234 ssh2", ip)
}

// sshSig is the signature of sshFail (a mined one: the address, the user and the port are masked).
func (e *env) sshSig() string {
	return e.svc.sigs.Of("linux-rsyslog", sshFail("203.0.113.1")).Signature
}

func (e *env) feedAll(src Source, texts []string) {
	e.t.Helper()
	for len(texts) > 0 {
		k := min(len(texts), MaxBatch)
		batch := make([]Line, k)
		for i := range batch {
			batch[i] = Line{SourceID: src.ID, At: e.svc.now(), Text: texts[i]}
		}
		if _, err := e.svc.Ingest(e.t.Context(), batch); err != nil {
			e.t.Fatal(err)
		}
		texts = texts[k:]
	}
}

func repeat(text string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = text
	}
	return out
}

func (e *env) top(src Source, sig string, window time.Duration, n int) []AddressCount {
	e.t.Helper()
	got, err := e.svc.TopAddresses(e.t.Context(), src.ID, sig, window, n)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

// addLinux is a source of a kind that no profile reads: its lines go to the generic reader of the remote address.
func (e *env) addLinux(name, ip string) Source {
	e.t.Helper()
	s, err := e.svc.AddSource(e.t.Context(), "admin@acme.example", Input{Kind: "linux-rsyslog", Name: name, SenderIP: ip, Proto: "udp", Port: 514})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func fmtTop(l []AddressCount) string {
	var b strings.Builder
	for _, c := range l {
		fmt.Fprintf(&b, "%s=%d ", c.Addr, c.Count)
	}
	return strings.TrimSpace(b.String())
}

// rank-by-count, ties by address, n and the window (INV-3: the same input gives the same answer).
func TestContract_TopAddresses_RanksByCountThenAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	var lines []string
	for ip, n := range map[string]int{"203.0.113.9": 5, "203.0.113.8": 3, "203.0.113.30": 3, "198.51.100.7": 1} {
		lines = append(lines, repeat(sshFail(ip), n)...)
	}
	e.feedAll(src, lines)
	sig := e.sshSig()
	all := e.top(src, sig, time.Hour, 10)
	// 203.0.113.30 and 203.0.113.8 tie at 3: the address order is numeric (netip), not the text order.
	if got, want := fmtTop(all), "203.0.113.9=5 203.0.113.8=3 203.0.113.30=3 198.51.100.7=1"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := fmtTop(e.top(src, sig, time.Hour, 2)); got != "203.0.113.9=5 203.0.113.8=3" {
		t.Fatalf("n=2: %q", got)
	}
	if n, _ := e.svc.Counts(t.Context(), src.ID, sig, time.Hour); n != 12 {
		t.Fatalf("Counts %d: the lines count whatever their address", n)
	}
	// IPv6 is an address like another (the miner reads its line as another signature: it masks it as hex).
	v6 := e.svc.sigs.Of("linux-rsyslog", sshFail("2001:db8::1")).Signature
	e.feedAll(src, append(repeat(sshFail("2001:db8::1"), 4), repeat(sshFail("::ffff:198.51.100.7"), 2)...))
	if got := fmtTop(e.top(src, v6, time.Hour, 10)); got != "2001:db8::1=4" && got != "2001:db8::1=4 198.51.100.7=2" {
		t.Fatalf("%q", got)
	}
}

func TestTopAddressesWindowsAndBounds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	e.feedAll(src, repeat(sshFail("203.0.113.1"), 4))
	e.advance(10 * time.Minute)
	e.feedAll(src, repeat(sshFail("203.0.113.2"), 2))
	sig := e.sshSig()
	for _, c := range []struct {
		window time.Duration
		want   string
	}{
		{5 * time.Minute, "203.0.113.2=2"},
		{30 * time.Minute, "203.0.113.1=4 203.0.113.2=2"},
		{24 * time.Hour, "203.0.113.1=4 203.0.113.2=2"},
	} {
		if got := fmtTop(e.top(src, sig, c.window, 10)); got != c.want {
			t.Errorf("window %v: %q, want %q", c.window, got, c.want)
		}
	}
	for _, w := range []time.Duration{0, time.Minute, 25 * time.Hour, -time.Hour} {
		if _, err := e.svc.TopAddresses(t.Context(), src.ID, sig, w, 5); !errors.Is(err, ErrBadWindow) {
			t.Errorf("window %v: %v", w, err)
		}
	}
	for _, n := range []int{0, -3} {
		if _, err := e.svc.TopAddresses(t.Context(), src.ID, sig, time.Hour, n); !errors.Is(err, ErrBadCount) {
			t.Errorf("n=%d: %v", n, err)
		}
	}
	// n over the cap is the cap: 60 addresses, one line each, and a question for 1,000.
	var lines []string
	for i := 0; i < 60; i++ {
		lines = append(lines, sshFail(fmt.Sprintf("203.0.114.%d", i+1)))
	}
	e.feedAll(src, lines)
	if got := e.top(src, sig, time.Hour, 1000); len(got) != MaxTopAddresses {
		t.Fatalf("%d addresses for n=1000, want %d", len(got), MaxTopAddresses)
	}
	// A signature never seen, a source never seen and a signature without addresses are empty lists, not errors.
	for _, c := range []struct{ source, sig string }{{src.ID, "never seen"}, {"ls-nothing", sig}, {src.ID, sigFor(22)}} {
		if got, err := e.svc.TopAddresses(t.Context(), c.source, c.sig, time.Hour, 5); err != nil || len(got) != 0 {
			t.Errorf("%+v: %v %v", c, got, err)
		}
	}
}

// The address is the remote peer of the line and never the device that sent the log: the sender of this source is 192.168.10.1.
func TestContract_TopAddresses_NeverTheSender(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 3) // srcip=45.9.148.20 dstip=10.0.0.1 and the sender is 192.168.10.1
	got := e.top(src, sigFor(22), time.Hour, 10)
	if fmtTop(got) != "45.9.148.20=3" {
		t.Fatalf("%q", fmtTop(got))
	}
	// A line of the device itself (a FortiGate local-out line names its own address as srcip) is not counted, in any form of the address.
	logid, action := fgN(23)
	for _, sender := range []string{"192.168.10.1", `"192.168.10.1"`} {
		e.feed(src, fmt.Sprintf(`type="traffic" subtype="local" logid="%s" srcip=%s dstip=8.8.8.8 action="%s"`, logid, sender, action), 20)
	}
	if got := e.top(src, sigFor(23), time.Hour, 10); len(got) != 0 {
		t.Fatalf("the log sender is counted: %q", fmtTop(got))
	}
	if n, _ := e.svc.Counts(t.Context(), src.ID, sigFor(23), time.Hour); n != 40 {
		t.Fatalf("Counts %d", n)
	}
}

// Addresses that are never counted: the ones the port lists (box, gateway, decoy), whatever the form the line writes them in, and the
// unspecified, loopback, multicast, link-local and broadcast ones. A private LAN address does count.
func TestContract_TopAddresses_NeverTheBoxTheGatewayADecoyOrASpecialAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	e.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.168.10.2"),          // the box
			netip.MustParseAddr("192.168.10.254"),        // the gateway
			netip.MustParseAddr("192.168.10.99"),         // a decoy
			netip.MustParseAddr("::ffff:192.168.10.100"), // listed in the mapped form
			netip.MustParseAddr("fd00::2%eth0"),          // listed with a zone
			netip.MustParseAddr("2001:db8::bad"),         // an IPv6 address of the box
			{},                                           // an invalid entry is ignored
		}, nil
	}
	var lines []string
	for _, ip := range []string{
		"192.168.10.2", "192.168.10.254", "192.168.10.99", "192.168.10.100", "::ffff:192.168.10.2", "[fd00::2]:22", "2001:db8::bad", "2001:DB8:0:0:0:0:0:BAD",
		"127.0.0.1", "127.9.9.9", "::1", "0.0.0.0", "::", "224.0.0.251", "ff02::fb", "169.254.1.1", "fe80::1", "255.255.255.255",
	} {
		lines = append(lines, repeat(sshFail(ip), 3)...)
	}
	lines = append(lines, repeat(sshFail("192.168.10.77"), 2)...) // an internal brute-forcer is real
	lines = append(lines, repeat(sshFail("10.9.9.9"), 1)...)
	e.feedAll(src, lines)
	sig := e.sshSig()
	if got := fmtTop(e.top(src, sig, time.Hour, 50)); got != "192.168.10.77=2 10.9.9.9=1" && got != "10.9.9.9=1 192.168.10.77=2" {
		t.Fatalf("got %q", got)
	}
	total := 0
	for sg := range sigsOf(e, lines) { // the miner reads an IPv6 line as another signature than an IPv4 one: add them up
		n, _ := e.svc.Counts(t.Context(), src.ID, sg, time.Hour)
		total += n
	}
	if total != 18*3+3 {
		t.Fatalf("Counts %d: the lines of those addresses still count", total)
	}
}

// The set is asked at most every 30 seconds; an error keeps the last set that was known; the addresses that came with the first error
// are used only while there is no earlier set.
func TestNeverCountPortIsCachedAndFailsSafe(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	var asks atomic.Int32
	var fail atomic.Bool
	box := netip.MustParseAddr("192.168.10.2")
	e.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) {
		asks.Add(1)
		if fail.Load() {
			return nil, errors.New("host unknown")
		}
		return []netip.Addr{box}, nil
	}
	feed := func() { e.feedAll(src, []string{sshFail("192.168.10.2"), sshFail("203.0.113.5")}) }
	feed()
	feed()
	if asks.Load() != 1 {
		t.Fatalf("asked %d times in one instant", asks.Load())
	}
	fail.Store(true)
	e.advance(31 * time.Second)
	feed()
	if asks.Load() != 2 {
		t.Fatalf("asked %d times after the TTL", asks.Load())
	}
	if got := fmtTop(e.top(src, e.sshSig(), time.Hour, 10)); got != "203.0.113.5=3" {
		t.Fatalf("after a failed ask the box was counted: %q", got)
	}
	// The box moves; a good answer after the failure replaces the set.
	fail.Store(false)
	box = netip.MustParseAddr("192.168.10.3")
	e.advance(31 * time.Second)
	e.feedAll(src, []string{sshFail("192.168.10.2"), sshFail("192.168.10.3")})
	if got := fmtTop(e.top(src, e.sshSig(), time.Hour, 10)); got != "203.0.113.5=3 192.168.10.2=1" {
		t.Fatalf("%q", got)
	}
	// No earlier set and an error: what the port returned with it is used (the container's own addresses are known even when the host is not).
	e2 := newEnv(t)
	s2 := e2.addLinux("FW-HQ", "192.168.10.1")
	e2.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.10.2")}, errors.New("host unknown")
	}
	e2.feedAll(s2, []string{sshFail("192.168.10.2"), sshFail("203.0.113.5")})
	if got := fmtTop(e2.top(s2, e2.sshSig(), time.Hour, 10)); got != "203.0.113.5=1" {
		t.Fatalf("%q", got)
	}
}

func (e *env) addrRows(src Source) (perSig, perBucket int) {
	e.t.Helper()
	perSig = count(e.t, e.vol, `SELECT coalesce(max(n), 0) FROM (SELECT count(*) AS n FROM logs_signature_addrs WHERE source_id = ? GROUP BY bucket, sig_hash)`, src.ID)
	perBucket = count(e.t, e.vol, `SELECT coalesce(max(n), 0) FROM (SELECT count(*) AS n FROM logs_signature_addrs WHERE source_id = ? GROUP BY bucket)`, src.ID)
	return perSig, perBucket
}

func sigsOf(e *env, lines []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		out[e.svc.sigs.Of("linux-rsyslog", l).Signature] = true
	}
	return out
}

func spoof(i int) string { // a different IPv4 address for each i (an IPv6 one is another signature to the miner)
	return fmt.Sprintf("%d.%d.%d.%d", 11+i/16777216%200, i/65536%256, i/256%256, i%256)
}

// INV-1: a flood of one-line spoofed addresses stays inside the quotas, and an address that really sent ten lines is the first of the answer,
// whether it comes before the flood, inside it, or after it, in one batch or spread over many.
func TestContract_TopAddresses_SpoofedFloodIsBoundedAndTheRealAttackerWins(t *testing.T) {
	t.Parallel()
	attacker := "203.0.113.200"
	for name, order := range map[string]func(e *env, src Source){ // each sends the attacker's lines in a different place; want is how many
		"attacker first": func(e *env, src Source) {
			e.feedAll(src, repeat(sshFail(attacker), 10))
			for i := 0; i < 3000; i += 500 {
				var l []string
				for k := 0; k < 500; k++ {
					l = append(l, sshFail(spoof(i+k)))
				}
				e.feedAll(src, l)
			}
		},
		"attacker last": func(e *env, src Source) {
			for i := 0; i < 3000; i += 500 {
				var l []string
				for k := 0; k < 500; k++ {
					l = append(l, sshFail(spoof(i+k)))
				}
				e.feedAll(src, l)
			}
			e.feedAll(src, repeat(sshFail(attacker), 10))
		},
		"attacker inside one batch": func(e *env, src Source) {
			for i := 0; i < 3000; i += 490 {
				var l []string
				for k := 0; k < 490; k++ {
					l = append(l, sshFail(spoof(i+k)))
				}
				l = append(l[:100], append(repeat(sshFail(attacker), 2), l[100:]...)...) // 2 of the attacker's lines in each of 7 batches
				e.feedAll(src, l)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			src := e.addLinux("FW-HQ", "192.168.10.1")
			order(e, src)
			sig := e.sshSig()
			got := e.top(src, sig, time.Hour, 5)
			want := 10
			if name == "attacker inside one batch" {
				want = 14
			}
			if len(got) == 0 || got[0].Addr != netip.MustParseAddr(attacker) || got[0].Count != want {
				t.Fatalf("top: %q, want the attacker with %d", fmtTop(got), want)
			}
			perSig, perBucket := e.addrRows(src)
			if perSig > MaxAddrsPerSignature || perBucket > MaxAddrRowsPerBucket {
				t.Fatalf("%d rows of a signature, %d of a bucket", perSig, perBucket)
			}
			if n, _ := e.svc.Counts(t.Context(), src.ID, sig, time.Hour); n < 3000 {
				t.Fatalf("Counts %d: the lines are counted whatever their address", n)
			}
		})
	}
}

// A one-line address never looks like more than it sent: no row is ever above the lines its address sent (no space-saving inflation).
func TestTopAddressesCountsAreNeverInflated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	for i := 0; i < 4000; i += 500 {
		var l []string
		for k := 0; k < 500; k++ {
			l = append(l, sshFail(spoof(i+k)))
		}
		e.feedAll(src, l)
	}
	for _, c := range e.top(src, e.sshSig(), time.Hour, 50) {
		if c.Count != 1 {
			t.Fatalf("%s has %d lines, it sent 1", c.Addr, c.Count)
		}
	}
}

// The bucket quota counts every signature of the source: 100 signatures of 50 addresses each is 5,000 rows asked and 1,000 kept, and an
// attacker of ten lines in a new signature takes the place of one-line rows.
func TestContract_TopAddresses_BucketQuotaCoversEverySignature(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"}
	line := func(k int, ip string) string {
		return fmt.Sprintf("<38>Nov  9 10:00:00 gw vpn: %s %s tunnel refused from %s", words[k%10], words[k/10%10], ip)
	}
	sigs := map[string]bool{}
	for k := 0; k < 100; k++ {
		var l []string
		for a := 0; a < 50; a++ {
			l = append(l, line(k, spoof(k*50+a)))
		}
		sigs[e.svc.sigs.Of("linux-rsyslog", l[0]).Signature] = true
		e.feedAll(src, l)
	}
	if len(sigs) < 60 {
		t.Fatalf("only %d signatures: the test does not spread the rows", len(sigs))
	}
	if _, perBucket := e.addrRows(src); perBucket != 500 { // the number itself: a quota that moves is a change of the ceiling that CONTRACT states
		t.Fatalf("%d rows in the bucket, want exactly the quota 500", perBucket)
	}
	e.feedAll(src, repeat(sshFail("203.0.113.201"), 10))
	if got := e.top(src, e.sshSig(), time.Hour, 3); len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("the attacker is not kept: %q", fmtTop(got))
	}
	if _, perBucket := e.addrRows(src); perBucket > MaxAddrRowsPerBucket {
		t.Fatalf("%d rows", perBucket)
	}
}

// The quotas are per source and bucket: another source and another bucket have their own.
func TestTopAddressesQuotasArePerSourceAndBucket(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.addLinux("FW-A", "192.168.10.1")
	b := e.addLinux("FW-B", "192.168.10.3")
	var l []string
	for i := 0; i < 200; i++ {
		l = append(l, sshFail(spoof(i)))
	}
	e.feedAll(a, l)
	e.feedAll(b, repeat(sshFail("203.0.113.9"), 2))
	if got := fmtTop(e.top(b, e.sshSig(), time.Hour, 5)); got != "203.0.113.9=2" {
		t.Fatalf("%q", got)
	}
	if got := e.top(a, e.sshSig(), time.Hour, 50); len(got) != 50 {
		t.Fatalf("%d", len(got))
	}
	e.advance(10 * time.Minute) // a new bucket has an empty quota
	e.feedAll(a, repeat(sshFail("203.0.113.10"), 2))
	got := e.top(a, e.sshSig(), time.Hour, 1)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("%q", fmtTop(got))
	}
}

// The counters of addresses go with the other 5-minute counters: after 24 hours and a bucket, by the housekeeping pass.
func TestPurgeDropsOldAddressCounters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	for _, h := range []int{0, 23, 25, 47} {
		*e.clock = t0.Add(-time.Duration(h) * time.Hour)
		e.feedAll(src, []string{sshFail("203.0.113.9")})
	}
	*e.clock = t0
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_addrs`); n != 2 {
		t.Fatalf("%d address rows, want 2 (0 h and 23 h)", n)
	}
	if got := fmtTop(e.top(src, e.sshSig(), CountsMaxWindow, 5)); got != "203.0.113.9=2" {
		t.Fatalf("%q", got)
	}
}

// SYS-5: the only job that touches the address counters while the module is off is the housekeeping purge (drops what is old); the
// writer is Ingest, which only the syslog job (not housekeeping, so not run with the module off) calls. What is kept stays readable.
func TestContract_SYS5_AddressCountersAreWrittenOnlyByJobsThatStopWithTheModule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	e.feedAll(src, repeat(sshFail("203.0.113.9"), 3))
	for _, j := range Jobs(e.svc) {
		if j.Housekeeping != (j.Name == "purge") {
			t.Errorf("job %s: housekeeping %v", j.Name, j.Housekeeping)
		}
	}
	if _, err := e.svc.Purge(t.Context()); err != nil { // the housekeeping pass with the module off: nothing in the window goes
		t.Fatal(err)
	}
	if got := fmtTop(e.top(src, e.sshSig(), time.Hour, 5)); got != "203.0.113.9=3" {
		t.Fatalf("%q", got)
	}
}

// The read uses its index and not a scan of the other sources.
func TestTopAddressesUsesItsIndex(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, err := e.vol.Reader().QueryContext(t.Context(), `EXPLAIN QUERY PLAN `+topAddrsSQL, "ls-x", int64(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for r.Next() {
		var a, b, c int
		var s string
		_ = r.Scan(&a, &b, &c, &s)
		plan.WriteString(s + "; ")
	}
	_ = r.Close()
	if !strings.Contains(plan.String(), "logs_signature_addrs_source") {
		t.Fatalf("TopAddresses does not use its index: %s", plan.String())
	}
}

// TestMeasureAddressCeilings measures the bytes the address counters take per source with every quota full and every value at its longest
// (the number written in CONTRACT), and what TopAddresses costs on them. VEDETTE_MEASURE=1.
func TestMeasureAddressCeilings(t *testing.T) {
	if os.Getenv("VEDETTE_MEASURE") == "" {
		t.Skip("set VEDETTE_MEASURE=1 to measure")
	}
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	size := func() int {
		return count(t, e.vol, `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`)
	}
	b0 := size()
	now := e.svc.now().Unix() / bucketSeconds
	buckets := 301 // 24 hours and a bucket, and the lag of the hourly purge: the ceiling D-206 states for the other 5-minute counters
	if err := e.svc.cfg.Volume.Write(t.Context(), func(tx *sql.Tx) error {
		for b := 0; b < buckets; b++ {
			for k := 0; k < MaxAddrRowsPerBucket; k++ {
				sig := fmt.Sprintf("%04d", k/MaxAddrsPerSignature)
				if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_addrs (source_id, bucket, sig_hash, addr, count) VALUES (?, ?, ?, ?, 1000000)`,
					src.ID, now-int64(b), sigHash(sig), addrBytes(k)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b1 := size()
	rows := buckets * MaxAddrRowsPerBucket
	t.Logf("addresses: %d rows, %d bytes/row (IPv6: 16 bytes), %.1f MiB per source", rows, (b1-b0)/rows, float64(b1-b0)/(1<<20))
	// A realistic row is an IPv4 address (about 11 bytes) and a count of a few digits.
	start := time.Now()
	_, err := e.svc.TopAddresses(t.Context(), src.ID, fmt.Sprintf("%04d", 3), CountsMaxWindow, 50)
	t.Logf("TopAddresses 24h on a full source: %v %v", time.Since(start), err)
}

func addrBytes(k int) []byte {
	a := netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, byte(k >> 8 & 0xff), byte(k & 0xff)})
	return a.AsSlice()
}

// TestMeasureIngestCostOfAddresses is a batch of 500 lines of the ssh layout under three shapes of address, to compare with and without the
// address counters (VEDETTE_MEASURE=1; see the numbers in D-210): one address, 500 different addresses (one signature), 500 addresses
// of 25 signatures.
func TestMeasureIngestCostOfAddresses(t *testing.T) {
	if os.Getenv("VEDETTE_MEASURE") == "" {
		t.Skip("set VEDETTE_MEASURE=1 to measure")
	}
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee"}
	run := func(name string, n int, f func(i int) string) {
		start := time.Now()
		for k := 0; k < n; k++ {
			l := make([]string, MaxBatch)
			for i := range l {
				l[i] = f(k*MaxBatch + i)
			}
			e.feedAll(src, l)
		}
		t.Logf("%s: %v per batch of 500", name, time.Since(start)/time.Duration(n))
	}
	run("one address", 20, func(int) string { return sshFail("203.0.113.9") })
	run("500 addresses, one signature", 20, func(i int) string { return sshFail(spoof(i)) })
	run("addresses of 25 signatures", 20, func(i int) string {
		return fmt.Sprintf("<38>Nov  9 10:00:00 gw vpn: %s tunnel refused from %s", words[i%25], spoof(i+100000))
	})
	// The worst case for the quotas: the bucket is full of one-line rows, and every batch brings 250 new addresses of two lines each, which
	// each push out a row (a delete and an insert).
	run("churn: 250 new addresses x 2 lines, bucket full", 20, func(i int) string {
		return fmt.Sprintf("<38>Nov  9 10:00:00 gw vpn: %s tunnel refused from %s", words[i/2%25], spoof(i/2+300000))
	})
}

// SourceNames is the narrow read: names and kinds from logs_sources, in creation order, and it asks the inventory nothing.
func TestSourceNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Inventory = nil
	if got, err := e.svc.SourceNames(t.Context()); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	a := e.add("FW-HQ", "192.168.10.1")
	e.advance(time.Second)
	b := e.add("FW-B", "192.168.10.3")
	got, err := e.svc.SourceNames(t.Context())
	want := []SourceName{{a.ID, "FW-HQ", "fortigate"}, {b.ID, "FW-B", "fortigate"}}
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("%v %v", got, err)
	}
}

// M1: an attacker that sends one line at a time (batches close every 2 seconds) behind a signature full of one-line addresses is not hidden: the
// exact count of an address that has no row is kept in memory, and the address gets its row at its second line with the count it sent.
func TestContract_TopAddresses_SlowAttackerBehindAFullSignatureIsKept(t *testing.T) {
	t.Parallel()
	for _, prefill := range []int{50, 60} {
		t.Run(fmt.Sprint(prefill), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			src := e.addLinux("FW-HQ", "192.168.10.1")
			var l []string
			for i := 0; i < prefill; i++ {
				l = append(l, sshFail(spoof(i)))
			}
			e.feedAll(src, l)
			spoofs := prefill
			for step := 0; step < 90; step++ { // 15 minutes: three buckets
				e.advance(10 * time.Second)
				e.feedAll(src, []string{sshFail("203.0.113.200"), sshFail(spoof(spoofs)), sshFail(spoof(spoofs + 1))}) // 10 noise lines a minute
				spoofs += 2
			}
			got := e.top(src, e.sshSig(), CountsMaxWindow, 3)
			if len(got) == 0 || got[0].Addr != netip.MustParseAddr("203.0.113.200") || got[0].Count != 90 {
				t.Fatalf("got %q, want the attacker with 90", fmtTop(got))
			}
			if perSig, _ := e.addrRows(src); perSig > 50 {
				t.Fatalf("%d rows of a signature", perSig)
			}
		})
	}
}

// The same behind a bucket that is full across signatures (500 rows of one-line addresses in 100 signatures).
func TestContract_TopAddresses_SlowAttackerBehindAFullBucketIsKept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	for k := 0; k < 100; k++ {
		var l []string
		for a := 0; a < 50; a++ {
			l = append(l, vpnLine(k, spoof(k*50+a)))
		}
		e.feedAll(src, l)
	}
	if _, perBucket := e.addrRows(src); perBucket != 500 {
		t.Fatalf("%d rows", perBucket)
	}
	for step := 0; step < 10; step++ {
		e.advance(10 * time.Second)
		e.feedAll(src, []string{sshFail("203.0.113.200"), vpnLine(3, spoof(900000+step))})
	}
	got := e.top(src, e.sshSig(), time.Hour, 3)
	if len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("got %q, want the attacker with 10", fmtTop(got))
	}
	if _, perBucket := e.addrRows(src); perBucket != 500 {
		t.Fatalf("%d rows", perBucket)
	}
}

func vpnLine(k int, ip string) string {
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"}
	return fmt.Sprintf("<38>Nov  9 10:00:00 gw vpn: %s %s tunnel refused from %s", words[k%10], words[k/10%10], ip)
}

// The memory of the addresses without a row is bounded.
func TestPendingAddressesAreBounded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	for i := 0; i < 6000; i += 500 {
		var l []string
		for k := 0; k < 500; k++ {
			l = append(l, sshFail(spoof(i+k)))
		}
		e.feedAll(src, l)
	}
	e.svc.pendMu.Lock()
	n := len(e.svc.pend)
	e.svc.pendMu.Unlock()
	if n == 0 || n > MaxPendingAddrs {
		t.Fatalf("%d addresses in memory", n)
	}
}

// A tie keeps the old row, at the quota of a signature and at the quota of a bucket: a newcomer needs more lines than the least counted row.
func TestTopAddressesTieKeepsTheOldRow(t *testing.T) {
	t.Parallel()
	t.Run("signature", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		src := e.addLinux("FW-HQ", "192.168.10.1")
		var l []string
		for i := 0; i < 50; i++ {
			l = append(l, sshFail(spoof(i)), sshFail(spoof(i)))
		}
		e.feedAll(src, l)
		e.feedAll(src, []string{sshFail("203.0.113.201"), sshFail("203.0.113.201")}) // 2 lines = the least row
		if got := e.top(src, e.sshSig(), time.Hour, 50); len(got) != 50 || fmtTop(got[:0]) != "" || has(got, "203.0.113.201") {
			t.Fatalf("a tie replaced a row: %d rows, newcomer in: %v", len(got), has(got, "203.0.113.201"))
		}
		e.feedAll(src, repeat(sshFail("203.0.113.202"), 3))
		if got := e.top(src, e.sshSig(), time.Hour, 1); len(got) != 1 || got[0].Count != 3 {
			t.Fatalf("%q", fmtTop(got))
		}
	})
	t.Run("bucket", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		src := e.addLinux("FW-HQ", "192.168.10.1")
		for k := 0; k < 100; k++ {
			var l []string
			for a := 0; a < 50; a++ {
				l = append(l, vpnLine(k, spoof(k*50+a)), vpnLine(k, spoof(k*50+a)))
			}
			e.feedAll(src, l)
		}
		e.feedAll(src, []string{sshFail("203.0.113.201"), sshFail("203.0.113.201")})
		if got := e.top(src, e.sshSig(), time.Hour, 5); len(got) != 0 {
			t.Fatalf("a tie replaced a row of the bucket: %q", fmtTop(got))
		}
		e.feedAll(src, repeat(sshFail("203.0.113.202"), 3))
		if got := e.top(src, e.sshSig(), time.Hour, 5); len(got) != 1 || got[0].Count != 3 {
			t.Fatalf("%q", fmtTop(got))
		}
		if _, perBucket := e.addrRows(src); perBucket != 500 {
			t.Fatalf("%d rows", perBucket)
		}
	})
}

func has(l []AddressCount, ip string) bool {
	for _, c := range l {
		if c.Addr == netip.MustParseAddr(ip) {
			return true
		}
	}
	return false
}

// M3: lines stored while the box's address was not known (the host had not answered) are not returned once it is, and until a whole answer has
// been had the port is asked at every batch.
func TestContract_TopAddresses_BoxAddressStoredBeforeItWasKnownIsNotReturned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.addLinux("FW-HQ", "192.168.10.1")
	known := false
	var asks atomic.Int32
	e.svc.cfg.NeverCount = func(context.Context) ([]netip.Addr, error) {
		asks.Add(1)
		if !known {
			return []netip.Addr{netip.MustParseAddr("172.18.0.5")}, errors.New("host unknown") // the container's own address only
		}
		return []netip.Addr{netip.MustParseAddr("172.18.0.5"), netip.MustParseAddr("192.168.10.2")}, nil
	}
	e.feedAll(src, repeat(sshFail("192.168.10.2"), 20)) // the box's LAN address, while the host has not answered
	e.feedAll(src, repeat(sshFail("203.0.113.9"), 2))
	e.feedAll(src, repeat(sshFail("203.0.113.9"), 2))
	if asks.Load() != 3 {
		t.Fatalf("asked %d times in 3 batches while the set is not known, want every batch", asks.Load())
	}
	known = true
	if got := fmtTop(e.top(src, e.sshSig(), time.Hour, 5)); got != "203.0.113.9=4" {
		t.Fatalf("the box's address is returned: %q", got)
	}
	before := asks.Load()
	e.feedAll(src, repeat(sshFail("203.0.113.9"), 1))
	e.feedAll(src, repeat(sshFail("203.0.113.9"), 1))
	if asks.Load() != before {
		t.Fatalf("asked again within the TTL of a whole answer")
	}
}

// R2 M1: a flood of one-line addresses on some signatures must not push the exact count of a slow attacker on another one out of memory,
// whatever the order of the signature hashes (the old order dropped by hash). The clock is injected, nothing sleeps.
func TestPendingFloodStarvesOnlyItsSignature(t *testing.T) {
	t.Parallel()
	for _, higher := range []bool{true, false} {
		t.Run(fmt.Sprint("floodHashHigher=", higher), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			src := e.addLinux("FW-HQ", "192.168.10.1")
			ssh := sigHash(e.sshSig())
			var l []string
			next := 0
			for k := 0; k < 100; k++ {
				if (sigHash(e.svc.sigs.Of("linux-rsyslog", vpnLine(k, spoof(0))).Signature) > ssh) != higher {
					continue
				}
				for a := 0; a < 200; a++ {
					l = append(l, vpnLine(k, spoof(next)))
					next++
				}
			}
			if len(l) < 4300 {
				t.Fatalf("only %d flood lines", len(l))
			}
			e.feedAll(src, l)
			for step := 0; step < 20; step++ {
				e.advance(10 * time.Second)
				e.feedAll(src, []string{sshFail("203.0.113.200")})
			}
			got := e.top(src, e.sshSig(), time.Hour, 3)
			if len(got) != 1 || got[0].Addr != netip.MustParseAddr("203.0.113.200") || got[0].Count != 20 {
				t.Fatalf("got %q, want the attacker with 20", fmtTop(got))
			}
		})
	}
}
