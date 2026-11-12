package listen

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestMeasureLimits measures the defaults of Limits on the box it runs on (VEDETTE_MEASURE=1; numbers in D-222): the memory of
// 1,000 idle TCP connections (4 senders x 250, the clients live in the same process and are counted too), and how many lines a
// second the listener hands to a Sink that does nothing, over one TCP connection and over UDP.
func TestMeasureLimits(t *testing.T) {
	if os.Getenv("VEDETTE_MEASURE") == "" {
		t.Skip("set VEDETTE_MEASURE=1 to measure")
	}
	t.Run("1000 idle connections", func(t *testing.T) {
		r := newRig(t, Limits{}, nil)
		srcs := map[netip.Addr]Source{}
		for i := 1; i <= 4; i++ {
			srcs[netip.AddrFrom4([4]byte{127, 0, 0, byte(i)})] = Source{ID: fmt.Sprint("src-", i), Proto: "tcp"}
		}
		if err := r.srv.SetSources(srcs); err != nil {
			t.Fatal(err)
		}
		r.start()
		addr := r.tcpAddr()
		before := heap(t)
		g0 := runtime.NumGoroutine()
		for a := range srcs {
			d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: a.AsSlice()}}
			for range 250 {
				c, err := d.DialContext(context.Background(), "tcp4", addr)
				if err != nil {
					t.Skipf("no loopback address %v here: %v", a, err)
				}
				t.Cleanup(func() { _ = c.Close() })
			}
		}
		waitFor(t, "1000 connections", func() bool { return r.srv.Status().Conns == 1000 })
		after := heap(t)
		t.Logf("1000 idle connections: %.1f MiB heap+stacks (%.0f bytes each, clients included), %d goroutines more",
			(after-before)/(1<<20), (after-before)/1000, runtime.NumGoroutine()-g0)
	})
	line := "<134>Nov 12 08:00:00 fw01 date=2026-11-12 time=08:00:00 devname=FW-HQ type=traffic subtype=forward srcip=192.168.10.20 dstip=8.8.8.8 action=accept\n"
	t.Run("tcp throughput", func(t *testing.T) {
		var n atomic.Int64
		r := newRig(t, Limits{Rate: 1e9, Burst: 1e9}, nil)
		r.srv.cfg.Sink = func(_ context.Context, l []Line) error { n.Add(int64(len(l))); return nil }
		r.set("tcp")
		r.start()
		c := dialTCP(t, r.tcpAddr())
		const total = 500_000
		start := time.Now()
		go func() {
			b := make([]byte, 0, 1<<20)
			for i := 0; i < total; i++ {
				b = append(b, line...)
				if len(b) > 1<<20-len(line) || i == total-1 {
					_, _ = c.Write(b)
					b = b[:0]
				}
			}
		}()
		waitFor(t, "every line", func() bool { return n.Load() == total })
		d := time.Since(start)
		t.Logf("tcp: %d lines in %v = %.0f lines/s", total, d, total/d.Seconds())
	})
	t.Run("udp throughput", func(t *testing.T) {
		var n atomic.Int64
		var end atomic.Bool
		r := newRig(t, Limits{Rate: 1e9, Burst: 1e9}, nil)
		r.srv.cfg.Sink = func(_ context.Context, l []Line) error {
			n.Add(int64(len(l)))
			if l[len(l)-1].Text == "<134>end" {
				end.Store(true)
			}
			return nil
		}
		r.set("udp")
		r.start()
		c, err := dialCtx("udp4", r.udpAddr())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		const total = 200_000
		start := time.Now()
		for range total {
			_, _ = c.Write([]byte(line))
		}
		sent := time.Since(start)
		_, _ = c.Write([]byte("<134>end")) // the last datagram, in order on loopback: once it is in a batch every earlier one has been read
		waitFor(t, "the end marker", end.Load)
		st := r.srv.Stats()
		t.Logf("udp: sent %d in %v (%.0f/s); received %d (the end marker included), queue-dropped %d (kernel drops are not seen)", total, sent, total/sent.Seconds(), n.Load(), st.QueueDropped)
	})
}

func heap(t *testing.T) float64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapInuse + m.StackInuse)
}
