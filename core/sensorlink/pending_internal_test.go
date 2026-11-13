package sensorlink

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeLn hands out the connections pushed to it, one per Accept.
type fakeLn struct {
	ch chan net.Conn
}

func (f *fakeLn) Accept() (net.Conn, error) {
	c, ok := <-f.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (f *fakeLn) Close() error   { return nil }
func (f *fakeLn) Addr() net.Addr { return &net.TCPAddr{} }

type fakeConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	next []time.Duration // when set, each call to now first moves the clock by the next step
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.next) > 0 {
		c.t, c.next = c.t.Add(c.next[0]), c.next[1:]
	}
	return c.t
}
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// D-326: a full pool evicts its oldest pending connection when that one has waited MinPendingAge, and closes a newcomer when every pending
// one is younger; a promoted (handshaken) connection leaves the pool and cannot be evicted; a late promotion fails.
func TestPendingPoolEvictsTheOldestOrRefusesTheNewest(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)}
	in := &fakeLn{ch: make(chan net.Conn, 16)}
	l := newPendingListener(in, 2, 250*time.Millisecond, time.Hour, clk.now)
	accept := func() (*fakeConn, *limitConn) {
		t.Helper()
		raw := &fakeConn{}
		in.ch <- raw
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return raw, c.(*limitConn)
	}
	rawA, a := accept()
	_, b := accept()
	// both pending; a newcomer while they are young (100 ms) is closed at once, and Accept moves on to the next one (300 ms: a is old enough)
	young := &fakeConn{}
	in.ch <- young
	rawC := &fakeConn{}
	in.ch <- rawC
	clk.mu.Lock()
	clk.next = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}
	clk.mu.Unlock()
	got, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c := got.(*limitConn)
	if !young.isClosed() {
		t.Error("a newcomer to a pool full of young connections was kept")
	}
	if !rawA.isClosed() || a.promote() {
		t.Error("the oldest pending connection (300 ms) was not evicted for the newcomer, or could still finish its handshake")
	}
	// b finishes its handshake: it leaves the pool and is not evicted later
	if !b.promote() {
		t.Fatal("a pending connection could not be promoted")
	}
	clk.add(time.Second)
	_, d := accept()
	_, e := accept() // the pool is c and d: e evicts c (1 s old), never b
	if b.Conn.(*fakeConn).isClosed() {
		t.Error("a promoted connection was evicted")
	}
	if c.promote() {
		t.Error("an evicted connection was promoted")
	}
	if !d.promote() || !e.promote() {
		t.Error("the remaining pending connections could not be promoted")
	}
	_ = b.Close()
	_ = b.Close() // twice is harmless
}

// D-326: a connection still pending after the deadline is closed, whatever net/http's own timeouts say. The listener's timer runs on
// the fake clock of a synctest bubble, so the deadline is exact and a slow machine cannot make it look late (D-373).
func TestPendingConnectionsHaveADeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		in := &fakeLn{ch: make(chan net.Conn, 2)}
		l := newPendingListener(in, 4, 0, 20*time.Millisecond, time.Now)
		raw := &fakeConn{}
		in.ch <- raw
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		<-time.After(20*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		if raw.isClosed() {
			t.Fatal("a pending connection was closed before its deadline")
		}
		<-time.After(time.Nanosecond)
		synctest.Wait()
		if !raw.isClosed() || c.(*limitConn).promote() {
			t.Fatal("a connection still in its handshake after the deadline was kept")
		}
		l.mu.Lock()
		n := len(l.pending)
		l.mu.Unlock()
		if n != 0 {
			t.Errorf("%d connections left in the pool after the deadline", n)
		}
	})
}
