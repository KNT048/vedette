package sensorlink_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// rawConn is one TLS connection of the active or passive role that the test drives by hand, so that a body can be left
// unfinished.
type rawConn struct {
	c net.Conn
	r *bufio.Reader
}

func (r *rig) dial(t *testing.T, cert tls.Certificate) *rawConn {
	t.Helper()
	c, err := (&tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: r.ca.pool, Certificates: []tls.Certificate{cert}, Time: r.clk.Now, NextProtos: []string{"http/1.1"},
	}}).DialContext(t.Context(), "tcp", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{c: c, r: bufio.NewReader(c)}
}

// post sends the headers of a POST that promises length bytes and then sends sent bytes of body (the rest never comes).
func (rc *rawConn) post(t *testing.T, path string, length, sent int) {
	t.Helper()
	hdr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: core\r\nX-Vedette-Proto: 1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, length)
	if _, err := rc.c.Write([]byte(hdr)); err != nil {
		t.Fatal(err)
	}
	if sent > 0 {
		if _, err := rc.c.Write(bytes.Repeat([]byte(" "), sent)); err != nil {
			t.Fatal(err)
		}
	}
}

// answer reads the response head within d; ok is false when nothing came (the server is still waiting for the body).
func (rc *rawConn) answer(d time.Duration) (status int, retryAfter string, ok bool) {
	_ = rc.c.SetReadDeadline(time.Now().Add(d))
	res, err := http.ReadResponse(rc.r, nil)
	if err != nil {
		return 0, "", false
	}
	_ = res.Body.Close()
	return res.StatusCode, res.Header.Get("Retry-After"), true
}

// SYS-6, spec sections 6 and 7 (M1 of the SP-1 review): the bodies core holds in memory are bounded per role. Not the heap but the
// number of bodies in flight is counted: each body the server is still waiting for holds one slot, the third (or the second
// result) is 503 store_busy with Retry-After 1 before a byte of its body is read, and a slot comes back when its request ends.
// Not parallel: it waits on real timeouts of unfinished bodies.
func TestBodiesInFlightAreBoundedPerRole(t *testing.T) {
	r := newRig(t, rigOpt{bodyTimeout: 5 * time.Second})
	pass := r.ca.leaf(t, leafOpts{serial: 100})
	act := r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}})

	t.Run("two bodies per role, the third is 503 before it is read", func(t *testing.T) {
		a, b, c := r.dial(t, pass), r.dial(t, pass), r.dial(t, pass)
		a.post(t, "/sensor/v1/observations", sensorlink.MaxObservationsBody, 100)
		b.post(t, "/sensor/v1/heartbeat", sensorlink.MaxHeartbeatBody, 100) // a heartbeat body is a body too
		time.Sleep(200 * time.Millisecond)                                  //nolint:forbidigo // real sockets: let both handlers reach their body read
		c.post(t, "/sensor/v1/observations", sensorlink.MaxObservationsBody, 0)
		st, retry, ok := c.answer(3 * time.Second)
		if !ok || st != 503 || retry != "1" {
			t.Fatalf("third body: %v %d retry=%q, want 503 with Retry-After 1 without reading", ok, st, retry)
		}
		if _, _, ok := a.answer(300 * time.Millisecond); ok {
			t.Error("the first body was answered before it was finished")
		}
		// the other role has its own slots
		act1 := r.dial(t, act)
		act1.post(t, "/sensor/v1/heartbeat", sensorlink.MaxHeartbeatBody, 0)
		if _, _, ok := act1.answer(300 * time.Millisecond); ok {
			t.Error("the active role was refused or answered although its slots are free")
		}
		// a slot comes back when its request ends: a closed connection frees it
		_ = a.c.Close()
		_ = b.c.Close()
		time.Sleep(300 * time.Millisecond) //nolint:forbidigo // real sockets: the server notices the close
		d := r.dial(t, pass)
		d.post(t, "/sensor/v1/observations", len(obsBody), 0)
		if _, err := d.c.Write([]byte(obsBody)); err != nil {
			t.Fatal(err)
		}
		if st, _, ok := d.answer(3 * time.Second); !ok || st != 200 {
			t.Errorf("after the slots were given back: %v %d, want 200", ok, st)
		}
	})

	t.Run("one result body at a time, and other routes keep their own slot", func(t *testing.T) {
		const id = "c0ffee00c0ffee00c0ffee00c0ffee00"
		time.Sleep(300 * time.Millisecond) //nolint:forbidigo // real sockets: the previous subtest's connections are being closed
		a, b := r.dial(t, act), r.dial(t, act)
		a.post(t, "/sensor/v1/jobs/"+id+"/result", sensorlink.MaxResultBody, 1<<20)
		time.Sleep(200 * time.Millisecond) //nolint:forbidigo // real sockets
		b.post(t, "/sensor/v1/jobs/"+id+"/result", sensorlink.MaxResultBody, 0)
		if st, retry, ok := b.answer(3 * time.Second); !ok || st != 503 || retry != "1" {
			t.Fatalf("second result body: %v %d retry=%q, want 503 Retry-After 1", ok, st, retry)
		}
		hb := r.dial(t, act)
		hb.post(t, "/sensor/v1/heartbeat", len(hbActive), 0)
		_, _ = hb.c.Write([]byte(hbActive))
		if st, _, ok := hb.answer(3 * time.Second); !ok || st != 200 {
			t.Errorf("a heartbeat while a result is being received: %v %d, want 200 (it has the role's other slot)", ok, st)
		}
	})

	t.Run("twelve uploads from one certificate hold one body", func(t *testing.T) {
		// the shape of the review's proof: many 10 MiB uploads at once, but here the server counts what it holds
		const id = "c0ffee00c0ffee00c0ffee00c0ffee11"
		time.Sleep(300 * time.Millisecond) //nolint:forbidigo // real sockets: the previous subtest's connections are being closed
		var busy, waiting int
		var cs []*rawConn
		for range 12 {
			c := r.dial(t, act)
			c.post(t, "/sensor/v1/jobs/"+id+"/result", sensorlink.MaxResultBody, 64<<10)
			cs = append(cs, c)
			r.clk.Advance(time.Second) // the rate limit is not what is being tested
		}
		for _, c := range cs {
			if st, _, ok := c.answer(500 * time.Millisecond); !ok {
				waiting++
			} else if st == 503 {
				busy++
			}
		}
		if waiting > sensorlink.MaxResultBodies || busy < 12-sensorlink.MaxResultBodies-1 {
			t.Errorf("12 uploads: %d still being received, %d refused; want at most %d held", waiting, busy, sensorlink.MaxResultBodies)
		}
	})
}

// M1: a result for a job that is not running is 404 without its body being read; a malformed id is 400 without it either.
func TestResultForAnUnknownJobIsRefusedBeforeTheBody(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	act := r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}})
	const known, unknown = "c0ffee00c0ffee00c0ffee00c0ffee00", "deadbeefdeadbeefdeadbeefdeadbeef"
	r.be.running = func(id string) bool { return id == known }
	for _, c := range []struct {
		name, id string
		status   int
	}{
		{"unknown job", unknown, 404},
		{"malformed id", "NOTHEX", 400},
		{"short id", "abc", 400},
	} {
		rc := r.dial(t, act)
		rc.post(t, "/sensor/v1/jobs/"+c.id+"/result", sensorlink.MaxResultBody, 0) // no body follows: it must not be waited for
		if st, _, ok := rc.answer(2 * time.Second); !ok || st != c.status {
			t.Errorf("%s: %v %d, want %d answered without a body", c.name, ok, st, c.status)
		}
	}
	for _, id := range r.be.asked {
		if id != unknown {
			t.Errorf("JobRunning was asked about %q: only well-formed ids may reach the backend", id)
		}
	}
	if calls := r.be.Calls(); len(calls) != 0 {
		t.Errorf("backend calls: %v", calls)
	}
	// the running job gets through
	rc := r.dial(t, act)
	rc.post(t, "/sensor/v1/jobs/"+known+"/result", len(resBody), 0)
	_, _ = rc.c.Write([]byte(resBody))
	if st, _, ok := rc.answer(2 * time.Second); !ok || st != 204 {
		t.Errorf("the running job: %v %d, want 204", ok, st)
	}
}

// L5: the listener of the sensor link takes at most MaxConns connections at once, and a connection that is closed gives its slot
// back.
func TestLimitListener(t *testing.T) {
	t.Parallel()
	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := sensorlink.LimitListener(inner, 2)
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var clients []net.Conn
	for range 3 {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		t.Cleanup(func() { _ = c.Close() })
	}
	var got []net.Conn
	for range 2 {
		select {
		case c := <-accepted:
			got = append(got, c)
		case <-time.After(3 * time.Second):
			t.Fatal("the first two connections were not accepted")
		}
	}
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted over the limit of 2")
	case <-time.After(300 * time.Millisecond):
	}
	_ = got[0].Close()
	_ = got[0].Close() // closing twice gives the slot back once
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("the slot of a closed connection was not given back")
	}
	if sensorlink.MaxConns != 64 {
		t.Errorf("MaxConns = %d, want 64", sensorlink.MaxConns)
	}
	_ = clients
}

// L5: Serve is the limit listener plus the TLS and timeouts of HTTPServer, and a handshake the server refuses goes to the log
// (ErrorLog is routed to slog) and not to stderr.
func TestServeAndErrorLog(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	hs := r.srv.HTTPServer("")
	if hs.ErrorLog == nil {
		t.Error("HTTPServer has no ErrorLog: refused handshakes would go to stderr")
	}
	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.srv.Serve(inner) }()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.ca.pool, Certificates: []tls.Certificate{r.ca.leaf(t, leafOpts{serial: 100})}, Time: r.clk.Now}
	// Serve uses GetCertificate of the Identity, which is the server leaf of the rig
	p := &peer{tr: &http.Transport{TLSClientConfig: cfg}}
	p.c = &http.Client{Transport: p.tr, Timeout: 10 * time.Second}
	t.Cleanup(p.tr.CloseIdleConnections)
	got, err := p.call(t, "https://"+inner.Addr().String(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil)
	if err != nil || got.status != 200 {
		t.Fatalf("a request through Serve: %v %v", err, got.status)
	}
	_ = inner.Close()
	select {
	case err := <-done:
		_ = err // net/http reports the closed listener
	case <-time.After(3 * time.Second):
		t.Error("Serve did not return when its listener closed")
	}
}
