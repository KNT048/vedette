package sensorlink_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// D-176 (WP-31 M3): a sensor cannot hold the connection slots of the link.

// send writes one request head (and the start of a chunked body when chunked), leaving the body unfinished.
func (rc *rawConn) send(t *testing.T, method, path string, hdr []string, chunked bool) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: core\r\n", method, path)
	for _, h := range hdr {
		b.WriteString(h + "\r\n")
	}
	if chunked {
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n") // one byte of a body that never ends
	} else {
		b.WriteString("\r\n")
	}
	if _, err := rc.c.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
}

// expectClosed reads the answer within 3 s and checks it is status with Connection: close, then that the server closed the
// connection (EOF) instead of waiting for the rest of the body.
func (rc *rawConn) expectClosed(t *testing.T, name string, status int) {
	t.Helper()
	_ = rc.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	res, err := http.ReadResponse(rc.r, nil)
	if err != nil {
		t.Errorf("%s: no answer: %v (the server is draining the body)", name, err)
		return
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != status {
		t.Errorf("%s: status %d, want %d", name, res.StatusCode, status)
	}
	if !res.Close {
		t.Errorf("%s: no Connection: close on a refusal that left the body unread", name)
	}
	_ = rc.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := rc.r.ReadByte(); err == nil || isTimeout(err) {
		t.Errorf("%s: the connection stayed open: %v", name, err)
	}
}

func TestEarlyRefusalsCloseTheConnection(t *testing.T) {
	t.Parallel()
	proto := "X-Vedette-Proto: 2"
	ct := "Content-Type: application/json"
	r := newRig(t, rigOpt{moduleOn: func(role sensorlink.Role) bool { return role != sensorlink.Active }})
	pass := r.ca.leaf(t, leafOpts{serial: 100})
	act := r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}})

	for _, body := range []string{"chunked", "length"} {
		hdr := func(h ...string) []string {
			if body == "length" {
				h = append(h, "Content-Length: 1000")
			}
			return h
		}
		chunked := body == "chunked"
		t.Run("426 "+body, func(t *testing.T) {
			rc := r.dial(t, pass)
			rc.send(t, "POST", "/sensor/v1/heartbeat", hdr("X-Vedette-Proto: 1", ct), chunked)
			rc.expectClosed(t, "426", 426)
		})
		t.Run("403 forbidden route "+body, func(t *testing.T) {
			rc := r.dial(t, pass)
			rc.send(t, "POST", "/sensor/v1/jobs", hdr(proto, ct), chunked)
			rc.expectClosed(t, "403", 403)
		})
		t.Run("409 module off "+body, func(t *testing.T) {
			rc := r.dial(t, act)
			rc.send(t, "POST", "/sensor/v1/heartbeat", hdr(proto, ct), chunked)
			rc.expectClosed(t, "409", 409)
		})
		t.Run("400 bad query "+body, func(t *testing.T) {
			rc := r.dial(t, pass)
			rc.send(t, "POST", "/sensor/v1/heartbeat?x=1", hdr(proto, ct), chunked)
			rc.expectClosed(t, "400 query", 400)
		})
		t.Run("400 bad content type "+body, func(t *testing.T) {
			rc := r.dial(t, pass)
			rc.send(t, "POST", "/sensor/v1/heartbeat", hdr(proto, "Content-Type: text/plain"), chunked)
			rc.expectClosed(t, "400 type", 400)
		})
	}

	t.Run("429 rate limited", func(t *testing.T) {
		r := newRig(t, rigOpt{}) // its own bucket
		pass := r.ca.leaf(t, leafOpts{serial: 100})
		p := r.good(t)
		for range 20 { // the burst; the clock does not move
			if got, err := p.call(t, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil); err != nil || got.status != 200 {
				t.Fatalf("burst: %v %d", err, got.status)
			}
		}
		rc := r.dial(t, pass)
		rc.send(t, "POST", "/sensor/v1/heartbeat", []string{proto, ct}, true)
		rc.expectClosed(t, "429", 429)
	})

	t.Run("409 poll in progress", func(t *testing.T) {
		r := newRig(t, rigOpt{})
		release := make(chan struct{})
		started := make(chan struct{})
		r.be.config = func(ctx context.Context, _ time.Duration, _ string) (sensorlink.ConfigReply, error) {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return sensorlink.ConfigReply{NotModified: true, ETag: `"e1"`}, nil
		}
		t.Cleanup(func() { close(release) })
		first := r.dial(t, r.ca.leaf(t, leafOpts{serial: 100}))
		first.send(t, "GET", "/sensor/v1/config", []string{"X-Vedette-Proto: 2"}, false)
		<-started
		second := r.dial(t, r.ca.leaf(t, leafOpts{serial: 100}))
		second.send(t, "GET", "/sensor/v1/config", []string{"X-Vedette-Proto: 2"}, false)
		_ = second.c.SetReadDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(second.r, nil)
		if err != nil || res.StatusCode != 409 {
			t.Fatalf("second poll: %v %v", err, res)
		}
		_ = res.Body.Close()
	})
}

func TestBodylessRouteWithABodyIs400AndClosed(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass := r.ca.leaf(t, leafOpts{serial: 100})
	act := r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}})
	for _, c := range []struct {
		name, path string
		cert       tls.Certificate
		hdr        []string
		chunked    bool
	}{
		{"config chunked", "/sensor/v1/config", pass, nil, true},
		{"config length", "/sensor/v1/config", pass, []string{"Content-Length: 1000"}, false},
		{"jobs chunked", "/sensor/v1/jobs", act, nil, true},
		{"jobs length", "/sensor/v1/jobs", act, []string{"Content-Length: 5"}, false},
	} {
		rc := r.dial(t, c.cert)
		rc.send(t, "GET", c.path, append([]string{"X-Vedette-Proto: 2"}, c.hdr...), c.chunked)
		rc.expectClosed(t, c.name, 400)
	}
	if calls := r.be.Calls(); len(calls) != 0 {
		t.Errorf("backend calls: %v, a GET with a body must not reach it", calls)
	}
	// a GET without a body is still served, and Content-Length: 0 is not a body
	if got, err := r.good(t).call(t, r.url(), "GET", "/sensor/v1/config", nil, nil); err != nil || got.status != 200 {
		t.Errorf("plain GET: %v %d", err, got.status)
	}
}

// serveRig runs the real listener of core (Serve: LimitListener, TLS, ConnState, timeouts) on a loopback port.
func serveRig(t *testing.T, o sensorlink.Options) (*rig, string) {
	t.Helper()
	r := newRig(t, rigOpt{})
	o.Identity, o.Backend, o.Now = r.id, r.be, r.clk.Now
	srv, err := sensorlink.NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l) }()
	return r, l.Addr().String()
}

func dialTo(t *testing.T, r *rig, addr string, cert tls.Certificate) *rawConn {
	t.Helper()
	c, err := (&tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: r.ca.pool, Certificates: []tls.Certificate{cert}, Time: r.clk.Now, NextProtos: []string{"http/1.1"},
	}}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{c: c, r: bufio.NewReader(c)}
}

// The review's attack: one passive certificate opens MaxConns connections and holds them. The slots a role may hold are its
// own share, so the scan role still polls; the connections over the share are closed at their first byte.
func TestOnePassiveCertificateCannotHoldEverySlot(t *testing.T) {
	t.Parallel()
	r, addr := serveRig(t, sensorlink.Options{})
	pass := r.ca.leaf(t, leafOpts{serial: 100})
	act := r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}})

	// the passive sensor opens every slot and keeps its connections idle after one request each (the clock moves so that the
	// rate limit is not what answers)
	var held []*rawConn
	for range sensorlink.MaxConns {
		c := dialTo(t, r, addr, pass)
		c.send(t, "GET", "/sensor/v1/config", []string{"X-Vedette-Proto: 2"}, false)
		held = append(held, c)
		r.clk.Advance(time.Second)
	}
	closed := 0
	for _, c := range held {
		_ = c.c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		if res, err := http.ReadResponse(c.r, nil); err != nil {
			closed++
		} else {
			_ = res.Body.Close()
		}
	}
	if want := sensorlink.MaxConns - sensorlink.MaxConnsPassive; closed < want {
		t.Errorf("%d of %d passive connections were closed, want at least %d (over the share of %d)", closed, sensorlink.MaxConns, want, sensorlink.MaxConnsPassive)
	}

	p := r.peer(t, act)
	p.c.Timeout = 3 * time.Second
	got, err := p.call(t, "https://"+addr, "GET", "/sensor/v1/jobs?wait=0", nil, nil)
	if err != nil || got.status != 200 {
		t.Fatalf("the scan role polling while a passive sensor holds its share: %v %d", err, got.status)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// D-176 (3): the server has a whole-request ReadTimeout and an IdleTimeout, and a long poll is not cut by it.
func TestReadTimeoutSparesTheLongPoll(t *testing.T) {
	t.Parallel()
	hs := mustServer(t).HTTPServer("")
	if want := sensorlink.ReadHeaderTimeout + sensorlink.BodyTimeout; hs.ReadTimeout != want {
		t.Errorf("ReadTimeout = %v, want ReadHeaderTimeout + BodyTimeout = %v", hs.ReadTimeout, want)
	}
	if hs.IdleTimeout != sensorlink.IdleTimeout || hs.ReadHeaderTimeout != sensorlink.ReadHeaderTimeout || hs.ConnState == nil {
		t.Errorf("HTTPServer: idle %v header %v ConnState nil=%v", hs.IdleTimeout, hs.ReadHeaderTimeout, hs.ConnState == nil)
	}

	r, addr := serveRig(t, sensorlink.Options{HeaderTimeout: 200 * time.Millisecond, BodyTimeout: 200 * time.Millisecond})
	r.be.jobs = func(ctx context.Context, _ time.Duration, _ []string) (sensorlink.JobsReply, error) {
		select {
		case <-time.After(1200 * time.Millisecond): // three times the ReadTimeout
		case <-ctx.Done():
			return sensorlink.JobsReply{}, ctx.Err()
		}
		return sensorlink.JobsReply{Instance: instanceID}, nil
	}
	p := r.peer(t, r.ca.leaf(t, leafOpts{serial: 200, uris: []string{"vedette:sensor:active"}}))
	got, err := p.call(t, "https://"+addr, "GET", "/sensor/v1/jobs?wait=5", nil, nil)
	if err != nil || got.status != 200 {
		t.Fatalf("a long poll longer than ReadTimeout: %v %d", err, got.status)
	}

	// a request that drips its body is cut off by the timeouts: the connection closes, the slot comes back
	slow := dialTo(t, r, addr, r.ca.leaf(t, leafOpts{serial: 100}))
	slow.post(t, "/sensor/v1/heartbeat", 1000, 1)
	_ = slow.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if res, err := http.ReadResponse(slow.r, nil); err == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
	_ = slow.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := slow.r.ReadByte(); err == nil || isTimeout(err) {
		t.Errorf("a dripping body kept its connection: %v", err)
	}
}

func mustServer(t *testing.T) *sensorlink.Server {
	t.Helper()
	r := newRig(t, rigOpt{})
	return r.srv
}
