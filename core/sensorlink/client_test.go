package sensorlink_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// step is one scripted answer of a fake core.
type step struct {
	status     int
	retryAfter string
	code       string
	body       string // a raw 200 body
	drop       bool   // close the connection without answering
}

type scriptedCore struct {
	ts   *httptest.Server
	mu   sync.Mutex
	got  []string // request bodies
	hdr  []http.Header
	next int
}

// scripted starts a fake core whose certificate comes from serverCA. It does not ask for a client certificate: it is for what
// the client does with answers, not for what the server does with certificates.
func scripted(t *testing.T, srvCert tls.Certificate, steps []step) *scriptedCore {
	t.Helper()
	s := &scriptedCore{}
	s.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, string(b))
		s.hdr = append(s.hdr, r.Header.Clone())
		i := s.next
		s.next++
		s.mu.Unlock()
		if i >= len(steps) {
			http.Error(w, "script over", 500)
			return
		}
		st := steps[i]
		switch {
		case st.drop:
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.Close()
		case st.status == 0 || st.status == 200:
			_, _ = w.Write([]byte(st.body))
		default:
			if st.retryAfter != "" {
				w.Header().Set("Retry-After", st.retryAfter)
			}
			w.WriteHeader(st.status)
			_, _ = w.Write([]byte(`{"error":{"code":"` + st.code + `","message":"x"}}`))
		}
	}))
	s.ts.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	s.ts.StartTLS()
	t.Cleanup(s.ts.Close)
	return s
}

func (s *scriptedCore) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

type clientRig struct {
	ca   *testCA
	clk  *clock
	path string
	c    *sensorlink.Client
}

// newClientRig writes a passive bundle (serial 100) and builds a client for base; the jitter is zero, so a backoff is half
// of its step.
func newClientRig(t *testing.T, ca *testCA, base string) *clientRig {
	t.Helper()
	r := &clientRig{ca: ca, clk: newClock()}
	r.path = filepath.Join(t.TempDir(), "passive", "sensor.pem")
	writeFile(t, r.path, ca.bundle(t, ca.leaf(t, leafOpts{serial: 100})))
	c, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: base, CredsPath: r.path, Now: r.clk.Now, Rand: func() float64 { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	return r
}

func (r *clientRig) replaceBundle(t *testing.T, serial int64) {
	t.Helper()
	tmp := r.path + ".new"
	writeFile(t, tmp, r.ca.bundle(t, r.ca.leaf(t, leafOpts{serial: serial})))
	if err := os.Rename(tmp, r.path); err != nil {
		t.Fatal(err)
	}
}

func batch(n int) *sensorlink.ObservationsRequest {
	req := &sensorlink.ObservationsRequest{Epoch: instanceID, Seq: 7}
	for range n {
		req.Items = append(req.Items, sensorlink.ObservationItem{IP: "192.168.10.2", Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: t0})
	}
	return req
}

const okObs = `{"ack_seq":7,"rejected":[{"index":1,"code":"budget_exhausted"}]}`

// PostObservations is one attempt: it makes exactly one request, never waits, and hands what core said to the capture process,
// which decides (D-122 (2), (7)).
func TestClientPostObservations(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	run := func(t *testing.T, st step, n int) (*scriptedCore, sensorlink.ObservationsReply, error) {
		core := scripted(t, ca.serverLeaf(t), []step{st, {body: okObs}})
		cr := newClientRig(t, ca, core.ts.URL)
		rep, err := cr.c.PostObservations(t.Context(), batch(n))
		return core, rep, err
	}
	t.Run("a 200 carries the partial success", func(t *testing.T) {
		core, rep, err := run(t, step{body: okObs}, 2)
		if err != nil || rep.AckSeq != 7 || len(rep.Rejected) != 1 || rep.Rejected[0].Code != "budget_exhausted" || core.requests() != 1 {
			t.Fatalf("%v %+v (%d requests)", err, rep, core.requests())
		}
	})
	t.Run("every status is an *Error after one request, with Retry-After capped at a minute", func(t *testing.T) {
		for _, c := range []struct {
			st    step
			after time.Duration
		}{
			{step{status: 429, retryAfter: "3", code: "rate_limited"}, 3 * time.Second},
			{step{status: 503, retryAfter: "3600", code: "store_busy"}, time.Minute},
			{step{status: 426, code: "proto_unsupported"}, 0},
			{step{status: 413, code: "payload_too_large"}, 0},
			{step{status: 400, code: "invalid_request"}, 0},
			{step{status: 409, code: "module_off"}, 0},
			{step{status: 500, code: "internal"}, 0},
		} {
			core, _, err := run(t, c.st, 2)
			var e *sensorlink.Error
			if !errors.As(err, &e) || e.Status != c.st.status || e.Code != c.st.code || e.RetryAfter != c.after || core.requests() != 1 {
				t.Errorf("%d: %v (%d requests, retry-after %v)", c.st.status, err, core.requests(), e)
			}
		}
	})
	t.Run("no answer is an error that is not an *Error", func(t *testing.T) {
		_, _, err := run(t, step{drop: true}, 1)
		var e *sensorlink.Error
		if err == nil || errors.As(err, &e) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	for _, jitter := range []float64{0, 0.5, 0.999999} {
		b := sensorlink.NewBackoff(func() float64 { return jitter })
		steps := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
		for i, s := range steps {
			got, hi := b.Next(), s*time.Second
			if got < hi/2 || got > hi {
				t.Errorf("jitter %v step %d: %v not in [%v, %v]", jitter, i, got, hi/2, hi)
			}
		}
		b.Reset()
		if got := b.Next(); got < 500*time.Millisecond || got > time.Second {
			t.Errorf("after Reset: %v", got)
		}
	}
}

// Every request carries the protocol header, says JSON, and does not ask for compression (D-109 (5)).
func TestClientRequestShape(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	core := scripted(t, ca.serverLeaf(t), []step{{body: `{"instance":"` + instanceID + `"}`}, {body: `{"interface":"","span":false,"extract":{"dns":false,"sni":false,"http":false,"flows":false},"filters":[]}`}})
	cr := newClientRig(t, ca, core.ts.URL)
	if inst, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"}); err != nil || inst != instanceID {
		t.Fatalf("heartbeat: %q %v", inst, err)
	}
	if _, err := cr.c.Config(t.Context(), `"e0"`, 0); err != nil {
		t.Fatal(err)
	}
	for i, h := range core.hdr {
		if h.Get(sensorlink.ProtoHeader) != "2" || h.Get("Accept-Encoding") != "" || h.Get("Content-Encoding") != "" {
			t.Errorf("request %d headers: %v", i, h)
		}
	}
	if core.hdr[0].Get("Content-Type") != "application/json" || core.hdr[1].Get("If-None-Match") != `"e0"` {
		t.Errorf("headers: %v %v", core.hdr[0], core.hdr[1])
	}
}

// D-110 (4): the client reads the bundle again when the file changes, picks the new certificate for the next connection and
// closes what is idle. The server end of this is the real one.
func TestClientPicksUpARotatedBundle(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	cr := newClientRig(t, r.ca, r.url())
	r.clk.Advance(0)
	hb := func() {
		t.Helper()
		if _, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"}); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}
	hb()
	hb()
	r.id.allow(sensorlink.Passive, 101, 100) // the new serial is current, the old one is the previous: both work
	cr.replaceBundle(t, 101)
	hb()
	hb()
	r.id.allow(sensorlink.Passive, 101) // and when the old one is retired nothing breaks: the client is on 101
	hb()
	r.mu.Lock()
	got := append([]int64(nil), r.serials...)
	r.mu.Unlock()
	want := []int64{100, 100, 101, 101, 101}
	if len(got) != len(want) {
		t.Fatalf("serials seen = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("serials seen = %v, want %v", got, want)
			break
		}
	}
	if cr.c.Stats().Reloads != 1 {
		t.Errorf("reloads = %d, want 1", cr.c.Stats().Reloads)
	}
}

// D-110 (4): a bundle that cannot be used (half written, damaged) never replaces the one in memory; the file is tried again
// after five seconds.
func TestClientKeepsTheBundleWhenTheFileIsHalfWritten(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	cr := newClientRig(t, r.ca, r.url())
	hb := func() error {
		_, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"})
		return err
	}
	if err := hb(); err != nil {
		t.Fatal(err)
	}
	good := r.ca.bundle(t, r.ca.leaf(t, leafOpts{serial: 101}))
	r.id.allow(sensorlink.Passive, 100, 101)
	for name, content := range map[string][]byte{
		"half":          good[:len(good)/2],
		"empty":         nil,
		"garbage":       []byte("not a pem"),
		"key only":      good[:strings.Index(string(good), "-----BEGIN CERTIFICATE")],
		"cut in the CA": good[:len(good)-60],
	} {
		if err := os.WriteFile(cr.path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		cr.clk.Advance(6 * time.Second)
		if err := hb(); err != nil {
			t.Errorf("%s: the client stopped working: %v", name, err)
		}
	}
	if cr.c.Stats().Reloads != 0 {
		t.Errorf("a bad file was loaded: %+v", cr.c.Stats())
	}
	// the writer finishes: within five seconds of the last bad read the file is not looked at again, after them it is
	if err := os.WriteFile(cr.path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = hb()
	if cr.c.Stats().Reloads != 0 {
		t.Error("the file was read again before the five seconds")
	}
	cr.clk.Advance(6 * time.Second)
	if err := hb(); err != nil || cr.c.Stats().Reloads != 1 {
		t.Errorf("after the wait: %v %+v", err, cr.c.Stats())
	}
	if last := r.serials[len(r.serials)-1]; last != 101 {
		t.Errorf("last request used serial %d, want 101", last)
	}
}

// Spec section 7: 403 cert_retired makes the client read the file at once, without waiting out the five seconds.
func TestClientCertRetiredForcesAReload(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	cr := newClientRig(t, r.ca, r.url())
	hb := func() error {
		_, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"})
		return err
	}
	if err := hb(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cr.path, []byte("half"), 0o600); err != nil { // the writer is mid-way: a failed read starts the wait
		t.Fatal(err)
	}
	_ = hb()
	cr.replaceBundle(t, 101) // finished within the five seconds
	r.id.allow(sensorlink.Passive, 101)
	err := hb() // 100 is retired; the open connection says so
	var e *sensorlink.Error
	if !errors.As(err, &e) || e.Code != sensorlink.CodeCertRetired {
		t.Fatalf("err = %v, want 403 cert_retired", err)
	}
	if err := hb(); err != nil {
		t.Errorf("after the forced reload: %v", err)
	}
}

// Spec section 4: the client checks the server: the chain to the CA in its bundle, EKU serverAuth, and the name it dials.
func TestClientChecksTheServer(t *testing.T) {
	t.Parallel()
	ca, other := newTestCA(t), newTestCA(t)
	for _, c := range []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"the core leaf", ca.serverLeaf(t), true},
		{"another CA", other.serverLeaf(t), false},
		{"clientAuth only", ca.leaf(t, leafOpts{serial: 8, noURI: true, ips: []net.IP{net.IPv4(127, 0, 0, 1)}}), false},
		{"another address", ca.leaf(t, leafOpts{serial: 8, noURI: true, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ips: []net.IP{net.IPv4(10, 9, 9, 9)}}), false},
		{"expired", ca.leaf(t, leafOpts{serial: 8, noURI: true, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ips: []net.IP{net.IPv4(127, 0, 0, 1)}, notBefore: t0.Add(-48 * time.Hour), notAfter: t0.Add(-time.Hour)}), false},
		{"the client leaf of a sensor", ca.leaf(t, leafOpts{serial: 8}), false},
	} {
		core := scripted(t, c.cert, []step{{body: `{"instance":"` + instanceID + `"}`}})
		cr := newClientRig(t, ca, core.ts.URL)
		_, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"})
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
		if !c.ok && core.requests() != 0 {
			t.Errorf("%s: the client sent a request to a server it should not trust", c.name)
		}
	}
}

// Spec section 3: what a sensor reads back is capped and strictly decoded as well.
func TestClientReplyLimits(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	okCfg := `{"interface":"","span":false,"extract":{"dns":false,"sni":false,"http":false,"flows":false},"filters":[]}`
	pad := strings.Repeat(" ", sensorlink.MaxConfigReply)
	core := scripted(t, ca.serverLeaf(t), []step{
		{body: okCfg + pad}, // over 64 KiB
		{body: strings.Replace(okCfg, `"span"`, `"extra":1,"span"`, 1)}, // unknown field
		{body: `{"instance":"nothex"}`},                                 // bad instance
		{body: `{"instance":"` + instanceID + `"}` + `{}`},              // trailing data
		{body: okCfg},
	})
	cr := newClientRig(t, ca, core.ts.URL)
	ctx := t.Context()
	if _, err := cr.c.Config(ctx, "", 0); err == nil {
		t.Error("a config over the cap was accepted")
	}
	if _, err := cr.c.Config(ctx, "", 0); err == nil {
		t.Error("a config with an unknown field was accepted")
	}
	if _, err := cr.c.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0"}); err == nil {
		t.Error("an instance that is not 32 hex was accepted")
	}
	if _, err := cr.c.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0"}); err == nil {
		t.Error("a reply with trailing data was accepted")
	}
	if _, err := cr.c.Config(ctx, "", 0); err != nil {
		t.Errorf("a good config: %v", err)
	}
}

// A long poll can be cancelled: the call returns at once with the context's error.
func TestClientLongPollCancel(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	hang := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hang }))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverLeaf(t)}}
	ts.StartTLS()
	t.Cleanup(func() { close(hang); ts.Close() })
	cr := newClientRig(t, ca, ts.URL)
	for name, poll := range map[string]func(context.Context) error{
		"config": func(ctx context.Context) error { _, err := cr.c.Config(ctx, "", 30*time.Second); return err },
		"jobs":   func(ctx context.Context) error { _, err := cr.c.Jobs(ctx, nil, 30*time.Second); return err },
	} {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- poll(ctx) }()
		<-time.After(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s: err = %v", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: the poll did not end when cancelled", name)
		}
	}
}

// NewClient refuses credentials it cannot use, and never hangs on a FIFO or follows a link.
func TestNewClientCredentials(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	good := ca.bundle(t, ca.leaf(t, leafOpts{serial: 100}))
	dir := t.TempDir()
	mk := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		writeFile(t, p, b)
		return p
	}
	srv := ca.leaf(t, leafOpts{serial: 8, noURI: true, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	other := ca.bundle(t, ca.leaf(t, leafOpts{serial: 100}))
	cases := map[string]string{
		"missing":             filepath.Join(dir, "nope.pem"),
		"empty":               mk("empty.pem", nil),
		"garbage":             mk("garbage.pem", []byte("hello")),
		"a server leaf":       mk("server.pem", ca.bundle(t, srv)),
		"two keys":            mk("twokeys.pem", append(append([]byte(nil), good...), other[:strings.Index(string(other), "-----BEGIN CERTIFICATE")]...)),
		"three certificates":  mk("three.pem", append(append([]byte(nil), good...), other[strings.Index(string(other), "-----BEGIN CERTIFICATE"):]...)),
		"over the size limit": mk("big.pem", append(append([]byte(nil), good...), make([]byte, sensorlink.MaxBundle)...)),
		"a directory":         dir,
	}
	// the key of another leaf with this leaf's certificate
	k1 := ca.bundle(t, ca.leaf(t, leafOpts{serial: 100}))
	k2 := ca.bundle(t, ca.leaf(t, leafOpts{serial: 100}))
	cut := func(b []byte) int { return strings.Index(string(b), "-----BEGIN CERTIFICATE") }
	cases["key of another certificate"] = mk("mismatch.pem", append(append([]byte(nil), k1[:cut(k1)]...), k2[cut(k2):]...))
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(mk("real.pem", good), link); err != nil {
		t.Fatal(err)
	}
	cases["a symlink"] = link
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases["a FIFO"] = fifo
	// L7: a key another user may read is refused (0640 is what core writes: owner and group read; 0600 is fine too), and so is a
	// path that goes through a symlink to a directory.
	for name, mode := range map[string]os.FileMode{"readable by other": 0o644, "writable by group": 0o660, "executable": 0o740, "readable by other only": 0o604} {
		p := mk(strings.ReplaceAll(name, " ", "_")+".pem", good)
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		cases[name] = p
	}
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "sensor.pem"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	cases["a symlinked directory"] = filepath.Join(dir, "linkdir", "sensor.pem")
	for name, mode := range map[string]os.FileMode{"mode 0600": 0o600, "mode 0640": 0o640, "mode 0400": 0o400} {
		p := mk(strings.ReplaceAll(name, " ", "_")+".pem", good)
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: "https://127.0.0.1:8444", CredsPath: p}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, path := range cases {
		done := make(chan error, 1)
		go func() {
			_, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: "https://127.0.0.1:8444", CredsPath: path})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: NewClient accepted it", name)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: NewClient hangs", name)
		}
	}
	if _, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: "https://127.0.0.1:8444", CredsPath: mk("ok.pem", good)}); err != nil {
		t.Errorf("a good bundle: %v", err)
	}
	for _, u := range []string{"http://127.0.0.1:8444", "127.0.0.1:8444", "https://", "https://h/path"} {
		if _, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: u, CredsPath: filepath.Join(dir, "ok.pem")}); err == nil {
			t.Errorf("base URL %q accepted", u)
		}
	}
}

// L1 of the SP-1 review: ParseBundle keeps its godoc promise that the leaf chains to the CA in the bundle. A bundle whose CA
// did not sign its leaf is refused, and so is a leaf that chains to the bundled CA but not for client auth.
func TestParseBundleChecksTheChain(t *testing.T) {
	t.Parallel()
	ours, other := newTestCA(t), newTestCA(t)
	signedByOther := ours.leaf(t, leafOpts{serial: 100, other: other}) // signed by other ...
	if _, err := sensorlink.ParseBundle(ours.bundle(t, signedByOther)); err == nil {
		t.Error("ParseBundle accepted a leaf that the bundle's CA did not sign") // ... but bundled with our CA
	}
	if _, err := sensorlink.ParseBundle(ours.bundle(t, ours.leaf(t, leafOpts{serial: 100}))); err != nil {
		t.Errorf("a good bundle: %v", err)
	}
	// the bundle of one CA with the CA certificate of another and a leaf of the first
	good := ours.bundle(t, ours.leaf(t, leafOpts{serial: 100}))
	foreign := other.bundle(t, other.leaf(t, leafOpts{serial: 100}))
	swapped := append(append([]byte(nil), good[:strings.LastIndex(string(good), "-----BEGIN CERTIFICATE")]...), foreign[strings.LastIndex(string(foreign), "-----BEGIN CERTIFICATE"):]...)
	if _, err := sensorlink.ParseBundle(swapped); err == nil {
		t.Error("ParseBundle accepted the CA of another bundle")
	}
}

// Info of the SP-1 review: the client never follows a redirect. A 3xx from core (or from whatever answers on the port) is an
// error of the request, and the Location is not requested, so the client certificate is not offered to another host.
func TestClientRefusesRedirects(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	var elsewhereHits atomic.Int32
	elsewhere := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhereHits.Add(1) }))
	elsewhere.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverLeaf(t)}}
	elsewhere.StartTLS()
	t.Cleanup(elsewhere.Close)
	core := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", elsewhere.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect) // 307 keeps the method and the body
	}))
	core.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverLeaf(t)}}
	core.StartTLS()
	t.Cleanup(core.Close)
	cr := newClientRig(t, ca, core.URL)
	_, err := cr.c.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"})
	var e *sensorlink.Error
	if !errors.As(err, &e) || e.Status != http.StatusTemporaryRedirect {
		t.Errorf("err = %v, want the 307 itself as an error", err)
	}
	if _, err := cr.c.PostObservations(t.Context(), batch(1)); !errors.As(err, &e) || e.Status != http.StatusTemporaryRedirect {
		t.Errorf("an observations batch answered by a redirect: %v, want the 307 as an error", err)
	}
	if n := elsewhereHits.Load(); n != 0 {
		t.Errorf("the client followed the redirect (%d requests elsewhere)", n)
	}
}
