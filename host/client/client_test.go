package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const rid = "11111111-1111-4111-8111-111111111111"

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestAbsentSocketIsUnreachable(t *testing.T) {
	t.Parallel()
	c := client.New(filepath.Join(shortDir(t), "none.sock"))
	defer c.Close()
	ctx := context.Background()
	_, err1 := c.Info(ctx)
	_, err2 := c.Run(ctx, "os.check", nil, rid, "admin")
	_, err3 := c.GetRun(ctx, "rn_0000000000000000")
	_, err4 := c.ListRuns(ctx, 5)
	_, err5 := c.Audit(ctx, 0, 5)
	for i, err := range []error{err1, err2, err3, err4, err5} {
		if !errors.Is(err, client.ErrUnreachable) {
			t.Errorf("call %d: err = %v, want ErrUnreachable", i, err)
		}
	}
	// A socket path that exists as a plain file, and a dead socket file, are unreachable too.
	dir := shortDir(t)
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(file).Info(ctx); !errors.Is(err, client.ErrUnreachable) {
		t.Errorf("plain file: %v", err)
	}
	dead := filepath.Join(dir, "dead.sock")
	ln := listenUnix(t, dead)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := client.New(dead).Info(ctx); !errors.Is(err, client.ErrUnreachable) {
		t.Errorf("dead socket: %v", err)
	}
	if client.IsCode(err1, api.CodeBusy) {
		t.Error("IsCode matched a non-host error")
	}
}

func TestTypedErrors(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil, func(o *server.Options) { o.RequestsPerMinute, o.WritesPerMinute = 0, 0 })
	ctx := context.Background()
	_, err := h.Client.Run(ctx, "no.such", nil, rid, "admin")
	var e *client.Error
	if !errors.As(err, &e) || e.Status != http.StatusNotFound || e.Code != api.CodeUnknownCommand || e.Message == "" {
		t.Fatalf("err = %v", err)
	}
	if !client.IsCode(err, api.CodeUnknownCommand) || client.IsCode(err, api.CodeBusy) {
		t.Fatal("IsCode")
	}
	_, err = h.Client.Run(ctx, "no.such", nil, "bad-id", "admin")
	if !errors.As(err, &e) || e.Code != api.CodeInvalidRequestID || len(e.Details) == 0 || e.Details[0].Field != api.HeaderRequestID {
		t.Fatalf("err = %v (%+v)", err, e)
	}
	_, err = h.Client.Run(ctx, "no.such", nil, rid, "bad actor")
	if !client.IsCode(err, api.CodeInvalidActor) {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.Client.Run(ctx, "a/b", nil, rid, "admin"); err == nil {
		t.Fatal("a command name with a slash was sent")
	}
	if _, err := h.Client.GetRun(ctx, "rn_0000000000000000"); !client.IsCode(err, api.CodeRunNotFound) {
		t.Fatalf("err = %v", err)
	}
	for range 60 {
		_, _ = h.Client.Info(ctx)
	}
	_, err = h.Client.Info(ctx)
	if !errors.As(err, &e) || e.Code != api.CodeRateLimited || e.RetryAfterS < 1 {
		t.Fatalf("err = %v", err)
	}
}

func TestUnexpectedResponseIsATypedError(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(shortDir(t), "f.sock")
	ln := listenUnix(t, sock)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, err := client.New(sock).Info(context.Background())
	var e *client.Error
	if !errors.As(err, &e) || e.Status != http.StatusBadGateway || e.Code != "unexpected_response" {
		t.Fatalf("err = %v", err)
	}
}

// flaky is a fake host whose first event stream dies after two events.
type flaky struct {
	mu      sync.Mutex
	lastIDs []string
}

func (f *flaky) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastIDs = append(f.lastIDs, r.Header.Get("Last-Event-ID"))
	attempt := len(f.lastIDs)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	ev := func(seq int, kind, status string) {
		_, _ = fmt.Fprintf(w, "id: %d\ndata: {\"seq\":%d,\"ts\":\"2026-11-09T12:00:00Z\",\"kind\":%q,\"status\":%q,\"line\":\"l%d\"}\n\n", seq, seq, kind, status, seq)
	}
	switch attempt {
	case 1:
		_, _ = fmt.Fprint(w, ": comment\n\n")
		ev(1, "state", "running")
		ev(2, "log", "")
		w.(http.Flusher).Flush()
		// return: the connection ends before the final event
	case 2:
		ev(2, "log", "") // a server that repeats an event: the reader must drop it
		ev(3, "state", "succeeded")
	}
}

func TestEventsResumeAfterDroppedConnection(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(shortDir(t), "f.sock")
	ln := listenUnix(t, sock)
	f := &flaky{}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := client.New(sock).Events(ctx, "rn_0000000000000000", 0)
	defer s.Close()
	var seqs []uint64
	for {
		ev, err := s.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, ev.Seq)
	}
	if fmt.Sprint(seqs) != "[1 2 3]" {
		t.Fatalf("seqs = %v", seqs)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.lastIDs) != "[ 2]" {
		t.Fatalf("Last-Event-ID headers = %q", f.lastIDs)
	}
}

func TestEventsGiveUpAfterRepeatedLoss(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(shortDir(t), "f.sock")
	ln := listenUnix(t, sock)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream") // immediately empty and closed, never progress
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s := client.New(sock).Events(ctx, "rn_0000000000000000", 0)
	defer s.Close()
	if _, err := s.Next(); !errors.Is(err, client.ErrStreamLost) || errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want a connection-lost error", err)
	}
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestEventLargerThan64KiBIsRefused(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(shortDir(t), "f.sock")
	ln := listenUnix(t, sock)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := "data: " + string(make([]byte, 0)) + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
		for range 1000 { // 1000 data lines of ~100 bytes and no blank line: one event of 100 KB
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := client.New(sock).Events(ctx, "rn_0000000000000000", 0)
	defer s.Close()
	if _, err := s.Next(); !errors.Is(err, client.ErrEventTooLarge) {
		t.Fatalf("err = %v", err)
	}
}
