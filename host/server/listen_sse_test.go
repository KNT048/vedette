package server_test

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

func TestListenPermissions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h := servertest.Prepare(t, f.cmds)
	ln, err := h.Server.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if st, err := os.Stat(filepath.Dir(h.Socket)); err != nil || st.Mode().Perm() != 0o750 || !st.IsDir() {
		t.Fatalf("dir: %v %v", st, err)
	}
	if st, err := os.Stat(h.Socket); err != nil || st.Mode().Perm() != 0o660 || st.Mode().Type() != os.ModeSocket {
		t.Fatalf("socket: %v %v", st, err)
	}
	if _, ok := ln.(*net.UnixListener); !ok {
		t.Fatalf("listener is %T, want a unix listener", ln)
	}
}

func TestListenRefusesUnsafeDirectoryAndPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	t.Run("open directory", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o777, 0o755, 0o770} {
			h := servertest.Prepare(t, f.cmds)
			dir := filepath.Dir(h.Socket)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dir, -1, os.Getgid()); err != nil { // a directory made under a sticky /tmp can inherit another group (macOS)
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if ln, err := h.Server.Listen(context.Background()); err == nil {
				_ = ln.Close()
				t.Errorf("mode %o directory was accepted", mode)
			}
		}
	})
	t.Run("existing 0750 and 0700 directories are fine and not modified", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o750, 0o700} {
			h := servertest.Prepare(t, f.cmds)
			dir := filepath.Dir(h.Socket)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dir, -1, os.Getgid()); err != nil { // a directory made under a sticky /tmp can inherit another group (macOS)
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			ln, err := h.Server.Listen(context.Background())
			if err != nil {
				t.Fatalf("mode %o: %v", mode, err)
			}
			_ = ln.Close()
			if st, _ := os.Stat(dir); st.Mode().Perm() != mode {
				t.Errorf("dir mode changed to %o", st.Mode().Perm())
			}
		}
	})
	t.Run("regular file at the socket path", func(t *testing.T) {
		t.Parallel()
		h := servertest.Prepare(t, f.cmds)
		if err := os.MkdirAll(filepath.Dir(h.Socket), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Dir(h.Socket), -1, os.Getgid()); err != nil { // a directory made under a sticky /tmp can inherit another group (macOS)
			t.Fatal(err)
		}
		if err := os.WriteFile(h.Socket, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
		if ln, err := h.Server.Listen(context.Background()); err == nil {
			_ = ln.Close()
			t.Fatal("a regular file was replaced")
		}
		if b, _ := os.ReadFile(h.Socket); string(b) != "precious" {
			t.Fatal("the file was modified")
		}
	})
	t.Run("stale socket is replaced, live one is refused", func(t *testing.T) {
		t.Parallel()
		h := servertest.Prepare(t, f.cmds)
		if err := os.MkdirAll(filepath.Dir(h.Socket), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Dir(h.Socket), -1, os.Getgid()); err != nil { // a directory made under a sticky /tmp can inherit another group (macOS)
			t.Fatal(err)
		}
		stale, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", h.Socket)
		if err != nil {
			t.Fatal(err)
		}
		stale.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = stale.Close() // leaves the socket file behind, nobody listening
		ln, err := h.Server.Listen(context.Background())
		if err != nil {
			t.Fatalf("stale socket: %v", err)
		}
		defer func() { _ = ln.Close() }()
		h2 := servertest.Prepare(t, f.cmds, func(o *server.Options) { o.SocketPath = h.Socket; o.StateDir += "2"; o.AuditPath += "2" })
		if ln2, err := h2.Server.Listen(context.Background()); err == nil {
			_ = ln2.Close()
			t.Fatal("a live socket was taken over")
		}
	})
}

func TestEventsResumeWithLastEventID(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	r := run(t, h.Client, "test.echo", echoArgs{Name: "x", Count: 3}, rid1)
	finish(t, h.Client, r.RunID) // 8 events: running, 3 x (log, progress), succeeded
	s := h.Client.Events(context.Background(), r.RunID, 5)
	defer s.Close()
	var seqs []uint64
	for {
		ev, err := s.Next()
		if err != nil {
			break
		}
		seqs = append(seqs, ev.Seq)
	}
	if !slices.Equal(seqs, []uint64{6, 7, 8}) {
		t.Fatalf("seqs = %v", seqs)
	}
	// Raw wire format and a bad header.
	hdr := goodHeaders(rid1)
	hdr["Last-Event-ID"] = "7"
	st, body := raw(t, h, http.MethodGet, "/v1/runs/"+r.RunID+"/events", hdr, "")
	if st != http.StatusOK || !strings.HasPrefix(string(body), "id: 8\ndata: {") {
		t.Fatalf("%d %q", st, body)
	}
	hdr["Last-Event-ID"] = "abc"
	if st, _ := raw(t, h, http.MethodGet, "/v1/runs/"+r.RunID+"/events", hdr, ""); st != http.StatusBadRequest {
		t.Fatalf("bad Last-Event-ID: %d", st)
	}
	if st, _ := raw(t, h, http.MethodGet, "/v1/runs/rn_0000000000000000/events", goodHeaders(rid1), ""); st != http.StatusNotFound {
		t.Fatalf("missing run: %d", st)
	}
}

func TestEventsStreamLiveAndRefusedRunsHaveAState(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	r := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := h.Client.Events(ctx, r.RunID, 0)
	defer s.Close()
	first, err := s.Next() // running
	second, err2 := s.Next()
	if err != nil || err2 != nil || first.Status != api.StatusRunning || second.Line != "started" {
		t.Fatalf("%+v %v / %+v %v", first, err, second, err2)
	}
	close(f.release) // the live stream must now deliver the final state and end
	last, err := s.Next()
	if err != nil || last.Status != api.StatusSucceeded {
		t.Fatalf("%+v %v", last, err)
	}
	if _, err := s.Next(); err == nil || err.Error() != "EOF" {
		t.Fatalf("after the final event: %v", err)
	}

	// A refused run has no event file: one state event is synthesised.
	_, _ = post(t, h, "nope", goodHeaders(rid2), `{}`)
	list, _ := h.Client.ListRuns(ctx, 10)
	var refused string
	for _, rr := range list {
		if rr.Status == api.StatusRefused {
			refused = rr.RunID
		}
	}
	s2 := h.Client.Events(ctx, refused, 0)
	defer s2.Close()
	ev, err := s2.Next()
	if err != nil || ev.Status != api.StatusRefused || ev.Seq != 1 {
		t.Fatalf("%+v %v", ev, err)
	}
}

func TestEventLinesAreBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	cmds := append([]server.Command{}, f.cmds...)
	cmds = append(cmds, server.Define(server.Spec[struct{}]{
		Name: "test.noisy", Write: true, Timeout: 5 * time.Second,
		Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			rc.Log(strings.Repeat("é", 3000))
			rc.Log("with\nnewline\x00and nul")
			rc.Progress(250)
			rc.Progress(-5)
			return nil, nil
		},
	}))
	h := servertest.Start(t, cmds)
	r := run(t, h.Client, "test.noisy", nil, rid1)
	finish(t, h.Client, r.RunID)
	s := h.Client.Events(context.Background(), r.RunID, 0)
	defer s.Close()
	var evs []api.Event
	for {
		ev, err := s.Next()
		if err != nil {
			break
		}
		evs = append(evs, ev)
	}
	if len(evs) != 6 || len(evs[1].Line) > 2048 || evs[2].Line != "with newline and nul" || *evs[3].Percent != 100 || *evs[4].Percent != 0 {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRegistryValidation(t *testing.T) {
	t.Parallel()
	ok := server.Define(server.Spec[struct{}]{Name: "a.b", Timeout: time.Second, Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }})
	if _, err := server.NewRegistry(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]server.Command{
		"no dot":        server.Define(server.Spec[struct{}]{Name: "ab", Timeout: time.Second, Run: ok2}),
		"upper":         server.Define(server.Spec[struct{}]{Name: "a.B", Timeout: time.Second, Run: ok2}),
		"slash":         server.Define(server.Spec[struct{}]{Name: "a/b", Timeout: time.Second, Run: ok2}),
		"space":         server.Define(server.Spec[struct{}]{Name: "a. b", Timeout: time.Second, Run: ok2}),
		"empty":         server.Define(server.Spec[struct{}]{Name: "", Timeout: time.Second, Run: ok2}),
		"no timeout":    server.Define(server.Spec[struct{}]{Name: "a.c", Run: ok2}),
		"huge timeout":  server.Define(server.Spec[struct{}]{Name: "a.c", Timeout: 3 * time.Hour, Run: ok2}),
		"no run":        server.Define(server.Spec[struct{}]{Name: "a.c", Timeout: time.Second}),
		"zero value":    {},
		"too many dots": server.Define(server.Spec[struct{}]{Name: "a.b.c.d.e", Timeout: time.Second, Run: ok2}),
	}
	for name, c := range bad {
		if _, err := server.NewRegistry(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := server.NewRegistry(ok, ok); err == nil {
		t.Error("duplicate accepted")
	}
}

func ok2(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil }

func TestCommandRunnerEnvironment(t *testing.T) {
	// No t.Parallel: t.Setenv.
	t.Setenv("VEDETTE_LEAK_CHECK", "must-not-appear")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("DEBIAN_FRONTEND", "dialog")
	r, err := server.NewCommandRunner(slog.New(slog.DiscardHandler), vexec.Binary{
		Name: "env", Path: "/usr/bin/env", Validate: func(a []string) error {
			if len(a) != 0 {
				return os.ErrInvalid
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := r.Run(ctx, "env", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	slices.Sort(got)
	want := []string{"DEBIAN_FRONTEND=noninteractive", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if !slices.Equal(got, want) {
		t.Fatalf("child environment = %q, want %q", got, want)
	}
	// A binary may not choose its own environment.
	_, err = server.NewCommandRunner(slog.New(slog.DiscardHandler), vexec.Binary{
		Name: "env", Path: "/usr/bin/env", Validate: func([]string) error { return nil }, Env: []string{"FOO=bar"},
	})
	if err == nil {
		t.Fatal("a binary with its own Env was accepted")
	}
}

func TestRegistryHasNoMutators(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeFor[*server.Registry]()
	var names []string
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"Lookup", "Names"}) {
		t.Fatalf("Registry methods = %v: the table must stay closed", names)
	}
}
