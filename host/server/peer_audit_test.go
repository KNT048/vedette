package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

func TestEveryConnectionIsPeerChecked(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	before := h.Peer.Calls()
	for range 3 { // DisableKeepAlives: three connections
		if st, _ := raw(t, h, http.MethodGet, "/v1/info", goodHeaders(rid1), ""); st != http.StatusOK {
			t.Fatalf("status %d", st)
		}
	}
	if got := h.Peer.Calls() - before; got != 3 {
		t.Fatalf("%d peer checks for 3 connections", got)
	}
}

func TestDeniedPeerIsClosedAndAudited(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	h.Peer.Deny(peer.Info{UID: 1000, PID: 777}, errors.New("not core"))
	for range 5 {
		c := h.NewClient(t)
		if _, err := c.Info(context.Background()); err == nil {
			t.Fatal("a denied peer got an answer")
		}
		if _, err := c.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid1, "admin"); err == nil {
			t.Fatal("a denied peer ran a command")
		}
	}
	if f.ran.Load() != 0 {
		t.Fatal("a command ran for a denied peer")
	}
	h.Peer.Allow(servertest.CoreInfo)
	var n int
	for _, a := range auditLines(t, h) {
		if a.Code != nil && *a.Code == api.CodePeerNotAllowed {
			n++
			if a.Result != "refused" || a.Peer.UID != 1000 || a.Peer.PID != 777 || a.Peer.Unit != "" || a.Command != "-" {
				t.Fatalf("audit = %+v", a)
			}
		}
	}
	if n != 1 { // ten denied connections inside the throttle interval: one line
		t.Fatalf("%d peer_not_allowed lines, want 1 (throttled)", n)
	}
	// After the interval the next denial is written, carrying the skipped count.
	h.Peer.Deny(peer.Info{UID: 1000, PID: 778}, errors.New("not core"))
	h.Clock.Advance(11 * time.Second)
	_, _ = h.NewClient(t).Info(context.Background())
	h.Peer.Allow(servertest.CoreInfo)
	recs := auditLines(t, h)
	last := recs[len(recs)-1]
	if last.Code == nil || *last.Code != api.CodePeerNotAllowed || !strings.Contains(string(last.ArgsRedacted), `"skipped":9`) {
		t.Fatalf("last = %+v %s", last, last.ArgsRedacted)
	}
}

func TestAuditChainIsValidAndOnlyGrows(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for i := range 4 {
		r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, uuid(i))
		finish(t, h.Client, r.RunID)
	}
	_, _ = post(t, h, "nope", goodHeaders(rid1), `{}`)
	checkChainFile(t, h.AuditPath, 5)
	st, err := os.Stat(h.AuditPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("audit file mode: %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Dir(h.AuditPath)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("audit dir mode: %v %v", st, err)
	}
}

// checkChainFile recomputes the chain independently of the server with core/chain.
func checkChainFile(t *testing.T, path string, wantLines int) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the test reads the audit file it created
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != wantLines {
		t.Fatalf("%d audit lines, want %d", len(lines), wantLines)
	}
	v := chain.NewVerifier("")
	for i, l := range lines {
		dec := json.NewDecoder(bytes.NewReader(l))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		for _, k := range []string{"seq", "id", "ts", "request_id", "actor", "peer", "command", "args_digest", "args_redacted", "result", "code", "run_id", "prev_hash", "hash"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("line %d lacks %s", i+1, k)
			}
		}
		hash, prev := m["hash"].(string), m["prev_hash"].(string)
		delete(m, "hash")
		conv := convertNumbers(m).(map[string]any)
		again, err := chain.HashCanonical(prev, conv)
		if err != nil {
			t.Fatal(err)
		}
		v.Add(m["id"].(string), prev, hash, again)
	}
	if res := v.Result(); !res.OK || res.Count != wantLines {
		t.Fatalf("chain result %+v", res)
	}
}

func convertNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Int64()
		return n
	case map[string]any:
		for k, e := range x {
			x[k] = convertNumbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = convertNumbers(e)
		}
	}
	return v
}

func TestBrokenAuditChainRefusesWritesAndReportsIt(t *testing.T) {
	t.Parallel()
	seed := func(t *testing.T) (*servertest.Harness, *fixture) {
		t.Helper()
		f := newFixture(t)
		h := servertest.Start(t, f.cmds)
		for i := range 3 {
			r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, uuid(i))
			finish(t, h.Client, r.RunID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Server.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		return h, f
	}
	tampers := map[string]func(lines [][]byte) []byte{
		"edited field": func(l [][]byte) []byte {
			l[1] = bytes.Replace(l[1], []byte(`"result":"ok"`), []byte(`"result":"no"`), 1)
			return join(l)
		},
		"deleted first line": func(l [][]byte) []byte { return join(l[1:]) },
		"deleted middle line": func(l [][]byte) []byte {
			return join([][]byte{l[0], l[2]})
		},
		"swapped lines": func(l [][]byte) []byte { return join([][]byte{l[1], l[0], l[2]}) },
		"torn last line": func(l [][]byte) []byte {
			return append(join(l), l[2][:40]...)
		},
		"garbage line": func(l [][]byte) []byte { return append(join(l), []byte("not json\n")...) },
		"blank line":   func(l [][]byte) []byte { return append(join(l), '\n') },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, f := seed(t)
			data, err := os.ReadFile(h.AuditPath)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
			broken := tamper(lines)
			if err := os.WriteFile(h.AuditPath, broken, 0o600); err != nil {
				t.Fatal(err)
			}
			h2 := servertest.Prepare(t, f.cmds, func(o *server.Options) {
				o.StateDir, o.AuditPath, o.SocketPath = h.StateDir, h.AuditPath, h.Socket+"2"
			})
			if err := h2.Server.AuditError(); !errors.Is(err, server.ErrAuditBroken) {
				t.Fatalf("AuditError = %v", err)
			}
			h2.Serve(t)
			// Reads still work and say the log is broken; writes are refused; nothing is appended.
			info, err := h2.Client.Info(context.Background())
			if err != nil || info.AuditOK {
				t.Fatalf("info = %+v, %v", info, err)
			}
			if _, err := h2.Client.ListRuns(context.Background(), 5); err != nil {
				t.Fatal(err)
			}
			_, err = h2.Client.Run(context.Background(), "test.echo", echoArgs{Name: "x"}, rid3, "admin")
			var e *client.Error
			if !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable || e.Code != api.CodeAuditUnavailable {
				t.Fatalf("Run err = %v", err)
			}
			if st, _ := post(t, h2, "nope", goodHeaders(rid3), `{}`); st != http.StatusServiceUnavailable {
				t.Fatalf("unknown command while broken: %d", st)
			}
			after, _ := os.ReadFile(h.AuditPath)
			if !bytes.Equal(after, broken) {
				t.Fatal("the host modified a broken audit file")
			}
			if f.ran.Load() != 3 {
				t.Fatalf("ran %d", f.ran.Load())
			}
		})
	}
}

func join(lines [][]byte) []byte {
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

func TestAuditFileMustBePrivate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil { //nolint:gosec // the test needs a too-open file
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // the test needs a too-open file
		t.Fatal(err)
	}
	reg, _ := server.NewRegistry(f.cmds...)
	_, err = server.New(server.Options{
		SocketPath: filepath.Join(dir, "s.sock"), StateDir: filepath.Join(dir, "state"), AuditPath: path,
		Registry: reg, PeerCheck: func(net.Conn) (peer.Info, error) { return peer.Info{}, errors.New("no") },
	})
	if err == nil {
		t.Fatal("a world-readable audit file was accepted")
	}
}

func TestRecoversRunsLeftInProgress(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	r := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started

	// Snapshot the files while the run is "running": this is what a crash would leave.
	crash := t.TempDir()
	copyTree(t, h.StateDir, filepath.Join(crash, "state"))
	copyTree(t, filepath.Dir(h.AuditPath), filepath.Join(crash, "log"))
	h2 := servertest.Prepare(t, newFixture(t).cmds, func(o *server.Options) {
		o.StateDir = filepath.Join(crash, "state")
		o.AuditPath = filepath.Join(crash, "log", "audit.jsonl")
		o.SocketPath = h.Socket + "2"
	})
	h2.Serve(t)

	got, err := h2.Client.GetRun(context.Background(), r.RunID)
	if err != nil || got.Status != api.StatusFailed || got.Error == nil || got.Error.Code != api.CodeHostRestarted || got.FinishedAt == nil {
		t.Fatalf("recovered run = %+v, %v", got, err)
	}
	var found bool
	for _, a := range auditLines(t, h2) {
		found = found || (a.RunID != nil && *a.RunID == r.RunID && a.Result == "failed" && *a.Code == api.CodeHostRestarted)
	}
	if !found {
		t.Fatal("recovery was not audited")
	}
	if h2.Server.AuditError() != nil {
		t.Fatal("audit chain broke during recovery")
	}
	// Its event stream ends with the failed state, and the lock is free.
	done := finish(t, h2.Client, r.RunID)
	if done.Status != api.StatusFailed {
		t.Fatalf("done = %+v", done)
	}
	next := run(t, h2.Client, "test.echo", echoArgs{Name: "after"}, rid2)
	finish(t, h2.Client, next.RunID)
	close(f.release)
}

// copyTree copies a directory tree with the private modes the host insists on (dirs 0700, files 0600).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(p) //nolint:gosec // copies files of a test tree
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600) //nolint:gosec // writes inside a temp dir the test created
	})
	if err != nil {
		t.Fatal(err)
	}
}
