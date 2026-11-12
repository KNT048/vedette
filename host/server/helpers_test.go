package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

const (
	rid1 = "11111111-1111-4111-8111-111111111111"
	rid2 = "22222222-2222-4222-8222-222222222222"
	rid3 = "33333333-3333-4333-8333-333333333333"
)

// echoArgs is the test command's args: typed fields, validated like a real command's.
type echoArgs struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// fixture holds the test commands and their observable effects.
type fixture struct {
	ran     atomic.Int64 // times a Run function started
	release chan struct{}
	started chan struct{}
	cmds    []server.Command
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{release: make(chan struct{}), started: make(chan struct{}, 16)}
	t.Cleanup(func() {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	})
	f.cmds = []server.Command{
		server.Define(server.Spec[echoArgs]{
			Name: "test.echo", Write: true, Timeout: 5 * time.Second,
			Validate: func(a *echoArgs) error {
				if !nameRE(a.Name) {
					return server.Invalid("name", "must match the name rule")
				}
				if a.Count < 0 || a.Count > 100 {
					return server.Invalid("count", "must be 0..100")
				}
				return nil
			},
			Run: func(_ context.Context, rc *server.RunContext, a echoArgs) (any, error) {
				f.ran.Add(1)
				for i := range a.Count {
					rc.Log("line " + a.Name)
					rc.Progress(i * 100 / max(a.Count, 1))
				}
				return map[string]string{"name": a.Name}, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.slow", Write: true, Timeout: 10 * time.Second,
			Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				f.ran.Add(1)
				rc.Log("started")
				f.started <- struct{}{}
				select {
				case <-f.release:
					return map[string]bool{"done": true}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.timeout", Write: true, Timeout: 50 * time.Millisecond,
			Run: func(ctx context.Context, _ *server.RunContext, _ struct{}) (any, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.hang", Write: true, Timeout: 50 * time.Millisecond,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				<-f.release // ignores its context on purpose
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.read", Write: false, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return map[string]bool{"ok": true}, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.refuse", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error {
				return server.Refuse(http.StatusPreconditionFailed, "low_disk", "Not enough free disk space.")
			},
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				f.ran.Add(1)
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.fail", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return nil, errors.New("internal detail: /etc/shadow password=hunter2")
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "test.panic", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				panic("boom")
			},
		}),
	}
	return f
}

func nameRE(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || !strings.ContainsRune("_.-", rune(c))) {
			return false
		}
	}
	return true
}

func start(t testing.TB, mutate ...func(*server.Options)) (*servertest.Harness, *fixture) {
	t.Helper()
	f := newFixture(t)
	return servertest.Start(t, f.cmds, mutate...), f
}

// raw sends one HTTP request over the unix socket with exactly the given headers.
func raw(t testing.TB, h *servertest.Harness, method, path string, hdr map[string]string, body string) (int, []byte) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", h.Socket)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://host"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func goodHeaders(id string) map[string]string {
	return map[string]string{
		"Content-Type": "application/json", api.HeaderProto: "1", api.HeaderActor: "admin@example.com", api.HeaderRequestID: id,
	}
}

func post(t testing.TB, h *servertest.Harness, command string, hdr map[string]string, body string) (int, api.ErrorBody) {
	t.Helper()
	st, b := raw(t, h, http.MethodPost, "/v1/commands/"+command, hdr, body)
	var eb api.ErrorBody
	_ = json.Unmarshal(b, &eb)
	return st, eb
}

// finish waits for the run to end by reading its event stream, then returns the stored run.
func finish(t testing.TB, c *client.Client, runID string) api.Run {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := c.Events(ctx, runID, 0)
	defer s.Close()
	for {
		_, err := s.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("events of %s: %v", runID, err)
		}
	}
	run, err := c.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if !run.Status.Terminal() {
		t.Fatalf("run %s is %s after its stream ended", runID, run.Status)
	}
	return run
}

func run(t testing.TB, c *client.Client, command string, args any, id string) api.Run {
	t.Helper()
	r, err := c.Run(context.Background(), command, args, id, "admin@example.com")
	if err != nil {
		t.Fatalf("Run %s: %v", command, err)
	}
	return r
}

func auditLines(t testing.TB, h *servertest.Harness) []api.AuditRecord {
	t.Helper()
	page, err := h.Client.Audit(context.Background(), 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	return page.Records
}

func lastAudit(t testing.TB, h *servertest.Harness) api.AuditRecord {
	t.Helper()
	recs := auditLines(t, h)
	if len(recs) == 0 {
		t.Fatal("no audit lines")
	}
	return recs[len(recs)-1]
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(bytes.TrimSpace(b))
}

// uuid returns a distinct valid request id for i.
func uuid(i int) string {
	return fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i)
}

// hangBound is how long a test waits for something that must happen before it calls the code hung (D-373): long enough
// that a loaded machine never trips it, so a red run means a real hang.
const hangBound = 30 * time.Second

// waitFor waits until cond reads true, at most hangBound. cond reads state; it never retries an action.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(hangBound)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("after %v: %s", hangBound, what)
		}
		<-tick.C
	}
}
