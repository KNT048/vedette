package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// Tests of what WP-07b part 1 added to the framework: results on failed and reverted runs, the
// reverted status, refusal hints, after-finish callbacks, state endpoints and host-originated audit lines.

func part1Commands(t testing.TB) (cmds []server.Command, after chan api.Status) {
	t.Helper()
	after = make(chan api.Status, 4)
	cmds = []server.Command{
		server.Define(server.Spec[struct{}]{
			Name: "p1.fail", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return nil, &server.Failure{Code: "health_check_failed", Message: "a check failed", Result: map[string]int{"installed": 2}}
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "p1.revert", Write: true, Timeout: time.Second,
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) {
				return nil, &server.Reverted{Code: "restore_health_failed", Message: "put back", Result: map[string]string{"restored": "no"}}
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "p1.retry", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error {
				return server.RefuseRetry(http.StatusConflict, "dpkg_locked", "locked", 60)
			},
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil },
		}),
		server.Define(server.Spec[struct{}]{
			Name: "p1.notfound", Write: true, Timeout: time.Second,
			Check: func(context.Context, struct{}) error {
				return server.Refuse(http.StatusNotFound, "backup_unknown", "no such backup")
			},
			Run: func(context.Context, *server.RunContext, struct{}) (any, error) { return nil, nil },
		}),
		server.Define(server.Spec[struct{}]{
			Name: "p1.after", Write: true, Timeout: time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				rc.AfterFinish(func(_ context.Context, st api.Status) { after <- st })
				return nil, nil
			},
		}),
		server.Define(server.Spec[struct{}]{
			Name: "p1.afterfail", Write: true, Timeout: time.Second,
			Run: func(_ context.Context, rc *server.RunContext, _ struct{}) (any, error) {
				rc.AfterFinish(func(_ context.Context, st api.Status) { after <- st })
				return nil, errors.New("boom")
			},
		}),
	}
	return cmds, after
}

func runWait(t *testing.T, h *servertest.Harness, name, id string) api.Run {
	t.Helper()
	r, err := h.Client.Run(context.Background(), name, nil, id, "admin")
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := h.Client.Events(ctx, r.RunID, 0)
	defer s.Close()
	for {
		if _, err := s.Next(); err != nil {
			break
		}
	}
	got, err := h.Client.GetRun(ctx, r.RunID)
	if err != nil || !got.Status.Terminal() {
		t.Fatalf("%+v %v", got, err)
	}
	return got
}

func TestPart1_FailedAndRevertedRunsKeepTheirResult(t *testing.T) {
	t.Parallel()
	cmds, _ := part1Commands(t)
	h := servertest.Start(t, cmds)
	r := runWait(t, h, "p1.fail", rid1)
	if r.Status != api.StatusFailed || r.Error.Code != "health_check_failed" || !strings.Contains(string(r.Result), `"installed":2`) {
		t.Fatalf("%+v", r)
	}
	r = runWait(t, h, "p1.revert", rid2)
	if r.Status != api.StatusReverted || r.Error.Code != "restore_health_failed" || !strings.Contains(string(r.Result), `"restored":"no"`) {
		t.Fatalf("%+v", r)
	}
	// The audit line of the reverted run says reverted, not failed.
	p, _ := h.Client.Audit(context.Background(), 0, 50)
	last := p.Records[len(p.Records)-1]
	if last.Command != "p1.revert" || last.Result != "reverted" {
		t.Fatalf("%+v", last)
	}
}

func TestPart1_RefusalsCarryTheirStatusAndRetryHint(t *testing.T) {
	t.Parallel()
	cmds, _ := part1Commands(t)
	h := servertest.Start(t, cmds)
	_, err := h.Client.Run(context.Background(), "p1.retry", nil, rid1, "admin")
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != 409 || ce.Code != "dpkg_locked" || ce.RetryAfterS != 60 {
		t.Fatalf("%v", err)
	}
	_, err = h.Client.Run(context.Background(), "p1.notfound", nil, rid2, "admin")
	if !errors.As(err, &ce) || ce.Status != 404 || ce.Code != "backup_unknown" {
		t.Fatalf("%v", err)
	}
	// A refusal may only use 404, 409 or 412.
	defer func() {
		if recover() == nil {
			t.Error("Refuse accepted a 500")
		}
	}()
	_ = server.Refuse(500, "x", "y")
}

func TestPart1_AfterFinishRunsOnlyAfterTheRunIsRecorded(t *testing.T) {
	t.Parallel()
	cmds, after := part1Commands(t)
	h := servertest.Start(t, cmds)
	r := runWait(t, h, "p1.after", rid1)
	select {
	case st := <-after:
		if st != api.StatusSucceeded {
			t.Fatalf("callback status %s", st)
		}
		// By the time the callback ran, the run is final and the lock is free.
		got, _ := h.Client.GetRun(context.Background(), r.RunID)
		if !got.Status.Terminal() {
			t.Fatalf("run not final in the callback: %+v", got)
		}
	case <-time.After(hangBound):
		t.Fatal("the callback never ran")
	}
	runWait(t, h, "p1.afterfail", rid2)
	select {
	case st := <-after:
		if st != api.StatusFailed {
			t.Fatalf("callback status %s, want failed", st)
		}
	case <-time.After(hangBound):
		t.Fatal("the callback of a failed run never ran")
	}
}

func TestPart1_StateEndpointsAnswerOnlyWhenWired(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil)
	for _, p := range []string{"/v1/state/os", "/v1/state/backups", "/v1/backups/" + strings.Repeat("a", 32) + "/content", "/v1/exports/" + strings.Repeat("a", 32) + "/content"} {
		st, _ := raw(t, h, http.MethodGet, p, goodHeaders(rid1), "")
		if st != http.StatusNotFound {
			t.Errorf("%s: %d without readers", p, st)
		}
	}
	var calls atomic.Int64
	h2 := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers = server.Readers{
			OS: func(context.Context) (any, error) { calls.Add(1); return map[string]string{"os": "x"}, nil },
			Backups: func(context.Context) (any, error) {
				return nil, server.NewReadError(http.StatusNotFound, "nothing_here", "nope")
			},
			BackupContent: func(id string) (server.File, error) {
				if id != strings.Repeat("c", 32) {
					return server.File{}, server.NewReadError(http.StatusForbidden, "contains_secrets", "no")
				}
				return server.File{Body: io.NopCloser(strings.NewReader("0123456789")), Size: 10, Name: "x.tar.gz", Type: "application/gzip"}, nil
			},
		}
	})
	st, body := raw(t, h2, http.MethodGet, "/v1/state/os", goodHeaders(rid1), "")
	if st != 200 || !strings.Contains(string(body), `"os":"x"`) || calls.Load() != 1 {
		t.Fatalf("%d %s", st, body)
	}
	if st, body = raw(t, h2, http.MethodGet, "/v1/state/backups", goodHeaders(rid1), ""); st != 404 || !strings.Contains(string(body), "nothing_here") {
		t.Fatalf("%d %s", st, body)
	}
	if st, body = raw(t, h2, http.MethodGet, "/v1/state/os?x=1", goodHeaders(rid1), ""); st != 400 {
		t.Fatalf("an unknown query parameter: %d %s", st, body)
	}
	if st, body = raw(t, h2, http.MethodGet, "/v1/backups/"+strings.Repeat("c", 32)+"/content", goodHeaders(rid1), ""); st != 200 || string(body) != "0123456789" {
		t.Fatalf("%d %s", st, body)
	}
	if st, body = raw(t, h2, http.MethodGet, "/v1/backups/"+strings.Repeat("d", 32)+"/content", goodHeaders(rid1), ""); st != 403 {
		t.Fatalf("%d %s", st, body)
	}
	// Not hex of 32: never reaches the reader.
	if st, _ = raw(t, h2, http.MethodGet, "/v1/backups/xyz/content", goodHeaders(rid1), ""); st != 404 {
		t.Fatalf("a bad id: %d", st)
	}
	// The protocol header is required on state reads like everywhere else.
	h3 := map[string]string{}
	if st, _ = raw(t, h2, http.MethodGet, "/v1/state/os", h3, ""); st != 400 {
		t.Fatalf("no protocol header: %d", st)
	}
	// POST to a state path is not a route.
	if st, _ = raw(t, h2, http.MethodPost, "/v1/state/os", goodHeaders(rid1), "{}"); st != 404 {
		t.Fatalf("POST: %d", st)
	}
}

func TestPart1_NoteWritesAHostLineToTheChain(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil)
	if err := h.Server.Note("os.reboot", "reboot_completed", map[string]any{"kind": "now", "token": "vdt_osquery_0123456789abcdef"}); err != nil { //nolint:gosec // a fake token, to prove it is redacted
		t.Fatal(err)
	}
	p, err := h.Client.Audit(context.Background(), 0, 10)
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	r := p.Records[0]
	if r.Actor != "system" || r.Command != "os.reboot" || r.Result != "ok" || r.Code == nil || *r.Code != "reboot_completed" || r.RunID != nil {
		t.Fatalf("%+v", r)
	}
	data, _ := os.ReadFile(h.AuditPath)
	if strings.Contains(string(data), "vdt_osquery_0123456789abcdef") {
		t.Error("a token in a note reached the audit file")
	}
	// The chain still verifies after a restart of the log.
	info, _ := h.Client.Info(context.Background())
	if !info.AuditOK {
		t.Error("audit chain broken by Note")
	}
	if h.Server.WriteActive() {
		t.Error("WriteActive is true with nothing running")
	}
}

func TestPart1_SensitiveKeysKeepNonSecretValuesReadable(t *testing.T) {
	t.Parallel()
	cmds := []server.Command{server.Define(server.Spec[struct {
		IncludeSecrets bool   `json:"include_secrets"`
		Token          string `json:"token"`
		KeyCount       int    `json:"key_count"`
	}]{Name: "p1.flags", Write: true, Timeout: time.Second, Run: func(context.Context, *server.RunContext, struct {
		IncludeSecrets bool   `json:"include_secrets"`
		Token          string `json:"token"`
		KeyCount       int    `json:"key_count"`
	}) (any, error) {
		return nil, nil
	}})}
	h := servertest.Start(t, cmds)
	if _, err := h.Client.Run(context.Background(), "p1.flags", json.RawMessage(`{"include_secrets":true,"token":"hunter2","key_count":3}`), rid1, "admin"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.AuditPath)
	s := string(data)
	if !strings.Contains(s, `"include_secrets":true`) || !strings.Contains(s, `"key_count":3`) {
		t.Errorf("a flag was redacted:\n%s", s)
	}
	if strings.Contains(s, "hunter2") || !strings.Contains(s, `"token":"[redacted]"`) {
		t.Errorf("a string under a sensitive key was not redacted:\n%s", s)
	}
}
