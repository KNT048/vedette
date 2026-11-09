package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
)

func TestInfo(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	info, err := h.Client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Proto != api.Proto || info.HostVersion != "test" || info.Runner != "podman" || !info.AuditOK {
		t.Fatalf("info = %+v", info)
	}
	if info.OS.Distro != "ubuntu" || info.OS.Release != "24.04" {
		t.Fatalf("os = %+v", info.OS)
	}
	want := []string{"test.echo", "test.fail", "test.hang", "test.panic", "test.read", "test.refuse", "test.slow", "test.timeout"}
	if strings.Join(info.Commands, ",") != strings.Join(want, ",") {
		t.Fatalf("commands = %v", info.Commands)
	}
}

func TestRunLifecycleEventsAndAudit(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	r := run(t, h.Client, "test.echo", echoArgs{Name: "hello", Count: 3}, rid1)
	if r.Status != api.StatusRunning || !strings.HasPrefix(r.RunID, "rn_") || len(r.RunID) != 19 || r.Actor != "admin@example.com" || r.RequestID != rid1 || r.AuditID == "" {
		t.Fatalf("run = %+v", r)
	}
	done := finish(t, h.Client, r.RunID)
	if done.Status != api.StatusSucceeded || done.FinishedAt == nil || string(done.Result) != `{"name":"hello"}` {
		t.Fatalf("done = %+v", done)
	}
	if f.ran.Load() != 1 {
		t.Fatalf("ran %d times", f.ran.Load())
	}

	// Events: running, 3 x (log, progress), succeeded, with increasing seq.
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
	if len(evs) != 8 || evs[0].Status != api.StatusRunning || evs[7].Status != api.StatusSucceeded || evs[7].Kind != api.KindState {
		t.Fatalf("events = %+v", evs)
	}
	for i, ev := range evs {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("event %d has seq %d", i, ev.Seq)
		}
	}
	if evs[1].Kind != api.KindLog || evs[1].Line != "line hello" || evs[2].Kind != api.KindProgress || evs[2].Percent == nil {
		t.Fatalf("events = %+v", evs[:3])
	}

	// GET /v1/runs/{id} and the list.
	got, err := h.Client.GetRun(context.Background(), r.RunID)
	if err != nil || got.Status != api.StatusSucceeded {
		t.Fatalf("GetRun = %+v, %v", got, err)
	}
	list, err := h.Client.ListRuns(context.Background(), 10)
	if err != nil || len(list) != 1 || list[0].RunID != r.RunID {
		t.Fatalf("ListRuns = %+v, %v", list, err)
	}

	// One audit line, ok, carrying the run and audit ids, peer and a verified chain.
	a := lastAudit(t, h)
	if a.Result != "ok" || a.RunID == nil || *a.RunID != r.RunID || a.ID != r.AuditID || a.Command != "test.echo" || a.Actor != "admin@example.com" || a.RequestID != rid1 {
		t.Fatalf("audit = %+v", a)
	}
	if a.Peer.UID != 10001 || a.Peer.Unit != "vedette-core.service" || len(a.Hash) != 64 {
		t.Fatalf("audit peer/hash = %+v", a)
	}
}

func TestRunsListNewestFirstAndLimit(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	var ids []string
	for i, id := range []string{rid1, rid2, rid3} {
		r := run(t, h.Client, "test.echo", echoArgs{Name: "n"}, id)
		finish(t, h.Client, r.RunID)
		ids = append(ids, r.RunID)
		h.Clock.Advance(time.Second * time.Duration(i+1))
	}
	list, err := h.Client.ListRuns(context.Background(), 2)
	if err != nil || len(list) != 2 || list[0].RunID != ids[2] || list[1].RunID != ids[1] {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=x", "limit=1&x=2"} {
		st, _ := raw(t, h, http.MethodGet, "/v1/runs?"+q, map[string]string{api.HeaderProto: "1"}, "")
		if st != http.StatusBadRequest {
			t.Errorf("?%s -> %d", q, st)
		}
	}
	if _, err := h.Client.GetRun(context.Background(), "rn_0000000000000000"); !client.IsCode(err, api.CodeRunNotFound) {
		t.Errorf("missing run: %v", err)
	}
	if _, err := h.Client.GetRun(context.Background(), "../etc/passwd"); !client.IsCode(err, api.CodeUnknownCommand) && !client.IsCode(err, api.CodeRunNotFound) {
		t.Errorf("path-like run id: %v", err)
	}
}

func TestHeaderValidation(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	body := `{"args":{"name":"x"}}`
	mod := func(k, v string) map[string]string {
		m := goodHeaders(rid1)
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name string
		hdr  map[string]string
		code string
	}{
		{"no request id", mod(api.HeaderRequestID, ""), api.CodeInvalidRequestID},
		{"request id not uuid", mod(api.HeaderRequestID, "abc"), api.CodeInvalidRequestID},
		{"request id uuid v1", mod(api.HeaderRequestID, "11111111-1111-1111-8111-111111111111"), api.CodeInvalidRequestID},
		{"request id with path", mod(api.HeaderRequestID, "../../etc/passwd"), api.CodeInvalidRequestID},
		{"no actor", mod(api.HeaderActor, ""), api.CodeInvalidActor},
		{"actor with space", mod(api.HeaderActor, "a b"), api.CodeInvalidActor},
		{"actor with newline-ish", mod(api.HeaderActor, "a;rm"), api.CodeInvalidActor},
		{"actor too long", mod(api.HeaderActor, strings.Repeat("a", 65)), api.CodeInvalidActor},
		{"no proto", mod(api.HeaderProto, ""), api.CodeInvalidArgs},
		{"proto 0", mod(api.HeaderProto, "0"), api.CodeInvalidArgs},
		{"proto 2", mod(api.HeaderProto, "2"), api.CodeInvalidArgs},
		{"proto text", mod(api.HeaderProto, "one"), api.CodeInvalidArgs},
		{"no content type", mod("Content-Type", ""), api.CodeInvalidArgs},
		{"form content type", mod("Content-Type", "application/x-www-form-urlencoded"), api.CodeInvalidArgs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, eb := post(t, h, "test.echo", tt.hdr, body)
			if st != http.StatusBadRequest || eb.Error.Code != tt.code || len(eb.Error.Details) == 0 {
				t.Fatalf("status %d body %+v", st, eb)
			}
		})
	}
	if f.ran.Load() != 0 {
		t.Fatal("a command ran on bad headers")
	}
	// A content type with a charset and an upper-case request id are fine.
	hdr := goodHeaders(strings.ToUpper(rid2))
	hdr["Content-Type"] = "application/json; charset=utf-8"
	if st, eb := post(t, h, "test.echo", hdr, body); st != http.StatusAccepted {
		t.Fatalf("good request: %d %+v", st, eb)
	}
	// GET endpoints need the proto header too.
	if st, _ := raw(t, h, http.MethodGet, "/v1/info", nil, ""); st != http.StatusBadRequest {
		t.Errorf("info without proto: %d", st)
	}
}

func TestStrictBodyAndArgs(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	big := `{"args":{"name":"` + strings.Repeat("a", 513<<10) + `"}}`
	tests := []struct {
		name string
		body string
		want string // a detail field that must be reported
	}{
		{"unknown args field", `{"args":{"name":"x","extra":1}}`, "args"},
		{"unknown envelope field", `{"args":{"name":"x"},"binary":"/bin/sh"}`, "body"},
		{"argv in envelope", `{"argv":["sh","-c","id"]}`, "body"},
		{"trailing data", `{"args":{"name":"x"}} {"args":{}}`, "body"},
		{"not json", `name=x`, "body"},
		{"args null", `{"args":null}`, "args"},
		{"args array", `{"args":["x"]}`, "args"},
		{"wrong type", `{"args":{"name":5}}`, "args"},
		{"empty name", `{"args":{"name":""}}`, "args.name"},
		{"count range", `{"args":{"name":"x","count":101}}`, "args.count"},
		{"too large", big, "body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, eb := post(t, h, "test.echo", goodHeaders(rid1), tt.body)
			if st != http.StatusBadRequest || eb.Error.Code != api.CodeInvalidArgs {
				t.Fatalf("status %d body %+v", st, eb)
			}
			ok := false
			for _, d := range eb.Error.Details {
				ok = ok || d.Field == tt.want
			}
			if !ok {
				t.Fatalf("details %+v lack %s", eb.Error.Details, tt.want)
			}
		})
	}
	if f.ran.Load() != 0 {
		t.Fatal("a command ran on bad args")
	}
	// Each refusal is a run and an audit line.
	list, _ := h.Client.ListRuns(context.Background(), 100)
	if len(list) != len(tests) {
		t.Fatalf("%d refused runs, want %d", len(list), len(tests))
	}
	for _, r := range list {
		if r.Status != api.StatusRefused || r.Error == nil || r.Error.Code != api.CodeInvalidArgs {
			t.Fatalf("run = %+v", r)
		}
	}
	if n := len(auditLines(t, h)); n != len(tests) {
		t.Fatalf("%d audit lines, want %d", n, len(tests))
	}
}

func TestUnknownCommandAndPaths(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for _, name := range []string{"os.install", "exec", "sh", "test.echo.extra", "TEST.ECHO", "a%20b", "..%2f..%2fbin%2fsh"} {
		st, eb := post(t, h, name, goodHeaders(rid1), `{"args":{}}`)
		if st != http.StatusNotFound || eb.Error.Code != api.CodeUnknownCommand {
			t.Errorf("%s: %d %+v", name, st, eb)
		}
	}
	list, _ := h.Client.ListRuns(context.Background(), 100)
	if len(list) != 6 { // the name with an encoded slash is not a command route at all
		t.Fatalf("%d runs", len(list))
	}
	for _, r := range list {
		if r.Status != api.StatusRefused || r.Error.Code != api.CodeUnknownCommand {
			t.Fatalf("run = %+v", r)
		}
	}
	last := lastAudit(t, h)
	if last.Result != "refused" || last.Code == nil || *last.Code != api.CodeUnknownCommand {
		t.Fatalf("audit = %+v", last)
	}
	// Paths and methods outside the API.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/"}, {http.MethodGet, "/v1/state/os"}, {http.MethodGet, "/v1/commands/test.read"},
		{http.MethodPost, "/v1/info"}, {http.MethodDelete, "/v1/runs/rn_0000000000000000"}, {http.MethodPost, "/v1/exec"},
		{http.MethodGet, "/v1/runs/a/b"}, {http.MethodPost, "/v1/commands/a/b"}, {http.MethodGet, "//v1/info"},
	} {
		st, b := raw(t, h, c.method, c.path, goodHeaders(rid1), "")
		var eb api.ErrorBody
		_ = json.Unmarshal(b, &eb)
		if st != http.StatusNotFound || eb.Error.Code != api.CodeUnknownCommand {
			t.Errorf("%s %s: %d %s", c.method, c.path, st, b)
		}
	}
}

func TestFailureDetailsStayInside(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for i, c := range []string{"test.fail", "test.panic"} {
		r := run(t, h.Client, c, nil, uuid(i))
		done := finish(t, h.Client, r.RunID)
		if done.Status != api.StatusFailed || done.Error == nil || done.Error.Code != api.CodeCommandFailed {
			t.Fatalf("%s: %+v", c, done)
		}
		b, _ := json.Marshal(done)
		if strings.Contains(string(b), "shadow") || strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "boom") {
			t.Fatalf("internal detail leaked: %s", b)
		}
		a := lastAudit(t, h)
		if a.Result != "failed" || a.Code == nil || *a.Code != api.CodeCommandFailed {
			t.Fatalf("audit = %+v", a)
		}
	}
}

func TestCheckRefusal(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	_, err := h.Client.Run(context.Background(), "test.refuse", nil, rid1, "admin")
	var e *client.Error
	if !errors.As(err, &e) || e.Status != http.StatusPreconditionFailed || e.Code != "low_disk" {
		t.Fatalf("err = %v", err)
	}
	if f.ran.Load() != 0 {
		t.Fatal("Run executed after a refusal")
	}
	list, _ := h.Client.ListRuns(context.Background(), 5)
	if len(list) != 1 || list[0].Status != api.StatusRefused || list[0].Error.Code != "low_disk" {
		t.Fatalf("list = %+v", list)
	}
	a := lastAudit(t, h)
	if a.Result != "refused" || *a.Code != "low_disk" {
		t.Fatalf("audit = %+v", a)
	}
	// The write lock is free again and the request id can be reused after a refusal.
	if _, err := h.Client.Run(context.Background(), "test.refuse", nil, rid1, "admin"); !client.IsCode(err, "low_disk") {
		t.Fatalf("retry: %v", err)
	}
	r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, rid2)
	finish(t, h.Client, r.RunID)
}

func TestReadCommandDoesNotLock(t *testing.T) {
	t.Parallel()
	h, f := start(t)
	slow := run(t, h.Client, "test.slow", nil, rid1)
	<-f.started
	r := run(t, h.Client, "test.read", nil, rid2)
	done := finish(t, h.Client, r.RunID)
	if done.Status != api.StatusSucceeded {
		t.Fatalf("read run = %+v", done)
	}
	if _, err := h.Client.GetRun(context.Background(), slow.RunID); err != nil {
		t.Fatal(err)
	}
	close(f.release)
	finish(t, h.Client, slow.RunID)
}

func TestAuditPaging(t *testing.T) {
	t.Parallel()
	h, _ := start(t)
	for i := range 5 {
		r := run(t, h.Client, "test.echo", echoArgs{Name: "x"}, uuid(i))
		finish(t, h.Client, r.RunID)
	}
	var seen []int64
	since := int64(0) // 5 runs, each with an accepted line and a result line: 10 lines
	for pages := 0; pages < 10; pages++ {
		page, err := h.Client.Audit(context.Background(), since, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range page.Records {
			seen = append(seen, rec.Seq)
		}
		if page.Next == "" {
			break
		}
		n, err := strconv.ParseInt(page.Next, 10, 64)
		if err != nil || n <= since {
			t.Fatalf("next = %q", page.Next)
		}
		since = n
	}
	if len(seen) != 10 {
		t.Fatalf("seen %v", seen)
	}
	for i, s := range seen {
		if s != int64(i+1) {
			t.Fatalf("seen %v", seen)
		}
	}
	for _, q := range []string{"since=-1", "since=x", "limit=0", "limit=501", "foo=1"} {
		st, _ := raw(t, h, http.MethodGet, "/v1/audit?"+q, map[string]string{api.HeaderProto: "1"}, "")
		if st != http.StatusBadRequest {
			t.Errorf("?%s -> %d", q, st)
		}
	}
}
