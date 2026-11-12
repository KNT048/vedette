package logexport_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/logexport"
)

func src(rows ...string) logexport.Source {
	return func(_ context.Context, _, _ time.Time, w io.Writer) error {
		for _, r := range rows {
			if _, err := io.WriteString(w, r+"\n"); err != nil {
				return err
			}
		}
		return nil
	}
}

func build(t *testing.T, r *logexport.Registry, format logexport.Format, ids ...string) (string, *logexport.Export) {
	t.Helper()
	e, err := r.Build(t.Context(), logexport.Request{Categories: ids, Format: format, MaxBytes: 1 << 20, ExportedAt: time.Date(2026, 11, 10, 1, 2, 3, 0, time.UTC), Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(e)
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Close()
	return string(b), e
}

func TestRegisterAcceptsOnlyTheEightCategoriesOnce(t *testing.T) {
	t.Parallel()
	r := logexport.New()
	for _, id := range logexport.CategoryIDs() {
		r.Register(id, src())
		if !r.Has(id) {
			t.Errorf("%s not registered", id)
		}
	}
	if len(logexport.CategoryIDs()) != 8 {
		t.Fatalf("INV-13 has 8 categories, got %d", len(logexport.CategoryIDs()))
	}
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		fn()
	}
	mustPanic("a ninth category", func() { logexport.New().Register("passwords", src()) })
	mustPanic("an empty category", func() { logexport.New().Register("", src()) })
	mustPanic("a nil source", func() { logexport.New().Register("audit", nil) })
	mustPanic("a second source", func() { r.Register("audit", src()) })
	var nilReg *logexport.Registry
	if nilReg.Has("audit") {
		t.Error("a nil registry has no source")
	}
}

func TestScrubDropsSecretKeysAtAnyDepthAndKeepsOrder(t *testing.T) {
	t.Parallel()
	drop := []string{"password", "Passwd", "secret", "token", "api_key", "apikey", "API-KEY", "key", "private_key", "privatekey", "passphrase", "credential", "credentials", "webhook", "webhook_url", "authorization",
		"client_secret", "db_password", "bot_token", "x_api_key", "slack_webhook", "slack-webhook-url", "ssh_credential",
		"sessionId", "session_token", "Set-Cookie", "cookie", "x-jwt", "jwt", "dbDSN", "dsn", "bearer_x", "connection_string", "ConnectionString", "tokens", "secrets_count"}
	keep := []string{"key_last4", "tokens_in", "tokens_out", "token_id", "hash", "prev_hash", "head_hash", "token_hash", "id", "conn_key", "keyboard", "src_ip", "detail", "events", "kind", "label"}
	for _, k := range drop {
		if !logexport.IsSecretKey(k) {
			t.Errorf("%q is a secret key", k)
		}
	}
	for _, k := range keep {
		if logexport.IsSecretKey(k) {
			t.Errorf("%q is not a secret key", k)
		}
	}
	out, err := logexport.Scrub([]byte(`{"z":1,"password":"p","a":{"api_key":"k","m":[{"token":"t","n":null},[{"secret":1,"ok":true}]],"b":"<&>"},"key_last4":"7Qk2","big":12345678901234567890,"f":1.50,` +
		`"events":"{\"text\":\"x\",\"Set-Cookie\":\"c\",\"n\":[{\"password\":\"p\",\"ok\":1}]}","list":"[1,{\"secret\":2}]","plain":"a {not json","num":"[1,2]"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"z":1,"a":{"m":[{"n":null},[{"ok":true}]],"b":"<&>"},"key_last4":"7Qk2","big":12345678901234567890,"f":1.50,` +
		`"events":"{\"text\":\"x\",\"n\":[{\"ok\":1}]}","list":"[1,{}]","plain":"a {not json","num":"[1,2]"}`
	if string(out) != want {
		t.Fatalf("scrub =\n%s\nwant\n%s", out, want)
	}
	for _, bad := range []string{`{`, `[1]x`, `{} {}`, `nope`, strings.Repeat("[", 200)} {
		if _, err := logexport.Scrub([]byte(bad)); err == nil {
			t.Errorf("%.20q should not scrub", bad)
		}
	}
}

func TestChainedCategoriesAreNotScrubbedAndTheOthersAre(t *testing.T) {
	t.Parallel()
	row := `{"id":"x","token":"t","detail":"{\"password\":\"p\"}","hash":"h"}`
	r := logexport.New()
	r.Register("audit", src(row))    // chained: as stored, its hash covers the columns
	r.Register("honeypot", src(row)) // not chained
	body, _ := build(t, r, logexport.JSON, "audit", "honeypot")
	if !strings.Contains(body, `"audit":[`+row+`]`) {
		t.Fatalf("a chained row must come out as it went in: %s", body)
	}
	if !strings.Contains(body, `"honeypot":[{"id":"x","detail":"{}","hash":"h"}]`) {
		t.Fatalf("a non-chained row is scrubbed: %s", body)
	}
	for id, want := range map[string]bool{"audit": true, "response": true, "ai_activity": true, "honeypot": false, "alerts": false, "scan_probes": false, "device_logs": false, "known_bad": false} {
		if logexport.Chained(id) != want {
			t.Errorf("Chained(%s) != %v", id, want)
		}
	}
}

func TestCategoryIDsIsACopy(t *testing.T) {
	t.Parallel()
	a := logexport.CategoryIDs()
	a[0] = "tampered"
	if logexport.CategoryIDs()[0] != "audit" || logexport.Valid("tampered") {
		t.Fatal("the list of categories can be changed from outside")
	}
}

func TestASourceThatPanicsFailsTheExportAndLeavesNoSpool(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := logexport.New()
	r.Register("audit", src(`{"a":1}`))
	r.Register("honeypot", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		_, _ = io.WriteString(w, "{\"a\":1}\n")
		panic("boom")
	})
	_, err := r.Build(t.Context(), logexport.Request{Categories: []string{"audit", "honeypot"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: dir})
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want the panic as an error", err)
	}
	if left, _ := readDir(dir); len(left) != 0 {
		t.Fatalf("spool left behind: %v", left)
	}
}

func TestJSONFileHasTheMockEnvelopeAndListsMissing(t *testing.T) {
	t.Parallel()
	r := logexport.New()
	r.Register("honeypot", src(`{"id":"r1","password":"x","hash":"h"}`, `{"id":"r2"}`))
	r.Register("audit", src(`{"id":"a1"}`))
	body, e := build(t, r, logexport.JSON, "honeypot", "alerts", "audit")
	want := `{"format":"vedette-logs/1","exported_at":"2026-11-10T01:02:03.000Z","from":null,"to":null,"time_zone":"","verification":"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(logexport.ChainNote) +
		`","missing":["alerts"],"counts":{"alerts":0,"audit":1,"honeypot":2},"chains":{"audit":null},"categories":{"honeypot":[{"id":"r1","hash":"h"},` + "\n" + `{"id":"r2"}],"alerts":[],"audit":[{"id":"a1"}]}}` + "\n"
	if body != want {
		t.Fatalf("file =\n%s\nwant\n%s", body, want)
	}
	if e.Rows != 3 || e.Counts["honeypot"] != 2 || len(e.Missing) != 1 || e.Missing[0] != "alerts" {
		t.Fatalf("export = %+v", e)
	}
}

func TestSourceErrorsAndBadLinesFailTheExport(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	for name, s := range map[string]logexport.Source{
		"error":     func(context.Context, time.Time, time.Time, io.Writer) error { return boom },
		"not JSON":  src(`not json`),
		"not a row": src(`[1,2]`),
	} {
		r := logexport.New()
		r.Register("audit", s)
		if _, err := r.Build(t.Context(), logexport.Request{Categories: []string{"audit"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: t.TempDir()}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A last line without a newline still counts.
	r := logexport.New()
	r.Register("audit", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		_, err := io.WriteString(w, `{"a":1}`)
		return err
	})
	body, _ := build(t, r, logexport.CSV, "audit")
	if body != "\ufeff# audit\na\n1\n" {
		t.Fatalf("csv = %q", body)
	}
}

func TestOverTheCapIsRefusedAndCleansUp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := logexport.New()
	r.Register("audit", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		for i := range 1000 {
			if _, err := fmt.Fprintf(w, "{\"id\":%d,\"text\":\"%s\"}\n", i, strings.Repeat("x", 100)); err != nil {
				return err
			}
		}
		return nil
	})
	_, err := r.Build(t.Context(), logexport.Request{Categories: []string{"audit"}, Format: logexport.JSON, MaxBytes: 10 << 10, Dir: dir})
	if !errors.Is(err, logexport.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// The cap is on all categories together, not on each.
	r2 := logexport.New()
	row := `{"t":"` + strings.Repeat("y", 400) + `"}`
	r2.Register("audit", src(row, row))
	r2.Register("response", src(row, row))
	if _, err := r2.Build(t.Context(), logexport.Request{Categories: []string{"audit", "response"}, Format: logexport.JSON, MaxBytes: 1200, Dir: dir}); !errors.Is(err, logexport.ErrTooLarge) {
		t.Fatalf("two categories: err = %v, want ErrTooLarge", err)
	}
	// One endless line is refused too.
	r3 := logexport.New()
	r3.Register("audit", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		for range 1000 {
			if _, err := io.WriteString(w, strings.Repeat("z", 1024)); err != nil {
				return err
			}
		}
		return nil
	})
	if _, err := r3.Build(t.Context(), logexport.Request{Categories: []string{"audit"}, Format: logexport.JSON, MaxBytes: 64 << 10, Dir: dir}); !errors.Is(err, logexport.ErrTooLarge) {
		t.Fatalf("a line without end: err = %v, want ErrTooLarge", err)
	}
	if left, _ := readDir(dir); len(left) != 0 {
		t.Fatalf("spool left behind: %v", left)
	}
}

func TestCloseRemovesTheSpool(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := logexport.New()
	r.Register("audit", src(`{"a":1}`))
	e, err := r.Build(t.Context(), logexport.Request{Categories: []string{"audit"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := readDir(dir); len(left) != 1 {
		t.Fatalf("spool = %v while the export is open", left)
	}
	_ = e.Close()
	_ = e.Close()
	if left, _ := readDir(dir); len(left) != 0 {
		t.Fatalf("spool left behind: %v", left)
	}
}

// A big log costs disk, not memory: 100,000 rows (about 33 MB of file) are read and written through while the heap
// stays far below the size of the file. GC is made eager so garbage does not hide a buffered file. The JSON and the CSV
// export run at the same time (under -race each takes tens of seconds), so the bound holds for both together.
func TestALargeLogStaysInBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	const n = 100_000
	detail := strings.Repeat("d", 250) // once: the source's own garbage is not what is measured
	r := logexport.New()
	r.Register("audit", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		for i := range n {
			if _, err := fmt.Fprintf(w, "{\"id\":\"au-%d\",\"ts\":\"2026-11-09T08:00:00.000Z\",\"detail\":\"%s\",\"password\":\"x\"}\n", i, detail); err != nil {
				return err
			}
		}
		return nil
	})
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var wg sync.WaitGroup
	for _, format := range []logexport.Format{logexport.JSON, logexport.CSV} {
		dir := t.TempDir()
		wg.Go(func() {
			e, err := r.Build(t.Context(), logexport.Request{Categories: []string{"audit"}, Format: format, MaxBytes: 1 << 30, Dir: dir})
			if err != nil {
				t.Error(err)
				return
			}
			size, err := io.Copy(io.Discard, e)
			_ = e.Close()
			if err != nil {
				t.Error(err)
				return
			}
			if e.Rows != n || size < 25<<20 {
				t.Errorf("%s: rows = %d, bytes = %d", format, e.Rows, size)
			}
		})
	}
	wg.Wait()
	close(stop)
	<-done
	if grown := peak.Load() - min(peak.Load(), base.HeapAlloc); grown > 12<<20 {
		t.Fatalf("the heap grew by %d MB while a 33 MB JSON file and its CSV went through", grown>>20)
	}
}

func readDir(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out, err
}
