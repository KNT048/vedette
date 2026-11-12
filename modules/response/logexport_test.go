package response_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/logexport"
)

// ExportLog is the "response" source of GET /core/logs/export: resp_log as stored, so the file verifies offline.
func TestExportLogKeepsTheChainAndTheRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	cut := e.clock.Now().Add(time.Minute)
	e.clock.Advance(2 * time.Minute)
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	stored, err := e.svc.Log(e.ctx())
	if err != nil || len(stored) < 4 {
		t.Fatalf("log = %d lines, %v", len(stored), err)
	}

	var out bytes.Buffer
	if err := e.svc.ExportLog(e.ctx(), time.Time{}, time.Time{}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(stored) {
		t.Fatalf("%d lines exported, %d stored", len(lines), len(stored))
	}
	v := chain.NewVerifier("")
	for i, l := range lines {
		var got map[string]string
		if err := json.Unmarshal([]byte(l), &got); err != nil {
			t.Fatal(err)
		}
		if got["id"] != stored[i].ID || got["hash"] != stored[i].Hash || got["prev_hash"] != stored[i].PrevHash || got["detail"] != stored[i].Detail || got["ts"] != stored[i].TS || got["kind"] != stored[i].Kind || got["actor"] != stored[i].Actor {
			t.Fatalf("line %d differs from the stored row: %s", i, l)
		}
		if _, has := got["seq"]; has {
			t.Fatal("seq is not part of the chain, nor of a download")
		}
		sum, err := chain.HashCanonical(got["prev_hash"], map[string]any{"id": got["id"], "ts": got["ts"], "kind": got["kind"], "actor": got["actor"], "detail": got["detail"]})
		if err != nil {
			t.Fatal(err)
		}
		v.Add(got["id"], got["prev_hash"], got["hash"], sum)
	}
	if r := v.Result(); !r.OK {
		t.Fatalf("the exported file does not verify offline: %+v", r)
	}

	// A range keeps the rows inside it, with their hashes unchanged.
	var late bytes.Buffer
	if err := e.svc.ExportLog(e.ctx(), cut, time.Time{}, &late); err != nil {
		t.Fatal(err)
	}
	n := strings.Count(late.String(), "\n")
	if n == 0 || n >= len(stored) || !strings.Contains(late.String(), `"hash":"`+stored[len(stored)-1].Hash+`"`) {
		t.Fatalf("from: %d of %d lines", n, len(stored))
	}
	var early bytes.Buffer
	if err := e.svc.ExportLog(e.ctx(), time.Time{}, cut, &early); err != nil {
		t.Fatal(err)
	}
	if m := strings.Count(early.String(), "\n"); m == 0 || m+n != len(stored) {
		t.Fatalf("to: %d + %d lines, want %d", m, n, len(stored))
	}
}

// The response chain goes out as stored (no scrubbing: it would break the hashes), so its lines must hold no secret when they
// are written. This checks today's lines, and that the file says where the chain starts and ends.
func TestExportLogRowsHoldNoSecretAndTheChainIsStated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.clock.Advance(time.Minute)
	e.fire(e.iocEvent("e2", "198.51.100.8"))

	reg := logexport.New()
	reg.Register("response", e.svc.ExportLog)
	exp, err := reg.Build(e.ctx(), logexport.Request{Categories: []string{"response"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp.Close() }()
	body, err := io.ReadAll(exp)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Chains     map[string]logexport.ChainInfo
		Categories map[string][]map[string]any
	}
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	rows := f.Categories["response"]
	ci := f.Chains["response"]
	if len(rows) < 4 || !ci.Complete || ci.AnchorKind != "genesis" || ci.Count != int64(len(rows)) || ci.HeadHash == nil || *ci.HeadHash != rows[len(rows)-1]["hash"] {
		t.Fatalf("chains.response = %+v (%d rows)", ci, len(rows))
	}
	for _, r := range rows {
		for k, v := range r {
			if logexport.IsSecretKey(k) {
				t.Errorf("a resp_log line has a secret-looking key %q", k)
			}
			if s, ok := v.(string); ok && (strings.Contains(strings.ToLower(s), "password") || strings.Contains(s, "Bearer ") || strings.Contains(s, "BEGIN ")) {
				t.Errorf("a resp_log line looks like it holds a secret in %q: %q", k, s)
			}
		}
	}
}
