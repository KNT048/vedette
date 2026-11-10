package honeypot_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/modules/honeypot"
)

// ExportHits is the "honeypot" source of GET /core/logs/export: the stored rows, columns of hp_hits, events as JSON,
// oldest first, bounded by the range, and nothing the table keeps only for itself.
func TestExportHitsIsTheStoredRowsInRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(sshLogin("192.168.10.157", 1, t0, "root").json(), sshLogin("192.168.10.158", 1, t0.Add(2*time.Minute), "admin").json())
	e.poll()
	hits, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil || len(hits) != 2 {
		t.Fatalf("%d hits, %v", len(hits), err)
	}

	var all bytes.Buffer
	if err := e.svc.ExportHits(e.ctx(), time.Time{}, time.Time{}, &all); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(all.String()), "\n")
	if len(rows) != 2 {
		t.Fatalf("%d lines: %s", len(rows), all.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(rows[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["src_ip"] != "192.168.10.157" || first["kind"] != "service" || first["service"] != "ssh" {
		t.Fatalf("oldest first: %v", first)
	}
	if _, isList := first["events"].([]any); !isList {
		t.Fatalf("events must be JSON, not a string: %T", first["events"])
	}
	if n, ok := first["conn_count"].(float64); !ok || n < 1 {
		t.Fatalf("conn_count = %v: a hit counts the connections it merged", first["conn_count"])
	}
	for _, k := range []string{"conn_key", "seq"} {
		if _, has := first[k]; has {
			t.Fatalf("%s is not part of a download", k)
		}
	}
	if strings.Contains(all.String(), "hunter2-never-stored") {
		t.Fatal("the password the attacker typed is in the export")
	}
	// The file is accepted by the exporter as it is, and loses no row to the scrubbing.
	r := logexport.New()
	r.Register("honeypot", e.svc.ExportHits)
	exp, err := r.Build(e.ctx(), logexport.Request{Categories: []string{"honeypot"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp.Close() }()
	if exp.Rows != 2 {
		t.Fatalf("rows = %d", exp.Rows)
	}

	// The range: both ends inclusive.
	var one bytes.Buffer
	if err := e.svc.ExportHits(e.ctx(), t0.Add(time.Minute), time.Time{}, &one); err != nil || strings.Count(one.String(), "\n") != 1 || !strings.Contains(one.String(), "192.168.10.158") {
		t.Fatalf("from: %v %s", err, one.String())
	}
	one.Reset()
	if err := e.svc.ExportHits(e.ctx(), time.Time{}, t0, &one); err != nil || strings.Count(one.String(), "\n") != 1 || !strings.Contains(one.String(), "192.168.10.157") {
		t.Fatalf("to (inclusive): %v %s", err, one.String())
	}
	one.Reset()
	if err := e.svc.ExportHits(e.ctx(), t0.Add(10*time.Second), t0.Add(50*time.Second), &one); err != nil || one.Len() != 0 {
		t.Fatalf("empty range: %v %q", err, one.String())
	}
}
