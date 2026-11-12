package main

import (
	"database/sql"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/logexport"
)

// The log sources of the binary (core INV-13): audit from core, response, honeypot, scan_probes and ai_activity from their
// modules; the rest have no source yet and the file says so instead of pretending to be complete.
func TestLogSourcesRegisteredByTheBinary(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, id := range []string{"audit", "response", "honeypot", "scan_probes", "ai_activity", "alerts"} {
		if !s.d.Logs.Has(id) {
			t.Errorf("%s has no log source", id)
		}
	}
	e, err := s.d.Logs.Build(t.Context(), logexport.Request{Categories: logexport.CategoryIDs(), Format: logexport.JSON, MaxBytes: 64 << 20, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	body, err := io.ReadAll(e)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"known_bad"}
	if slices.Compare(e.Missing, want) != 0 {
		t.Fatalf("missing = %v, want %v (when a module registers its source, move it out of this list)", e.Missing, want)
	}
	if !strings.Contains(string(body), `"missing":["known_bad"]`) {
		t.Fatalf("the file does not say what is missing: %.400s", body)
	}
}

// The "alerts" category is notify's delivery log through the real registry: the row is in the file, a token in its link or destination is not.
func TestLogExportAlertsComesFromNotifyAndCarriesNoToken(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	tok := strings.Join([]string{"tok", "alerts", "5d2b7e"}, "-")
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('sd-export-1', 'approval', 'act-1', 'webhook', ?, '2026-11-09T08:00:00.000Z', 1, 'Block 203.0.113.9', ?, '{}')`,
			"https://hooks.example.com/"+tok, "https://box.example:8443/approve/"+tok+"?x="+tok)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.d.Logs.Build(t.Context(), logexport.Request{Categories: []string{"alerts"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	body, err := io.ReadAll(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "sd-export-1") || !strings.Contains(string(body), "Block 203.0.113.9") || strings.Contains(string(body), tok) {
		t.Fatalf("the alerts export: %s", body)
	}
}
