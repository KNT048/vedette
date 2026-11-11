package main

import (
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
	for _, id := range []string{"audit", "response", "honeypot", "scan_probes", "ai_activity"} {
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
	want := []string{"alerts", "known_bad"}
	if slices.Compare(e.Missing, want) != 0 {
		t.Fatalf("missing = %v, want %v (when a module registers its source, move it out of this list)", e.Missing, want)
	}
	if !strings.Contains(string(body), `"missing":["alerts","known_bad"]`) {
		t.Fatalf("the file does not say what is missing: %.400s", body)
	}
}
