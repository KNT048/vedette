package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	d := t.TempDir()
	withFile, bare := filepath.Join(d, "a"), filepath.Join(d, "b")
	for _, p := range []string{withFile, bare} {
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(withFile, "LICENSE"), []byte("MIT text A"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string][]pkg{"MIT": {
		{Name: "a", Versions: []string{"1.0.0"}, Paths: []string{withFile}, License: "MIT"},
		{Name: "b", Versions: []string{"2.0.0"}, Paths: []string{bare}, License: "MIT"},
	}})
	out := filepath.Join(d, "o", "l.txt")
	if err := render(in, out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out) //nolint:gosec // temp file of this test
	if s := string(b); !strings.Contains(s, "MIT text A") || !strings.Contains(s, "b 2.0.0") || !strings.Contains(s, "ships no license file") {
		t.Fatalf("unexpected output:\n%s", s)
	}
	in, _ = json.Marshal(map[string][]pkg{"": {{Name: "c", Paths: []string{bare}}}})
	if render(in, out) == nil {
		t.Fatal("a package with no license at all must fail")
	}
}
