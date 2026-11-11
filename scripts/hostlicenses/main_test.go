package main

import (
	"context"
	"os/exec" //nolint:depguard // the test asks go which modules are linked: fixed argv, no shell
	"strings"
	"testing"
	"time"
)

// The file names every module linked into the static host binary (asked from go itself, apart from the generator's own code path)
// and carries the Go license; a module without a license file would have failed the generation.
func TestGenerateNamesEveryLinkedModule(t *testing.T) {
	text, err := generate("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-f", "{{if .Module}}{{.Module.Path}}{{end}}", "github.com/knt048/vedette/cmd/vedette-host")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for p := range strings.SplitSeq(string(out), "\n") {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if !strings.Contains(string(text), "== "+p+" ") && !strings.Contains(string(text), "== "+p+" (") {
			t.Errorf("the file does not name the linked module %s", p)
		}
	}
	if len(seen) < 2 {
		t.Errorf("only %d linked modules found: the go list query is wrong", len(seen))
	}
	for _, want := range []string{"== Go standard library and runtime (LICENSE)", "== github.com/knt048/vedette ("} {
		if !strings.Contains(string(text), want) {
			t.Errorf("the file lacks %q", want)
		}
	}
}
