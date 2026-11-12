package main

import (
	"bytes"
	"context"
	"os"
	"os/exec" //nolint:depguard // the test asks go which modules are linked: fixed argv, no shell
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The file names every module linked into the static host binary (asked from go itself, apart from the generator's own code path)
// and carries the Go license; a module without a license file would have failed the generation.
func TestGenerateNamesEveryLinkedModule(t *testing.T) {
	text, err := generate("linux", "amd64", defaultPkg, "vedette-host", "")
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

// The one exception (D-454) covers censys-sdk-go at v0.19.1 only: the same path at another version, and any other module without
// a license file, still fail; a module that has a license file keeps its own text even when it is listed.
func TestNoLicenseFileException(t *testing.T) {
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "README.md"), []byte("License: MIT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := section(&w, "github.com/censys/censys-sdk-go v0.19.1", empty, "github.com/censys/censys-sdk-go@v0.19.1"); err != nil {
		t.Fatalf("the recorded exception failed: %v", err)
	}
	for _, want := range []string{
		"== github.com/censys/censys-sdk-go v0.19.1 (MIT per the README, https://github.com/censys/censys-sdk-go/blob/v0.19.1/README.md; upstream has no LICENSE file)",
		"Permission is hereby granted, free of charge",
	} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("the exception's section lacks %q:\n%s", want, w.String())
		}
	}
	for _, c := range []struct{ title, key string }{
		{"github.com/censys/censys-sdk-go v0.19.2", "github.com/censys/censys-sdk-go@v0.19.2"},
		{"github.com/censys/censys-sdk-go v0.19.0", "github.com/censys/censys-sdk-go@v0.19.0"},
		{"example.com/unlicensed v1.0.0", "example.com/unlicensed@v1.0.0"},
	} {
		if err := section(&bytes.Buffer{}, c.title, empty, c.key); err == nil || !strings.Contains(err.Error(), "has no license file") {
			t.Errorf("%s without a license file: err = %v, want 'has no license file'", c.key, err)
		}
	}
	withFile := t.TempDir()
	if err := os.WriteFile(filepath.Join(withFile, "LICENSE"), []byte("upstream text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	if err := section(&w, "github.com/censys/censys-sdk-go v0.19.1", withFile, "github.com/censys/censys-sdk-go@v0.19.1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "upstream text") || strings.Contains(w.String(), "MIT per the README") {
		t.Errorf("a module with a license file must ship that file, not the exception:\n%s", w.String())
	}
}

// The images run the generator over their own main package: the sensor binary has its own list, under its own name.
func TestGenerateOverAnotherMainPackage(t *testing.T) {
	text, err := generate("linux", "amd64", "github.com/knt048/vedette/cmd/vedette-sensor", "vedette-sensor", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Third-party licenses of vedette-sensor", "== Go standard library and runtime (LICENSE)", "== github.com/knt048/vedette ("} {
		if !strings.Contains(string(text), want) {
			t.Errorf("the file lacks %q", want)
		}
	}
}
