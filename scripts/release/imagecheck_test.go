package main

import (
	"debug/buildinfo"
	"runtime/debug"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// The expectations come from the files of this tree: the Go of GOLANG_IMAGE, the patched nuclei go.mod, the committed pack index.
func TestLoadImageExpectFromTheTree(t *testing.T) {
	e, err := loadImageExpect("../..", []string{"k"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.GoVersion, "go1.") || e.NucleiMod.Module.Mod.Path != "github.com/projectdiscovery/nuclei/v3" || len(e.NucleiMod.Require) == 0 ||
		e.PackVersion == "" || !sha256HexRE.MatchString(e.PackSHA256) {
		t.Errorf("expectations: %+v", e)
	}
}

// Exact module versions: go1.27.1 is not go1.27.10, x/net v0.50.1 is not v0.50.10, and every linked module must be required.
func TestCheckNucleiBuildIsExact(t *testing.T) {
	mod, err := modfile.Parse("go.mod", []byte("module github.com/projectdiscovery/nuclei/v3\n\ngo 1.26.0\n\nrequire (\n\tgolang.org/x/net v0.50.1\n\texample.com/a v1.0.0 // indirect\n)\n\nreplace example.com/a => example.com/fork v1.0.1\n"), nil)
	must(t, err)
	e := imageExpect{GoVersion: "go1.27.1", NucleiMod: mod}
	good := func() *buildinfo.BuildInfo {
		return &buildinfo.BuildInfo{GoVersion: "go1.27.1", Main: debug.Module{Path: "github.com/projectdiscovery/nuclei/v3", Version: "(devel)"},
			Deps: []*debug.Module{{Path: "golang.org/x/net", Version: "v0.50.1"}, {Path: "example.com/a", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1"}}}}
	}
	if err := checkNucleiBuild("nuclei", good(), e); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		change func(*buildinfo.BuildInfo)
		want   string
	}{
		"go prefix":  {func(b *buildinfo.BuildInfo) { b.GoVersion = "go1.27.10" }, "built with go1.27.10"},
		"dep prefix": {func(b *buildinfo.BuildInfo) { b.Deps[0].Version = "v0.50.10" }, "golang.org/x/net v0.50.10, " + nucleiGoMod + " requires v0.50.1"},
		"extra dep": {func(b *buildinfo.BuildInfo) {
			b.Deps = append(b.Deps, &debug.Module{Path: "example.com/b", Version: "v1"})
		}, "does not require"},
		"no replace":   {func(b *buildinfo.BuildInfo) { b.Deps[1].Replace = nil }, `replaced by ""`},
		"other module": {func(b *buildinfo.BuildInfo) { b.Main.Path = "github.com/other/nuclei" }, "is module"},
		"other replaced": {func(b *buildinfo.BuildInfo) {
			b.Deps[0].Replace = &debug.Module{Path: "evil.example/net", Version: "v1"}
		}, "replaced by"},
	} {
		b := good()
		c.change(b)
		if err := checkNucleiBuild("nuclei", b, e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
}

func TestParsePins(t *testing.T) {
	m, err := parsePins([]byte("# c\n\nA=1\nB=x@sha256:ab\n"))
	if err != nil || m["A"] != "1" || m["B"] != "x@sha256:ab" {
		t.Errorf("%v %v", m, err)
	}
	if _, err := parsePins([]byte("A = 1\n")); err == nil {
		t.Error("a spaced line accepted")
	}
}
