package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = `# Third-party components

## Libraries bundled in the web app

| Package | License | Used for |
|---|---|---|
| react, react-dom | MIT | framework |
| radix-ui (@radix-ui/*) | MIT | primitives |

## Go libraries

| Library | Version | License | How used |
|---|---|---|---|
| modernc.org/sqlite | v1.61.1 | BSD-3-Clause | engine |
| golang.org/x/sync, golang.org/x/sys | v0.24.0, v0.49.0 | BSD-3-Clause | helpers |
| golang.org/x/exp | v0.0.0-20261011100332-faecfb24eb49 | BSD-3-Clause | pseudo-version |
| github.com/knt048/lgpl | v1.0.0 | LGPL-2.1 | allowed |

## Tools

| Component | License | How used |
|---|---|---|
| golangci-lint | GPL-3.0 | tool, not linked; github.com/x/notamodule v9.9.9 here is ignored |
`

var linked = []module{
	{path: "modernc.org/sqlite", version: "v1.61.1"},
	{path: "golang.org/x/sync", version: "v0.24.0"},
	{path: "golang.org/x/sys", version: "v0.49.0"},
	{path: "golang.org/x/exp", version: "v0.0.0-20261011100332-faecfb24eb49"},
	{path: "github.com/knt048/lgpl", version: "v1.0.0"},
}

var webDeps = []string{"react", "react-dom", "radix-ui", "@radix-ui/react-dialog"}

func has(t *testing.T, probs []string, sub string) {
	t.Helper()
	for _, p := range probs {
		if strings.Contains(p, sub) {
			return
		}
	}
	t.Errorf("no problem mentions %q; got %q", sub, probs)
}

func TestCleanNotices(t *testing.T) {
	if p := check(fixture, linked, webDeps, map[string][]string{"MIT": {"react"}, "LGPL-2.1-or-later": {"x"}}); len(p) != 0 {
		t.Fatalf("expected no problem, got %q", p)
	}
}

func TestMissingGoModule(t *testing.T) {
	l := append([]module{{path: "github.com/new/dep", version: "v1.2.3"}}, linked...)
	p := check(fixture, l, webDeps, nil)
	if len(p) != 1 {
		t.Fatalf("want exactly the missing module, got %q", p)
	}
	has(t, p, "github.com/new/dep v1.2.3 is not in the notices")
}

func TestWrongVersion(t *testing.T) {
	l := []module{{path: "golang.org/x/sys", version: "v0.50.0"}}
	p := check(fixture, l, webDeps, nil)
	has(t, p, "lists golang.org/x/sys v0.49.0, the binaries link v0.50.0")
	// a date written where the pseudo-version belongs is a version difference too
	bad := strings.Replace(fixture, "v0.0.0-20261011100332-faecfb24eb49", "v0.0.0-20230725000000-aaaaaaaaaaaa", 1)
	has(t, check(bad, linked, webDeps, nil), "golang.org/x/exp v0.0.0-20230725000000-aaaaaaaaaaaa, the binaries link")
}

func TestRowWithUnpairedVersions(t *testing.T) {
	bad := strings.Replace(fixture, "v0.24.0, v0.49.0", "v0.24.0, 2023-07-25", 1)
	has(t, check(bad, linked, webDeps, nil), "2 module paths but 1 versions")
}

func TestGPLRowOfLinkedModule(t *testing.T) {
	bad := strings.Replace(fixture, "| github.com/knt048/lgpl | v1.0.0 | LGPL-2.1 |", "| github.com/knt048/lgpl | v1.0.0 | AGPL-3.0 |", 1)
	has(t, check(bad, linked, webDeps, nil), `listed as "AGPL-3.0"`)
	bad = strings.Replace(fixture, "| github.com/knt048/lgpl | v1.0.0 | LGPL-2.1 |", "| github.com/knt048/lgpl | v1.0.0 | GPL-2.0-or-later |", 1)
	has(t, check(bad, linked, webDeps, nil), `listed as "GPL-2.0-or-later"`)
}

func TestToolRowsMayBeGPL(t *testing.T) {
	// the golangci-lint row is GPL-3.0 and is not linked: no problem (it is a tool table, not a Version table)
	if p := check(fixture, linked, webDeps, nil); len(p) != 0 {
		t.Fatalf("tool rows must be ignored, got %q", p)
	}
}

func TestGPLLicenseFileInLinkedModule(t *testing.T) {
	dir := t.TempDir()
	text := "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("GNU GENERAL PUBLIC LICENSE"), 0o600); err != nil { // not a license file
		t.Fatal(err)
	}
	l := []module{{path: "golang.org/x/sys", version: "v0.49.0", dir: dir}}
	p := check(fixture, l, webDeps, nil)
	if len(p) != 1 {
		t.Fatalf("want one problem, got %q", p)
	}
	has(t, p, "ships a GPL/AGPL license text (LICENSE)")

	// the MPL names the GPL as a possible secondary license: a sentence, not the title of a GPL text
	mpl := t.TempDir()
	if err := os.WriteFile(filepath.Join(mpl, "LICENSE-3RD-PARTY.md"), []byte("means either the GNU General Public License, Version 2.0, the GNU Lesser\nGeneral Public License"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := check(fixture, []module{{path: "golang.org/x/sys", version: "v0.49.0", dir: mpl}}, webDeps, nil); len(p) != 0 {
		t.Fatalf("a mention of the GPL is not a GPL text, got %q", p)
	}

	lesser := t.TempDir()
	if err := os.WriteFile(filepath.Join(lesser, "COPYING.LESSER"), []byte("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3"), 0o600); err != nil {
		t.Fatal(err)
	}
	l = []module{{path: "golang.org/x/sys", version: "v0.49.0", dir: lesser}}
	if p := check(fixture, l, webDeps, nil); len(p) != 0 {
		t.Fatalf("the Lesser text is allowed, got %q", p)
	}
}

func TestWebDependencyMissing(t *testing.T) {
	p := check(fixture, linked, append([]string{"zod", "@new/pkg"}, webDeps...), nil)
	has(t, p, "web production dependency zod is not in the web table")
	has(t, p, "web production dependency @new/pkg is not in the web table")
	if len(p) != 2 {
		t.Fatalf("react, react-dom, radix-ui and the @radix-ui scope are named; got %q", p)
	}
}

func TestWebTreeGPL(t *testing.T) {
	out := []byte(`{"MIT":[{"name":"react","versions":["19"]}],"GPL-3.0":[{"name":"evil","versions":["1.0.0"]}],"LGPL-3.0":[{"name":"ok"}]}`)
	lic, err := parseLicenses(out)
	if err != nil {
		t.Fatal(err)
	}
	p := check(fixture, linked, webDeps, lic)
	if len(p) != 1 {
		t.Fatalf("want one problem (GPL-3.0), got %q", p)
	}
	has(t, p, `license "GPL-3.0": evil`)
	if _, err := parseLicenses([]byte("not json")); err == nil {
		t.Fatal("a broken pnpm output must be an error, not an empty result")
	}
}

func TestWebRowGPL(t *testing.T) {
	bad := strings.Replace(fixture, "| react, react-dom | MIT |", "| react, react-dom | GPL-3.0 |", 1)
	has(t, check(bad, linked, webDeps, nil), "web package")
}

func TestParseModulesSkipsMainAndStd(t *testing.T) {
	m := parseModules("github.com/knt048/vedette||/src\n\ngolang.org/x/sys|v0.49.0|/cache/x\n")
	if len(m) != 1 || m[0].path != "golang.org/x/sys" || m[0].dir != "/cache/x" {
		t.Fatalf("got %+v", m)
	}
}
