// Command noticescheck holds THIRD_PARTY_NOTICES.md to what the project ships (WP-08i, D-159). It fails when
//   - a Go module linked into a shipped binary (go list -deps of the given commands, linux, no cgo, amd64 and arm64) is not in a
//     "Version" table of the notices, or is listed with another version;
//   - a direct production dependency of the web app is not named in the web table;
//   - a license that is GPL or AGPL appears in a notices row of a linked module or web package, in a license file at the top of
//     a linked module, or (with -web-licenses) among the licenses `pnpm licenses list --prod` reports for the whole web tree.
//
// It needs no network once the Go modules are cached. Fixed argv (go, pnpm), no shell. Run by `make notices-check`.
//
//	go run ./scripts/noticescheck -notices THIRD_PARTY_NOTICES.md -cmd ./cmd/vedette -web web
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec" //nolint:depguard // build helper outside the product: fixed argv (go, pnpm), no shell
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxLicense = 1 << 20

type module struct{ path, version, dir string }

type row struct {
	line    int
	cells   []string // first cell: names, then version (Go tables) or license
	license string
}

type tables struct{ goRows, webRows []row }

var (
	modPath    = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._-]*\.[a-z]{2,}/[A-Za-z0-9._/~-]*[A-Za-z0-9]`)
	modVersion = regexp.MustCompile(`v\d+\.\d+\.\d+[A-Za-z0-9.+-]*`)
	// a GPL or AGPL license; LGPL has no word boundary before "GPL" and is allowed
	gplName = regexp.MustCompile(`(?i)\ba?gpl`)
	// the title line of a GPL or AGPL text (the Lesser text has another title; a sentence that names the GPL, as in the MPL, is not a title)
	gplText     = regexp.MustCompile(`(?m)^\s*GNU (GENERAL|AFFERO GENERAL) PUBLIC LICENSE\s*$`)
	licenseName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicense|notice)([-._].*)?$`)
)

func main() {
	notices := flag.String("notices", "", "the notices file")
	var cmds multi
	flag.Var(&cmds, "cmd", "a shipped main package, e.g. ./cmd/vedette (repeatable)")
	web := flag.String("web", "", "the web app folder (package.json inside)")
	webLicenses := flag.Bool("web-licenses", false, "also run `pnpm licenses list --prod` in the web folder and refuse GPL/AGPL anywhere in the tree")
	flag.Parse()
	if *notices == "" || len(cmds) == 0 || *web == "" {
		fmt.Fprintln(os.Stderr, "noticescheck: -notices, -cmd and -web are required")
		os.Exit(2)
	}
	problems, err := run(*notices, cmds, *web, *webLicenses)
	if err != nil {
		fmt.Fprintln(os.Stderr, "noticescheck:", err)
		os.Exit(1)
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "noticescheck:", p)
		}
		fmt.Fprintf(os.Stderr, "noticescheck: %d problem(s); fix THIRD_PARTY_NOTICES.md (or the dependency)\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("noticescheck: ok")
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(noticesPath string, cmds []string, webDir string, webLicenses bool) ([]string, error) {
	text, err := os.ReadFile(noticesPath) //nolint:gosec // the path is the repo's own notices file, given on the command line
	if err != nil {
		return nil, err
	}
	linked, err := linkedModules(cmds)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	b, err := os.ReadFile(filepath.Join(webDir, "package.json")) //nolint:gosec // as above
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, fmt.Errorf("web package.json: %w", err)
	}
	deps := make([]string, 0, len(pkg.Dependencies))
	for d := range pkg.Dependencies {
		deps = append(deps, d)
	}
	var lic map[string][]string
	if webLicenses {
		if lic, err = pnpmLicenses(webDir); err != nil {
			return nil, err
		}
	}
	return check(string(text), linked, deps, lic), nil
}

func goList(goarch, cmd string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "go", "list", "-deps", "-f", `{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}`, cmd) //nolint:gosec // fixed argv, no shell
	// what the images and the package build: static, Linux
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s (%s): %w: %s", cmd, goarch, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// linkedModules is the union, over the commands and both architectures, of the modules that provide a linked package. The main module
// (no version) is left out.
func linkedModules(cmds []string) ([]module, error) {
	seen := map[string]bool{}
	var out []module
	for _, cmd := range cmds {
		for _, arch := range []string{"amd64", "arm64"} {
			b, err := goList(arch, cmd)
			if err != nil {
				return nil, err
			}
			for _, m := range parseModules(string(b)) {
				if !seen[m.path+"@"+m.version] {
					seen[m.path+"@"+m.version] = true
					out = append(out, m)
				}
			}
		}
	}
	return out, nil
}

func parseModules(list string) []module {
	var out []module
	for l := range strings.SplitSeq(list, "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 3 || f[1] == "" { // the main module and the standard library carry no version
			continue
		}
		out = append(out, module{f[0], f[1], f[2]})
	}
	return out
}

func pnpmLicenses(webDir string) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "pnpm", "--dir", webDir, "licenses", "list", "--prod", "--json") //nolint:gosec // fixed argv, no shell
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("pnpm licenses: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseLicenses(b)
}

// parseLicenses reads the output of `pnpm licenses list --json`: license name -> packages. It returns license -> package names.
func parseLicenses(b []byte) (map[string][]string, error) {
	var raw map[string][]struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("pnpm licenses output: %w", err)
	}
	out := map[string][]string{}
	for l, pk := range raw {
		for _, p := range pk {
			out[l] = append(out[l], p.Name)
		}
	}
	return out, nil
}

func cells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(strings.TrimSuffix(line, "|"), "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parseTables reads the Go tables (header: Library | Version | License | ...) and the web table (header: Package | License | ...).
func parseTables(text string) tables {
	var t tables
	kind := ""
	for i, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, "|") {
			kind = ""
			continue
		}
		c := cells(l)
		if strings.Trim(strings.Join(c, ""), "-: ") == "" { // the |---|---| line
			continue
		}
		if len(c) >= 2 && c[0] == "Library" && c[1] == "Version" {
			kind = "go"
			continue
		}
		if len(c) >= 2 && c[0] == "Package" && c[1] == "License" {
			kind = "web"
			continue
		}
		switch {
		case kind == "go" && len(c) >= 3:
			t.goRows = append(t.goRows, row{line: i + 1, cells: c[:2], license: c[2]})
		case kind == "web" && len(c) >= 2:
			t.webRows = append(t.webRows, row{line: i + 1, cells: c[:1], license: c[1]})
		}
	}
	return t
}

// pairs maps each module of a Go row to the version written for it (same order in both cells).
func (r row) pairs() (map[string]string, error) {
	mods := modPath.FindAllString(r.cells[0], -1)
	vers := modVersion.FindAllString(r.cells[1], -1)
	if len(mods) != len(vers) {
		return nil, fmt.Errorf("line %d: %d module paths but %d versions (write one vN.N.N or pseudo-version per module, same order)", r.line, len(mods), len(vers))
	}
	out := map[string]string{}
	for i, m := range mods {
		out[m] = vers[i]
	}
	return out, nil
}

// check returns the problems, sorted for stable output. linked: modules in the binaries; webDeps: production dependency names;
// webLicenses: license -> package names of the whole prod tree (nil: not checked).
func check(notices string, linked []module, webDeps []string, webLicenses map[string][]string) []string {
	t := parseTables(notices)
	var probs []string
	listed := map[string][]string{} // module -> the versions written, one per row
	rowOf := map[string][]row{}
	for _, r := range t.goRows {
		p, err := r.pairs()
		if err != nil {
			probs = append(probs, "notices "+err.Error())
			continue
		}
		for m, v := range p {
			listed[m] = append(listed[m], v)
			rowOf[m] = append(rowOf[m], r)
		}
	}
	for _, m := range linked {
		vs, ok := listed[m.path]
		if !ok {
			probs = append(probs, fmt.Sprintf("linked module %s %s is not in the notices", m.path, m.version))
			continue
		}
		for i, v := range vs {
			if v != m.version {
				probs = append(probs, fmt.Sprintf("notices line %d lists %s %s, the binaries link %s", rowOf[m.path][i].line, m.path, v, m.version))
			}
		}
		for _, r := range rowOf[m.path] {
			if gplName.MatchString(r.license) {
				probs = append(probs, fmt.Sprintf("notices line %d: linked module %s is listed as %q; GPL/AGPL is never shipped in a binary", r.line, m.path, r.license))
			}
		}
		for _, f := range gplLicenseFiles(m.dir) {
			probs = append(probs, fmt.Sprintf("linked module %s %s ships a GPL/AGPL license text (%s)", m.path, m.version, f))
		}
	}
	probs = append(probs, checkWeb(t.webRows, webDeps, webLicenses)...)
	slices.Sort(probs)
	return slices.Compact(probs)
}

func checkWeb(rows []row, deps []string, lic map[string][]string) []string {
	var probs []string
	named := map[string]bool{}
	for _, r := range rows {
		for _, tok := range strings.FieldsFunc(r.cells[0], func(c rune) bool { return strings.ContainsRune(" ,()`+", c) }) {
			named[tok] = true
		}
		if gplName.MatchString(r.license) {
			probs = append(probs, fmt.Sprintf("notices line %d: web package %q is listed as %q; GPL/AGPL is never shipped", r.line, r.cells[0], r.license))
		}
	}
	for _, d := range deps {
		scope, _, scoped := strings.Cut(d, "/")
		if !named[d] && (!scoped || !named[scope+"/*"]) {
			probs = append(probs, fmt.Sprintf("web production dependency %s is not in the web table of the notices", d))
		}
	}
	for l, pk := range lic {
		if gplName.MatchString(l) {
			slices.Sort(pk)
			probs = append(probs, fmt.Sprintf("web production tree has license %q: %s", l, strings.Join(pk, ", ")))
		}
	}
	return probs
}

// gplLicenseFiles lists the license files at the top of a module folder that hold a GPL or AGPL text.
func gplLicenseFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() || !licenseName.MatchString(e.Name()) {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name())) //nolint:gosec // a file of the module cache
		if err != nil {
			continue
		}
		buf, _ := io.ReadAll(io.LimitReader(f, maxLicense))
		_ = f.Close()
		if gplText.Match(buf) {
			out = append(out, e.Name())
		}
	}
	return out
}
