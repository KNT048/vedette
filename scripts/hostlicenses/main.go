// Command hostlicenses writes the third-party license file that the vedette-host .deb ships as
// /usr/share/doc/vedette-host/third-party-licenses (WP-08g, D-155): the Go license for the standard library and runtime that
// the static binary contains, then the license files of every module linked into ./cmd/vedette-host (the main module
// included), found with `go list -deps` in the module cache. A linked module without a license file is an error, so a new
// dependency cannot ship unlicensed (one recorded exception at one exact version: noLicenseFile, D-454). Run by `make host-deb`; the file is generated into dist/, never committed.
//
//	go run ./scripts/hostlicenses -goos linux -goarch amd64 -out dist/host-deb/amd64/third-party-licenses
//
// The container images use the same program over their own main package (-pkg, -name, -tags): each Containerfile build stage
// runs it and the image carries the result as /usr/share/doc/vedette/third-party-licenses (D-155 (10)). The scan-base image
// also runs it inside the nuclei source tree over ./cmd/nuclei (nuclei-third-party-licenses, D-454).
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // build helper outside the product: fixed argv (go), no shell
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxLicense = 1 << 20

// licenseName matches the license files at the top of a module: LICENSE, LICENSE.md, COPYING, UNLICENSE, NOTICE...
var licenseName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicense|notice)([-._].*)?$`)

const defaultPkg = "github.com/knt048/vedette/cmd/vedette-host"

type module struct{ path, version, dir string }

// noLicenseFile is the one exception to "a linked module without a license file is an error" (D-454): a module at ONE exact
// version whose author states the license elsewhere, shipped with the standard text of that license, as Debian and Fedora
// package such modules. A new version of the module fails again until someone re-reads its source and updates this entry.
var noLicenseFile = map[string]struct{ heading, text string }{
	// nuclei (scan-base image, D-319) links it. The README at the tag shows the MIT badge, linked to opensource.org/licenses/MIT;
	// the repository has no LICENSE file (main neither, 2026-11-12) and its issues are disabled (D-454).
	"github.com/censys/censys-sdk-go@v0.19.1": {
		heading: "MIT per the README, https://github.com/censys/censys-sdk-go/blob/v0.19.1/README.md; upstream has no LICENSE file",
		text:    mitCensys,
	},
}

// The standard MIT text (https://opensource.org/license/mit). Upstream names no holder or year; the holder is the publisher.
const mitCensys = `The MIT License (MIT)

Copyright (c) Censys, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`

func main() {
	goos := flag.String("goos", "linux", "target GOOS")
	goarch := flag.String("goarch", "amd64", "target GOARCH")
	out := flag.String("out", "", "file to write")
	pkg := flag.String("pkg", defaultPkg, "main package whose linked modules are listed")
	name := flag.String("name", "vedette-host", "name of the program, for the file heading")
	tags := flag.String("tags", "", "build tags of the binary (e.g. webui), as for go build -tags")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "hostlicenses: -out is required")
		os.Exit(2)
	}
	text, err := generate(*goos, *goarch, *pkg, *name, *tags)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(*out), 0o755) //nolint:gosec // dist/ of the build, read by the packager
	}
	if err == nil {
		err = os.WriteFile(*out, text, 0o644) //nolint:gosec // a public license file
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostlicenses:", err)
		os.Exit(1)
	}
}

func goCmd(goos, goarch string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // fixed argv built in this file, no shell
	// the same build the package makes: no cgo, so the set of linked packages is the set of the static binary
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return b, nil
}

// modules lists the modules that provide the packages linked into the host binary.
func modules(goos, goarch, pkg, tags string) ([]module, error) {
	args := []string{"list", "-deps"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "-f", `{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}`, pkg)
	b, err := goCmd(goos, goarch, args...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []module
	for l := range strings.SplitSeq(string(b), "\n") {
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		p := strings.Split(l, "|")
		if len(p) != 3 || p[2] == "" {
			return nil, fmt.Errorf("unexpected go list line %q", l)
		}
		out = append(out, module{p[0], p[1], p[2]})
	}
	slices.SortFunc(out, func(a, b module) int { return strings.Compare(a.path, b.path) })
	return out, nil
}

func licenseFiles(dir string) (map[string][]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range ents {
		if !e.Type().IsRegular() || !licenseName.MatchString(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a license file found by name in a module directory
		if err != nil {
			return nil, err
		}
		if len(b) > maxLicense {
			return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Join(dir, e.Name()), maxLicense)
		}
		out[e.Name()] = b
	}
	return out, nil
}

// section writes the license files found in dir; a module (path@version) with none is looked up in noLicenseFile.
func section(w *bytes.Buffer, title, dir, pathAtVersion string) error {
	files, err := licenseFiles(dir)
	if err != nil {
		return err
	}
	if x, ok := noLicenseFile[pathAtVersion]; ok && len(files) == 0 {
		files = map[string][]byte{x.heading: []byte(x.text)}
	}
	if len(files) == 0 {
		return fmt.Errorf("%s has no license file in %s", title, dir)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		fmt.Fprintf(w, "================================================================================\n== %s (%s)\n================================================================================\n", title, n)
		w.Write(files[n])
		if !bytes.HasSuffix(files[n], []byte("\n")) {
			w.WriteByte('\n')
		}
		w.WriteByte('\n')
	}
	return nil
}

// generate returns the text of the file.
func generate(goos, goarch, pkg, name, tags string) ([]byte, error) {
	mods, err := modules(goos, goarch, pkg, tags)
	if err != nil {
		return nil, err
	}
	root, err := goCmd(goos, goarch, "env", "GOROOT")
	if err != nil {
		return nil, err
	}
	var w bytes.Buffer
	fmt.Fprintf(&w, "Third-party licenses of %s\n\n", name)
	w.WriteString("The Go standard library and runtime, then every Go module linked into the binary.\nVedette itself is Apache-2.0.\n\n")
	if err := section(&w, "Go standard library and runtime", strings.TrimSpace(string(root)), ""); err != nil {
		return nil, err
	}
	for _, m := range mods {
		title := m.path
		if m.version != "" {
			title += " " + m.version
		}
		if err := section(&w, title, m.dir, m.path+"@"+m.version); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}
