// Command weblicenses writes the third-party license file of the web interface that the core image carries (D-155 (10), Apache-2.0 4(a), MIT).
// It asks pnpm for the production tree of web/ and writes, for every package, its name, versions, license, and the text of its license files.
// A package with neither a license file nor a declared license fails the run; one with only the declared license is written as such.
// Run it where the web dependencies are installed (make webui-dist); the output is generated, never committed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxFile = 1 << 20

var licenseName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicense|notice)([-._].*)?$`)

type pkg struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Paths    []string `json:"paths"`
	License  string   `json:"license"`
	Homepage string   `json:"homepage"`
}

func main() {
	web := flag.String("web", "web", "folder of the web project")
	out := flag.String("out", "", "file to write")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "weblicenses: -out is required")
		os.Exit(2)
	}
	if err := run(*web, *out); err != nil {
		fmt.Fprintln(os.Stderr, "weblicenses:", err)
		os.Exit(1)
	}
}

func run(web, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "pnpm", "--dir", web, "licenses", "list", "--prod", "--json") //nolint:gosec // fixed argv, no shell
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		return fmt.Errorf("pnpm licenses: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return render(b, out)
}

func render(pnpmJSON []byte, out string) error {
	var byLicense map[string][]pkg
	if err := json.Unmarshal(pnpmJSON, &byLicense); err != nil {
		return fmt.Errorf("pnpm licenses output: %w", err)
	}
	var all []pkg
	for _, ps := range byLicense {
		all = append(all, ps...)
	}
	if len(all) == 0 {
		return fmt.Errorf("pnpm reported no production packages")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	var w strings.Builder
	w.WriteString("Third-party licenses of the web interface embedded in vedette-core (production dependencies of web/).\n")
	for _, p := range all {
		if len(p.Paths) == 0 {
			return fmt.Errorf("%s: pnpm gave no folder", p.Name)
		}
		texts, err := licenseTexts(p.Paths[0])
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
		if len(texts) == 0 && (p.License == "" || strings.EqualFold(p.License, "unknown")) {
			return fmt.Errorf("%s %s has neither a license file nor a declared license", p.Name, strings.Join(p.Versions, ","))
		}
		fmt.Fprintf(&w, "\n================================================================================\n%s %s\nLicense: %s\n", p.Name, strings.Join(p.Versions, ", "), p.License)
		if p.Homepage != "" {
			fmt.Fprintf(&w, "Homepage: %s\n", p.Homepage)
		}
		if len(texts) == 0 {
			// some packages publish no license file; the license they declare in package.json is all there is to carry
			w.WriteString("\n(the package ships no license file; the license above is the one it declares in package.json)\n")
		}
		for _, t := range texts {
			fmt.Fprintf(&w, "\n--- %s ---\n%s\n", t.name, strings.TrimRight(t.body, "\n"))
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil { //nolint:gosec // build output, world-readable
		return err
	}
	return os.WriteFile(out, []byte(w.String()), 0o644) //nolint:gosec // build output, world-readable
}

type text struct{ name, body string }

func licenseTexts(dir string) ([]text, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ts []text
	for _, e := range ents {
		if e.IsDir() || !licenseName.MatchString(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // folder reported by pnpm
		if err != nil {
			return nil, err
		}
		if len(b) > maxFile {
			return nil, fmt.Errorf("%s is larger than %d bytes", e.Name(), maxFile)
		}
		ts = append(ts, text{e.Name(), string(b)})
	}
	return ts, nil
}
