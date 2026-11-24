package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Fixtures, docs and examples use only documentation and private-use address ranges (192.0.2.0/24, 198.51.100.0/24,
// 10.0.0.0/8, 192.168.1.0/24, 100.64.0.0/10 outside the ranges below). The prefixes below belong to a real network and must
// not appear in any file of the repository. They are assembled from parts so this file does not contain them itself.
var forbiddenAddressPrefixes = []string{
	"192.168." + "18.",
	"100." + "65.",
}

func TestNoRealNetworkAddressesInTheRepository(t *testing.T) {
	skipDirs := map[string]bool{".git": true, "node_modules": true, "dist": true, ".dev": true, "bin": true}
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: test, paths come from walking the repository
		if err != nil {
			return err
		}
		if bytes.IndexByte(b, 0) >= 0 {
			return nil // binary
		}
		plain := bytes.ReplaceAll(b, []byte(`\.`), []byte(".")) // a regular expression spells the dots as \.
		for _, pre := range forbiddenAddressPrefixes {
			if bytes.Contains(plain, []byte(pre)) {
				rel, _ := filepath.Rel(repoRoot, p)
				t.Errorf("%s contains the address prefix %q: use 10.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24 or another example range", rel, pre)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
