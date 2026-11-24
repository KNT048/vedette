package main

import (
	"bytes"
	"context"
	"os"
	"os/exec" //nolint:depguard // CI guard outside the product: fixed argv (git), no shell
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

// repoFiles lists the files of the repository at root: the tracked ones and new ones not yet added, never the files git
// ignores (local notes, build output, other checkouts kept inside the directory), which are not part of the repository.
func repoFiles(root string) ([]string, error) {
	//nolint:gosec // G204: fixed argv, no shell; root is the repository or a test directory
	out, err := exec.CommandContext(context.Background(), "git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range bytes.Split(out, []byte{0}) {
		if len(f) > 0 {
			files = append(files, string(f))
		}
	}
	return files, nil
}

// addressHits returns "file: prefix" for each repository file under root that holds a forbidden prefix.
func addressHits(root string) ([]string, error) {
	files, err := repoFiles(root)
	if err != nil {
		return nil, err
	}
	var hits []string
	for _, rel := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		st, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue // deleted in the working tree, not committed yet
			}
			return nil, err
		}
		if !st.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: test, paths come from git's list of the repository
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue // binary
		}
		plain := bytes.ReplaceAll(b, []byte(`\.`), []byte(".")) // a regular expression spells the dots as \.
		for _, pre := range forbiddenAddressPrefixes {
			if bytes.Contains(plain, []byte(pre)) {
				hits = append(hits, rel+": "+pre)
			}
		}
	}
	return hits, nil
}

func TestNoRealNetworkAddressesInTheRepository(t *testing.T) {
	hits, err := addressHits(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		t.Errorf("%s: use 10.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24 or another example range", h)
	}
}

// The guard reads the files of the repository, not every file on disk: a git-ignored local file holding a prefix does not fail
// it, while a tracked file or a new file not yet added does.
func TestAddressGuardReadsOnlyTheRepositorysFiles(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		//nolint:gosec // G204: fixed git subcommands of this test, no shell
		if out, err := exec.CommandContext(context.Background(), "git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write(".gitignore", "local-notes.md\n")
	write("local-notes.md", "test box at "+forbiddenAddressPrefixes[0]+"7\n")
	write("fixture.txt", "address 192.0.2.7\n")
	git("add", ".gitignore", "fixture.txt")
	if hits, err := addressHits(root); err != nil || len(hits) != 0 {
		t.Fatalf("an ignored local file failed the guard: %v %v", hits, err)
	}
	write("fixture.txt", "address "+forbiddenAddressPrefixes[1]+"1.1\n")
	write("new.txt", "address "+forbiddenAddressPrefixes[0]+"9\n")
	hits, err := addressHits(root)
	if err != nil || len(hits) != 2 {
		t.Fatalf("a tracked file and a new file with a prefix: %v %v", hits, err)
	}
}
