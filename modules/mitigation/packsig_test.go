package mitigation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-346: the statement binds the version, every byte of every document and the set of documents.
func TestStatementBindsVersionBytesAndSet(t *testing.T) {
	a, b := Doc{Name: "CVE-2024-0001.json", Data: []byte(`{"a":1}`)}, Doc{Name: "CVE-2024-0002.json", Data: []byte(`{"b":2}`)}
	base, err := Statement("2026.11.1", []Doc{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(base), StatementHeader+"\nversion 2026.11.1\n") || strings.Count(string(base), "\n") != 4 {
		t.Fatalf("statement:\n%s", base)
	}
	if same, _ := Statement("2026.11.1", []Doc{b, a}); !bytes.Equal(same, base) {
		t.Fatal("the order of the documents changes the statement")
	}
	changed := []byte(`{"a":2}`)
	for name, docs := range map[string][]Doc{
		"a byte":    {{Name: a.Name, Data: changed}, b},
		"a doc out": {a},
		"a doc in":  {a, b, {Name: "CVE-2024-0003.json", Data: []byte(`{}`)}},
		"renamed":   {{Name: "CVE-2024-0009.json", Data: a.Data}, b},
		"swapped":   {{Name: a.Name, Data: b.Data}, {Name: b.Name, Data: a.Data}},
	} {
		if s, err := Statement("2026.11.1", docs); err != nil || bytes.Equal(s, base) {
			t.Errorf("%s: the statement did not change (%v)", name, err)
		}
	}
	if s, _ := Statement("2026.11.2", []Doc{a, b}); bytes.Equal(s, base) {
		t.Error("the version is not bound")
	}
	for name, c := range map[string]struct {
		v    string
		docs []Doc
	}{
		"empty version":   {"", []Doc{a}},
		"two-line ver":    {"1\nCVE", []Doc{a}},
		"padded version":  {" 1", []Doc{a}},
		"long version":    {strings.Repeat("1", 65), []Doc{a}},
		"twice":           {"1", []Doc{a, a}},
		"newline in name": {"1", []Doc{{Name: "a\nb.json", Data: nil}}},
		"path":            {"1", []Doc{{Name: "../x.json"}}},
		"not json":        {"1", []Doc{{Name: "x.txt"}}},
		"space":           {"1", []Doc{{Name: "a b.json"}}},
	} {
		if _, err := Statement(c.v, c.docs); !errors.Is(err, ErrBadPackSet) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for n, s := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadPackDirIsBoundedAndFailsClosed(t *testing.T) {
	if _, err := ReadPackDir(filepath.Join(t.TempDir(), "none")); !errors.Is(err, ErrNoPackDir) {
		t.Fatalf("missing dir: %v", err)
	}
	readme := t.TempDir()
	writeFiles(t, readme, map[string]string{"README.md": "packs go here"})
	if _, err := ReadPackDir(readme); !errors.Is(err, ErrNoPackDir) {
		t.Fatalf("a directory with only a README: %v", err)
	}
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"VERSION": "2026.11.1\n", "packs.minisig": "sig", "packs.list": "ignored", "README.md": "x", ".DS_Store": "finder", "CVE-2024-0001.json": "{}"})
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, filepath.Join(dir, "sub"), map[string]string{"CVE-2024-0009.json": "{}"})
	u, err := ReadPackDir(dir)
	if err != nil || u.Version != "2026.11.1" || string(u.Signature) != "sig" || len(u.Docs) != 1 || u.Docs[0].Name != "CVE-2024-0001.json" {
		t.Fatalf("read: %+v %v", u, err)
	}
	for name, edit := range map[string]func(d string){
		"no version":   func(d string) { _ = os.Remove(filepath.Join(d, "VERSION")) },
		"no signature": func(d string) { _ = os.Remove(filepath.Join(d, "packs.minisig")) },
		"stray file":   func(d string) { writeFiles(t, d, map[string]string{"run.sh": "x"}) },
		"big doc": func(d string) {
			writeFiles(t, d, map[string]string{"CVE-2024-0002.json": strings.Repeat(" ", maxDocBytes+1)})
		},
		"big sig": func(d string) {
			writeFiles(t, d, map[string]string{"packs.minisig": strings.Repeat("s", maxSigBytes+1)})
		},
		"link": func(d string) {
			if err := os.Symlink("/etc/hosts", filepath.Join(d, "CVE-2024-0003.json")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		d := t.TempDir()
		writeFiles(t, d, map[string]string{"VERSION": "1", "packs.minisig": "sig", "CVE-2024-0001.json": "{}"})
		edit(d)
		if _, err := ReadPackDir(d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
