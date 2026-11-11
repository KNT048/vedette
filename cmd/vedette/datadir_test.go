package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestTightenDataDir(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name       string
		from, want os.FileMode
	}{
		{"0755 becomes 0750", 0o755, 0o750},
		{"0777 becomes 0750", 0o777, 0o750},
		{"0750 stays", 0o750, 0o750},
		{"0700 stays", 0o700, 0o700},
		{"0705 becomes 0700", 0o705, 0o700},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, c.from); err != nil {
				t.Fatal(err)
			}
			tightenDataDir(dir, log)
			fi, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != c.want {
				t.Errorf("mode %v, want %v", fi.Mode().Perm(), c.want)
			}
		})
	}
	tightenDataDir(filepath.Join(t.TempDir(), "missing"), log) // no panic, nothing created
}
