package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// testUID is the owner the cases use: the current user, or 65532 (the container user) when the tests run as root, because the function
// never acts for uid 0. As root the directories are chowned to it.
func testUID() int {
	if os.Geteuid() == 0 {
		return 65532
	}
	return os.Geteuid()
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, testUID(), testUID()); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestTightenDataDir(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	me := testUID()
	cases := []struct {
		name       string
		from, want os.FileMode
	}{
		{"0755 becomes 0750", 0o755, 0o750},
		{"0777 becomes 0750", 0o777, 0o750},
		{"0750 stays", 0o750, 0o750},
		{"0700 stays", 0o700, 0o700},
		{"0705 becomes 0700", 0o705, 0o700},
		{"setgid is kept", os.ModeSetgid | 0o775, os.ModeSetgid | 0o750},
		{"sticky is kept", os.ModeSticky | 0o777, os.ModeSticky | 0o750},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			mkdirMode(t, dir, c.from)
			tightenDataDir(dir, dir, me, log)
			fi, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSticky | os.ModeSetuid); got != c.want {
				t.Errorf("mode %v, want %v", got, c.want)
			}
		})
	}

	mode := func(p string) os.FileMode {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	t.Run("not owned is untouched", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "data")
		mkdirMode(t, dir, 0o777)
		tightenDataDir(dir, dir, me+1, log)
		if got := mode(dir); got != 0o777 {
			t.Errorf("mode %v, want 0777", got)
		}
	})
	t.Run("root is never acted on", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs a directory really owned by uid 0: run as root")
		}
		dir := filepath.Join(t.TempDir(), "data") // owned by uid 0, not chowned
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		wide := os.FileMode(0o777)
		if err := os.Chmod(dir, wide); err != nil {
			t.Fatal(err)
		}
		tightenDataDir(dir, dir, 0, log)
		if got := mode(dir); got != 0o777 {
			t.Errorf("mode %v, want 0777", got)
		}
	})
	t.Run("a directory other than the data dir is untouched", func(t *testing.T) {
		root := t.TempDir()
		data, other := filepath.Join(root, "data"), filepath.Join(root, "other")
		mkdirMode(t, data, 0o755)
		mkdirMode(t, other, 0o777)
		tightenDataDir(other, data, me, log)
		if got := mode(other); got != 0o777 {
			t.Errorf("other: mode %v, want 0777", got)
		}
		if got := mode(data); got != 0o755 {
			t.Errorf("data: mode %v, want 0755", got)
		}
	})
	t.Run("a symlink is untouched", func(t *testing.T) {
		root := t.TempDir()
		target, link := filepath.Join(root, "target"), filepath.Join(root, "link")
		mkdirMode(t, target, 0o777)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		tightenDataDir(link, link, me, log)
		if got := mode(target); got != 0o777 {
			t.Errorf("target: mode %v, want 0777", got)
		}
	})
	t.Run("a missing directory is not created", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		tightenDataDir(missing, missing, me, log)
		if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stat err %v, want not exist", err)
		}
	})
}
