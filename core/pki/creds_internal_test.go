package pki

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
)

// L3 of the SP-1 review: a directory that was checked is compared, once opened, with the one that was checked
// (os.SameFile). A directory swapped in between (the volume is shared with a container under attack) is refused, not
// followed. These tests set a package hook that runs in the gap, so they are not parallel.
func TestAnOpenedDirectoryIsTheOneThatWasChecked(t *testing.T) {
	defer func() { testHookAfterDirCheck = nil }()
	data := []byte("bundle")
	mk := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "creds")
		if err := os.MkdirAll(filepath.Join(d, "passive"), 0o750); err != nil {
			t.Fatal(err)
		}
		return d
	}
	entries := func(t *testing.T, d string) int {
		t.Helper()
		e, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		return len(e)
	}
	t.Run("the creds directory is replaced after the check", func(t *testing.T) {
		d := mk(t)
		swapped := filepath.Join(filepath.Dir(d), "swapped")
		calls := 0
		testHookAfterDirCheck = func() {
			calls++
			if calls != 1 {
				return
			}
			if err := os.Rename(d, d+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(swapped, "passive"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(swapped, d); err != nil { // another real directory under the same name
				t.Fatal(err)
			}
		}
		if err := WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, ErrCredsPath) {
			t.Fatalf("err = %v, want ErrCredsPath", err)
		}
		if n := entries(t, filepath.Join(d, "passive")); n != 0 {
			t.Errorf("something was written into the directory that was swapped in: %d entries", n)
		}
	})
	t.Run("the role directory is replaced after the check", func(t *testing.T) {
		d := mk(t)
		calls := 0
		testHookAfterDirCheck = func() {
			calls++
			if calls != 2 { // 1: after the creds directory check, 2: after the role directory check
				return
			}
			if err := os.Rename(filepath.Join(d, "passive"), filepath.Join(d, "passive.moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(d, "passive"), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		if err := WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, ErrCredsPath) {
			t.Fatalf("err = %v, want ErrCredsPath", err)
		}
		if n := entries(t, filepath.Join(d, "passive")); n != 0 {
			t.Errorf("something was written into the directory that was swapped in: %d entries", n)
		}
	})
	t.Run("nothing swapped: it works", func(t *testing.T) {
		testHookAfterDirCheck = nil
		d := mk(t)
		if err := WriteBundle(d, sensorlink.Passive, data); err != nil {
			t.Fatal(err)
		}
	})
}
