package pki_test

import (
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/pki"
	"github.com/knt048/vedette/core/sensorlink"
)

func pemDecode(b []byte) []byte {
	blk, _ := pem.Decode(b)
	return blk.Bytes
}

func bigFromHex(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatal(s)
	}
	return n
}

// withTimeout fails a test that hangs (a FIFO at the name must be refused, not opened).
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("hangs")
	}
}

// the writer needs only bytes: any bundle will do
func someBundle(t *testing.T) []byte {
	t.Helper()
	e := newEnv(t)
	a := e.open(t)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "passive", pki.BundleName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// D-110 (4): the writer refuses a symlink, a FIFO or a directory at the name and a symlinked directory on the way, writes
// nothing through them, and leaves what was there alone.
func TestWriteBundleRefusesWhatItShouldNotTouch(t *testing.T) {
	t.Parallel()
	data := someBundle(t)
	plant := func(t *testing.T, dir string, f func(top, role string, victim string)) (victim string) {
		t.Helper()
		victim = filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
			t.Fatal(err)
		}
		f(dir, filepath.Join(dir, "passive"), victim)
		return victim
	}
	mk := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "creds")
		if err := os.MkdirAll(filepath.Join(d, "passive"), 0o750); err != nil {
			t.Fatal(err)
		}
		return d
	}
	untouched := func(t *testing.T, victim string) {
		t.Helper()
		if b, err := readFile(victim); err != nil || string(b) != "do not touch" {
			t.Errorf("the file behind the link was touched: %q %v", b, err)
		}
	}
	t.Run("symlink at the name", func(t *testing.T) {
		d := mk(t)
		victim := plant(t, d, func(_, role, v string) { _ = os.Symlink(v, filepath.Join(role, pki.BundleName)) })
		if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
		untouched(t, victim)
		if fi, err := os.Lstat(filepath.Join(d, "passive", pki.BundleName)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Error("the planted link was replaced instead of refused")
		}
	})
	t.Run("dangling symlink at the name", func(t *testing.T) {
		d := mk(t)
		_ = os.Symlink(filepath.Join(t.TempDir(), "nowhere"), filepath.Join(d, "passive", pki.BundleName))
		if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
	})
	t.Run("FIFO at the name", func(t *testing.T) {
		d := mk(t)
		if err := syscall.Mkfifo(filepath.Join(d, "passive", pki.BundleName), 0o600); err != nil {
			t.Fatal(err)
		}
		withTimeout(t, 5*time.Second, func() {
			if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
				t.Errorf("err = %v, want ErrCredsPath", err)
			}
		})
	})
	t.Run("directory at the name", func(t *testing.T) {
		d := mk(t)
		if err := os.Mkdir(filepath.Join(d, "passive", pki.BundleName), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
	})
	t.Run("symlinked role directory", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "creds")
		_ = os.MkdirAll(d, 0o750)
		out := t.TempDir()
		_ = os.Symlink(out, filepath.Join(d, "passive"))
		if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
		if ents, _ := os.ReadDir(out); len(ents) != 0 {
			t.Errorf("wrote through the symlinked directory: %v", ents)
		}
	})
	t.Run("role directory is a file", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "creds")
		_ = os.MkdirAll(d, 0o750)
		_ = os.WriteFile(filepath.Join(d, "passive"), []byte("x"), 0o600)
		if err := pki.WriteBundle(d, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
	})
	t.Run("symlinked creds directory", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "creds")
		_ = os.Symlink(target, link)
		if err := pki.WriteBundle(link, sensorlink.Passive, data); !errors.Is(err, pki.ErrCredsPath) {
			t.Errorf("err = %v, want ErrCredsPath", err)
		}
		if ents, _ := os.ReadDir(target); len(ents) != 0 {
			t.Errorf("wrote through the symlinked creds directory: %v", ents)
		}
	})
	t.Run("creds path is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "creds")
		_ = os.WriteFile(f, nil, 0o600)
		if err := pki.WriteBundle(f, sensorlink.Passive, data); err == nil {
			t.Error("a regular file as the creds directory was accepted")
		}
	})
	t.Run("a role that is not a role", func(t *testing.T) {
		d := mk(t)
		for _, r := range []sensorlink.Role{"", "..", "../x", "passive/../active", "server", "PASSIVE"} {
			if err := pki.WriteBundle(d, r, data); err == nil {
				t.Errorf("role %q accepted", r)
			}
		}
		if ents, _ := os.ReadDir(filepath.Dir(d)); len(ents) != 1 {
			t.Errorf("something was made beside the creds directory: %v", ents)
		}
	})
}

func TestWriteBundleWritesAndReplaces(t *testing.T) {
	t.Parallel()
	data := someBundle(t)
	d := filepath.Join(t.TempDir(), "creds") // does not exist yet: made
	if err := pki.WriteBundle(d, sensorlink.Active, data); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "active", pki.BundleName)
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o640 || fi.Size() != int64(len(data)) {
		t.Fatalf("%v %v", fi, err)
	}
	// replacing an existing file works and leaves no temporary file behind
	again := append(append([]byte(nil), data...), '\n')
	if err := pki.WriteBundle(d, sensorlink.Active, again); err != nil {
		t.Fatal(err)
	}
	if b, _ := readFile(p); len(b) != len(again) {
		t.Error("the file was not replaced")
	}
	if ents, _ := os.ReadDir(filepath.Join(d, "active")); len(ents) != 1 {
		t.Errorf("left over: %v", ents)
	}
	// a file that was left 0600 comes out 0640 again
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteBundle(d, sensorlink.Active, data); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
}

// D-110 (4): the file is replaced by a rename, so a reader that opens it at any moment sees one whole bundle, never half of
// one (the sensor's reader tolerates a half file too, see sensorlink tests; this is the writer's side).
func TestAHalfWrittenBundleIsNeverVisible(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.dir, "passive", pki.BundleName)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	reads := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := readFile(p)
			if err != nil {
				select {
				case bad <- "read: " + err.Error():
				default:
				}
				return
			}
			reads++
			if _, err := sensorlink.ParseBundle(b); err != nil {
				select {
				case bad <- "parse: " + err.Error():
				default:
				}
				return
			}
		}
	}()
	for range 150 {
		e.clk.Advance(time.Second)
		if err := a.Start(t.Context(), e.dir); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case m := <-bad:
		t.Fatalf("a reader saw a bad bundle after %d reads: %s", reads, m)
	default:
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Errorf("left over: %v", ents)
	}
}
