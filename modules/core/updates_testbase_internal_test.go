package core

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// The test-channel release source (#469): honoured only by a -test. build, only for a private or loopback http(s) address.
func TestReleaseBaseTestChannel(t *testing.T) {
	const lan = "http://172.30.77.1:5078/release"
	dir := t.TempDir()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, testBaseFile), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(version, base, data string) *OSHandlers {
		h := &OSHandlers{log: slog.New(slog.DiscardHandler)}
		h.upd = updCheck{version: version, base: base, dataDir: data}
		return h
	}
	write(lan + "\n")
	for _, c := range []struct {
		name, version, base, data, want string
	}{
		{"test build honours the file", "0.0.1-test.1", DefaultReleaseBase, dir, lan},
		{"release version ignores it", "0.1.0", DefaultReleaseBase, dir, DefaultReleaseBase},
		{"other prerelease ignores it", "0.1.0-rc.1", DefaultReleaseBase, dir, DefaultReleaseBase},
		{"dev build ignores it", "0.0.0-dev", DefaultReleaseBase, dir, DefaultReleaseBase},
		{"configured base wins", "0.0.1-test.1", "http://127.0.0.1:9", dir, "http://127.0.0.1:9"},
		{"no data dir", "0.0.1-test.1", DefaultReleaseBase, "", DefaultReleaseBase},
		{"no file", "0.0.1-test.1", DefaultReleaseBase, t.TempDir(), DefaultReleaseBase},
	} {
		if got := mk(c.version, c.base, c.data).releaseBase(); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	for _, bad := range []string{"https://example.com/x", "http://8.8.8.8:5078", "ftp://172.30.1.1", "http://172.30.1.1/x/", "http://172.30.1.1/?a=b", "http://u@172.30.1.1", "172.30.1.1", ""} {
		write(bad)
		if got := mk("0.0.1-test.1", DefaultReleaseBase, dir).releaseBase(); got != DefaultReleaseBase {
			t.Errorf("%q was accepted: %q", bad, got)
		}
	}
}
