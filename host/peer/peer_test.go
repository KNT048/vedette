package peer_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/peer"
)

const (
	unit   = "vedette-core.service"
	anchor = "/system.slice/vedette-core.service"
)

func TestInUnit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"unit cgroup", "0::/system.slice/vedette-core.service\n", true},
		{"quadlet container scope", "0::/system.slice/vedette-core.service/libpod-payload-0123abcd\n", true},
		{"no trailing newline", "0::/system.slice/vedette-core.service", true},
		// Review M2: the unit name somewhere else in the path must not match.
		{"user manager subtree", "0::/user.slice/user-10001.slice/user@10001.service/app.slice/vedette-core.service\n", false},
		{"nested inside another unit", "0::/system.slice/vedette-scan.service/libpod-payload-abc/vedette-core.service\n", false},
		{"newline injected into a dir name", "0::/system.slice/evil.service/vedette-core.service\n1:x:y\n", false},
		{"second line spoofs the unit", "0::/user.slice/x\n0::/system.slice/vedette-core.service\n", false},
		{"spoof line after a v1 line", "1:name=systemd:/a\n0::/system.slice/vedette-core.service\n", false},
		{"hybrid v1 lines are refused", "12:pids:/other\n0::/system.slice/vedette-core.service\n", false},
		{"other unit", "0::/system.slice/vedette-sensor.service\n", false},
		{"prefix of unit", "0::/system.slice/vedette-core.service.d\n", false},
		{"suffix of unit", "0::/system.slice/xvedette-core.service\n", false},
		{"sibling with same prefix", "0::/system.slice/vedette-core.service-b/x\n", false},
		{"same uid other process", "0::/user.slice/user-1000.slice/session-3.scope\n", false},
		{"root cgroup", "0::/\n", false},
		{"v1 only", "1:name=systemd:/system.slice/vedette-core.service\n", false},
		{"dotdot", "0::/system.slice/vedette-core.service/../evil\n", true}, // the kernel never prints "..": prefix rule still holds
		{"deleted", "0::/system.slice/vedette-core.service (deleted)\n", false},
		{"relative path", "0::system.slice/vedette-core.service\n", false},
		{"empty", "", false},
		{"garbage", "hello", false},
		{"nul", "0::/system.slice/vedette-core.service\x00\n", false},
		{"tab", "0::/system.slice/vedette-core.service/a\tb\n", false},
		{"oversized", "0::/system.slice/vedette-core.service/" + strings.Repeat("a", 70<<10) + "\n", false},
		{"controllers on unified id", "0:cpu:/system.slice/vedette-core.service\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := peer.InUnit([]byte(tt.data), anchor); got != tt.want {
				t.Fatalf("InUnit(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
	// A custom anchor (rootless core under a user manager) is exact too.
	user := "/user.slice/user-990.slice/user@990.service/app.slice/vedette-core.service"
	if !peer.InUnit([]byte("0::"+user+"/libpod-1\n"), user) || peer.InUnit([]byte("0::/system.slice/vedette-core.service\n"), user) {
		t.Error("custom anchor")
	}
	if peer.InUnit([]byte("0::/x\n"), "relative") || peer.InUnit([]byte("0::/x\n"), "/a/../x") {
		t.Error("an invalid anchor matched")
	}
}

func TestValidAnchor(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"/system.slice/vedette-core.service", "/a", "/user.slice/user-1.slice/user@1.service/app.slice/x.service"} {
		if err := peer.ValidAnchor(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/", "a/b", "/a/", "/a//b", "/a/../b", "/a/./b", "/a b", "/a\nb", "/a\x00", "/" + strings.Repeat("a", 300), "/a\x7f"} {
		if peer.ValidAnchor(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPidFromFdinfo(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int{"pos:\t0\nflags:\t02000002\nPid:\t4242\nNSpid:\t4242\n": 4242, "Pid: 7\n": 7} {
		if got, err := peer.PidFromFdinfo([]byte(in)); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Pid:\t-1\n", "Pid:\t0\n", "Pid:\tabc\n", "pos: 0\n"} {
		if _, err := peer.PidFromFdinfo([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestStartTicks(t *testing.T) {
	t.Parallel()
	stat := "4242 (my (weird) name) S 1 4242 4242 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 987654 12345 67 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	if got, err := peer.StartTicks([]byte(stat)); err != nil || got != 987654 {
		t.Fatalf("got %d %v", got, err)
	}
	for _, bad := range []string{"", "no paren", "1 (a) S 1 2", "1 (a) S" + strings.Repeat(" 1", 18) + " x"} {
		if _, err := peer.StartTicks([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDecideEachLayer(t *testing.T) {
	t.Parallel()
	good := func(int) ([]byte, error) { return []byte("0::/system.slice/vedette-core.service/libpod-1\n"), nil }
	other := func(int) ([]byte, error) { return []byte("0::/system.slice/ssh.service\n"), nil }
	fail := func(int) ([]byte, error) { return nil, errors.New("no such process") }
	tests := []struct {
		name string
		c    peer.Cred
		uid  int
		unit string
		read func(int) ([]byte, error)
		ok   bool
	}{
		{"all layers pass", peer.Cred{UID: 10001, PID: 42}, 10001, unit, good, true},
		{"layer 2: wrong uid", peer.Cred{UID: 1000, PID: 42}, 10001, unit, good, false},
		{"layer 2: root is not core", peer.Cred{UID: 0, PID: 42}, 10001, unit, good, false},
		{"layer 3: same uid, other cgroup", peer.Cred{UID: 10001, PID: 42}, 10001, unit, other, false},
		{"layer 3: cgroup unreadable", peer.Cred{UID: 10001, PID: 42}, 10001, unit, fail, false},
		{"no pid", peer.Cred{UID: 10001, PID: 0}, 10001, unit, good, false},
		{"misconfigured uid 0", peer.Cred{UID: 0, PID: 42}, 0, unit, good, false},
		{"misconfigured unit", peer.Cred{UID: 10001, PID: 42}, 10001, "", good, false},
		{"layer 3: spoofed path under another parent", peer.Cred{UID: 10001, PID: 42}, 10001, unit, func(int) ([]byte, error) {
			return []byte("0::/user.slice/user-10001.slice/vedette-core.service\n"), nil
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, err := peer.Decide(tt.c, tt.uid, tt.unit, "", tt.read)
			if tt.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, peer.ErrNotAllowed) {
				t.Fatalf("err = %v, want ErrNotAllowed", err)
			}
			if tt.ok && info.Unit != unit {
				t.Fatalf("info = %+v", info)
			}
			if !tt.ok && info.Unit != "" {
				t.Fatalf("denied peer carries a unit: %+v", info)
			}
		})
	}
}

func FuzzInUnit(f *testing.F) {
	f.Add("0::/system.slice/vedette-core.service\n")
	f.Add("12:pids:/a\n0::/b\n")
	f.Add("::\n:::\n0::\n0:\n")
	f.Fuzz(func(t *testing.T, s string) {
		if !peer.InUnit([]byte(s), anchor) {
			return
		}
		// Whatever matched is exactly one line "0::<anchor>" or "0::<anchor>/..." with no control characters.
		line := strings.TrimSuffix(s, "\n")
		path, ok := strings.CutPrefix(line, "0::")
		if !ok || (path != anchor && !strings.HasPrefix(path, anchor+"/")) || strings.ContainsAny(line, "\n\x00\t\r") {
			t.Fatalf("matched %q", s)
		}
	})
}

func FuzzStartTicks(f *testing.F) {
	f.Add("1 (a) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20\n")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = peer.StartTicks([]byte(s)) })
}
