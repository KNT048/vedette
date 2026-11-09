package peer_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/peer"
)

const unit = "vedette-core.service"

func TestInUnit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"unit cgroup", "0::/system.slice/vedette-core.service\n", true},
		{"quadlet container scope", "0::/system.slice/vedette-core.service/libpod-payload-0123abcd\n", true},
		{"user slice quadlet", "0::/user.slice/user-990.slice/user@990.service/app.slice/vedette-core.service\n", true},
		{"hybrid v1 lines ignored", "12:pids:/other\n1:name=systemd:/other\n0::/system.slice/vedette-core.service\n", true},
		{"no trailing newline", "0::/system.slice/vedette-core.service", true},
		{"other unit", "0::/system.slice/vedette-sensor.service\n", false},
		{"prefix of unit", "0::/system.slice/vedette-core.service.d\n", false},
		{"suffix of unit", "0::/system.slice/xvedette-core.service\n", false},
		{"substring in component", "0::/system.slice/a-vedette-core.service-b\n", false},
		{"same uid other process", "0::/user.slice/user-1000.slice/session-3.scope\n", false},
		{"root cgroup", "0::/\n", false},
		{"v1 only", "1:name=systemd:/system.slice/vedette-core.service\n", false},
		{"v1 line must not count", "1:name=systemd:/system.slice/vedette-core.service\n0::/user.slice\n", false},
		{"two unified lines", "0::/system.slice/vedette-core.service\n0::/x\n", false},
		{"dotdot", "0::/system.slice/../vedette-core.service\n", false},
		{"deleted", "0::/system.slice/vedette-core.service (deleted)\n", false},
		{"relative path", "0::system.slice/vedette-core.service\n", false},
		{"empty", "", false},
		{"garbage", "hello", false},
		{"nul", "0::/vedette-core.service\x00\n", false},
		{"oversized", "0::/" + strings.Repeat("a", 70<<10) + "/vedette-core.service\n", false},
		{"controllers on unified id", "0:cpu:/system.slice/vedette-core.service\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := peer.InUnit([]byte(tt.data), unit); got != tt.want {
				t.Fatalf("InUnit(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
	if peer.InUnit([]byte("0::/x/bad unit.service\n"), "bad unit.service") {
		t.Error("an invalid unit name matched")
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, err := peer.Decide(tt.c, tt.uid, tt.unit, tt.read)
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
		if !peer.InUnit([]byte(s), unit) {
			return
		}
		// Whatever matched must really contain the unit as a whole path component of a "0::" line.
		ok := false
		for _, line := range strings.Split(s, "\n") {
			if p, found := strings.CutPrefix(line, "0::"); found {
				for _, c := range strings.Split(p, "/") {
					if c == unit {
						ok = true
					}
				}
			}
		}
		if !ok || strings.Contains(s, "..") && strings.Contains(s, "/../") {
			t.Fatalf("matched without a unit component: %q", s)
		}
	})
}
