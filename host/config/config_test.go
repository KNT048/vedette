package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/config"
)

const good = `# written by the installer
core_uid = 10001
core_gid = 10002
sensor_uid = 10003
sensor_gid = 10004
core_unit = vedette-core.service
socket = /run/vedette/host.sock
socket_gid=10002
`

func TestParse(t *testing.T) {
	t.Parallel()
	c, err := config.Parse(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	want := config.Config{CoreUID: 10001, CoreGID: 10002, SensorUID: 10003, SensorGID: 10004, CoreUnit: "vedette-core.service", Socket: "/run/vedette/host.sock", SocketGID: 10002}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

// The sensor ids are optional as a pair: the host starts without them, and only the units that
// need them answer host_conf_incomplete (D-123).
func TestParseSensorIdsAreOptionalAsAPair(t *testing.T) {
	t.Parallel()
	bare := strings.Replace(strings.Replace(good, "sensor_uid = 10003\n", "", 1), "sensor_gid = 10004\n", "", 1)
	c, err := config.Parse(strings.NewReader(bare))
	if err != nil || c.SensorUID != 0 || c.SensorGID != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParseCoreCgroup(t *testing.T) {
	t.Parallel()
	c, err := config.Parse(strings.NewReader(good + "core_cgroup = /user.slice/user-990.slice/user@990.service/app.slice/vedette-core.service\n"))
	if err != nil || c.CoreCgroup != "/user.slice/user-990.slice/user@990.service/app.slice/vedette-core.service" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParseCoreData(t *testing.T) {
	t.Parallel()
	c, err := config.Parse(strings.NewReader(good + "core_data = /var/lib/vedette\n"))
	if err != nil || c.CoreData != "/var/lib/vedette" {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err = config.Parse(strings.NewReader(good)); err != nil || c.CoreData != "" {
		t.Fatalf("core_data is optional: %+v %v", c, err)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"empty":              "",
		"missing key":        "core_uid=1\ncore_gid=1\ncore_unit=a.service\nsocket=/x/y\n",
		"only sensor_uid":    strings.Replace(good, "sensor_gid = 10004\n", "", 1),
		"only sensor_gid":    strings.Replace(good, "sensor_uid = 10003\n", "", 1),
		"core_gid not sock":  strings.Replace(good, "socket_gid=10002", "socket_gid=990", 1),
		"sensor_uid is 0":    strings.Replace(good, "10003", "0", 1),
		"sensor_gid is 0":    strings.Replace(good, "10004", "0", 1),
		"sensor_uid is core": strings.Replace(good, "10003", "10001", 1),
		"sensor_gid is core": strings.Replace(good, "10004", "10002", 1),
		"hex sensor_uid":     strings.Replace(good, "10003", "0x10", 1),
		"sensor_uid repeats": good + "sensor_uid = 5\n",
		"missing core_gid":   strings.Replace(good, "core_gid = 10002\n", "", 1),
		"core_gid repeated":  good + "core_gid = 5\n",
		"negative core_gid":  strings.Replace(good, "10002", "-1", 1),
		"hex core_gid":       strings.Replace(good, "10002", "0x10", 1),
		"empty core_gid":     strings.Replace(good, "10002", "", 1),
		"unknown key":        good + "extra = 1\n",
		"duplicate":          good + "core_uid = 5\n",
		"root uid":           strings.Replace(good, "10001", "0", 1),
		"negative uid":       strings.Replace(good, "10001", "-1", 1),
		"huge uid":           strings.Replace(good, "10001", "99999999999999999999", 1),
		"hex uid":            strings.Replace(good, "10001", "0x10", 1),
		"unit not service":   strings.Replace(good, "vedette-core.service", "vedette-core.socket", 1),
		"unit with slash":    strings.Replace(good, "vedette-core.service", "../x.service", 1),
		"unit with space":    strings.Replace(good, "vedette-core.service", "a b.service", 1),
		"relative socket":    strings.Replace(good, "/run/vedette/host.sock", "run/host.sock", 1),
		"dotdot socket":      strings.Replace(good, "/run/vedette/host.sock", "/run/../etc/host.sock", 1),
		"double slash":       strings.Replace(good, "/run/vedette/host.sock", "/run//host.sock", 1),
		"trailing slash":     strings.Replace(good, "/run/vedette/host.sock", "/run/vedette/", 1),
		"long socket":        strings.Replace(good, "/run/vedette/host.sock", "/"+strings.Repeat("a", 120), 1),
		"no equals":          good + "garbage\n",
		"bad key chars":      good + "Core-Uid = 1\n",
		"too large":          good + "# " + strings.Repeat("x", config.MaxSize) + "\n",
		"nul in value":       strings.Replace(good, "10001", "1\x0000", 1),
		"socket is root":     strings.Replace(good, "/run/vedette/host.sock", "/", 1),
		"empty value":        strings.Replace(good, "10001", "", 1),
		"cgroup relative":    good + "core_cgroup = system.slice/x\n",
		"cgroup dotdot":      good + "core_cgroup = /a/../b\n",
		"cgroup repeated":    good + "core_cgroup = /a\ncore_cgroup = /b\n",
		"core_data relative": good + "core_data = var/lib/vedette\n",
		"core_data dotdot":   good + "core_data = /var/lib/../../etc\n",
		"core_data root":     good + "core_data = /\n",
		"core_data trailing": good + "core_data = /var/lib/vedette/\n",
		"core_data double":   good + "core_data = /var//lib\n",
		"core_data repeated": good + "core_data = /a\ncore_data = /b\n",
		"core_data long":     good + "core_data = /" + strings.Repeat("a", 220) + "\n",
		"core_data empty":    good + "core_data =\n",
		"inline comment":     strings.Replace(good, "10001", "10001 # core", 1),
		"yaml-ish":           "core_uid: 1\n",
		"newline in socket":  strings.Replace(good, "/run/vedette/host.sock", "/run/a\rb", 1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse(strings.NewReader(in))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoadChecksFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(good), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	me := os.Getuid()
	if _, err := config.Load(write("ok.conf", 0o640), me); err != nil {
		t.Fatalf("0640 file: %v", err)
	}
	for _, mode := range []os.FileMode{0o660, 0o666, 0o602} {
		if _, err := config.Load(write("bad.conf", mode), me); !errors.Is(err, config.ErrInvalid) {
			t.Errorf("mode %o: err = %v", mode, err)
		}
	}
	if _, err := config.Load(write("owner.conf", 0o600), me+1); !errors.Is(err, config.ErrInvalid) {
		t.Errorf("wrong owner: err = %v", err)
	}
	if _, err := config.Load(dir, me); err == nil {
		t.Error("a directory was accepted")
	}
	if _, err := config.Load(filepath.Join(dir, "missing"), me); err == nil {
		t.Error("a missing file was accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(good)
	f.Add("core_uid = 1\ncore_gid = 1\n")
	f.Add("\x00\n=\n===")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := config.Parse(strings.NewReader(s))
		if err != nil {
			return
		}
		if c.CoreUID <= 0 || c.CoreGID < 0 || c.SocketGID < 0 || c.CoreUnit == "" || config.ValidSocketPath(c.Socket) != nil {
			t.Fatalf("accepted an unsafe config: %+v", c)
		}
	})
}
