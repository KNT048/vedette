package ops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-529 (FULL-2): install.sh --uninstall never touches OpenVAS. Vedette's part of it is only the two compose files of the package (dpkg
// removes them with vedette-host) and podman's API socket when vedette-host enabled it; the project greenbone-community-edition, its
// containers, volumes and images, the compose provider package and /run/vedette-greenbone are left as they are. Nothing of the
// uninstall section of install.sh may name them, so no later edit removes them by accident, and it never suggests wiping podman's
// storage (review r1 L5: podman system reset deletes OpenVAS's volumes). The W4-1 guard keeps podman while they are there
// (TestInstallSh_UninstallKeepsAPodmanThatHoldsOthers, case "OpenVAS of greenbone.up").
func TestInstallSh_UninstallNeverNamesOpenVAS(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "\n# ---- uninstall ---")
	j := strings.Index(s, "\ncase $MODE in\n")
	if i < 0 || j < i || !strings.Contains(s[i:j], "\ndo_uninstall() {\n") {
		t.Fatal("install.sh has no uninstall section ending before the mode switch")
	}
	section := strings.ToLower(strings.Replace(s[i:j], installShFunc(t, "remove_podman_socket"), "", 1))
	for _, banned := range []string{
		"greenbone-community-edition", "registry.community.greenbone.net", "community/", "compose", "_data_vol", "_socket_vol",
		"/run/vedette-greenbone", "podman.socket", "/usr/lib/vedette/greenbone", "volume prune", "system prune", "image prune",
		"system reset", "volume rm",
	} {
		if strings.Contains(section, banned) {
			t.Errorf("the uninstall section of install.sh names %q: it must leave OpenVAS's project alone (D-529)", banned)
		}
	}
}

// review r1 L5: the uninstall disables podman.socket only when vedette-host's marker says vedette-host enabled it.
func TestInstallSh_UninstallDisablesPodmanSocketOnlyWhenVedetteEnabledIt(t *testing.T) {
	t.Parallel()
	for _, marked := range []bool{true, false} {
		dir, host := t.TempDir(), t.TempDir()
		if marked {
			if err := os.WriteFile(filepath.Join(host, "greenbone-podman-socket.enabled"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		fakeProgram(t, dir, "systemctl", `echo "$*" >>"$FAKE/calls"`+"\n")
		out, err := runInstallShFns(t, dir, []string{"FAKE=" + dir, "HOST_STATE=" + host}, []string{"remove_podman_socket"}, "remove_podman_socket")
		if err != nil {
			t.Fatalf("remove_podman_socket: %v\n%s", err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: a file of the test's own temp dir
		if want := map[bool]string{true: "disable --now podman.socket\n", false: ""}[marked]; string(calls) != want {
			t.Errorf("marker %v: systemctl calls %q, want %q", marked, calls, want)
		}
		if _, err := os.Stat(filepath.Join(host, "greenbone-podman-socket.enabled")); err == nil {
			t.Errorf("marker %v: the marker is still there", marked)
		}
	}
}
