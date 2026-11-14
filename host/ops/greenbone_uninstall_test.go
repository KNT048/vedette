package ops_test

import (
	"os"
	"strings"
	"testing"
)

// D-529 (FULL-2): install.sh --uninstall never touches OpenVAS. Vedette's part of it is only the two compose files of the package (dpkg
// removes them with vedette-host); the project greenbone-community-edition, its containers, volumes and images, the compose provider
// package, podman's API socket and /run/vedette-greenbone are left as they are. Nothing of the uninstall section of install.sh may name
// them, so no later edit removes them by accident. The W4-1 guard keeps podman while they are there
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
	section := strings.ToLower(s[i:j])
	for _, banned := range []string{
		"greenbone-community-edition", "registry.community.greenbone.net", "community/", "compose", "_data_vol", "_socket_vol",
		"/run/vedette-greenbone", "podman.socket", "/usr/lib/vedette/greenbone", "volume prune", "system prune", "image prune",
	} {
		if strings.Contains(section, banned) {
			t.Errorf("the uninstall section of install.sh names %q: it must leave OpenVAS's project alone (D-529)", banned)
		}
	}
}
