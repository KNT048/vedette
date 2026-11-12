package main

import (
	"os"
	"os/exec" //nolint:depguard // test of a release artifact outside the product: runs install.sh's own sh function, fixed argv
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
)

// install.sh host_version_ok is the same rule as release.ParseHostPackageName (D-316): the sh function itself runs on each version.
func TestInstallShHostVersionRuleIsTheOneRule(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "\nhost_version_ok() {\n")
	if i < 0 {
		t.Fatal("no host_version_ok in install.sh")
	}
	j := strings.Index(s[i+1:], "\n}\n")
	if j < 0 {
		t.Fatal("host_version_ok has no end")
	}
	fn := s[i+1:i+1+j+2] + "\n"
	for _, v := range []string{
		"1.4.0", "0.2.0-rc.1", "0.0.1-test.1", "1.0.0-0a.1", "1.0.0-" + strings.Repeat("a", 32), "1.0.0-" + strings.Repeat("a", 33),
		"0.2.0-rc-1", "0.2.0~rc.1", "1.4.0+b1", "01.4.0", "1.4", "v1.4.0", "1.0.0-01", "1.0.0-rc..1", "1.0.0-", "1.0.0-rc.", "",
		"1.0.0 ", "1.0.0\n1.0.0", "1.0.0-a_b",
	} {
		_, _, want := release.ParseHostPackageName(release.HostPackageName(v, "amd64"))
		got := exec.CommandContext(t.Context(), "sh", "-c", fn+`host_version_ok "$1"`, "sh", v).Run() == nil //nolint:gosec // the sh function of install.sh under test; the version is $1, never part of the script
		if got != want {
			t.Errorf("%q: install.sh says %v, the Go rule %v", v, got, want)
		}
	}
}
