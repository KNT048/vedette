package ops

import (
	"os"
	"os/exec" //nolint:depguard // the test runs install.sh's own sh function with a fixed argv; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
)

// D-316 (9): what recordAddedPackages writes is what install.sh --uninstall reads. The sh function by_us_packages of
// install.sh runs on a host state written by the Go code: both lists, merged, sorted, only valid package names, and
// the host's list ignored when it is a link.
func TestInstallShUninstallReadsTheListTheHostWrites(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "\nHOST_STATE="+suState+"\n") {
		t.Fatalf("install.sh does not set HOST_STATE=%s", suState)
	}
	i := strings.Index(s, "\nby_us_packages() {\n")
	if i < 0 {
		t.Fatal("no by_us_packages in install.sh")
	}
	j := strings.Index(s[i+1:], "\n}\n")
	if j < 0 {
		t.Fatal("by_us_packages has no end")
	}
	fn := "set -eu\n" + s[i+1:i+1+j+2] + "\n"

	run := func(state, host string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), "sh", "-c", fn+`STATE=$1 HOST_STATE=$2 by_us_packages`, "sh", state, host).Output() //nolint:gosec // the sh function of install.sh under test; the paths are $1 and $2
		if err != nil {
			t.Fatalf("by_us_packages: %v", err)
		}
		return string(out)
	}

	state, host := t.TempDir(), t.TempDir()
	if got := run(state, host); got != "" {
		t.Fatalf("no list: %q", got)
	}
	o := &Ops{cfg: Config{StateDir: host}}
	if err := os.MkdirAll(suDir(host), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := o.recordAddedPackages([]string{"conntrack", "libnetfilter-cttimeout1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "installed-by-us"), []byte("podman\nconntrack\nNot A Name\n../x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := run(state, host), "conntrack\nlibnetfilter-cttimeout1\npodman\n"; got != want {
		t.Fatalf("by_us_packages %q, want %q", got, want)
	}

	hostList := filepath.Join(suDir(host), suAddedName)
	other := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(other, []byte("openssh-server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hostList); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, hostList); err != nil {
		t.Fatal(err)
	}
	if got := run(state, host); got != "conntrack\npodman\n" {
		t.Fatalf("a link in place of the host's list was read: %q", got)
	}
}
