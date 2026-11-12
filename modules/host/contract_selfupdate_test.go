package host_test

import (
	"slices"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// host.self_update (D-316, spec 6.14), slice 2a. Check and Run up to the park are tested in
// host/ops/selfupdate_test.go and the validators in host/ops/selfupdate_internal_test.go; the command joins
// the registry, and the rows of INV-28, INV-30 and POST-5 their tests here, with slice 2b.

// FORBID-7 (second layer): os.install never upgrades vedette-host from the host's own cgroup, even when a
// mirror offered it (none does, D-81): the name is dropped from the host's own list.
func TestContract_FORBID7_OSInstallNeverUpgradesTheHostPackage(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.RuleText("apt-get", "dist-upgrade",
		"Inst vedette-host [1.3.0] (1.4.0 Vedette:24.04/noble-security [amd64])\nInst libc6 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates [amd64])\n", 0, "", "")
	e.m.Rule("apt-get", "update", "apt_update.txt", 0, "", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	e.ok(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"})
	var installs [][]string
	for _, c := range aptCalls(e) {
		if slices.Contains(c, "install") {
			installs = append(installs, c)
		}
	}
	if len(installs) != 1 || slices.Contains(installs[0], "vedette-host") || !slices.Contains(installs[0], "libc6") {
		t.Fatalf("apt-get install calls %q", installs)
	}
}
