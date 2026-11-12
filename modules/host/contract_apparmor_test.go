package host_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
)

// The containers' AppArmor profile at host start (D-458): every unit selects vedette-container and Podman refuses a container
// whose named profile is not loaded, core's included. Where AppArmor is on and the kernel does not list the profile, Start loads
// it with the one fixed apparmor_parser argv, unless an administrator disabled it or the file is gone, and audits the outcome;
// it never blocks the start.

func TestContract_AppArmor_StartLoadsAMissingProfileOnce(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.AppArmor("crun (unconfined)", "containers-default-0.57.4-apparmor1 (enforce)")
	rec := e.startHost(t)
	if c := e.m.Calls(ops.BinAppArmorParser); len(c) != 1 || !slices.Equal(c[0], ops.AppArmorLoadArgs()) {
		t.Fatalf("apparmor_parser calls %q, want one %q", c, ops.AppArmorLoadArgs())
	}
	if !slices.Equal(ops.AppArmorLoadArgs(), []string{"--replace", "--skip-read-cache", "--write-cache", "/etc/apparmor.d/vedette-container"}) {
		t.Errorf("argv %q", ops.AppArmorLoadArgs())
	}
	if txt := rec.text(); strings.Count(txt, `container.start apparmor_profile_loaded {"profile":"vedette-container"}`) != 1 || strings.Contains(txt, "apparmor_profile_missing") {
		t.Errorf("audit: %s", txt)
	}
}

func TestContract_AppArmor_ALoadedProfileInAnyModeIsLeftAlone(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"enforce", "complain"} {
		e := startCtr(t)
		e.m.AppArmor("crun (unconfined)", "vedette-container ("+mode+")")
		rec := e.startHost(t)
		if c := e.m.Calls(ops.BinAppArmorParser); len(c) != 0 || strings.Contains(rec.text(), "apparmor_profile") {
			t.Errorf("%s: calls %q, audit %s", mode, c, rec.text())
		}
	}
}

func TestContract_AppArmor_OffMeansNothing(t *testing.T) {
	t.Parallel()
	e := startCtr(t)
	e.m.AppArmor()
	e.m.WriteRoot("sys/module/apparmor/parameters/enabled", "N\n")
	rec := e.startHost(t)
	if c := e.m.Calls(ops.BinAppArmorParser); len(c) != 0 || strings.Contains(rec.text(), "apparmor_profile") {
		t.Errorf("AppArmor off: calls %q, audit %s", c, rec.text())
	}
	// a machine without the module parameter at all (no AppArmor in the kernel) is the same
	e2 := startCtr(t)
	rec2 := e2.startHost(t)
	if c := e2.m.Calls(ops.BinAppArmorParser); len(c) != 0 || strings.Contains(rec2.text(), "apparmor_profile") {
		t.Errorf("no AppArmor: calls %q, audit %s", c, rec2.text())
	}
}

// Each way the profile stays missing is one audit line with its reason, no load where loading would be wrong, and the start goes on.
func TestContract_AppArmor_MissingReasonsAreAuditedAndNeverBlockTheStart(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		reason string
		setup  func(e *ctrEnv)
		loads  bool
	}{
		{"disabled", func(e *ctrEnv) { e.m.WriteRoot("etc/apparmor.d/disable/vedette-container", "") }, false},
		{"file_missing", func(e *ctrEnv) { e.m.RemoveRoot("etc/apparmor.d/vedette-container") }, false},
		{"profiles_unreadable", func(e *ctrEnv) { e.m.RemoveRoot("sys/kernel/security/apparmor/profiles") }, false},
		{"parser_missing", func(e *ctrEnv) { _ = os.Remove(filepath.Join(e.m.Bin, ops.BinAppArmorParser)) }, false},
		{"load_failed", func(e *ctrEnv) {
			e.m.RuleText(ops.BinAppArmorParser, "--replace", "AppArmor parser error\n", 1, "", "")
		}, true},
		{"not_listed_after_load", func(e *ctrEnv) { e.m.Mark("aa-noload", true) }, true},
	} {
		e := startCtr(t)
		e.m.AppArmor("crun (unconfined)")
		tc.setup(e)
		rec := e.startHost(t)
		if got := len(e.m.Calls(ops.BinAppArmorParser)); (got == 1) != tc.loads || got > 1 {
			t.Errorf("%s: %d apparmor_parser calls, want a load %t", tc.reason, got, tc.loads)
		}
		txt := rec.text()
		if strings.Count(txt, `container.start apparmor_profile_missing {"profile":"vedette-container","reason":"`+tc.reason+`"}`) != 1 || strings.Contains(txt, "apparmor_profile_loaded") {
			t.Errorf("%s: audit %s", tc.reason, txt)
		}
		// the start went on: the host's own later steps ran (it reads core's container state over the socket)
		if _, err := e.h.Client.StateContainers(t.Context()); err != nil {
			t.Errorf("%s: the host does not answer after start: %v", tc.reason, err)
		}
	}
}

// The runner's grammar: exactly the one argv, never another file, never a removal or a profile from stdin.
func TestContract_AppArmor_ParserGrammarIsOneArgv(t *testing.T) {
	t.Parallel()
	if err := ops.ValidateAppArmorParser(ops.AppArmorLoadArgs()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		{"--replace", "--write-cache", "/etc/apparmor.d/vedette-container"}, {"-R", "/etc/apparmor.d/vedette-container"},
		{"--replace", "--skip-read-cache", "--write-cache", "/etc/apparmor.d/other"}, {"--replace", "--skip-read-cache", "--write-cache"},
		{"--replace", "--skip-read-cache", "--write-cache", "/etc/apparmor.d/vedette-container", "/etc/apparmor.d/x"}, {"--replace"}, {},
	} {
		if ops.ValidateAppArmorParser(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
