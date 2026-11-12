package host_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops/opstest"
)

// host.self_update (D-316, spec 6.14), slice 2a. Check and Run up to the park are tested in
// host/ops/selfupdate_test.go and the validators in host/ops/selfupdate_internal_test.go; the command joins
// the registry, and the rows of INV-28, INV-30 and POST-5 their tests here, with slice 2b.

// FORBID-7 (second layer): os.install never upgrades vedette-host from the host's own cgroup, even when a
// mirror offered it (none does, D-81): the name is dropped from the host's own list, with an architecture
// suffix too, and apt's validator refuses it.
func TestContract_FORBID7_OSInstallNeverUpgradesTheHostPackage(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.RuleText("apt-get", "dist-upgrade",
		"Inst vedette-host:amd64 [1.3.0] (1.4.0 Vedette:24.04/noble-security [amd64])\nInst libc6 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates [amd64])\n", 0, "", "")
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

// --- slice 2b: the applier, the settle loop and the host's own restart (opstest.SUWorld) -------------------

const (
	suFrom = "1.3.0"
	suTo   = "1.4.0"
)

func suFile(w *opstest.SUWorld, rel string) string {
	return filepath.Join(w.M.State, "selfupdate", rel)
}

func suExists(w *opstest.SUWorld, rel string) bool {
	_, err := os.Lstat(suFile(w, rel))
	return err == nil
}

// suRun sends the update and waits for its end.
func suRun(t *testing.T, w *opstest.SUWorld) api.Run {
	t.Helper()
	run, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	return w.RunEnded(run.RunID)
}

func suWant(t *testing.T, r api.Run, status api.Status, code string) {
	t.Helper()
	if r.Status != status || (code == "" && r.Error != nil) || (code != "" && (r.Error == nil || r.Error.Code != code)) {
		t.Fatalf("want %s %s, got %+v %+v", status, code, r, r.Error)
	}
}

// keptVersions are the versions of the files in packages/.
func keptVersions(t *testing.T, w *opstest.SUWorld) []string {
	t.Helper()
	es, err := os.ReadDir(suFile(w, "packages"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(e.Name(), "vedette-host_"), "_amd64.deb"))
	}
	return out
}

// assertSettledOn is POST-5: dpkg shows version installed, the running host is that version, versions.json
// names it current (and previous when given) with their kept files, packages/ holds only those, staged/ is
// empty, the journal and the applier copy are gone, and the one audit chain still verifies.
func assertSettledOn(t *testing.T, w *opstest.SUWorld, version, previous string) {
	t.Helper()
	w.Until("the journal to go", func() bool { return !suExists(w, "journal.json") }) // removed right after the settle
	if got := w.M.Marked("inst-new"); got != (version == w.To) {
		t.Errorf("dpkg shows the new version installed: %v", got)
	}
	info, err := w.Client().Info(context.Background())
	if err != nil || info.HostVersion != version {
		t.Errorf("host_version %q %v", info.HostVersion, err)
	}
	st, err := w.Client().StateHost(context.Background())
	if err != nil || st.Version != version || st.Update != nil || (previous == "") != (st.Previous == nil) || (st.Previous != nil && st.Previous.Version != previous) {
		t.Errorf("state/host %+v %v", st, err)
	}
	want := []string{version}
	if previous != "" {
		want = append(want, previous)
	}
	slices.Sort(want)
	if got := keptVersions(t, w); !slices.Equal(got, want) {
		t.Errorf("packages/ %v, want %v", got, want)
	}
	if es, _ := os.ReadDir(suFile(w, "staged")); len(es) != 0 {
		t.Errorf("staged/ %v", es)
	}
	for _, f := range []string{"journal.json", "applier"} {
		if suExists(w, f) {
			t.Errorf("%s is still there", f)
		}
	}
	if err := w.Host().Srv.AuditError(); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

// INV-28, POST-5: the applier installs, postinst restarts the host, the new host resumes the parked run with
// its lock and settles it succeeded; the applier that ran is the copy of the old binary.
func TestContract_SelfUpdate_TheHostRestartedByPostinstKeepsTheRunAndSettlesIt(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	r := suRun(t, w)
	suWant(t, r, api.StatusSucceeded, "")
	if res := result[api.HostSelfUpdateResult](t, r); res.From != suFrom || res.To != suTo || !res.Changed {
		t.Fatalf("%+v", res)
	}
	if h := w.Hosts(); !slices.Equal(h, []string{suFrom, suTo}) {
		t.Fatalf("hosts %v", h)
	}
	argv, bins := w.Dispatches()
	if len(argv) != 1 || argv[0][len(argv[0])-3] != suFile(w, "applier") || string(bins[0]) != string(w.OldExe) {
		t.Fatalf("dispatches %q", argv)
	}
	assertSettledOn(t, w, suTo, suFrom)
}

// applierCalls are the calls of a fake that carry argv (the applier's apt-get and dpkg forms).
func callsWith(w *opstest.SUWorld, bin, word string) [][]string {
	var out [][]string
	for _, c := range w.M.Calls(bin) {
		if slices.Contains(c, word) {
			out = append(out, c)
		}
	}
	return out
}

// writeRefused asserts that a write command gets 409 transition_pending (the self-update gate).
func writeRefused(t *testing.T, w *opstest.SUWorld) {
	t.Helper()
	_, err := w.Client().Run(context.Background(), api.CmdOSCheck, struct{}{}, "0000bbbb-5555-4555-8555-555555555555", "admin@example.com")
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != 409 || ce.Code != api.CodeTransitionPending {
		t.Fatalf("a write while the self-update is open: %v", err)
	}
}

// INV-28 (apply), POST-5 reverted: the new host never writes started.json, so the applier puts the kept
// package of from back and the old host runs again; versions.json does not change.
func TestContract_SelfUpdate_AnUnhealthyNewHostIsReplacedByThePreviousPackage(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("new-host-dead", true)
	r := suRun(t, w)
	suWant(t, r, api.StatusReverted, api.CodeSelfUpdateUnhealthy)
	if res := result[api.HostSelfUpdateResult](t, r); res.RolledBackTo != suFrom {
		t.Fatalf("%+v", res)
	}
	if len(callsWith(w, "apt-get", "--allow-downgrades")) != 1 {
		t.Fatalf("apt-get %v", w.M.Calls("apt-get"))
	}
	assertSettledOn(t, w, suFrom, "")
}

// The new host starts but crash-loops (NRestarts grows within the 30 s): unhealthy, reverted.
func TestContract_SelfUpdate_ANewHostThatCrashLoopsIsReverted(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("crash-loop", true)
	suWant(t, suRun(t, w), api.StatusReverted, api.CodeSelfUpdateUnhealthy)
	assertSettledOn(t, w, suFrom, "")
}

// apt fails without changing anything: the rollback sees from installed and healthy, so it reinstalls nothing.
func TestContract_SelfUpdate_ARollbackWhoseEffectIsAlreadyThereDoesNotReinstall(t *testing.T) {
	t.Parallel()
	nothingChanged(t, "apt-fails")
}

// unattended-upgrades takes the lock between Check and the install: apt waits DPkg::Lock::Timeout (here in vain:
// it exits 100 having changed nothing), and the rollback sees from installed and healthy.
func TestContract_SelfUpdate_UnattendedUpgradesTakingTheLockBetweenCheckAndInstallIsWaitedFor(t *testing.T) {
	t.Parallel()
	w := nothingChanged(t, "lock-outlives")
	if c := callsWith(w, "apt-get", "DPkg::Lock::Timeout=600"); len(c) != 1 {
		t.Fatalf("apt %v", c)
	}
}

func nothingChanged(t *testing.T, marker string) *opstest.SUWorld {
	t.Helper()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark(marker, true)
	suWant(t, suRun(t, w), api.StatusReverted, api.CodeInstallFailed)
	if c := callsWith(w, "apt-get", "--allow-downgrades"); len(c) != 0 {
		t.Fatalf("reinstalled %v", c)
	}
	if !slices.Equal(w.Hosts(), []string{suFrom}) {
		t.Fatalf("hosts %v", w.Hosts())
	}
	assertSettledOn(t, w, suFrom, "")
	return w
}

// apt unpacked the new package and then failed: the previous one is reinstalled from packages/.
func TestContract_SelfUpdate_AnAptFailureReinstallsThePrevious(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("apt-fails-unpacked", true)
	suWant(t, suRun(t, w), api.StatusReverted, api.CodeInstallFailed)
	c := callsWith(w, "apt-get", "--allow-downgrades")
	if len(c) != 1 || c[0][len(c[0])-1] != suFile(w, "packages/vedette-host_"+suFrom+"_amd64.deb") {
		t.Fatalf("rollback %v", c)
	}
	assertSettledOn(t, w, suFrom, "")
}

// The rollback fails too: the run ends rollback_failed, the applier stops (no loop), the journal and the
// applier copy stay for the RUNBOOK, and every write is refused.
func TestContract_SelfUpdate_ARollbackThatFailsStopsAndKeepsTheJournal(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("new-host-dead", true)
	w.M.Mark("rollback-apt-fails", true)
	r, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	w.Until("the applier to end", func() bool { return w.Applies.Load() == 1 && !w.M.Marked("applier-running") })
	if w.Host() != nil {
		t.Fatal("a host runs although the new one never starts")
	}
	w.StartHost() // systemd keeps trying the broken new host; one that comes up reads the journal and settles the run
	suWant(t, w.RunEnded(r.RunID), api.StatusFailed, api.CodeRollbackFailed)
	if !suExists(w, "journal.json") || !suExists(w, "applier") || w.Applies.Load() != 1 {
		t.Fatalf("journal %v applier %v applies %d", suExists(w, "journal.json"), suExists(w, "applier"), w.Applies.Load())
	}
	writeRefused(t, w)
}

// policy-rc.d forbids the restart: postinst does not restart the host, so the applier restarts it itself.
func TestContract_SelfUpdate_PostinstWithoutRestartIsRestartedByTheApplier(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("policy-rc.d", true)
	suWant(t, suRun(t, w), api.StatusSucceeded, "")
	if len(callsWith(w, "systemctl", "restart")) != 1 {
		t.Fatalf("systemctl %v", w.M.Calls("systemctl"))
	}
	assertSettledOn(t, w, suTo, suFrom)
}

// "dpkg interrupted": vedette-host is half-installed and apt refuses everything, so the applier uses dpkg -i of
// this one package (never dpkg --configure -a).
func TestContract_SelfUpdate_ADpkgInterruptedMidUnpackIsFinishedWithDpkgInstallNotApt(t *testing.T) {
	t.Parallel()
	dpkgInterrupted(t, false)
}

// "lock taken right after the probe": dpkg -i meets the lock once; the applier waits and retries once.
func TestContract_SelfUpdate_DpkgInstallWaitsForTheLockAndRetriesOnceWithinTenMinutes(t *testing.T) {
	t.Parallel()
	dpkgInterrupted(t, true)
}

func dpkgInterrupted(t *testing.T, lockOnce bool) {
	t.Helper()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("dpkg-lock-once", lockOnce)
	// Check refuses a half-installed host (current_package_missing): the box gets so after the dispatch, as after
	// a first applier cut short mid-unpack.
	w.Hold = make(chan struct{})
	run, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	w.Until("the dispatch", func() bool { a, _ := w.Dispatches(); return len(a) == 1 })
	w.M.Mark("half", true)
	close(w.Hold)
	suWant(t, w.RunEnded(run.RunID), api.StatusSucceeded, "")
	want := 1
	if lockOnce {
		want = 2
	}
	if c := callsWith(w, "dpkg", "-i"); len(c) != want || len(callsWith(w, "apt-get", "DPkg::Lock::Timeout=600")) != 0 {
		t.Fatalf("dpkg -i %v, apt %v", c, w.M.Calls("apt-get"))
	}
	for _, c := range w.M.AllCalls() {
		if strings.Contains(c, "--configure") {
			t.Fatalf("ran %s", c)
		}
	}
	assertSettledOn(t, w, suTo, suFrom)
}

// A failed dispatch (the unit name is taken) ends the run applier_failed, cleans up and releases the lock.
func TestContract_SelfUpdate_AFailedDispatchSettlesApplierFailedAndCleansUp(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("dispatch-fails", true)
	suWant(t, suRun(t, w), api.StatusFailed, api.CodeApplierFailed)
	w.Until("the journal to go", func() bool { return !suExists(w, "journal.json") })
	if suExists(w, "applier") || len(keptVersions(t, w)) != 1 {
		t.Fatal("files left behind")
	}
	if _, err := w.Client().Run(context.Background(), api.CmdOSCheck, struct{}{}, "0000cccc-5555-4555-8555-555555555555", "admin@example.com"); err != nil {
		t.Fatalf("the lock is still held: %v", err)
	}
}

// INV-28: a dead applier is seen by the settle loop (not only at a start) and started once more, from the same
// copy of the old binary with the same argv.
func TestContract_SelfUpdate_ADeadApplierIsSeenByTheSettleLoopAndDispatchedAgainOnce(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	var died atomic.Bool
	w.Stop = func(phase string) bool { return phase == "installing" && died.CompareAndSwap(false, true) }
	suWant(t, suRun(t, w), api.StatusSucceeded, "")
	argv, bins := w.Dispatches()
	if len(argv) != 2 || !slices.Equal(argv[0], argv[1]) || string(bins[1]) != string(w.OldExe) {
		t.Fatalf("dispatches %q", argv)
	}
	assertSettledOn(t, w, suTo, suFrom)
}

// An applier that dies twice ends self_update_interrupted: the journal stays and writes are refused (RUNBOOK).
func TestContract_SelfUpdate_AnApplierThatDiesTwiceIsInterrupted(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.Stop = func(phase string) bool { return phase == "installing" }
	suWant(t, suRun(t, w), api.StatusFailed, api.CodeSelfUpdateInterrupted)
	if a, _ := w.Dispatches(); len(a) != 2 || !suExists(w, "journal.json") {
		t.Fatalf("dispatches %d, journal %v", len(a), suExists(w, "journal.json"))
	}
	writeRefused(t, w)
}

// "applier dies at minute 75": a second applier could not end by the deadline (130), so none is started.
func TestContract_SelfUpdate_ASecondApplierIsNotStartedWhenItWouldPassTheDeadline(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.Stop = func(phase string) bool {
		if phase == "installing" {
			w.Clock.Advance(75 * time.Minute)
			return true
		}
		return false
	}
	suWant(t, suRun(t, w), api.StatusFailed, api.CodeSelfUpdateInterrupted)
	if a, _ := w.Dispatches(); len(a) != 1 {
		t.Fatalf("dispatches %d", len(a))
	}
}

// The merge gate of the parked run (deferred file of slice 1): a panic of the settle goroutine ends the run
// failed and raises the write gate; the journal stays (RUNBOOK).
func TestContract_SelfUpdate_APanicOfTheSettleLoopEndsTheRunFailed(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("dispatch-panics", true)
	suWant(t, suRun(t, w), api.StatusFailed, api.CodeSelfUpdateInterrupted)
	writeRefused(t, w)
}

// The safety net: an applier that never ends is given up past the deadline plus the margin, whatever the unit does.
func TestContract_SelfUpdate_AnApplierPastTheDeadlineIsGivenUp(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.Hold = make(chan struct{}) // the applier never starts its work: the unit stays active
	run, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	w.Until("the dispatch", func() bool { a, _ := w.Dispatches(); return len(a) == 1 })
	w.Clock.Advance(130*time.Minute + 16*time.Minute)
	suWant(t, w.RunEnded(run.RunID), api.StatusFailed, api.CodeSelfUpdateInterrupted)
	writeRefused(t, w)
}

// A restart past the deadline plus the margin does not keep the run (Resume says no): the lock is never held for
// ever across restarts; the orphan journal still gates the writes.
func TestContract_SelfUpdate_ARestartPastTheDeadlineDoesNotKeepTheRun(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.Hold = make(chan struct{})
	run, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	w.Until("the dispatch", func() bool { a, _ := w.Dispatches(); return len(a) == 1 })
	w.StopHost()
	w.Clock.Advance(130*time.Minute + 16*time.Minute)
	w.StartHost()
	suWant(t, w.RunEnded(run.RunID), api.StatusFailed, api.CodeHostRestarted)
	writeRefused(t, w)
}

// An orphan journal after dispatch (the run file was lost): the next host raises the write gate, follows the
// journal without a run and lowers the gate once it ended.
func TestContract_SelfUpdate_AnOrphanJournalAfterDispatchGatesWritesUntilItsPhaseEnds(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.Hold = make(chan struct{})
	run, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	w.Until("the dispatch", func() bool { a, _ := w.Dispatches(); return len(a) == 1 })
	w.StopHost()
	if err := os.Remove(filepath.Join(w.M.State, "runs", run.RunID+".json")); err != nil {
		t.Fatal(err)
	}
	w.StartHost()
	writeRefused(t, w)
	close(w.Hold)
	w.Until("the orphan journal to end", func() bool { return !suExists(w, "journal.json") })
	if _, err := w.Client().Run(context.Background(), api.CmdOSCheck, struct{}{}, "0000dddd-5555-4555-8555-555555555555", "admin@example.com"); err != nil {
		t.Fatalf("the gate is still up: %v", err)
	}
	assertSettledOn(t, w, suTo, suFrom)

}

// "SIGTERM before parking": nothing was dispatched, so the staged journal (attempt 0) is cleaned at the next start.
func TestContract_SelfUpdate_ASIGTERMBeforeParkingStartsNoApplierAndTheStagedJournalIsCleared(t *testing.T) {
	t.Parallel()
	s := opstest.NewSUWorld(t, suFrom, suTo)
	staged := `{"run_id":"rn_0123456789abcdef","request_id":"01234567-89ab-4def-8123-456789abcdef",` +
		`"from":{"version":"1.3.0","sha256":"` + strings.Repeat("ab", 32) + `"},"to":{"version":"1.4.0","sha256":"` + strings.Repeat("cd", 32) + `","size":10},` +
		`"applier_sha256":"` + strings.Repeat("ef", 32) + `","phase":"staged","attempt":0,"boot_id":"` + opstest.BootID + `",` +
		`"started_at":"2026-11-12T10:00:00Z","deadline":"2026-11-12T12:10:00Z","reason":null,"log":[]}`
	for name, body := range map[string]string{"journal.json": staged, "applier": "x", "staged/" + strings.Repeat("cd", 32) + ".deb": "x"} {
		if err := os.WriteFile(suFile(s, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.Restart()
	for _, f := range []string{"journal.json", "applier", "staged/" + strings.Repeat("cd", 32) + ".deb"} {
		if suExists(s, f) {
			t.Errorf("%s was not cleaned", f)
		}
	}
	if a, _ := s.Dispatches(); len(a) != 0 {
		t.Fatalf("dispatched %v", a)
	}
	if b, _ := os.ReadFile(s.AuditPath()); !strings.Contains(string(b), "self_update_abandoned") {
		t.Fatal("no self_update_abandoned line")
	}
}

// A new dependency the mirror has is installed with the package (the happy path's simulation has one); one the
// mirror lacks is refused before anything changes.
func TestContract_SelfUpdate_AMissingDependencyIsRefusedBeforeAnyChange(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.ClearRules("apt-get")
	w.M.Rule("apt-get", "-q update", "apt_update.txt", 0, "", "")
	w.M.SimInstall("E: Unable to satisfy dependencies: vedette-host : Depends: conntrack-ng but it is not installable\n", 100)
	suWant(t, suRun(t, w), api.StatusFailed, api.CodeDependenciesUnavailable)
	if a, _ := w.Dispatches(); len(a) != 0 || suExists(w, "journal.json") || suExists(w, "applier") {
		t.Fatal("something was left or dispatched")
	}
}

// INV-30: the applier never opens the audit chain, a socket or host.lock: its code imports neither the server
// nor a network package and never writes an audit note; every scenario above checks the one chain still verifies.
func TestContract_SelfUpdate_TheApplierNeverWritesTheAuditChain(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"../../host/ops/selfupdateapply.go", "../../cmd/vedette-host/apply.go"} {
		src, err := os.ReadFile(f) //nolint:gosec // test: fixed file names
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, 0) // comments are not part of the code
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == "github.com/knt048/vedette/host/server" || p == "net" || strings.HasPrefix(p, "net/") || p == "github.com/knt048/vedette/host/client" {
				t.Errorf("%s imports %s", f, p)
			}
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if slices.Contains([]string{"note", "Note", "noteDownload", "LockState", "openAudit"}, v.Name) {
					t.Errorf("%s uses %s", f, v.Name)
				}
			case *ast.BasicLit:
				if strings.Contains(v.Value, "audit.jsonl") || strings.Contains(v.Value, "host.lock") {
					t.Errorf("%s names %s", f, v.Value)
				}
			}
			return true
		})
	}
}

// An applier cut at checking: the second one checks the effect first (the new version is installed and
// healthy) and does not install again.
func TestContract_SelfUpdate_AnApplierCutAtCheckingFinishesWithoutInstallingAgain(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	var died atomic.Bool
	w.Stop = func(phase string) bool { return phase == "checking" && died.CompareAndSwap(false, true) }
	suWant(t, suRun(t, w), api.StatusSucceeded, "")
	if c := callsWith(w, "apt-get", "DPkg::Lock::Timeout=600"); len(c) != 1 {
		t.Fatalf("apt %v", c)
	}
	assertSettledOn(t, w, suTo, suFrom)
}

// An applier cut at rolling_back: the second one does the rollback once and the run is reverted.
func TestContract_SelfUpdate_AnApplierCutAtRollingBackRollsBack(t *testing.T) {
	t.Parallel()
	w := opstest.NewSUWorld(t, suFrom, suTo)
	w.M.Mark("new-host-dead", true)
	var died atomic.Bool
	w.Stop = func(phase string) bool { return phase == "rolling_back" && died.CompareAndSwap(false, true) }
	r, err := w.Send(w.Args())
	if err != nil {
		t.Fatal(err)
	}
	// The old host was stopped for the new one, which never came: a host of the installed (new) version comes
	// back as systemd retries, so there is a host to see the dead applier and start it again.
	w.Until("the first applier to die", func() bool { return died.Load() && !w.M.Marked("applier-running") })
	if w.Host() == nil {
		w.M.Mark("new-host-dead", false)
		w.StartHost()
	}
	suWant(t, w.RunEnded(r.RunID), api.StatusReverted, api.CodeSelfUpdateUnhealthy)
	if a, _ := w.Dispatches(); len(a) != 2 || len(callsWith(w, "apt-get", "--allow-downgrades")) != 1 {
		t.Fatalf("dispatches %d, apt %v", len(a), w.M.Calls("apt-get"))
	}
}
