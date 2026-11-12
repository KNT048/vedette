package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// host.self_update, slice 2a: the argv validators of the two runners, the strict readers of the state
// files and the time limits (spec 6.14, D-316). Small and table-driven; fuzz targets keep them honest.

const suState = "/var/lib/vedette-host"

var (
	suSHA    = strings.Repeat("ab", 32)
	suStaged = suState + "/selfupdate/staged/" + suSHA + ".deb"
	suKept   = suState + "/selfupdate/packages/vedette-host_1.3.0_amd64.deb"
)

// INV-27: one systemd-run form, the run id the only part that changes.
func TestValidateSystemdRun(t *testing.T) {
	t.Parallel()
	v := validateSystemdRun(suState)
	good := systemdRunArgv(suState, "rn_0123456789abcdef")
	if err := v(good); err != nil {
		t.Fatalf("%q: %v", good, err)
	}
	if !slices.Contains(good, "--property=RuntimeMaxSec=60min") || good[len(good)-3] != suState+"/selfupdate/applier" {
		t.Fatalf("argv %q", good)
	}
	bad := [][]string{nil, good[:len(good)-1], append(slices.Clone(good), "x")}
	for i := range good {
		b := slices.Clone(good)
		b[i] += "x"
		bad = append(bad, b)
	}
	for _, id := range []string{"rn_0123456789ABCDEF", "rn_0123", "", "--help", "rn_0123456789abcdef\n"} {
		b := slices.Clone(good)
		b[len(b)-1] = id
		bad = append(bad, b)
	}
	other := slices.Clone(good)
	other[len(other)-3] = "/usr/lib/vedette/vedette-host"
	bad = append(bad, other, validSystemdRunOtherState())
	for _, b := range bad {
		if v(b) == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func validSystemdRunOtherState() []string { return systemdRunArgv("/tmp/evil", "rn_0123456789abcdef") }

func FuzzValidateSystemdRun(f *testing.F) {
	f.Add(strings.Join(systemdRunArgv(suState, "rn_0123456789abcdef"), "\x00"))
	f.Add("--unit=vedette-host\x00/bin/sh")
	v := validateSystemdRun(suState)
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		if v(args) == nil && !slices.Equal(args, systemdRunArgv(suState, args[len(args)-1])) {
			t.Fatalf("accepted %q", args)
		}
	})
}

// INV-27: what the host runner refuses and only the applier runner accepts.
func TestTheHostRunnerNeverInstallsAndTheApplierRunnerDoes(t *testing.T) {
	t.Parallel()
	applierOnly := map[string][][]string{
		binAptGet:    {aptInstallArgv(suStaged, false, 600), aptInstallArgv(suKept, true, 0)},
		binDpkg:      {dpkgInstallArgv(suStaged), dpkgInstallArgv(suKept)},
		binSystemctl: {argsRestartHost, argsShowHost},
	}
	for bin, forms := range applierOnly {
		for _, a := range forms {
			if err := ValidateHostArgv(suState, "vedette-core.service", bin, a); err == nil {
				t.Errorf("the host runner accepts %s %q", bin, a)
			}
			if err := ValidateApplierArgv(suState, bin, a); err != nil {
				t.Errorf("the applier runner refuses %s %q: %v", bin, a, err)
			}
		}
	}
	// os.install's upgrade form never takes vedette-host, with or without an architecture (FORBID-7, review L1).
	for _, n := range []string{hostPkg, hostPkg + ":amd64", hostPkg + ":arm64"} {
		if ValidateHostArgv(suState, "vedette-core.service", binAptGet, append(slices.Clone(argsInstallPre), "libc6", n)) == nil {
			t.Errorf("os.install's apt accepts %s", n)
		}
	}
	// A host.conf that names vedette-host as core's unit does not open a way to stop or restart it.
	for _, a := range [][]string{{"stop", hostUnit}, {"start", hostUnit}, {"restart", hostUnit}} {
		if ValidateHostArgv(suState, hostUnit, binSystemctl, a) == nil {
			t.Errorf("the host runner accepts systemctl %q", a)
		}
	}
	hostForms := map[string][][]string{
		binSystemdRun: {systemdRunArgv(suState, "rn_0123456789abcdef")},
		binDpkgDeb:    {dpkgDebFieldArgv(suStaged)},
		binDpkgQuery:  {argsDpkgQueryHost},
		binAptGet:     {aptSimInstallArgv(suStaged), argsUpdate},
		binSystemctl:  {{"is-active", upgradeUnit}},
	}
	for bin, forms := range hostForms {
		for _, a := range forms {
			if err := ValidateHostArgv(suState, "vedette-core.service", bin, a); err != nil {
				t.Errorf("the host runner refuses %s %q: %v", bin, a, err)
			}
		}
	}
	// The applier never starts units and never asks dpkg-deb.
	for _, bin := range []string{binSystemdRun, binDpkgDeb, binPodman, binIP} {
		if ValidateApplierArgv(suState, bin, []string{"--version"}) == nil {
			t.Errorf("the applier runner has %s", bin)
		}
	}
	// Paths: only the staged and kept forms under this state directory.
	for _, p := range []string{
		suState + "/selfupdate/staged/" + suSHA + ".deb.x", suState + "/selfupdate/staged/../" + suSHA + ".deb",
		suState + "/selfupdate/packages/vedette-host_1.3.0_i386.deb", suState + "/selfupdate/packages/vedette-host_1.3.0-rc-1_amd64.deb",
		suState + "/selfupdate/packages/vedette-host_1.3.0~rc.1_amd64.deb", "/tmp/selfupdate/staged/" + suSHA + ".deb", "/var/lib/vedette/core/host-packages/x.deb",
	} {
		if ValidateApplierArgv(suState, binDpkg, dpkgInstallArgv(p)) == nil || ValidateApplierArgv(suState, binAptGet, aptInstallArgv(p, true, 600)) == nil {
			t.Errorf("accepted the path %q", p)
		}
	}
	// apt's own lock wait is 0..600 s, nothing else (review M6: what is left of the budget after the probe).
	for _, v := range []string{"601", "-1", "06", "1e3", "", "600 "} {
		a := aptInstallArgv(suStaged, false, 600)
		a[len(argsAptInstallHead)] = "DPkg::Lock::Timeout=" + v
		if ValidateApplierArgv(suState, binAptGet, a) == nil {
			t.Errorf("accepted the lock timeout %q", v)
		}
	}
	// --allow-downgrades only with a kept file, never with the staged one.
	if ValidateApplierArgv(suState, binAptGet, aptInstallArgv(suStaged, true, 600)) == nil || ValidateApplierArgv(suState, binAptGet, aptInstallArgv(suKept, false, 600)) == nil {
		t.Error("allow-downgrades and the file do not go together")
	}
}

func FuzzValidateSelfUpdateArgv(f *testing.F) {
	for _, a := range [][]string{aptInstallArgv(suStaged, false, 600), aptInstallArgv(suKept, true, 0), dpkgInstallArgv(suKept), aptSimInstallArgv(suStaged), dpkgDebFieldArgv(suStaged)} {
		f.Add(strings.Join(a, "\x00"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		a := strings.Split(joined, "\x00")
		last := a[len(a)-1]
		if ValidateApplierArgv(suState, binAptGet, a) == nil {
			n, _ := strconv.Atoi(strings.TrimPrefix(a[len(argsAptInstallHead)], "DPkg::Lock::Timeout="))
			if !slices.Equal(a, aptInstallArgv(last, slices.Contains(a, "--allow-downgrades"), n)) || n > 600 {
				t.Fatalf("applier apt accepted %q", a)
			}
		}
		if ValidateApplierArgv(suState, binDpkg, a) == nil && !slices.Equal(a, []string{"--audit"}) && !slices.Equal(a, dpkgInstallArgv(last)) {
			t.Fatalf("applier dpkg accepted %q", a)
		}
		for _, bin := range []string{binDpkgDeb, binAptGet} {
			if ValidateHostArgv(suState, "vedette-core.service", bin, a) == nil && slices.Contains(a, "install") && !slices.Contains(a, "-s") {
				t.Fatalf("host %s accepted a real install %q", bin, a)
			}
		}
		if (strings.Contains(last, "..") || strings.Contains(last, "//")) && (ValidateApplierArgv(suState, binDpkg, a) == nil || ValidateApplierArgv(suState, binAptGet, a) == nil) {
			t.Fatalf("accepted the path %q", last)
		}
	})
}

// The one file-name validator (spec 6.14): SemVer form, no "-" inside the prerelease, no build metadata.
func TestHostPackageName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"vedette-host_1.4.0_amd64.deb": "1.4.0", "vedette-host_0.2.0-rc.1_arm64.deb": "0.2.0-rc.1", "vedette-host_1.4.0-test.1_amd64.deb": "1.4.0-test.1",
	} {
		if v, _, ok := parseHostPkgName(name); !ok || v != want {
			t.Errorf("%s: %q %v", name, v, ok)
		}
	}
	for _, name := range []string{
		"vedette-host_1.4_amd64.deb", "vedette-host_01.4.0_amd64.deb", "vedette-host_1.4.0~rc.1_amd64.deb", "vedette-host_1.4.0-rc-1_amd64.deb",
		"vedette-host_1.4.0+b1_amd64.deb", "vedette-host_1.4.0_i386.deb", "vedette-host_1.4.0_amd64.deb/", "../vedette-host_1.4.0_amd64.deb",
		"vedette-core_1.4.0_amd64.deb", "vedette-host_1.4.0_amd64.deb.tmp", "",
	} {
		if _, _, ok := parseHostPkgName(name); ok {
			t.Errorf("accepted %q", name)
		}
	}
	if debVersion("0.2.0-rc.1") != "0.2.0~rc.1" || debVersion("1.4.0") != "1.4.0" {
		t.Error("debVersion")
	}
	if !isTestVersion("1.4.0-test.2") || !isTestVersion("1.4.0-TEST") || isTestVersion("1.4.0-rc.1") {
		t.Error("isTestVersion")
	}
}

func FuzzParseHostPkgName(f *testing.F) {
	f.Add("vedette-host_1.4.0_amd64.deb")
	f.Add("vedette-host_0.2.0-rc.1_arm64.deb")
	f.Fuzz(func(t *testing.T, name string) {
		if v, arch, ok := parseHostPkgName(name); ok && hostPkgName(v, arch) != name {
			t.Fatalf("%q -> %q %q", name, v, arch)
		}
	})
}

func goodJournal() suJournal {
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	return suJournal{
		RunID: "rn_0123456789abcdef", RequestID: "01234567-89ab-4def-8123-456789abcdef",
		From: suRef{Version: "1.3.0", SHA256: suSHA}, To: suTo{Version: "1.4.0", SHA256: strings.Repeat("cd", 32), Size: 1234},
		ApplierSHA256: strings.Repeat("ef", 32), Phase: phStaged, Attempt: 0, BootID: "11111111-2222-4333-8444-555555555555",
		StartedAt: at, Deadline: at.Add(suRunWindow), Log: []string{},
	}
}

func suJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The journal reader is strict: one valid shape, everything else refused.
func TestJournalReaderIsStrict(t *testing.T) {
	t.Parallel()
	if _, err := parseSUJournal(suJSON(t, goodJournal())); err != nil {
		t.Fatal(err)
	}
	reason := "self_update_unhealthy"
	odd := "something"
	for name, mut := range map[string]func(*suJournal){
		"attempt 0 dispatched": func(j *suJournal) { j.Phase = phDispatched },
		"attempt 1 staged":     func(j *suJournal) { j.Attempt = 1 },
		"attempt 3":            func(j *suJournal) { j.Phase, j.Attempt = phDispatched, 3 },
		"unknown phase":        func(j *suJournal) { j.Phase = "done" },
		"deadline too far":     func(j *suJournal) { j.Deadline = j.StartedAt.Add(suRunWindow + time.Second) },
		"deadline before":      func(j *suJournal) { j.Deadline = j.StartedAt },
		"to not above from":    func(j *suJournal) { j.To.Version = "1.3.0" },
		"debian form":          func(j *suJournal) { j.To.Version = "1.4.0~rc.1" },
		"run id":               func(j *suJournal) { j.RunID = "rn_x" },
		"request id":           func(j *suJournal) { j.RequestID = "x" },
		"boot id":              func(j *suJournal) { j.BootID = "" },
		"size":                 func(j *suJournal) { j.To.Size = maxHostPackage + 1 },
		"sha":                  func(j *suJournal) { j.ApplierSHA256 = "AB" },
		"reason":               func(j *suJournal) { j.Reason = &odd },
		"control in log":       func(j *suJournal) { j.Log = []string{"a\x1b[31m"} },
		"long log line":        func(j *suJournal) { j.Log = []string{strings.Repeat("a", maxSULogLine+1)} },
		"too many lines":       func(j *suJournal) { j.Log = make([]string, maxSULogLines+1) },
	} {
		j := goodJournal()
		mut(&j)
		if _, err := parseSUJournal(suJSON(t, j)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	j := goodJournal()
	j.Phase, j.Attempt, j.Reason = phRollingBack, 2, &reason
	if _, err := parseSUJournal(suJSON(t, j)); err != nil {
		t.Errorf("a rollback journal: %v", err)
	}
	raw := suJSON(t, goodJournal())
	for name, b := range map[string][]byte{
		"unknown field": []byte(strings.Replace(string(raw), `"log":[]`, `"log":[],"x":1`, 1)),
		"no log":        []byte(strings.Replace(string(raw), `,"log":[]`, ``, 1)),
		"trailing":      append(slices.Clone(raw), []byte(" {}")...),
		"null":          []byte("null"),
		"too large":     []byte(`{"run_id":"` + strings.Repeat("a", maxSUFile) + `"}`),
	} {
		if _, err := parseSUJournal(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Review M1: a journal at its limits (50 lines of 512 bytes of "<", or of the characters JSON doubles) is
// written within the reader's cap and reads back; the writer refuses what the reader would.
func TestAFullJournalIsWrittenWithinTheReadersLimit(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"<", `"`, "\u2028"} {
		j := goodJournal()
		line := strings.Repeat(c, maxSULogLine/len(c))
		for range maxSULogLines {
			j.Log = append(j.Log, line)
		}
		b, err := encodeSU(j)
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		if _, err := parseSUJournal(b); err != nil {
			t.Fatalf("%q: written %d bytes that do not read: %v", c, len(b), err)
		}
	}
	if _, err := encodeSU(map[string]string{"x": strings.Repeat("a", maxSUFile)}); err == nil {
		t.Fatal("the writer accepted more than the reader does")
	}
}

func FuzzParseSUJournal(f *testing.F) {
	f.Add(suJSON(f, goodJournal()))
	f.Add([]byte(`{"phase":"staged"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		j, err := parseSUJournal(b)
		if err != nil {
			return
		}
		if again, err := parseSUJournal(suJSON(t, j)); err != nil || again.RunID != j.RunID || again.Phase != j.Phase {
			t.Fatalf("does not round trip: %v", err)
		}
	})
}

func TestVersionsAndStartedReadersAreStrict(t *testing.T) {
	t.Parallel()
	good := `{"current":{"version":"1.3.0","sha256":"` + suSHA + `","size":10},"previous":null}`
	if _, err := parseSUVersions([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{
		strings.Replace(good, `"previous":null`, `"previous":{"version":"1.3.0","sha256":"`+suSHA+`","size":10}`, 1),
		strings.Replace(good, `1.3.0`, `1.3.0~rc.1`, 1), strings.Replace(good, `"size":10`, `"size":0`, 1), good + "x", `null`,
	} {
		if _, err := parseSUVersions([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	st := `{"version":"1.4.0","pid":4242,"boot_id":"11111111-2222-4333-8444-555555555555","at":"2026-11-12T10:00:00Z"}`
	if _, err := parseSUStarted([]byte(st)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{strings.Replace(st, `4242`, `1`, 1), strings.Replace(st, `1.4.0`, `1.4 0`, 1), strings.Replace(st, `"at"`, `"x"`, 1), st + "{}"} {
		if _, err := parseSUStarted([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func FuzzParseSUVersions(f *testing.F) {
	f.Add([]byte(`{"current":{"version":"1.3.0","sha256":"` + suSHA + `","size":10},"previous":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := parseSUVersions(b); err == nil {
			if _, err := parseSUVersions(suJSON(t, v)); err != nil {
				t.Fatalf("does not round trip: %v", err)
			}
		}
	})
}

func FuzzParseSUStarted(f *testing.F) {
	f.Add([]byte(`{"version":"1.4.0","pid":4242,"boot_id":"11111111-2222-4333-8444-555555555555","at":"2026-11-12T10:00:00Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := parseSUStarted(b); err == nil {
			if _, err := parseSUStarted(suJSON(t, s)); err != nil {
				t.Fatalf("does not round trip: %v", err)
			}
		}
	})
}

// The simulated install: a new dependency is fine; removing, purging or upgrading another package is not.
func TestSelfUpdateSimulation(t *testing.T) {
	t.Parallel()
	ok := "Inst conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nInst vedette-host [1.3.0] (1.4.0 local-deb [amd64])\nConf vedette-host (1.4.0 local-deb [amd64])\n"
	added, accepted := SelfUpdateSim([]byte(ok + "Inst libnetfilter-cttimeout1 (1.0.1-1 Ubuntu:24.04/noble [amd64])\n"))
	if !accepted || !slices.Equal(added, []string{"conntrack", "libnetfilter-cttimeout1"}) {
		t.Fatalf("a plain install with two new dependencies: %v %v", added, accepted)
	}
	if added, accepted := SelfUpdateSim([]byte("Inst vedette-host [1.3.0] (1.4.0 local-deb [amd64])\n")); !accepted || len(added) != 0 {
		t.Fatalf("an install with no new dependency: %v %v", added, accepted)
	}
	for name, out := range map[string]string{
		"removal":         ok + "Remv podman [4.9.3]\n",
		"purge":           ok + "Purg podman [4.9.3]\n",
		"other upgrade":   ok + "Inst podman [4.9.3] (5.0.0 Ubuntu:24.04/noble-updates [amd64])\n",
		"no host line":    "Inst conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\n",
		"line too long":   ok + strings.Repeat("x", maxSimLine+1) + "\n",
		"empty":           "",
		"host named late": strings.Replace(ok, "Inst vedette-host", "Inst vedette-hostx", 1),
		"not a name":      ok + "Inst ../../etc/passwd (1.0 x [amd64])\n",
		"foreign arch":    ok + "Inst libfoo1:i386 (1.0 Ubuntu:24.04/noble [i386])\n", // install.sh's list filter would never purge it
	} {
		if added, accepted := SelfUpdateSim([]byte(out)); accepted || added != nil {
			t.Errorf("%s: accepted (%v)", name, added)
		}
	}
}

func FuzzSelfUpdateSim(f *testing.F) {
	f.Add([]byte("Inst vedette-host [1.3.0] (1.4.0 local-deb [amd64])\n"))
	f.Add([]byte("Inst conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nInst vedette-host [1.3.0] (1.4.0 local-deb [amd64])\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		added, ok := SelfUpdateSim(b)
		if ok && (strings.Contains(string(b), "\nRemv ") || strings.HasPrefix(string(b), "Remv ")) {
			t.Fatal("a removal was accepted")
		}
		for _, n := range added {
			if !ok || !addedPkgName(n) || strings.Contains(n, ":") || isHostPkg(n) {
				t.Fatalf("added %q (ok %v)", n, ok)
			}
		}
	})
}

// D-316 (9): the packages a self-update adds are merged into selfupdate/installed-by-us (sorted, unique, 0600)
// before anything is installed; nothing new writes nothing; a link in its place stops the run.
func TestRecordAddedPackages(t *testing.T) {
	t.Parallel()
	o := &Ops{cfg: Config{StateDir: t.TempDir()}}
	if err := os.MkdirAll(suDir(o.cfg.StateDir), 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(suDir(o.cfg.StateDir), suAddedName)
	if err := o.recordAddedPackages(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no new package wrote the file: %v", err)
	}
	if err := o.recordAddedPackages([]string{"conntrack", "libnetfilter-cttimeout1"}); err != nil {
		t.Fatal(err)
	}
	if err := o.recordAddedPackages([]string{"zstd", "conntrack"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p) //nolint:gosec // the test's own temp state directory
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "conntrack\nlibnetfilter-cttimeout1\nzstd\n" {
		t.Fatalf("installed-by-us is %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", p); err != nil {
		t.Fatal(err)
	}
	if err := o.recordAddedPackages([]string{"conntrack"}); err == nil {
		t.Fatal("a link in place of installed-by-us was written through")
	}
}

// checkSelfUpdateLimits is the host.self_update part of TestTimeLimitsAreConsistent (spec 6.14 "Thời hạn").
func checkSelfUpdateLimits(t *testing.T) {
	t.Helper()
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "vedette-host.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), fmt.Sprintf("\nTimeoutStartSec=%dmin\n", int(hostStartLimit.Minutes()))) {
		t.Errorf("vedette-host.service does not declare TimeoutStartSec=%v", hostStartLimit)
	}
	// One applier run, from the applier's own bounds (contexts, not estimates): an effect check (a second applier
	// starts with one), a half (lock waits shared with apt's own timeout, the tool with postinst's restart or the
	// applier's own restart, then the health windows), the rollback's effect check, and the rollback's half.
	if applyStep != applierLockBudget+hostStartLimit || applyHalf != applyStep+suHealthWindow+suStableWindow {
		t.Error("the applier's step and half are not the sums they are documented as")
	}
	if one := 2*applyEffect + 2*applyHalf; one > applierRuntimeMax {
		t.Errorf("one applier run needs %v, RuntimeMaxSec is %v", one, applierRuntimeMax)
	}
	if lock := aptInstallArgv("x", false, 1<<20)[len(argsAptInstallHead)]; lock != fmt.Sprintf("DPkg::Lock::Timeout=%d", int(applierLockBudget.Seconds())) {
		t.Errorf("apt's own lock wait %s is not capped by the budget", lock)
	}
	if suAptUpdateLimit >= suPreParkTimeout {
		t.Errorf("apt-get update (%v) does not fit the pre-park timeout (%v)", suAptUpdateLimit, suPreParkTimeout)
	}
	// The run: before parking and two applier runs. A retry after a full-length first run is not guaranteed: a
	// second one starts only when now + one run <= deadline, so none outlives it (core waits coreWaitPastDeadline more).
	if need := suPreParkTimeout + 2*applierRuntimeMax; need > suRunWindow {
		t.Errorf("the run window %v does not cover %v", suRunWindow, need)
	}
	if suRunWindow+suPreParkTimeout > 3*time.Hour { // server.maxParkWindow, measured from the start of the run
		t.Errorf("the run window does not fit the server's park window")
	}
	if coreWaitPastDeadline <= suSafetyMargin {
		t.Errorf("core gives the run up %v past the deadline, before the host's safety net (%v) settles it", coreWaitPastDeadline, suSafetyMargin)
	}
}

// State formats (spec 6.14, review M6): the files of the self-update as this release writes them (taken at the
// phase checking, testdata/selfupdate-state-v1) read with this release's strict readers. A release that changes
// a format adds its own folder, and the folder of the release before must still read: the previous host may be
// put back on the state the new one wrote before the run succeeded.
func TestTheStateFormatsOfEachReleaseRead(t *testing.T) {
	t.Parallel()
	dirs, _ := filepath.Glob(filepath.Join("testdata", "selfupdate-state-*"))
	if len(dirs) == 0 {
		t.Fatal("no state folder")
	}
	for _, d := range dirs {
		read := func(name string) []byte {
			b, err := os.ReadFile(filepath.Join(d, name)) //nolint:gosec // test: fixed names
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		if _, err := parseSUVersions(read(suVersionsName)); err != nil {
			t.Errorf("%s versions: %v", d, err)
		}
		if j, err := parseSUJournal(read(suJournalName)); err != nil || j.Phase != phChecking {
			t.Errorf("%s journal: %v", d, err)
		}
		if _, err := parseSUStarted(read(suStartedName)); err != nil {
			t.Errorf("%s started: %v", d, err)
		}
	}
}

// A test build of vedette-host is refused on a release host and taken by a test host (slice 6 lab, D-382).
func TestRefuseTestBuild(t *testing.T) {
	for _, c := range []struct {
		target, running string
		testOnly, want  bool
	}{
		{"1.4.0-test.1", "1.3.0", false, true},
		{"1.4.0-test.1", "1.3.0", true, false},
		{"0.0.1-test.2", "0.0.1-test.1", false, false},
		{"1.4.0", "1.3.0", false, false},
		{"1.4.0", "1.3.0-test.1", false, false},
	} {
		if got := refuseTestBuild(c.target, c.running, c.testOnly); got != c.want {
			t.Errorf("refuseTestBuild(%q, %q, %v) = %v, want %v", c.target, c.running, c.testOnly, got, c.want)
		}
	}
}
