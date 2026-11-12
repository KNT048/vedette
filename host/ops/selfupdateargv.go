package ops

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	vexec "github.com/knt048/vedette/core/exec"
)

// The argv of host.self_update (docs/specs/host-api.md section 6.14 "Argv mới", D-316). There are two
// runners. The host runner (newRunner) gains the read-only and simulated forms and the one systemd-run that
// starts the applier; it never accepts apt-get install of a file, dpkg -i, or a restart of vedette-host
// itself (INV-27). The applier runner (newApplierRunner) is built only in -self-update-apply mode, outside
// the host's cgroup, and is the only one that installs. Every path is built here from the state directory
// (a constant of the build or the checked -state-dir flag) and a 64-hex name or a name that passes the one
// package file-name validator; nothing comes from a request.

const (
	binSystemdRun = "systemd-run"
	binDpkgDeb    = "dpkg-deb"
	binDpkgQuery  = "dpkg-query"

	hostPkg     = "vedette-host"
	hostUnit    = "vedette-host.service"
	upgradeUnit = "vedette-host-upgrade.service"
)

// selfupdate directory layout under the state directory.
const (
	suDirName      = "selfupdate"
	suStagedName   = "staged"
	suPackagesName = "packages"
	suApplierName  = "applier"
)

func suDir(stateDir string) string       { return filepath.Join(stateDir, suDirName) }
func stagedDir(stateDir string) string   { return filepath.Join(stateDir, suDirName, suStagedName) }
func keptDir(stateDir string) string     { return filepath.Join(stateDir, suDirName, suPackagesName) }
func applierPath(stateDir string) string { return filepath.Join(stateDir, suDirName, suApplierName) }

var stagedNameRE = regexp.MustCompile(`^[0-9a-f]{64}\.deb$`)

// stagedPath is <state>/selfupdate/staged/<sha256>.deb.
func stagedPath(stateDir, sha string) string { return filepath.Join(stagedDir(stateDir), sha+".deb") }

// isStagedPath accepts exactly <state>/selfupdate/staged/<64 hex>.deb.
func isStagedPath(stateDir, p string) bool {
	rest, ok := strings.CutPrefix(p, stagedDir(stateDir)+"/")
	return ok && stagedNameRE.MatchString(rest)
}

// isKeptPath accepts exactly <state>/selfupdate/packages/vedette-host_<SemVer>_<amd64|arm64>.deb.
func isKeptPath(stateDir, p string) bool {
	rest, ok := strings.CutPrefix(p, keptDir(stateDir)+"/")
	if !ok {
		return false
	}
	_, _, ok = parseHostPkgName(rest)
	return ok
}

// --- the host runner's forms ---------------------------------------------------------------------

// argsDpkgQueryHost is the one dpkg-query: the version and the status of vedette-host, as "<version>|<status>".
var argsDpkgQueryHost = []string{"-W", "-f=${Version}|${db:Status-Status}", hostPkg}

var argsDebFields = []string{"Package", "Version", "Architecture"}

func dpkgDebFieldArgv(staged string) []string {
	return append([]string{"--field", staged}, argsDebFields...)
}

func validateDpkgDeb(stateDir string) func([]string) error {
	return func(args []string) error {
		if len(args) != 5 || args[0] != "--field" || (!isStagedPath(stateDir, args[1]) && !isKeptPath(stateDir, args[1])) || !slices.Equal(args[2:], argsDebFields) {
			return errors.New("not the fixed dpkg-deb command line")
		}
		return nil
	}
}

func validateDpkgQuery(args []string) error {
	if !slices.Equal(args, argsDpkgQueryHost) {
		return errors.New("not the fixed dpkg-query command line")
	}
	return nil
}

// argsAptSimInstallPre is the simulated install of the staged file (spec 6.14 Run 3b): never without -s.
var argsAptSimInstallPre = []string{"-s", "-q", "-o", "Debug::NoLocking=1", "--no-remove", "--no-install-recommends", "install"}

func aptSimInstallArgv(staged string) []string {
	return append(slices.Clone(argsAptSimInstallPre), staged)
}

// validateHostApt is the host runner's apt-get: the three shapes of os.check and os.install (validateApt)
// and the simulated install of the staged file. It never accepts a real install of a file.
func validateHostApt(stateDir string) func([]string) error {
	return func(args []string) error {
		if validateApt(args) == nil {
			return nil
		}
		if len(args) == len(argsAptSimInstallPre)+1 && slices.Equal(args[:len(argsAptSimInstallPre)], argsAptSimInstallPre) && isStagedPath(stateDir, args[len(args)-1]) {
			return nil
		}
		return errors.New("not one of the fixed apt command lines")
	}
}

// systemdRunDescription is the transient unit's description (one argv element).
const systemdRunDescription = "--description=vedette-host self-update (applier)"

// systemdRunArgv starts the applier copy in its own transient unit (spec 6.14 Run 7). runID is the only
// part that changes; RuntimeMaxSec is applierRuntimeMax.
func systemdRunArgv(stateDir, runID string) []string {
	return []string{
		"--unit=" + strings.TrimSuffix(upgradeUnit, ".service"), "--collect", "--quiet", "--service-type=exec",
		fmt.Sprintf("--property=RuntimeMaxSec=%dmin", int(applierRuntimeMax.Minutes())),
		"--setenv=NEEDRESTART_MODE=l", "--setenv=NEEDRESTART_SUSPEND=1", systemdRunDescription,
		applierPath(stateDir), applyFlag, runID,
	}
}

// applyFlag is the flag of cmd/vedette-host that runs the applier.
const applyFlag = "-self-update-apply"

var runIDArgRE = regexp.MustCompile(`^rn_[0-9a-f]{16}$`)

// validateSystemdRun accepts exactly systemdRunArgv with a well-formed run id.
func validateSystemdRun(stateDir string) func([]string) error {
	want := systemdRunArgv(stateDir, "")
	return func(args []string) error {
		if len(args) != len(want) || !slices.Equal(args[:len(want)-1], want[:len(want)-1]) || !runIDArgRE.MatchString(args[len(args)-1]) {
			return errors.New("not the fixed systemd-run command line")
		}
		return nil
	}
}

// --- the applier runner's forms --------------------------------------------------------------------

// argsAptInstallHead and argsAptInstallTail frame the applier's apt-get install (spec 6.14 applier step 3): apt
// waits for dpkg's frontend lock itself for what is left of the lock budget (DPkg::Lock::Timeout, 0 to 600 s),
// removes nothing, installs new dependencies from the mirror.
var (
	argsAptInstallHead = []string{"-y", "-q", "--no-remove", "--no-install-recommends", "-o"}
	argsAptInstallTail = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	aptLockTimeoutRE   = regexp.MustCompile(`^DPkg::Lock::Timeout=(0|[1-9][0-9]{0,2})$`)
)

// aptInstallArgv installs the staged file, or with downgrade the kept file of the version that was running
// (the rollback; --allow-downgrades only ever with a kept file, never with the staged one). lockS is apt's own
// lock wait in seconds, clamped to 0..600.
func aptInstallArgv(file string, downgrade bool, lockS int) []string {
	a := slices.Clone(argsAptInstallHead)
	a = append(a, fmt.Sprintf("DPkg::Lock::Timeout=%d", min(max(lockS, 0), int(applierLockBudget.Seconds()))))
	a = append(a, argsAptInstallTail...)
	if downgrade {
		a = append(a, "--allow-downgrades")
	}
	return append(a, "install", file)
}

func validateApplierApt(stateDir string) func([]string) error {
	return func(args []string) error {
		h, t := len(argsAptInstallHead), len(argsAptInstallTail)
		bad := errors.New("not one of the fixed apt command lines of the applier")
		if len(args) < h+1+t+2 || !slices.Equal(args[:h], argsAptInstallHead) || !slices.Equal(args[h+1:h+1+t], argsAptInstallTail) {
			return bad
		}
		if m := aptLockTimeoutRE.FindStringSubmatch(args[h]); m == nil || len(m[1]) > 3 || atoiMax(m[1]) > int(applierLockBudget.Seconds()) {
			return bad
		}
		rest := args[h+1+t:]
		switch {
		case len(rest) == 2 && rest[0] == "install" && isStagedPath(stateDir, rest[1]):
			return nil
		case len(rest) == 3 && rest[0] == "--allow-downgrades" && rest[1] == "install" && isKeptPath(stateDir, rest[2]):
			return nil
		}
		return bad
	}
}

// atoiMax reads up to three decimal digits (the regexp checked them).
func atoiMax(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func dpkgInstallArgv(file string) []string { return []string{"-i", file} }

func validateApplierDpkg(stateDir string) func([]string) error {
	return func(args []string) error {
		switch {
		case slices.Equal(args, []string{"--audit"}):
			return nil
		case len(args) == 2 && args[0] == "-i" && (isStagedPath(stateDir, args[1]) || isKeptPath(stateDir, args[1])):
			return nil
		}
		return errors.New("not one of the fixed dpkg command lines of the applier")
	}
}

var (
	argsShowHost    = []string{"show", hostUnit, "-p", "ActiveState,MainPID,NRestarts"}
	argsRestartHost = []string{"restart", hostUnit}
)

func validateApplierSystemctl(args []string) error {
	if slices.Equal(args, argsShowHost) || slices.Equal(args, argsRestartHost) {
		return nil
	}
	return errors.New("not one of the fixed systemctl command lines of the applier")
}

// applierEnv is the environment of every child of the applier (spec 6.14, as install.sh apt_run).
var applierEnv = []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "NEEDRESTART_SUSPEND=1"}

func pathOf(paths map[string]string, name string) string {
	if v, ok := paths[name]; ok {
		return v
	}
	return prodPaths[name]
}

// applierBinaries are the binaries of the applier's runner (built with vexec.NewRunner in -self-update-apply mode,
// slice 2b); paths overrides the constant paths (tests).
func applierBinaries(stateDir string, paths map[string]string) []vexec.Binary {
	bins := []vexec.Binary{
		{Name: binAptGet, Path: pathOf(paths, binAptGet), Validate: validateApplierApt(stateDir), MaxOutput: 16 << 20},
		{Name: binDpkg, Path: pathOf(paths, binDpkg), Validate: validateApplierDpkg(stateDir), MaxOutput: 4 << 20},
		{Name: binDpkgQuery, Path: pathOf(paths, binDpkgQuery), Validate: validateDpkgQuery, MaxOutput: 1 << 12},
		{Name: binSystemctl, Path: pathOf(paths, binSystemctl), Validate: validateApplierSystemctl, MaxOutput: 1 << 12},
	}
	for i := range bins {
		bins[i].Env = slices.Clone(applierEnv)
	}
	return bins
}

// ValidateHostArgv runs the host runner's validator of bin on args (contract tests and fuzz): the same
// validators newRunner gives the runner.
func ValidateHostArgv(stateDir, coreUnit, bin string, args []string) error {
	return validateIn(hostBinaries(stateDir, coreUnit, nil, 1), bin, args)
}

// ValidateApplierArgv is ValidateHostArgv for the applier runner.
func ValidateApplierArgv(stateDir, bin string, args []string) error {
	return validateIn(applierBinaries(stateDir, nil), bin, args)
}

func validateIn(bins []vexec.Binary, bin string, args []string) error {
	for _, b := range bins {
		if b.Name == bin {
			return b.Validate(args)
		}
	}
	return fmt.Errorf("%s is not a binary of this runner", bin)
}
