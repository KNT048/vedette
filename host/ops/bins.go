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

// Binary names in the command runner. The paths are constants of the appliance (Debian and Ubuntu
// ship them there); only tests replace them, through Deps.BinPaths, and never the validators.
const (
	binAptGet    = "apt-get"
	binAptConfig = "apt-config"
	binDpkg      = "dpkg"
	binSystemctl = "systemctl"
	binJournal   = "journalctl"
)

// binNetplan names the netplan grammar of validateNetplan. It is NOT in the production runner
// (D-87 style review of slice 3-3): netplan generate returns with slice 3-4 and a directory the host
// creates itself. Only a CI test builds a runner with it.
const binNetplan = "netplan"

var prodPaths = map[string]string{
	binAptGet:    "/usr/bin/apt-get",
	binAptConfig: "/usr/bin/apt-config",
	binDpkg:      "/usr/bin/dpkg",
	binSystemctl: "/usr/bin/systemctl",
	binJournal:   "/usr/bin/journalctl",
}

// The fixed timers of unattended security updates (spec 6.3).
var aptTimers = []string{"apt-daily.timer", "apt-daily-upgrade.timer"}

// pkgNameRE is the Debian package-name rule with an optional architecture qualifier as apt prints
// it on multiarch. The first character is alphanumeric, so a name can never look like an option,
// and so is the last: apt reads a trailing "-" as "remove this package" and a trailing "+" as
// "install it".
var pkgNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,126}[a-z0-9](:[a-z0-9][a-z0-9-]{0,18}[a-z0-9])?$`)

// maxInstallNames bounds the argv of one apt install.
const maxInstallNames = 3000

var (
	argsUpdate     = []string{"-q", "update"}
	argsSimulate   = []string{"-q", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"}
	argsInstallPre = []string{
		"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
		"--no-remove", "install", "--only-upgrade",
	}
)

// validateApt accepts exactly three shapes of argv: the index update, the simulated upgrade
// (dist-upgrade only ever with -s: never a real one, never a release upgrade), and an
// upgrade-only install of named packages that pass the package-name rule.
func validateApt(args []string) error {
	switch {
	case slices.Equal(args, argsUpdate), slices.Equal(args, argsSimulate):
		return nil
	case len(args) > len(argsInstallPre) && slices.Equal(args[:len(argsInstallPre)], argsInstallPre):
		names := args[len(argsInstallPre):]
		if len(names) > maxInstallNames {
			return errors.New("too many packages")
		}
		for _, n := range names {
			if !pkgNameRE.MatchString(n) {
				return fmt.Errorf("package name %q is not valid", clipText(n, 40))
			}
		}
		return nil
	}
	return errors.New("not one of the fixed apt command lines")
}

func exactly(want ...string) func([]string) error {
	return func(args []string) error {
		if !slices.Equal(args, want) {
			return errors.New("not the fixed command line")
		}
		return nil
	}
}

// journalUnits is the closed set of units logs.export may read (spec 6.13).
var journalUnits = []string{"vedette-core", "vedette-sensor", "vedette-honeypot", "vedette-scan", "vedette-greenbone", "vedette-host"}

var journalTimeRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$`)

func validateJournal(args []string) error {
	if len(args) != 9 || args[0] != "-u" || !slices.Contains(journalUnits, args[1]) ||
		args[2] != "--since" || !journalTimeRE.MatchString(args[3]) ||
		args[4] != "--until" || !journalTimeRE.MatchString(args[5]) ||
		args[6] != "-o" || args[7] != "json" || args[8] != "--no-pager" {
		return errors.New("not the fixed journalctl command line")
	}
	return nil
}

// validateSystemctl accepts the few verbs the OS commands need, on fixed units only: the core
// unit from host.conf (stop/start/is-active, for restores and health), the two apt timers, reboot.
func validateSystemctl(coreUnit string) func([]string) error {
	return func(args []string) error {
		switch {
		case slices.Equal(args, []string{"reboot"}):
			return nil
		case len(args) == 2 && coreUnit != "" && args[1] == coreUnit && (args[0] == "stop" || args[0] == "start" || args[0] == "is-active"):
			return nil
		case len(args) == 2 && args[0] == "is-enabled" && slices.Contains(aptTimers, args[1]):
			return nil
		case len(args) == 4 && (args[0] == "enable" || args[0] == "disable") && args[1] == "--now" && slices.Equal(args[2:], aptTimers):
			return nil
		}
		return errors.New("not one of the fixed systemctl command lines")
	}
}

// netplanRootDirRE is the directory netplan generate may be pointed at: absolute, clean, made of plain
// characters, at least two levels deep and not under a system directory. "generate" without
// --root-dir, or with "/", would regenerate the real network configuration, so those are refused.
// The grammar checks the string only: a path that is a symlink to "/" passes it. That is why no
// production runner has it (slice 3-4 creates the directory itself, root-owned and opened without
// following links); only a CI test runs it, on a directory of its own.
var netplanRootDirRE = regexp.MustCompile(`^(/[A-Za-z0-9_.-]+){2,16}$`)

var systemTopDirs = []string{"bin", "boot", "dev", "etc", "lib", "lib64", "proc", "root", "run", "sbin", "sys", "usr", "var"}

// validateNetplan accepts exactly "generate --root-dir <dir>" (the netplan apply of net.apply
// joins the grammar with slice 3-4).
func validateNetplan(args []string) error {
	if len(args) != 3 || args[0] != "generate" || args[1] != "--root-dir" {
		return errors.New("not the fixed netplan command line")
	}
	d := args[2]
	if len(d) > 255 || !netplanRootDirRE.MatchString(d) || filepath.Clean(d) != d { // Clean removes "." and ".." segments, so any that were there make it differ
		return errors.New("the netplan root directory is not a plain absolute path")
	}
	if slices.Contains(systemTopDirs, strings.Split(d, "/")[1]) {
		return errors.New("the netplan root directory is under a system directory")
	}
	return nil
}

// newRunner builds the runner of the OS commands: PATH, LANG=C and DEBIAN_FRONTEND=noninteractive,
// no shell. paths overrides the constant paths (tests).
func newRunner(log logger, coreUnit string, paths map[string]string, streamLimit int64) (*vexec.Runner, error) {
	p := func(name string) string {
		if v, ok := paths[name]; ok {
			return v
		}
		return prodPaths[name]
	}
	return newCommandRunner(log,
		vexec.Binary{Name: binAptGet, Path: p(binAptGet), Validate: validateApt, MaxOutput: 16 << 20},
		vexec.Binary{Name: binAptConfig, Path: p(binAptConfig), Validate: exactly("dump")},
		vexec.Binary{Name: binDpkg, Path: p(binDpkg), Validate: exactly("--audit")},
		vexec.Binary{Name: binSystemctl, Path: p(binSystemctl), Validate: validateSystemctl(coreUnit)},
		vexec.Binary{Name: binJournal, Path: p(binJournal), Validate: validateJournal, MaxOutput: streamLimit + 1},
	)
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
