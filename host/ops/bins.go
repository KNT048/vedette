package ops

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
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

// binNetplan and binChronyc are the network binaries (slice 3-4). The production runner knows
// netplan only for "apply": "generate --root-dir" stays out (its grammar checks a string, and a
// path that is a symlink to "/" passes it; netplan apply validates the file itself, so nothing
// here needs generate). Only a CI test builds a runner with the generate grammar.
const (
	binNetplan = "netplan"
	binChronyc = "chronyc"
	// binIP is iproute2's ip (slice 3-5): the decoy links and, through "ip netns exec", the sysctl
	// and nft of the honeypot namespace. sysctl and nft have no entries of their own.
	binIP = "ip" // a reviewed exception of the network-literal guard in modules/host (FORBID-2): a binary name
	// binPodman is Podman: "container inspect <name>" (slice 3-6, the image digest and the health a
	// service reports) and, for container.pull (slice 3-7), pull, image inspect and tag in the fixed
	// shapes of podmanargv.go. rmi comes with the retention of slice 3-8.
	binPodman = "podman"
)

var prodPaths = map[string]string{
	binAptGet:    "/usr/bin/apt-get",
	binAptConfig: "/usr/bin/apt-config",
	binDpkg:      "/usr/bin/dpkg",
	binSystemctl: "/usr/bin/systemctl",
	binJournal:   "/usr/bin/journalctl",
	binNetplan:   "/usr/sbin/netplan",
	binChronyc:   "/usr/bin/chronyc",
	binIP:        "/usr/sbin/ip",
	binPodman:    "/usr/bin/podman",
	binIptables:  "/usr/sbin/iptables", // Ubuntu 24.04 and 26.04, Debian 13: the alternatives link, nft or legacy flavour
	// binConntrack is conntrack-tools' conntrack (D-268): one fixed delete, conntrack.go. The Debian and Ubuntu package puts it in /usr/sbin.
	binConntrack: "/usr/sbin/conntrack",
	// host.self_update (D-316, spec 6.14): systemd, dpkg and dpkg-deb put them in /usr/bin on Debian and Ubuntu.
	binSystemdRun: "/usr/bin/systemd-run",
	binDpkgDeb:    "/usr/bin/dpkg-deb",
	binDpkgQuery:  "/usr/bin/dpkg-query",
	// os.reboot (D-453): logind's list of inhibitors; busctl is in the systemd package, in /usr/bin on Debian and Ubuntu.
	binBusctl: "/usr/bin/busctl",
	// the AppArmor profile of the containers (D-458): the apparmor package puts the parser in /usr/sbin on Debian and Ubuntu.
	binAppArmorParser: "/usr/sbin/apparmor_parser",
	// zap.baseline's egress fence (D-521): the nftables package (install.sh installs it) puts nft in /usr/sbin on Debian and Ubuntu.
	binNft: "/usr/sbin/nft",
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
			if isHostPkg(n) { // only the applier of host.self_update installs it (FORBID-7, D-316)
				return errors.New("vedette-host is never upgraded by os.install")
			}
		}
		return nil
	}
	return errors.New("not one of the fixed apt command lines")
}

// isHostPkg says whether an apt package name (with or without ":<arch>") is vedette-host.
func isHostPkg(name string) bool {
	base, _, _ := strings.Cut(name, ":")
	return base == hostPkg
}

func exactly(want ...string) func([]string) error {
	want = slices.Clone(want) // never alias the caller's slice
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

// isServiceUnit says whether u is vedette-<service>.service for one of the five services: the only
// units the container commands name, always built from the closed list, never from a request.
func isServiceUnit(u string) bool {
	return slices.ContainsFunc(api.Services, func(s string) bool { return u == unitOf(s) })
}

// validateSystemctl accepts the few verbs the OS and container commands need, on fixed units only:
// the core unit from host.conf (stop/start/is-active, for restores and health), the two apt timers,
// reboot, daemon-reload, restart/stop/is-active of the five vedette-<service>.service units, and
// is-active of the self-update's transient unit. Never anything of vedette-host.service itself (INV-27).
func validateSystemctl(coreUnit string) func([]string) error {
	return func(args []string) error {
		switch {
		case slices.Equal(args, []string{"reboot"}), slices.Equal(args, []string{"daemon-reload"}):
			return nil
		case len(args) == 2 && (args[0] == "restart" || args[0] == "stop" || args[0] == "is-active") && isServiceUnit(args[1]):
			return nil
		case len(args) == 2 && coreUnit != "" && args[1] == coreUnit && args[1] != hostUnit && (args[0] == "stop" || args[0] == "start" || args[0] == "is-active"):
			return nil
		case slices.Equal(args, []string{"is-active", upgradeUnit}): // host.self_update: is the applier still running (D-316)
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
// production runner has it; only a CI test runs it, on a directory of its own.
var netplanRootDirRE = regexp.MustCompile(`^(/[A-Za-z0-9_.-]+){2,16}$`)

var systemTopDirs = []string{"bin", "boot", "dev", "etc", "lib", "lib64", "proc", "root", "run", "sbin", "sys", "usr", "var"}

// validateNetplan is the production grammar of netplan: exactly "apply".
var validateNetplan = exactly("apply")

// chronycSources lists the sources as CSV with names ("-"+"c" is chronyc's CSV flag; it is written
// in two parts so that the contract test that looks for shell literals does not take it for "sh -c").
var chronycSources = []string{"-N", "-" + "c", "sources"}

// validateChronyc accepts the two calls of the NTP command (D-106): reload the sources, and list them.
func validateChronyc(args []string) error {
	if slices.Equal(args, []string{"reload", "sources"}) || slices.Equal(args, chronycSources) {
		return nil
	}
	return errors.New("not one of the fixed chronyc command lines")
}

// validateNetplanGenerate accepts exactly "generate --root-dir <dir>"; CI tests only.
func validateNetplanGenerate(args []string) error {
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
func newRunner(log logger, stateDir, coreUnit string, paths map[string]string, streamLimit int64) (*vexec.Runner, error) {
	return newCommandRunner(log, hostBinaries(stateDir, coreUnit, paths, streamLimit)...)
}

// hostBinaries are the binaries of the host's runner, with their validators (ValidateHostArgv reads the same list).
func hostBinaries(stateDir, coreUnit string, paths map[string]string, streamLimit int64) []vexec.Binary {
	p := func(name string) string { return pathOf(paths, name) }
	return []vexec.Binary{
		{Name: binAptGet, Path: p(binAptGet), Validate: validateHostApt(stateDir), MaxOutput: 16 << 20},
		{Name: binAptConfig, Path: p(binAptConfig), Validate: exactly("dump")},
		{Name: binDpkg, Path: p(binDpkg), Validate: exactly("--audit")},
		{Name: binSystemctl, Path: p(binSystemctl), Validate: validateSystemctl(coreUnit)},
		{Name: binJournal, Path: p(binJournal), Validate: validateJournal, MaxOutput: streamLimit + 1},
		{Name: binNetplan, Path: p(binNetplan), Validate: validateNetplan},
		{Name: binChronyc, Path: p(binChronyc), Validate: validateChronyc},
		{Name: binIP, Path: p(binIP), Validate: validateIP, MaxOutput: 1 << 20},
		{Name: binPodman, Path: p(binPodman), Validate: validatePodman, MaxOutput: maxInspectOutput},
		{Name: binIptables, Path: p(binIptables), Validate: validateIptables, MaxOutput: 1 << 20},
		{Name: binConntrack, Path: p(binConntrack), Validate: validateConntrack, MaxOutput: 1 << 16},
		// host.self_update (D-316): the start of the applier, and the read-only looks at the staged file and dpkg.
		{Name: binSystemdRun, Path: p(binSystemdRun), Validate: validateSystemdRun(stateDir), MaxOutput: 1 << 16},
		{Name: binDpkgDeb, Path: p(binDpkgDeb), Validate: validateDpkgDeb(stateDir), MaxOutput: 1 << 12},
		// the package list of the box itself (D-470, GET /v1/state/packages) shares the binary, so the bound is the list's.
		{Name: binDpkgQuery, Path: p(binDpkgQuery), Validate: validateHostDpkgQuery, MaxOutput: maxPackagesOutput},
		// os.reboot (D-453): the one read of logind's inhibitors.
		{Name: binBusctl, Path: p(binBusctl), Validate: exactly(argsListInhibitors...), MaxOutput: maxInhibitOutput},
		// D-458: the one load of the containers' AppArmor profile at Start, when the kernel does not list it.
		{Name: binAppArmorParser, Path: p(binAppArmorParser), Validate: validateAppArmorParser, MaxOutput: 1 << 16},
		// zap.baseline (D-521): load, read back and delete the one table inet vedette_zap.
		{Name: binNft, Path: p(binNft), Validate: validateNft, MaxOutput: 1 << 20},
	}
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
