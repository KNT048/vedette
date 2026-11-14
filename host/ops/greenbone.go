package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// OpenVAS (Greenbone Community Edition; host-api §6.16, D-529, FULL-2): greenbone.up, greenbone.down and greenbone.sync_feed run
// Greenbone's official compose project with `podman compose` and the docker-compose v2 provider, through the runner with fixed argv:
//
//	podman compose -p greenbone-community-edition -f /usr/lib/vedette/greenbone/compose.yaml -f /usr/lib/vedette/greenbone/compose.vedette.yaml
//	    up -d | stop | ps --services --status running | pull <the seven feed services> | up -d <the seven feed services>
//	podman compose version --short
//	podman exec -u gvmd greenbone-community-edition-gvmd-1 gvmd --user=admin --new-password=<48 hex>
//	systemctl enable --now podman.socket | systemctl is-active podman.socket
//	apt-get update | apt-get ... --no-install-recommends install docker-compose-v2 (Ubuntu) or docker-compose (Debian)
//
// The project is not Vedette's: its name, its volumes and its images are Greenbone's own, and install.sh --uninstall never names them.
// The two compose files ship in the vedette-host package (deploy/greenbone): Greenbone's file, unmodified apart from the digest pins, and
// Vedette's override (the gvmd socket on a host directory, the web interface and its helpers off, labels).
//
// The GMP password is core's (core/secrets); it reaches the host as the args of greenbone.up and leaves it only as the argv of gvmd's
// own command for it (Greenbone's documented way: https://greenbone.github.io/docs/latest/22.4/container/workflows.html, "Setting up an
// admin user password"). That argv is visible in the box's process list (podman exec, then gvmd in the container) for the second the
// command runs, to local users of the box only, never to a container; gvmd has no other way to take it. It is never logged, audited
// (the server redacts the key "password"), stored by the host or put in an error.

const (
	gbProject       = "greenbone-community-edition"
	gbFilesDir      = "/usr/lib/vedette/greenbone"
	gbComposeFile   = gbFilesDir + "/compose.yaml"
	gbOverrideFile  = gbFilesDir + "/compose.vedette.yaml"
	gbGvmdContainer = gbProject + "-gvmd-1" // docker-compose v2's name of the first container of the service gvmd
	// gbGvmdUID is the uid and gid of the user gvmd in Greenbone's gvmd image (addgroup/adduser --gid/--uid 1001 in its Dockerfile):
	// gvmd makes its socket in the directory, which the host gives to it.
	gbGvmdUID        = 1001
	gbPodmanSocket   = "podman.socket"
	gbProviderFloorM = 2
	gbProviderFloorN = 24 // the oldest docker-compose v2 on a supported release (Ubuntu 24.04's 2.24.6): profiles and merging by target

	gbUpLimit    = 60 * time.Minute // exposure's own bound of Up: the first one pulls about 9 GB and fills the feed volumes
	gbSyncLimit  = 60 * time.Minute
	gbDownLimit  = 5 * time.Minute
	gbStepWait   = 2 * time.Minute  // one podman, systemctl or apt-get update call other than the long ones
	gbAptWait    = 15 * time.Minute // the install of the provider package
	gbLoginEvery = 10 * time.Second // how often the login is tried while gvmd starts
	gbLoginWait  = 20 * time.Minute // gvmd migrates its database and creates its admin user before the login can be set
)

// gbFeedServices are the seven feed data services of Greenbone's feed update, in the order of its workflow page.
var gbFeedServices = []string{"notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data", "cert-bund-data", "report-formats", "data-objects"}

// gbMustRun are the services a scan needs running after up: the manager, the scanner, the database and the scanner's store.
var gbMustRun = []string{"gvmd", "ospd-openvas", "pg-gvm", "redis-server"}

// gbProviderPkg is the package of docker-compose v2 per distribution: Ubuntu 24.04's "docker-compose" is the old Python v1 (its v2 is
// docker-compose-v2, which 26.04 keeps), Debian 13's "docker-compose" is v2 (2.26.1). Sources: packages.ubuntu.com, packages.debian.org.
var gbProviderPkg = map[string]string{"ubuntu": "docker-compose-v2", "debian": "docker-compose"}

var (
	gbPasswordRE = regexp.MustCompile(`^[0-9a-f]{48}$`)
	gbVersionRE  = regexp.MustCompile(`(?m)^v?([0-9]+)\.([0-9]+)\.[0-9]+`)
	errGBArgv    = errors.New("not one of the fixed OpenVAS command lines")
	errGBStopped = errors.New("ops: stopped by greenbone.down")
)

// ---- argv (the runner's validators accept exactly these) ----

func gbComposeArgv(verb ...string) []string {
	return append([]string{"compose", "-p", gbProject, "-f", gbComposeFile, "-f", gbOverrideFile}, verb...)
}

func gbUpArgv() []string       { return gbComposeArgv("up", "-d") }
func gbStopArgv() []string     { return gbComposeArgv("stop") }
func gbPsArgv() []string       { return gbComposeArgv("ps", "--services", "--status", "running") }
func gbPullFeedArgv() []string { return gbComposeArgv(append([]string{"pull"}, gbFeedServices...)...) }
func gbUpFeedArgv() []string {
	return gbComposeArgv(append([]string{"up", "-d"}, gbFeedServices...)...)
}
func gbVersionArgv() []string { return []string{"compose", "version", "--short"} }

// gbLoginArgv sets the GMP password of the admin user, as Greenbone's documentation does it (gvmd --new-password, as the user gvmd).
func gbLoginArgv(password string) []string {
	return []string{"exec", "-u", "gvmd", gbGvmdContainer, "gvmd", "--user=" + api.GreenboneUser, "--new-password=" + password}
}

// isGreenbonePodmanArgv says whether args is one of the fixed podman shapes of the OpenVAS commands. The login's password must be
// 48 lower-case hex characters; nothing else varies.
func isGreenbonePodmanArgv(args []string) bool {
	for _, want := range [][]string{gbUpArgv(), gbStopArgv(), gbPsArgv(), gbPullFeedArgv(), gbUpFeedArgv(), gbVersionArgv()} {
		if slices.Equal(args, want) {
			return true
		}
	}
	if len(args) == 7 {
		pw, ok := strings.CutPrefix(args[6], "--new-password=")
		return ok && gbPasswordRE.MatchString(pw) && slices.Equal(args, gbLoginArgv(pw))
	}
	return false
}

var (
	argsPodmanSocketEnable = []string{"enable", "--now", gbPodmanSocket}
	argsPodmanSocketActive = []string{"is-active", gbPodmanSocket}
)

// gbAptInstallArgv installs the compose provider: never a removal, the administrator's configuration files kept.
func gbAptInstallArgv(pkg string) []string {
	return []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--no-remove", "--no-install-recommends", "install", pkg}
}

func isGreenboneAptArgv(args []string) bool {
	for _, pkg := range gbProviderPkg {
		if slices.Equal(args, gbAptInstallArgv(pkg)) {
			return true
		}
	}
	return false
}

// ---- the commands ----

func gbArgs(a api.GreenboneUpArgs) error {
	if !gbPasswordRE.MatchString(a.Password) {
		return server.Invalid("password", "must be 48 lower-case hex characters") // never the value
	}
	return nil
}

func (o *Ops) cmdGreenboneUp() server.Command {
	// Not a write command, like zap.baseline: the first up takes many minutes and must not hold the global lock of container.*,
	// the decoys and updates. It touches only Greenbone's project and its own directory, one OpenVAS operation at a time.
	return server.Define(server.Spec[api.GreenboneUpArgs]{
		Name: api.CmdGreenboneUp, Write: false, Timeout: gbUpLimit + 10*time.Minute,
		Validate: func(a *api.GreenboneUpArgs) error { return gbArgs(*a) },
		Run: func(ctx context.Context, rc *server.RunContext, a api.GreenboneUpArgs) (any, error) {
			if err := gbArgs(a); err != nil {
				return nil, err
			}
			return struct{}{}, o.gbOp(ctx, false, gbUpLimit, func(ctx context.Context) error { return o.gbUp(ctx, rc.Log, a.Password) })
		},
	})
}

func (o *Ops) cmdGreenboneDown() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdGreenboneDown, Write: false, Timeout: gbDownLimit + time.Minute,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return struct{}{}, o.gbOp(ctx, true, gbDownLimit, func(ctx context.Context) error { return o.gbDown(ctx, rc.Log) })
		},
	})
}

func (o *Ops) cmdGreenboneSyncFeed() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdGreenboneSyncFeed, Write: false, Timeout: gbSyncLimit + 10*time.Minute,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return struct{}{}, o.gbOp(ctx, false, gbSyncLimit, func(ctx context.Context) error { return o.gbSyncFeed(ctx, rc.Log) })
		},
	})
}

// gbOp runs f as the one OpenVAS operation of the host, bounded by limit. Another one waits for it (within its own bound); down
// (preempt) first cancels the one that runs, so turning OpenVAS off never waits for an image pull of up to an hour.
func (o *Ops) gbOp(ctx context.Context, preempt bool, limit time.Duration, f func(context.Context) error) error {
	if preempt {
		o.gbMu.Lock()
		if o.gbCancel != nil {
			o.gbCancel()
		}
		o.gbMu.Unlock()
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	select {
	case o.gbSem <- struct{}{}:
	case <-ctx.Done():
		return fail(api.CodeGreenboneFailed, "Another OpenVAS operation of the host did not end in time.")
	}
	defer func() { <-o.gbSem }()
	cctx, stop := context.WithCancelCause(ctx)
	o.gbMu.Lock()
	o.gbCancel = func() { stop(errGBStopped) }
	o.gbMu.Unlock()
	defer func() {
		o.gbMu.Lock()
		o.gbCancel = nil
		o.gbMu.Unlock()
		stop(nil)
	}()
	err := f(cctx)
	switch {
	case err == nil:
	case errors.Is(context.Cause(cctx), errGBStopped):
		return fail(api.CodeGreenboneCancelled, "OpenVAS was turned off while this ran.")
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return fail(api.CodeGreenboneFailed, fmt.Sprintf("OpenVAS: the host's step did not finish within its limit of %d minutes.", int(limit/time.Minute)))
	}
	return err
}

// gbExecFn runs one allowlisted binary (o.execIn; internal tests replace it).
func (o *Ops) gx() zapExecFn {
	if o.gbExec != nil {
		return o.gbExec
	}
	return o.execIn
}

// gbStep runs one call bounded by wait (or ctx, whichever ends first) and reports its exit code (-1 with the error when it could not run).
func (o *Ops) gbStep(ctx context.Context, wait time.Duration, name string, args ...string) (string, int, error) {
	cctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	res, code, err := o.gx()(cctx, name, nil, args...)
	if err != nil {
		return "", -1, err
	}
	return string(res.Stdout), code, nil
}

// gbFailed logs what a step printed (never for the login, whose argv holds the password) and returns the failure the page shows.
func (o *Ops) gbFailed(ctx context.Context, step string, code int, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	attrs := []any{"step", step, "exit_code", code}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	o.log.ErrorContext(ctx, "greenbone: a step failed", attrs...)
	return fail(api.CodeGreenboneFailed, "OpenVAS: "+step+" failed. The box log has the details.")
}

func (o *Ops) gbUp(ctx context.Context, logf func(string), password string) error {
	for _, f := range []string{gbComposeFile, gbOverrideFile} {
		if st, err := os.Lstat(o.path(f)); err != nil || !st.Mode().IsRegular() {
			return fail(api.CodeGreenboneFailed, "OpenVAS: the compose files of the vedette-host package are missing ("+f+"). Reinstall or update vedette-host.")
		}
	}
	if err := o.gbProvider(ctx, logf); err != nil {
		return err
	}
	if _, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketEnable...); err != nil || code != 0 {
		return o.gbFailed(ctx, "starting podman's API socket (podman.socket), which docker-compose talks to,", code, err)
	}
	if out, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketActive...); err != nil || code != 0 || strings.TrimSpace(out) != "active" {
		return o.gbFailed(ctx, "checking that podman's API socket (podman.socket) is active", code, err)
	}
	if err := o.gbSocketDir(); err != nil {
		o.log.ErrorContext(ctx, "greenbone: the socket directory", "error", err.Error())
		return fail(api.CodeGreenboneFailed, "OpenVAS: the host could not prepare "+api.GreenboneSocketDir+". The box log has the details.")
	}
	logf("starting OpenVAS (Greenbone Community Edition, project " + gbProject + "); the first start downloads about 9 GB of images and the feed")
	if _, code, err := o.gbStep(ctx, gbUpLimit, binPodman, gbUpArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose up", code, err)
	}
	if err := o.gbLogin(ctx, password); err != nil {
		return err
	}
	logf("the GMP login is set")
	return o.gbRunning(ctx)
}

// gbProvider makes sure podman compose finds docker-compose v2, 2.24 or newer, and installs the distribution's package when it does
// not (on the first up: OpenVAS is optional, so install.sh does not install it). Verified by its effect: podman compose version.
func (o *Ops) gbProvider(ctx context.Context, logf func(string)) error {
	if o.gbProviderOK(ctx) {
		return nil
	}
	pf, err := o.platform()
	if err != nil {
		return err
	}
	pkg, ok := gbProviderPkg[pf.Distro]
	if !ok {
		return fail(api.CodeGreenboneNoProvider, "OpenVAS needs docker-compose v2, which Vedette installs only on Ubuntu and Debian.")
	}
	if o.installing.Load() || o.dpkgLocked() {
		return lockedRefusal()
	}
	logf("installing " + pkg + " (docker-compose v2, the compose provider of podman compose)")
	if _, code, err := o.gbStep(ctx, gbStepWait, binAptGet, argsUpdate...); err != nil || code != 0 {
		return o.gbFailed(ctx, "apt-get update before installing "+pkg, code, err)
	}
	if _, code, err := o.gbStep(ctx, gbAptWait, binAptGet, gbAptInstallArgv(pkg)...); err != nil || code != 0 {
		return o.gbFailed(ctx, "installing "+pkg, code, err)
	}
	if !o.gbProviderOK(ctx) {
		return fail(api.CodeGreenboneNoProvider, fmt.Sprintf("OpenVAS: %s is installed, but podman compose does not find docker-compose %d.%d or newer.", pkg, gbProviderFloorM, gbProviderFloorN))
	}
	o.note(api.CmdGreenboneUp, "greenbone_provider_installed", map[string]any{"package": pkg})
	return nil
}

func (o *Ops) gbProviderOK(ctx context.Context) bool {
	out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbVersionArgv()...)
	if err != nil || code != 0 {
		return false
	}
	m := gbVersionRE.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		return false
	}
	maj, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return maj > gbProviderFloorM || (maj == gbProviderFloorM && minor >= gbProviderFloorN)
}

// gbSocketDir makes gvmd's socket directory: /run/vedette-greenbone (0755, root) and in it gvmd/ (0755, gvmd's uid and gid), so gvmd
// can make its socket there, core can reach it, and nobody else can put a socket in its place. The host makes the parent at its own
// start too (core's unit mounts it), and /run is empty after a boot.
func (o *Ops) gbSocketDir() error {
	if err := gbDir(o.path(api.GreenboneRunDir), o.cfg.OwnerUID, -1); err != nil {
		return err
	}
	if o.d.GreenboneUID > 0 { // tests: their own uid, their group left as it is
		return gbDir(o.path(api.GreenboneSocketDir), o.d.GreenboneUID, -1)
	}
	return gbDir(o.path(api.GreenboneSocketDir), gbGvmdUID, gbGvmdUID)
}

// gbDir makes path a directory (never through a symlink) with mode 0755 owned by uid:gid (gid -1: the group is left as made; the
// host runs as root, so a directory it makes is root's group).
func gbDir(path string, uid, gid int) error {
	f, err := openDirNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("ops: create %s: %w", path, err)
		}
		f, err = openDirNoFollow(path)
	}
	if err != nil {
		return fmt.Errorf("ops: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		return fmt.Errorf("ops: %s is not a directory", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != uid || (gid >= 0 && int(sys.Gid) != gid) {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("ops: chown %s: %w", path, err)
		}
	}
	if st.Mode().Perm() != 0o755 {
		if err := f.Chmod(0o755); err != nil {
			return fmt.Errorf("ops: chmod %s: %w", path, err)
		}
	}
	return nil
}

// gbLogin sets the GMP password on gvmd, again every few seconds while gvmd still migrates its database or has not made its admin
// user yet (a first start, or a volume that was wiped, W4-1). Its output is never read or logged.
func (o *Ops) gbLogin(parent context.Context, password string) error {
	ctx, cancel := context.WithTimeout(parent, gbLoginWait)
	defer cancel()
	for tries := 1; ; tries++ {
		_, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbLoginArgv(password)...)
		if err == nil && code == 0 {
			return nil
		}
		if !o.d.Sleep(ctx, gbLoginEvery) {
			if parent.Err() != nil { // turned off, or up's own bound: gbOp says which
				return parent.Err()
			}
			o.log.ErrorContext(ctx, "greenbone: setting the GMP login failed", "tries", tries, "exit_code", code) // never the argv
			return fail(api.CodeGreenboneFailed, "OpenVAS started, but its manager (gvmd) did not take Vedette's login within 20 minutes. The box log has the details.")
		}
	}
}

func (o *Ops) gbRunning(ctx context.Context) error {
	out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbPsArgv()...)
	if err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose ps", code, err)
	}
	running := strings.Fields(out)
	var missing []string
	for _, s := range gbMustRun {
		if !slices.Contains(running, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		o.log.ErrorContext(ctx, "greenbone: services not running after up", "missing", strings.Join(missing, " "))
		return fail(api.CodeGreenboneFailed, "OpenVAS started, but these services of it do not run: "+strings.Join(missing, ", ")+". The box log has the details.")
	}
	return nil
}

func (o *Ops) gbDown(ctx context.Context, logf func(string)) error {
	logf("stopping OpenVAS (its volumes, the feed and gvmd's database, are kept)")
	if _, code, err := o.gbStep(ctx, gbDownLimit, binPodman, gbStopArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose stop", code, err)
	}
	out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbPsArgv()...)
	if err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose ps", code, err)
	}
	if s := strings.Fields(out); len(s) > 0 {
		o.log.ErrorContext(ctx, "greenbone: services still running after stop", "running", strings.Join(s, " "))
		return fail(api.CodeGreenboneFailed, "OpenVAS: these services still run after the stop: "+strings.Join(s, ", ")+".")
	}
	return nil
}

func (o *Ops) gbSyncFeed(ctx context.Context, logf func(string)) error {
	logf("updating OpenVAS's feed: pulling " + strings.Join(gbFeedServices, ", "))
	if _, code, err := o.gbStep(ctx, gbSyncLimit, binPodman, gbPullFeedArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "pulling the feed images", code, err)
	}
	if _, code, err := o.gbStep(ctx, gbSyncLimit, binPodman, gbUpFeedArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "starting the feed services again", code, err)
	}
	return nil
}

// gbAtStart makes the parent of gvmd's socket directory, which core's unit mounts (a missing source would stop core from starting).
func (o *Ops) gbAtStart() {
	if err := gbDir(o.path(api.GreenboneRunDir), o.cfg.OwnerUID, -1); err != nil {
		o.log.Error("greenbone: could not make the directory core mounts for OpenVAS", "dir", api.GreenboneRunDir, "error", err.Error())
	}
}
