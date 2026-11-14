package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
//	podman exec -u gvmd greenbone-community-edition-gvmd-1 timeout -k 5 60 gvmd --user=admin --new-password=<48 hex>
//	podman image inspect --format {{.Id}} registry.community.greenbone.net/community/<feed service> | podman rmi <64 hex>
//	systemctl is-enabled | enable --now | start | is-active podman.socket
//	apt-get update | apt-get ... --no-install-recommends install docker-compose-v2 (Ubuntu) or docker-compose (Debian)
//
// The project is not Vedette's: its name, its volumes and its images are Greenbone's own, and install.sh --uninstall never names them.
// The two compose files ship in the vedette-host package (deploy/greenbone): Greenbone's file, unmodified apart from the digest pins, and
// Vedette's override (the gvmd socket on a host directory, the web interface and its helpers off, labels).
//
// The GMP password is core's (core/secrets); it reaches the host as the args of greenbone.up (N42-4, D-590). Before compose up the host
// writes it to <state>/greenbone/gvmd-admin-password (the directory root's 0700, the file gvmd's uid 1001, 0400, through a temp file and
// a rename; the state directory must be the shipped /var/lib/vedette-host, which compose.vedette.yaml names), and the override gives it
// to gvmd as a compose file secret (a read-only bind mount at /run/secrets/vedette-gmp-password); gvmd's command reads it into PASSWORD
// and runs the image's own start-gvmd, which creates the admin user with it before the daemon starts (`gvmd --create-user=admin
// --password=$PASSWORD`; a missing or empty file stops the container before that). A volume created by an OpenVAS enabled after D-590
// therefore never has gvmd's default login, however long gvmd then loads its feed (well over the 20 minutes the earlier login wait
// allowed on the N100). A volume created before D-590 was created as admin/admin and keeps that password until the re-sync takes;
// meanwhile only root and core reach gvmd's socket through /run/vedette-greenbone (D-590 records the limits). The file stays on disk:
// a recreated gvmd and the re-sync at the host's start need it.
// The re-sync (gbResync) sets the password with gvmd's own command (Greenbone's documented way:
// https://greenbone.github.io/docs/latest/22.4/container/workflows.html, "Setting up an admin user password") after every up, and
// at the host's start when gvmd runs: `gvmd --new-password` waits on gvmd's lock while the feed loads, each try ended by the image's
// timeout, the pause between tries doubling from 10 seconds to 5 minutes, with no wall-clock bound; it goes on while gvmd's container
// exists in any state (a gvmd that restarts mid-load does not end it) and ends when it takes, at greenbone.down, at the next up, or
// when the host stops. The password is visible in the box's process list as the argv of `gvmd --create-user` (once per gvmd start,
// seconds) and of each re-sync try (at most 65 seconds each, one at a time), to local users of the box. It is never logged, audited
// (the server redacts the key "password") or put in an error.

const (
	gbProject       = "greenbone-community-edition"
	gbFilesDir      = "/usr/lib/vedette/greenbone"
	gbComposeFile   = gbFilesDir + "/compose.yaml"
	gbOverrideFile  = gbFilesDir + "/compose.vedette.yaml"
	gbGvmdContainer = gbProject + "-gvmd-1" // docker-compose v2's name of the first container of the service gvmd
	gbRegistry      = "registry.community.greenbone.net/community/"
	// gbGvmdUID is the uid and gid of the user gvmd in Greenbone's gvmd image (addgroup/adduser --gid/--uid 1001 in its Dockerfile):
	// gvmd makes its socket in the directory, which the host gives to it.
	gbGvmdUID        = 1001
	gbPodmanSocket   = "podman.socket"
	gbSocketMarker   = "greenbone-podman-socket.enabled" // in the state directory: vedette-host enabled podman.socket (install.sh reads it)
	gbProviderFloorM = 2
	gbProviderFloorN = 24 // the oldest docker-compose v2 on a supported release (Ubuntu 24.04's 2.24.6): profiles and merging by target

	gbUpLimit    = 60 * time.Minute // exposure's own bound of Up: the first one pulls about 9 GB and fills the feed volumes
	gbSyncLimit  = 60 * time.Minute
	gbDownLimit  = 5 * time.Minute
	gbQueueWait  = 30 * time.Minute // how long an up or a feed update waits for the operation before it (the down that cancels it: none)
	gbDownQueue  = 2 * time.Minute  // how long a down waits for the operation it cancelled to end
	gbStepWait   = 2 * time.Minute  // one podman, systemctl or apt-get update call other than the long ones
	gbAptWait    = 15 * time.Minute // the install of the provider package
	gbLoginEvery = 10 * time.Second // the first pause of the background re-sync of the login; it doubles up to gbLoginMax
	gbLoginMax   = 5 * time.Minute
	gbLoginTry   = 90 * time.Second // one try: the image's `timeout -k 5 60` ends gvmd first, podman exec then returns
	gbLoginLog   = time.Hour        // a re-sync that has not taken says so once an hour

	// gbPasswordDir and gbPasswordName: the GMP password for gvmd's start, <state>/greenbone/gvmd-admin-password. gbPasswordShipped is
	// that path with the shipped state directory: compose.vedette.yaml names it as the secret vedette-gmp-password (the two must agree,
	// TestGreenboneOverrideNamesThePasswordFile), so OpenVAS runs only with -state-dir /var/lib/vedette-host.
	gbPasswordDir     = "greenbone"
	gbPasswordName    = "gvmd-admin-password" //nolint:gosec // G101: a file name, not a credential
	gbPasswordShipped = "/var/lib/vedette-host/" + gbPasswordDir + "/" + gbPasswordName
)

// gbFeedServices are the seven feed data services of Greenbone's feed update, in the order of its workflow page.
var gbFeedServices = []string{"notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data", "cert-bund-data", "report-formats", "data-objects"}

// gbMustRun are the services a scan needs running after up: the manager, the scanner, the database and the scanner's store.
var gbMustRun = []string{"gvmd", "ospd-openvas", "pg-gvm", "redis-server"}

// gbProviderPkg is the package of docker-compose v2 per distribution: Ubuntu 24.04's "docker-compose" is the old Python v1 (its v2 is
// docker-compose-v2, which 26.04 keeps: 2.40.3 on the N100 and .181, review r1 M3), Debian 13's "docker-compose" is v2 (2.26.1).
// Sources: packages.ubuntu.com, packages.debian.org. docker-compose-v2 Recommends docker.io: it is always installed without
// recommends, so no Docker daemon ever comes with it.
var gbProviderPkg = map[string]string{"ubuntu": "docker-compose-v2", "debian": "docker-compose"}

var (
	gbPasswordRE = regexp.MustCompile(`^[0-9a-f]{48}$`)
	gbVersionRE  = regexp.MustCompile(`(?m)^v?([0-9]+)\.([0-9]+)\.[0-9]+`)
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

// gbImageIDArgv reads the image ID of one feed service's image (Greenbone's tag, as compose pulls it).
func gbImageIDArgv(service string) []string {
	return []string{"image", "inspect", "--format", "{{.Id}}", gbRegistry + service}
}

// gbLoginArgv sets the GMP password of the admin user, as Greenbone's documentation does it (gvmd --new-password, as the user gvmd),
// through the image's coreutils timeout: a gvmd that waits on its lock is ended inside the container, so a try never outlives itself.
func gbLoginArgv(password string) []string {
	return []string{"exec", "-u", "gvmd", gbGvmdContainer, "timeout", "-k", "5", "60", "gvmd", "--user=" + api.GreenboneUser, "--new-password=" + password}
}

// gbGvmdExistsArgv asks whether gvmd's container exists, in any state (exit 0 yes, 1 no): the re-sync goes on while it does.
func gbGvmdExistsArgv() []string { return []string{"container", "exists", gbGvmdContainer} }

// isGreenbonePodmanArgv says whether args is one of the fixed podman shapes of the OpenVAS commands. The login's password must be
// 48 lower-case hex characters; nothing else varies. (rmi <image ID> is validatePodman's own shape.)
func isGreenbonePodmanArgv(args []string) bool {
	fixed := [][]string{gbUpArgv(), gbStopArgv(), gbPsArgv(), gbPullFeedArgv(), gbUpFeedArgv(), gbVersionArgv(), gbGvmdExistsArgv()}
	for _, s := range gbFeedServices {
		fixed = append(fixed, gbImageIDArgv(s))
	}
	for _, want := range fixed {
		if slices.Equal(args, want) {
			return true
		}
	}
	if len(args) == 11 {
		pw, ok := strings.CutPrefix(args[10], "--new-password=")
		return ok && gbPasswordRE.MatchString(pw) && slices.Equal(args, gbLoginArgv(pw))
	}
	return false
}

var (
	argsPodmanSocketEnabled = []string{"is-enabled", gbPodmanSocket}
	argsPodmanSocketEnable  = []string{"enable", "--now", gbPodmanSocket}
	argsPodmanSocketStart   = []string{"start", gbPodmanSocket}
	argsPodmanSocketActive  = []string{"is-active", gbPodmanSocket}
)

func isPodmanSocketArgv(args []string) bool {
	return slices.Equal(args, argsPodmanSocketEnabled) || slices.Equal(args, argsPodmanSocketEnable) ||
		slices.Equal(args, argsPodmanSocketStart) || slices.Equal(args, argsPodmanSocketActive)
}

// gbAptInstallArgv installs the compose provider: never a removal, never a recommended package (docker-compose-v2 recommends the Docker
// daemon), the administrator's configuration files kept.
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
		Name: api.CmdGreenboneUp, Write: false, Timeout: gbQueueWait + gbUpLimit + 10*time.Minute,
		Validate: func(a *api.GreenboneUpArgs) error { return gbArgs(*a) },
		Run: func(ctx context.Context, rc *server.RunContext, a api.GreenboneUpArgs) (any, error) {
			if err := gbArgs(a); err != nil {
				return nil, err
			}
			return gbResult(o.gbOp(ctx, false, gbUpLimit, func(ctx context.Context) error { return o.gbUp(ctx, rc.Log, a.Password) }))
		},
	})
}

func (o *Ops) cmdGreenboneDown() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdGreenboneDown, Write: false, Timeout: gbDownQueue + gbDownLimit + time.Minute,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return gbResult(o.gbOp(ctx, true, gbDownLimit, func(ctx context.Context) error { return o.gbDown(ctx, rc.Log) }))
		},
	})
}

func (o *Ops) cmdGreenboneSyncFeed() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdGreenboneSyncFeed, Write: false, Timeout: gbQueueWait + gbSyncLimit + 10*time.Minute,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return gbResult(o.gbOp(ctx, false, gbSyncLimit, func(ctx context.Context) error { return o.gbSyncFeed(ctx, rc.Log) }))
		},
	})
}

// gbResult is a command's outcome: an empty result when it worked, the error alone when not.
func gbResult(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// gbOp runs f as the one OpenVAS operation of the host, bounded by limit from the moment it has the slot. An up or a feed update waits
// for the one before it (at most gbQueueWait). A down (preempt) is a new generation: it cancels the operation that runs, and every up
// or feed update that was already waiting gives up when its turn comes (greenbone_cancelled), so turning OpenVAS off never loses to an
// up queued before it (review r1 L1); the down waits at most gbDownQueue for the cancelled one to end.
func (o *Ops) gbOp(ctx context.Context, preempt bool, limit time.Duration, f func(context.Context) error) error {
	o.gbMu.Lock()
	if preempt {
		o.gbGen++
		if o.gbCancel != nil {
			o.gbCancel()
		}
		if o.gbResyncStop != nil { // the background re-sync of the login ends too (gbResync)
			o.gbResyncStop()
			o.gbResyncStop = nil
		}
	}
	gen := o.gbGen
	onQueue := o.gbOnQueue
	o.gbMu.Unlock()
	if onQueue != nil && !preempt {
		onQueue()
	}
	queue := gbQueueWait
	if preempt {
		queue = gbDownQueue
	}
	qctx, qcancel := context.WithTimeout(ctx, queue)
	select {
	case o.gbSem <- struct{}{}:
		qcancel()
	case <-qctx.Done():
		qcancel()
		return fail(api.CodeGreenboneFailed, "Another OpenVAS operation of the host did not end in time.")
	}
	defer func() { <-o.gbSem }()
	o.gbMu.Lock()
	if o.gbGen != gen { // a down came while this one waited
		o.gbMu.Unlock()
		return fail(api.CodeGreenboneCancelled, "OpenVAS was turned off while this waited.")
	}
	cctx, stop := context.WithCancelCause(ctx)
	o.gbCancel = func() { stop(errGBStopped) }
	o.gbMu.Unlock()
	defer func() {
		o.gbMu.Lock()
		o.gbCancel = nil
		o.gbMu.Unlock()
		stop(nil)
	}()
	lctx, lcancel := context.WithTimeout(cctx, limit)
	defer lcancel()
	err := f(lctx)
	switch {
	case err == nil:
	case errors.Is(context.Cause(cctx), errGBStopped):
		return fail(api.CodeGreenboneCancelled, "OpenVAS was turned off while this ran.")
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return fail(api.CodeGreenboneFailed, fmt.Sprintf("OpenVAS: the host's step did not finish within its limit of %d minutes.", int(limit/time.Minute)))
	}
	return err
}

// gx runs one allowlisted binary (o.execIn; internal tests replace it through gbExec).
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
	if err := o.gbPodmanSocketOn(ctx); err != nil {
		return err
	}
	if err := o.gbSocketDir(); err != nil {
		o.log.ErrorContext(ctx, "greenbone: the socket directory", "error", err.Error())
		return fail(api.CodeGreenboneFailed, "OpenVAS: the host could not prepare "+api.GreenboneSocketDir+". The box log has the details.")
	}
	if _, file := o.gbPasswordPath(); file != o.path(gbPasswordShipped) {
		return fail(api.CodeGreenboneFailed, "OpenVAS needs vedette-host's state directory at /var/lib/vedette-host (its compose override names the GMP login file "+gbPasswordShipped+"), but this host runs with "+o.cfg.StateDir+".")
	}
	if err := o.gbPasswordWrite(password); err != nil {
		o.log.ErrorContext(ctx, "greenbone: the GMP password file", "error", err.Error()) // the path and the cause, never the value
		return fail(api.CodeGreenboneFailed, "OpenVAS: the host could not write the GMP login for gvmd under "+filepath.Dir(gbPasswordShipped)+". The box log has the details.")
	}
	logf("starting OpenVAS (Greenbone Community Edition, project " + gbProject + "); the first start downloads about 9 GB of images and the feed")
	if _, code, err := o.gbStep(ctx, gbUpLimit, binPodman, gbUpArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose up", code, err)
	}
	if err := o.gbRunning(ctx); err != nil {
		return err
	}
	o.gbResyncStart(func() bool { return ctx.Err() == nil }, password) //nolint:contextcheck // the re-sync outlives the up on purpose: the process's context, ended by down or the next up
	logf("OpenVAS runs; gvmd creates its admin user with Vedette's GMP login, and the host sets the login again in the background once gvmd has loaded its feed (an existing volume keeps its own)")
	return nil
}

// gbPasswordPath is the directory and the file of the GMP password for gvmd's start, in the state directory.
func (o *Ops) gbPasswordPath() (dir, file string) {
	return o.stateFile(gbPasswordDir), o.stateFile(gbPasswordDir, gbPasswordName)
}

// gbPasswordWrite puts the GMP password where compose.vedette.yaml gives it to gvmd as a file secret: the directory root's (the host's
// owner uid) and 0700, the file gvmd's uid and 0400, through a temp file made 0400 and owned by gvmd before the password is written,
// then a rename; temp files a write cut short left behind are removed first. Only root and gvmd read it; the runtime bind-mounts the
// file itself, so gvmd needs no way through the directory. A directory of another owner or open to others is refused, not repaired.
// Never logged.
func (o *Ops) gbPasswordWrite(password string) error {
	dir, file := o.gbPasswordPath()
	if err := privDir(dir, o.cfg.OwnerUID); err != nil {
		return err
	}
	if stale, err := filepath.Glob(filepath.Join(dir, ".tmp-*")); err == nil {
		for _, s := range stale {
			_ = os.Remove(s)
		}
	}
	uid, gid := gbGvmdUID, gbGvmdUID
	if o.d.GreenboneUID > 0 { // tests: their own uid, their group left as it is
		uid, gid = o.d.GreenboneUID, -1
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("ops: write the GMP password file: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	for _, step := range []func() error{
		func() error { return f.Chmod(0o400) },
		func() error { return f.Chown(uid, gid) },
		func() error { _, err := f.WriteString(password + "\n"); return err },
		f.Sync,
		f.Close,
		func() error { return os.Rename(tmp, file) },
	} {
		if err := step(); err != nil {
			return fmt.Errorf("ops: write the GMP password file: %w", err)
		}
	}
	ok = true
	syncDir(dir)
	return nil
}

// gbResyncStart starts the background re-sync of the login (gbResync) in place of one that runs. It runs on the process's own
// context, not the caller's. ok is asked under gbMu, where a down bumps the generation and cancels the operation that runs: an up
// passes "my context is not cancelled", the resume at the host's start "no down and no up since I looked", so a re-sync never starts
// after the down that ended its up, and a resume never replaces the re-sync of a newer up.
func (o *Ops) gbResyncStart(ok func() bool, password string) {
	o.mu.Lock()
	parent := o.loopCtx
	o.mu.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	o.gbMu.Lock()
	defer o.gbMu.Unlock()
	if !ok() {
		return
	}
	if o.gbResyncStop != nil {
		o.gbResyncStop()
	}
	ctx, cancel := context.WithCancel(parent)
	o.gbResyncStop = cancel
	go o.gbResync(ctx, cancel, password)
}

// gbResume, at the host's start (review r1 M1): a host that restarted while gvmd loaded its feed lost the re-sync of its up, and core
// does not send greenbone.up again while its own state says OpenVAS was started. When the password file is there and compose lists
// gvmd as running, the re-sync starts again with the file's password. A stopped project (OpenVAS turned off) is left alone. Run beside
// Start, never blocking it; nothing of the password is logged.
func (o *Ops) gbResume(ctx context.Context) {
	o.gbMu.Lock()
	gen := o.gbGen
	o.gbMu.Unlock()
	password, err := o.gbPasswordRead()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			o.log.ErrorContext(ctx, "greenbone: the GMP password file could not be read at start; the login is set again at the next start of OpenVAS", "error", err.Error())
		}
		return
	}
	out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbPsArgv()...)
	if err != nil || code != 0 || !slices.Contains(strings.Fields(out), "gvmd") {
		return
	}
	o.gbResyncStart(func() bool { return o.gbGen == gen && o.gbResyncStop == nil }, password) //nolint:contextcheck // the re-sync runs on the process's context (loopCtx), like ctx here
}

// gbPasswordRead reads the password file (never through a symlink, at most 64 bytes) and accepts only the 48 hex characters core makes.
func (o *Ops) gbPasswordRead() (string, error) {
	_, file := o.gbPasswordPath()
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the host's own file in its state directory
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 64)
	n, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", fmt.Errorf("ops: read the GMP password file: %w", err)
	}
	if pw := strings.TrimSuffix(string(b[:n]), "\n"); gbPasswordRE.MatchString(pw) {
		return pw, nil
	}
	return "", errors.New("ops: the GMP password file does not hold a password of the expected form")
}

// gbResync sets the GMP password on gvmd with gvmd's own command until it takes: a volume created before D-590 (as admin/admin), or
// one whose admin user has another password (core's data restored without the volumes, W4-1), keeps it, and gvmd takes a new one only
// once its main process has loaded its feed and released its lock, which on a first start can take hours (N42-4). The pause between
// tries doubles from gbLoginEvery to gbLoginMax (review r1 M3). No wall-clock bound: it goes on while gvmd's container exists, in any
// state (a gvmd that restarts mid-load does not end it), and ends when the password takes, when ctx ends (greenbone.down, the next up,
// the host stopping), or when the container is gone. One try at a time, each ended by the image's timeout; the first failure is
// logged, then one line an hour (tries and the last exit code); the argv and the output are never logged or read.
func (o *Ops) gbResync(ctx context.Context, cancel context.CancelFunc, password string) {
	defer cancel()
	wait := gbLoginEvery
	var logged time.Time
	for tries := 1; ; tries++ {
		_, code, err := o.gbStep(ctx, gbLoginTry, binPodman, gbLoginArgv(password)...)
		if err != nil {
			code = -1
		}
		switch {
		case ctx.Err() != nil:
			return
		case code == 0:
			o.log.InfoContext(ctx, "greenbone: gvmd took Vedette's GMP login", "tries", tries)
			return
		case !o.gbGvmdExists(ctx):
			o.log.WarnContext(ctx, "greenbone: gvmd's container is gone; the GMP login is set again at the next start of OpenVAS", "tries", tries, "exit_code", code)
			return
		case tries == 1:
			o.log.InfoContext(ctx, "greenbone: gvmd did not take the GMP login yet (it loads its feed first); the host tries again in the background", "exit_code", code)
			logged = o.d.Now()
		case o.d.Now().Sub(logged) >= gbLoginLog:
			o.log.InfoContext(ctx, "greenbone: gvmd still does not take the GMP login; the host keeps trying", "tries", tries, "exit_code", code)
			logged = o.d.Now()
		}
		if !o.d.Sleep(ctx, wait) {
			return
		}
		wait = min(2*wait, gbLoginMax)
	}
}

// gbGvmdExists says whether gvmd's container exists, in any state; when podman cannot tell, it says yes, so the re-sync keeps trying
// (at most every gbLoginMax).
func (o *Ops) gbGvmdExists(ctx context.Context) bool {
	_, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbGvmdExistsArgv()...)
	return err != nil || code != 1
}

// gbPodmanSocketOn makes sure podman's API socket listens (docker-compose talks to it). vedette-host enables it only when it was not
// enabled, and then leaves the marker gbSocketMarker so that install.sh --uninstall disables it again; an administrator's own enable
// stays theirs (review r1 L5). An enabled socket that is not active is started.
func (o *Ops) gbPodmanSocketOn(ctx context.Context) error {
	out, _, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketEnabled...)
	if err != nil {
		return o.gbFailed(ctx, "asking whether podman's API socket (podman.socket) is enabled", -1, err)
	}
	if strings.TrimSpace(out) != "enabled" {
		if _, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketEnable...); err != nil || code != 0 {
			return o.gbFailed(ctx, "enabling podman's API socket (podman.socket), which docker-compose talks to,", code, err)
		}
		if err := writeFileAtomic(o.stateFile(gbSocketMarker), []byte("vedette-host enabled podman.socket for OpenVAS (D-529); install.sh --uninstall disables it\n"), 0o600); err != nil {
			o.log.ErrorContext(ctx, "greenbone: could not record that podman.socket was enabled", "error", err.Error())
		}
		o.note(api.CmdGreenboneUp, "greenbone_podman_socket_enabled", map[string]any{"unit": gbPodmanSocket})
	}
	if out, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketActive...); err == nil && code == 0 && strings.TrimSpace(out) == "active" {
		return nil
	}
	if _, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketStart...); err != nil || code != 0 {
		return o.gbFailed(ctx, "starting podman's API socket (podman.socket)", code, err)
	}
	if out, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, argsPodmanSocketActive...); err != nil || code != 0 || strings.TrimSpace(out) != "active" {
		return o.gbFailed(ctx, "checking that podman's API socket (podman.socket) is active", code, err)
	}
	return nil
}

// gbProvider makes sure podman compose finds docker-compose v2, 2.24 or newer, and installs the distribution's package when it does
// not (on the first up: OpenVAS is optional, so install.sh does not install it). Verified by its effect: podman compose version. A
// floor, not a pinned version: the package comes from the distribution's archive, whose security updates must flow in (as nmap, D-146).
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
	logf("installing " + pkg + " (docker-compose v2, the compose provider of podman compose; no recommended packages)")
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

// gbRunDir makes /run/vedette-greenbone: 0750, root, the group of core (host.conf core_gid), so core can reach gvmd's socket below it
// and no other local user can, not even a host account that happens to have gvmd's uid 1001 (review r1 M1). gvmd does not need it:
// the runtime bind-mounts the gvmd/ folder below it straight onto /run/gvmd. Core's unit mounts it, so the host makes it at its own
// start too, and /run is empty after a boot.
func (o *Ops) gbRunDir() error {
	gid := -1
	if o.cfg.CoreGID > 0 {
		gid = o.cfg.CoreGID
	}
	return gbDir(o.path(api.GreenboneRunDir), o.cfg.OwnerUID, gid, 0o750)
}

// gbSocketDir makes gvmd's socket directory: the parent (gbRunDir) and in it gvmd/ (0755, gvmd's uid and gid), so gvmd can make its
// socket there.
func (o *Ops) gbSocketDir() error {
	if err := o.gbRunDir(); err != nil {
		return err
	}
	if o.d.GreenboneUID > 0 { // tests: their own uid, their group left as it is
		return gbDir(o.path(api.GreenboneSocketDir), o.d.GreenboneUID, -1, 0o755)
	}
	return gbDir(o.path(api.GreenboneSocketDir), gbGvmdUID, gbGvmdUID, 0o755)
}

// gbDir makes path a directory (never through a symlink) with mode perm owned by uid:gid (gid -1: the group is left as made; the host
// runs as root, so a directory it makes is root's group).
func gbDir(path string, uid, gid int, perm os.FileMode) error {
	f, err := openDirNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
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
	if st.Mode().Perm() != perm {
		if err := f.Chmod(perm); err != nil {
			return fmt.Errorf("ops: chmod %s: %w", path, err)
		}
	}
	return nil
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

// gbSyncFeed is Greenbone's feed update: pull the seven feed images, start their services again, then remove the feed images they
// replaced (review r1 M4: each weekly pull would leave several GB of untagged images). Only the previous image of each of the seven
// exact feed repositories, by its ID, without force: podman itself refuses one a container still uses or that has another name.
func (o *Ops) gbSyncFeed(ctx context.Context, logf func(string)) error {
	before := o.gbFeedImageIDs(ctx)
	logf("updating OpenVAS's feed: pulling " + strings.Join(gbFeedServices, ", "))
	if _, code, err := o.gbStep(ctx, gbSyncLimit, binPodman, gbPullFeedArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "pulling the feed images", code, err)
	}
	if _, code, err := o.gbStep(ctx, gbSyncLimit, binPodman, gbUpFeedArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "starting the feed services again", code, err)
	}
	after := o.gbFeedImageIDs(ctx)
	removed := 0
	for _, s := range gbFeedServices {
		old := before[s]
		if old == "" || after[s] == "" || old == after[s] {
			continue
		}
		args, err := rmiArgv(old)
		if err != nil {
			continue
		}
		if _, code, err := o.gbStep(ctx, gbStepWait, binPodman, args...); err != nil || code != 0 {
			o.log.WarnContext(ctx, "greenbone: the previous feed image was not removed", "service", s, "image", old, "exit_code", code)
			continue
		}
		removed++
	}
	logf(fmt.Sprintf("the feed is updated; %d previous feed image(s) removed", removed))
	return nil
}

// gbFeedImageIDs reads the image ID of each feed service's image; a service whose image cannot be read is left out.
func (o *Ops) gbFeedImageIDs(ctx context.Context) map[string]string {
	ids := map[string]string{}
	for _, s := range gbFeedServices {
		out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbImageIDArgv(s)...)
		if id := strings.TrimPrefix(strings.TrimSpace(out), "sha256:"); err == nil && code == 0 && imageIDRE.MatchString(id) {
			ids[s] = id
		}
	}
	return ids
}

// gbAtStart makes the parent of gvmd's socket directory, which core's unit mounts (a missing source would stop core from starting).
func (o *Ops) gbAtStart() {
	if err := o.gbRunDir(); err != nil {
		o.log.Error("greenbone: could not make the directory core mounts for OpenVAS", "dir", api.GreenboneRunDir, "error", err.Error())
	}
}
