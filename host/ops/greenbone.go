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

// OpenVAS (Greenbone Community Edition; host-api §6.16): greenbone.up, greenbone.down and greenbone.sync_feed run
// Greenbone's official compose project with `podman compose` and the docker-compose v2 provider, through the runner with fixed argv:
//
//	podman compose -p greenbone-community-edition -f /usr/lib/vedette/greenbone/compose.yaml -f /usr/lib/vedette/greenbone/compose.vedette.yaml
//	    up -d | stop | stop gvmd | ps --services --status running | pull <the four feed services> | up -d <the four feed services>
//	podman compose version --short
//	podman exec -u gvmd greenbone-community-edition-gvmd-1 timeout -k 5 60 gvmd --user=admin --new-password=<48 hex>
//	podman image inspect --format {{.Id}} registry.community.greenbone.net/community/<feed or SCAP/CERT service> | podman rmi <64 hex>
//	podman exec greenbone-community-edition-pg-gvm-1 psql -U gvmd -d gvmd [-At] -v ON_ERROR_STOP=1 --command=<gbSchemasSQL | gbDropSQL>
//	podman container inspect --format <the label io.vedette.started-by> | rm --force --ignore greenbone-community-edition-<scap-data|cert-bund-data|dfn-cert-data>-1
//	podman volume exists | rm greenbone-community-edition_<scap_data_vol|cert_data_vol>
//	systemctl is-enabled | enable --now | start | is-active podman.socket
//	apt-get update | apt-get ... --no-install-recommends install docker-compose-v2 (Ubuntu) or docker-compose (Debian)
//
// The project is not Vedette's: its name, its volumes and its images are Greenbone's own, and install.sh --uninstall never names them.
// The two compose files ship in the vedette-host package (deploy/greenbone): Greenbone's file, unmodified apart from the digest pins, and
// Vedette's override (the gvmd socket on a host directory, the web interface and its helpers off, the SCAP and CERT data off, labels, a 10 MB log file and a
// memory limit per service).
// The one exception to "never removes anything of the project" is gbLean: at each up, what is left of the SCAP and CERT data an OpenVAS
// started by an older release (or by an older build after a rollback): three containers, two volumes, two schemas in gvmd's database, and the
// three images when Vedette's label was on their container.
//
// The GMP password is core's (core/secrets); it reaches the host as the args of greenbone.up. Before compose up the host
// writes it to <state>/greenbone/gvmd-admin-password (the directory root's 0700, the file gvmd's uid 1001, 0400, through a temp file and
// a rename; the state directory must be the shipped /var/lib/vedette-host, which compose.vedette.yaml names), and the override gives it
// to gvmd as a compose file secret (a read-only bind mount at /run/secrets/vedette-gmp-password); gvmd's command reads it into PASSWORD
// and runs the image's own start-gvmd, which creates the admin user with it before the daemon starts (`gvmd --create-user=admin
// --password=$PASSWORD`; a missing or empty file stops the container before that). A volume created by an OpenVAS enabled by this release
// therefore never has gvmd's default login, however long gvmd then loads its feed (well over the 20 minutes the earlier login wait
// allowed on a test box). A volume created by an older release was created as admin/admin and keeps that password until the re-sync takes;
// meanwhile only root and core reach gvmd's socket through /run/vedette-greenbone. The file stays on disk:
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
	gbGvmdUID      = 1001
	gbPodmanSocket = "podman.socket"
	gbSocketMarker = "greenbone-podman-socket.enabled" // in the state directory: vedette-host enabled podman.socket (install.sh reads it)
	// The floor of docker-compose: 2.24.4, the first with the merge tag !override that compose.vedette.yaml uses for gvmd's volumes
	// (2.24.0-2.24.3 ignore it silently and mount the SCAP/CERT volumes again). Ubuntu 24.04 ships 2.24.6.
	gbProviderFloorM = 2
	gbProviderFloorN = 24
	gbProviderFloorP = 4

	gbUpLimit    = 60 * time.Minute // exposure's own bound of Up: the first one pulls several GB and fills the feed volumes
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

// gbFeedServices are the feed data services of Greenbone's feed update that Vedette runs, in the order of its workflow page: the SCAP and
// CERT data (scap-data, dfn-cert-data, cert-bund-data) are off (compose.vedette.yaml).
var gbFeedServices = []string{"notus-data", "vulnerability-tests", "report-formats", "data-objects"}

// LEAN-1 stage A (gbLean): what is left of the SCAP and CERT data on a box whose OpenVAS ran them. The three services (their containers
// are <project>-<service>-1 and their images Greenbone's tag of the service), the two volumes, and gvmd's two schemas.
var (
	gbLeanServices = []string{"scap-data", "cert-bund-data", "dfn-cert-data"}
	gbLeanVolumes  = []string{gbProject + "_scap_data_vol", gbProject + "_cert_data_vol"}
)

const (
	gbPgContainer = gbProject + "-pg-gvm-1" // docker-compose v2's name of the container of the service pg-gvm
	gbLabel       = "io.vedette.started-by" // compose.vedette.yaml's label on every service Vedette ran
	// gbSchemasSQL names the SCAP/CERT schemas that hold feed data: one of their main tables has a page. A schema alone is not enough:
	// gvmd itself makes both schemas again, empty, when the feed files are missing, so asking only whether they exist
	// would stop gvmd and drop them at every up.
	gbSchemasSQL = "SELECT DISTINCT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace" +
		" WHERE n.nspname IN ('scap', 'cert') AND c.relkind = 'r' AND c.relname IN ('cves', 'cpes', 'cert_bund_advs', 'dfn_cert_advs')" +
		" AND pg_relation_size(c.oid) > 0"
	// gbDropSQL is one transaction (psql --command runs a string of statements as one). It gives up rather than wait behind a lock,
	// and the server ends it before the host's own limit (gbRemoveLimit) cuts the client, so a drop never commits after gvmd runs again.
	gbDropSQL     = "SET lock_timeout = '2min'; SET statement_timeout = '10min'; DROP SCHEMA IF EXISTS scap CASCADE; DROP SCHEMA IF EXISTS cert CASCADE"
	gbDropTries   = 6                // psql tries while PostgreSQL starts (pg-gvm is only "started" when gvmd's up returns)
	gbDropEvery   = 10 * time.Second // between two tries
	gbRemoveLimit = 15 * time.Minute // one drop, or the removal of one data volume (11 GB of files on a test box)
)

// gbMustRun are the services a scan needs running after up: the manager, the scanner, the database and the scanner's store.
var gbMustRun = []string{"gvmd", "ospd-openvas", "pg-gvm", "redis-server"}

// gbProviderPkg is the package of docker-compose v2 per distribution: Ubuntu 24.04's "docker-compose" is the old Python v1 (its v2 is
// docker-compose-v2, which 26.04 keeps: 2.40.3 on the test boxes), Debian 13's "docker-compose" is v2 (2.26.1).
// Sources: packages.ubuntu.com, packages.debian.org. docker-compose-v2 Recommends docker.io: it is always installed without
// recommends, so no Docker daemon ever comes with it.
var gbProviderPkg = map[string]string{"ubuntu": "docker-compose-v2", "debian": "docker-compose"}

var (
	gbPasswordRE = regexp.MustCompile(`^[0-9a-f]{48}$`)
	gbVersionRE  = regexp.MustCompile(`(?m)^v?([0-9]+)\.([0-9]+)\.([0-9]+)`)
	errGBStopped = errors.New("ops: stopped by greenbone.down")
)

// ---- argv (the runner's validators accept exactly these) ----

func gbComposeArgv(verb ...string) []string {
	return append([]string{"compose", "-p", gbProject, "-f", gbComposeFile, "-f", gbOverrideFile}, verb...)
}

func gbUpArgv() []string       { return gbComposeArgv("up", "-d") }
func gbStopArgv() []string     { return gbComposeArgv("stop") }
func gbStopGvmdArgv() []string { return gbComposeArgv("stop", "gvmd") }
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

// gbDropArgv drops gvmd's SCAP and CERT schemas (gbLean), with psql of Greenbone's pg-gvm image as gvmd's database user.
func gbDropArgv() []string {
	return []string{"exec", gbPgContainer, "psql", "-U", "gvmd", "-d", "gvmd", "-v", "ON_ERROR_STOP=1", "--command=" + gbDropSQL}
}

// gbSchemasArgv prints the SCAP/CERT schemas that hold feed data, one name a line.
func gbSchemasArgv() []string {
	return []string{"exec", gbPgContainer, "psql", "-U", "gvmd", "-d", "gvmd", "-At", "-v", "ON_ERROR_STOP=1", "--command=" + gbSchemasSQL}
}

// gbLeanLabelArgv reads Vedette's label of the container of one SCAP or CERT service (no such container: exit code not 0).
func gbLeanLabelArgv(service string) []string {
	return []string{"container", "inspect", "--format", `{{index .Config.Labels "` + gbLabel + `"}}`, gbProject + "-" + service + "-1"}
}

// gbLeanRmArgv removes the container of one SCAP or CERT service (stopping it first; none: nothing, exit 0).
func gbLeanRmArgv(service string) []string {
	return []string{"rm", "--force", "--ignore", gbProject + "-" + service + "-1"}
}

func gbVolumeExistsArgv(volume string) []string { return []string{"volume", "exists", volume} }
func gbVolumeRmArgv(volume string) []string     { return []string{"volume", "rm", volume} }

// isGreenbonePodmanArgv says whether args is one of the fixed podman shapes of the OpenVAS commands. The login's password must be
// 48 lower-case hex characters; nothing else varies. (rmi <image ID> is validatePodman's own shape.)
func isGreenbonePodmanArgv(args []string) bool {
	fixed := [][]string{gbUpArgv(), gbStopArgv(), gbStopGvmdArgv(), gbPsArgv(), gbPullFeedArgv(), gbUpFeedArgv(), gbVersionArgv(), gbGvmdExistsArgv(), gbDropArgv(), gbSchemasArgv()}
	for _, s := range gbFeedServices {
		fixed = append(fixed, gbImageIDArgv(s))
	}
	for _, s := range gbLeanServices {
		fixed = append(fixed, gbImageIDArgv(s), gbLeanRmArgv(s), gbLeanLabelArgv(s))
	}
	for _, v := range gbLeanVolumes {
		fixed = append(fixed, gbVolumeExistsArgv(v), gbVolumeRmArgv(v))
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
	logf("starting OpenVAS (Greenbone Community Edition, project " + gbProject + "); the first start downloads several GB of images and the feed")
	if _, code, err := o.gbStep(ctx, gbUpLimit, binPodman, gbUpArgv()...); err != nil || code != 0 {
		return o.gbFailed(ctx, "podman compose up", code, err)
	}
	if err := o.gbRunning(ctx); err != nil {
		return err
	}
	if err := o.gbLean(ctx, logf); err != nil {
		return err
	}
	o.gbResyncStart(func() bool { return ctx.Err() == nil }, password) //nolint:contextcheck // the re-sync outlives the up on purpose: the process's context, ended by down or the next up
	logf("OpenVAS runs; gvmd creates its admin user with Vedette's GMP login, and the host sets the login again in the background once gvmd has loaded its feed (an existing volume keeps its own)")
	return nil
}

// gbLean removes what is left of the SCAP and CERT data (LEAN-1 stage A): compose no longer runs or mounts them
// (compose.vedette.yaml), but on a box whose OpenVAS ran them (an older release, or an older build after a rollback) their containers,
// volumes (11 GB + 182 MB on a test box), images (1.75 GB + 200 MB) and gvmd's two schemas (37 GB in PostgreSQL) stay until removed.
// It runs at every up, after the services run, and decides each step from the box as it is, so a step that failed, or data an older
// build brought back, is handled at the next up; on a lean box it costs a few reads.
//
//  1. The three containers: Vedette's label is read, then the container is removed (stopped first). Always first, whatever the rest
//     does: compose stop does not stop a service whose profile is off, so a running one would make greenbone.down fail.
//  2. The schemas, only when one still holds feed data (gbSchemasSQL): compose stop gvmd, the drop (one transaction, lock and
//     statement timeouts), compose up again whatever the drop did, so gvmd never stays stopped. Why it is safe and why gvmd must be
//     stopped (the CASCADE also drops the views gvmd's result queries join, which gvmd makes again at its start): read from
//     gvmd 26.43.0's source. PostgreSQL that is still starting is asked again, a few times.
//  3. The two volumes that exist (without force: a volume a container still uses is refused).
//  4. The image of each service whose container carried Vedette's label (by the ID of Greenbone's tag, without force; a refusal, e.g.
//     another project's container uses it, is logged and the rest goes on). An image without such a container is never removed: a
//     customer's own Greenbone keeps its images.
//
// A step that fails is logged and the up goes on; the next up tries again. A pass that removed something writes an audit note. Only
// a gvmd that does not start again, or the up's own cancel or limit, is an error of the up. "Upgraded" is decided by Greenbone's
// project name, which Vedette shares with the official compose: a customer's own project of that name would lose its two
// data volumes and its schemas the same way; its images are kept by the label rule.
func (o *Ops) gbLean(ctx context.Context, logf func(string)) error {
	var removed []string // containers
	ours := map[string]bool{}
	for _, s := range gbLeanServices {
		out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbLeanLabelArgv(s)...)
		if err != nil || code != 0 {
			continue // no such container
		}
		ours[s] = strings.TrimSpace(out) == "vedette-host"
		if _, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbLeanRmArgv(s)...); err != nil || code != 0 {
			o.gbLeanFailed(ctx, "removing the container of "+s, code, err)
			continue
		}
		removed = append(removed, s)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	dropped, err := o.gbLeanSchemas(ctx, logf)
	if err != nil {
		return err
	}
	var volumes []string
	for _, v := range gbLeanVolumes {
		_, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbVolumeExistsArgv(v)...)
		if err != nil || code != 0 {
			if code != 1 {
				o.gbLeanFailed(ctx, "asking whether "+v+" exists", code, err)
			}
			continue
		}
		if _, code, err := o.gbStep(ctx, gbRemoveLimit, binPodman, gbVolumeRmArgv(v)...); err != nil || code != 0 {
			o.gbLeanFailed(ctx, "removing the volume "+v, code, err)
			continue
		}
		volumes = append(volumes, v)
	}
	var images []string
	for _, s := range gbLeanServices {
		if !ours[s] {
			continue
		}
		out, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbImageIDArgv(s)...)
		id := strings.TrimPrefix(strings.TrimSpace(out), "sha256:")
		if err != nil || code != 0 || !imageIDRE.MatchString(id) {
			continue // no image of that tag
		}
		args, _ := rmiArgv(id)
		if _, code, err := o.gbStep(ctx, gbStepWait, binPodman, args...); err != nil || code != 0 {
			o.gbLeanFailed(ctx, "removing the image of "+s+" (another container may use it)", code, err)
			continue
		}
		images = append(images, gbRegistry+s)
	}
	if len(removed) > 0 || dropped || len(volumes) > 0 || len(images) > 0 { // what this pass removed, whether or not every step worked
		o.note(api.CmdGreenboneUp, "greenbone_scap_cert_removed", map[string]any{"containers": removed, "schemas_dropped": dropped, "volumes": volumes, "images": images})
		logf(fmt.Sprintf("removed of the SCAP and CERT data: %d container(s), gvmd's schemas %t, %d volume(s), %d image(s)", len(removed), dropped, len(volumes), len(images)))
	}
	return ctx.Err()
}

// gbLeanSchemas drops gvmd's SCAP and CERT schemas when one still holds feed data, with gvmd stopped, and starts gvmd again. It says
// whether it dropped them; the error is only a gvmd that does not run again, or the up's own end.
func (o *Ops) gbLeanSchemas(ctx context.Context, logf func(string)) (bool, error) {
	out, ok := o.gbPsql(ctx, gbStepWait, gbSchemasArgv(), "asking gvmd's database for its SCAP and CERT schemas")
	if !ok || strings.TrimSpace(out) == "" {
		return false, ctx.Err()
	}
	logf("dropping the SCAP and CERT data in gvmd's database, which Vedette does not use; gvmd stops for this and starts again")
	if _, code, err := o.gbStep(ctx, gbStepWait, binPodman, gbStopGvmdArgv()...); err != nil || code != 0 {
		o.gbLeanFailed(ctx, "stopping gvmd", code, err)
		ok = false
	} else if ctx.Err() == nil {
		_, ok = o.gbPsql(ctx, gbRemoveLimit, gbDropArgv(), "dropping gvmd's SCAP and CERT schemas")
	}
	// gvmd starts again whatever the stop and the drop did. Not after a cancel: that is a down, which stops the project anyway (and an
	// up cut by its limit is sent again; its gbLean starts gvmd).
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if _, code, err := o.gbStep(ctx, gbUpLimit, binPodman, gbUpArgv()...); err != nil || code != 0 {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, o.gbFailed(ctx, "podman compose up (gvmd again, after the SCAP and CERT data)", code, err)
	}
	if err := o.gbRunning(ctx); err != nil {
		return false, err
	}
	return ok, nil
}

// gbPsql runs one fixed psql argv in pg-gvm, trying again while PostgreSQL starts; it returns what psql printed and whether it worked.
func (o *Ops) gbPsql(ctx context.Context, wait time.Duration, args []string, step string) (string, bool) {
	var code int
	var err error
	for try := 1; ctx.Err() == nil; try++ {
		var out string
		if out, code, err = o.gbStep(ctx, wait, binPodman, args...); err == nil && code == 0 {
			return out, true
		}
		if try == gbDropTries || !o.d.Sleep(ctx, gbDropEvery) {
			break
		}
	}
	o.gbLeanFailed(ctx, step, code, err)
	return "", false
}

// gbLeanFailed logs a step of gbLean that did not work; the up goes on and the next one tries again.
func (o *Ops) gbLeanFailed(ctx context.Context, step string, code int, err error) {
	if ctx.Err() != nil {
		return // the up's end, not a failed step
	}
	attrs := []any{"step", step, "exit_code", code}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	o.log.WarnContext(ctx, "greenbone: removing the SCAP and CERT data did not finish; the next start of OpenVAS tries again", attrs...)
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

// gbResync sets the GMP password on gvmd with gvmd's own command until it takes: a volume created by an older release (as admin/admin), or
// one whose admin user has another password (core's data restored without the volumes), keeps it, and gvmd takes a new one only
// once its main process has loaded its feed and released its lock, which on a first start can take hours. The pause between
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
		if err := writeFileAtomic(o.stateFile(gbSocketMarker), []byte("vedette-host enabled podman.socket for OpenVAS; install.sh --uninstall disables it\n"), 0o600); err != nil {
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
// floor, not a pinned version: the package comes from the distribution's archive, whose security updates must flow in (as nmap).
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
		return fail(api.CodeGreenboneNoProvider, fmt.Sprintf("OpenVAS: %s is installed, but podman compose does not find docker-compose %d.%d.%d or newer.", pkg, gbProviderFloorM, gbProviderFloorN, gbProviderFloorP))
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
	v := [3]int{}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return slices.Compare(v[:], []int{gbProviderFloorM, gbProviderFloorN, gbProviderFloorP}) >= 0
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
	// compose stop leaves a service whose profile is off; ps lists it still (its orphans). The SCAP/CERT data containers of an
	// earlier OpenVAS are removed at the next up (gbLean) and are not a failure of the down.
	if s := slices.DeleteFunc(strings.Fields(out), func(x string) bool { return slices.Contains(gbLeanServices, x) }); len(s) > 0 {
		o.log.ErrorContext(ctx, "greenbone: services still running after stop", "running", strings.Join(s, " "))
		return fail(api.CodeGreenboneFailed, "OpenVAS: these services still run after the stop: "+strings.Join(s, ", ")+".")
	}
	return nil
}

// gbSyncFeed is Greenbone's feed update: pull the four feed images Vedette runs, start their services again, then remove the feed
// images they replaced (review r1 M4: each weekly pull would leave several GB of untagged images). Only the previous image of each of
// the four exact feed repositories, by its ID, without force: podman itself refuses one a container still uses or that has another name.
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
