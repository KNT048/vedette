package ops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// OpenVAS (D-529, FULL-2): the argv of greenbone.*, and up, down and the feed update against a fake podman, systemctl and apt-get
// that never run anything.

const gbTestPW = "0123456789abcdef0123456789abcdef0123456789abcdef"

func TestGreenboneArgvIsFixedAndValidated(t *testing.T) {
	t.Parallel()
	const state, unit = "/var/lib/vedette-host", "vedette-core.service"
	ok := map[string][]string{
		"podman up":         gbUpArgv(),
		"podman stop":       gbStopArgv(),
		"podman ps":         gbPsArgv(),
		"podman pull":       gbPullFeedArgv(),
		"podman upfeed":     gbUpFeedArgv(),
		"podman version":    gbVersionArgv(),
		"podman login":      gbLoginArgv(gbTestPW),
		"podman exists":     gbGvmdExistsArgv(),
		"podman inspect":    gbImageIDArgv("vulnerability-tests"),
		"podman rmi":        {"rmi", strings.Repeat("ab", 32)},
		"podman stop gvmd":  gbStopGvmdArgv(),
		"podman drop":       gbDropArgv(),
		"podman schemas":    gbSchemasArgv(),
		"podman label":      gbLeanLabelArgv("cert-bund-data"),
		"podman rm scap":    gbLeanRmArgv("scap-data"),
		"podman rm dfn":     gbLeanRmArgv("dfn-cert-data"),
		"podman vol exists": gbVolumeExistsArgv(gbProject + "_cert_data_vol"),
		"podman vol rm":     gbVolumeRmArgv(gbProject + "_scap_data_vol"),
		"podman inspect sc": gbImageIDArgv("scap-data"),
		"systemctl enabled": argsPodmanSocketEnabled,
		"systemctl en":      argsPodmanSocketEnable,
		"systemctl start":   argsPodmanSocketStart,
		"systemctl act":     argsPodmanSocketActive,
		"apt-get ubuntu":    gbAptInstallArgv("docker-compose-v2"),
		"apt-get debian":    gbAptInstallArgv("docker-compose"),
		"apt-get update ":   argsUpdate,
	}
	for name, a := range ok {
		bin, _, _ := strings.Cut(name, " ")
		if err := ValidateHostArgv(state, unit, bin, a); err != nil {
			t.Errorf("%s: refused %q: %v", name, a, err)
		}
	}
	if got := strings.Join(gbUpArgv(), " "); got != "compose -p greenbone-community-edition -f /usr/lib/vedette/greenbone/compose.yaml -f /usr/lib/vedette/greenbone/compose.vedette.yaml up -d" {
		t.Errorf("up argv %q", got)
	}
	// review r1 M3: docker-compose-v2 Recommends docker.io; no distribution's install may bring a Docker daemon
	for _, pkg := range gbProviderPkg {
		if a := gbAptInstallArgv(pkg); !slices.Contains(a, "--no-install-recommends") || !slices.Contains(a, "--no-remove") || a[len(a)-2] != "install" {
			t.Errorf("%s is installed with %q", pkg, a)
		}
	}
	// review r1 L3: every login try runs under the image's timeout
	if got := strings.Join(gbLoginArgv(gbTestPW)[:8], " "); got != "exec -u gvmd greenbone-community-edition-gvmd-1 timeout -k 5 60" {
		t.Errorf("login argv starts %q", got)
	}
	swap := func(a []string, from, to string) []string {
		b := slices.Clone(a)
		b[slices.Index(b, from)] = to
		return b
	}
	bad := map[string][]string{
		"podman another project":    swap(gbUpArgv(), gbProject, "vedette"),
		"podman another file":       swap(gbUpArgv(), gbOverrideFile, "/tmp/evil.yaml"),
		"podman down -v":            gbComposeArgv("down", "-v"),
		"podman rm":                 gbComposeArgv("rm", "-f"),
		"podman pull everything":    gbComposeArgv("pull"),
		"podman pull another":       swap(gbPullFeedArgv(), "notus-data", "gvmd"),
		"podman pull scap again":    append(gbPullFeedArgv(), "scap-data"),
		"podman stop another":       gbComposeArgv("stop", "pg-gvm"),
		"podman drop elsewhere":     swap(gbDropArgv(), gbPgContainer, "vedette-core"),
		"podman drop other sql":     swap(gbDropArgv(), "--command="+gbDropSQL, "--command=DROP SCHEMA public CASCADE"),
		"podman drop another db":    swap(gbDropArgv(), "-d", "-h"),
		"podman psql as root":       append([]string{"exec", "-u", "root"}, gbDropArgv()[1:]...),
		"podman rm gvmd":            gbLeanRmArgv("gvmd"),
		"podman label of gvmd":      gbLeanLabelArgv("gvmd"),
		"podman other query":        swap(gbSchemasArgv(), "--command="+gbSchemasSQL, "--command=SELECT * FROM users"),
		"podman psql short option":  append(swap(gbDropArgv(), "--command="+gbDropSQL, "-"+"c"), gbDropSQL),
		"podman rm pg":              {"rm", "--force", "--ignore", gbPgContainer},
		"podman rm volumes too":     {"rm", "--force", "--ignore", "--volumes", gbProject + "-scap-data-1"},
		"podman vol rm psql":        gbVolumeRmArgv(gbProject + "_psql_data_vol"),
		"podman vol rm force":       {"volume", "rm", "-f", gbProject + "_scap_data_vol"},
		"podman vol prune":          {"volume", "prune", "-f"},
		"podman up one more":        append(gbUpFeedArgv(), "gsad"),
		"podman exec elsewhere":     swap(gbLoginArgv(gbTestPW), gbGvmdContainer, "vedette-core"),
		"podman exec as root":       swap(gbLoginArgv(gbTestPW), "gvmd", "root"),
		"podman no timeout":         {"exec", "-u", "gvmd", gbGvmdContainer, "gvmd", "--user=admin", "--new-password=" + gbTestPW},
		"podman longer timeout":     swap(gbLoginArgv(gbTestPW), "60", "86400"),
		"podman short password":     gbLoginArgv("abc"),
		"podman upper password":     gbLoginArgv(strings.ToUpper(gbTestPW)),
		"podman shell password":     gbLoginArgv(gbTestPW[:40] + "';reboot"),
		"podman another user":       swap(gbLoginArgv(gbTestPW), "--user=admin", "--user=root"),
		"podman another gvmd verb":  swap(gbLoginArgv(gbTestPW), "--user=admin", "--delete-user=admin"),
		"podman create a user":      swap(gbLoginArgv(gbTestPW), "--user=admin", "--create-user=admin"),
		"podman exists elsewhere":   {"container", "exists", "vedette-core"},
		"podman exec a shell":       {"exec", "-u", "gvmd", gbGvmdContainer, "timeout", "-k", "5", "60", "sh", "-c", "--new-password=" + gbTestPW},
		"podman inspect gvmd":       gbImageIDArgv("gvmd"),
		"podman inspect elsewhere":  {"image", "inspect", "--format", "{{.Id}}", "docker.io/library/nginx"},
		"podman rmi force":          {"rmi", "-f", strings.Repeat("ab", 32)},
		"podman prune":              {"image", "prune", "-a", "-f"},
		"systemctl another socket":  {"enable", "--now", "docker.socket"},
		"systemctl disable socket":  {"disable", "--now", "podman.socket"},
		"apt-get another package":   gbAptInstallArgv("podman-compose"),
		"apt-get with recommends":   slices.DeleteFunc(gbAptInstallArgv("docker-compose-v2"), func(s string) bool { return s == "--no-install-recommends" }),
		"apt-get compose v1 remove": gbAptInstallArgv("docker-compose-"),
	}
	for name, a := range bad {
		bin, _, _ := strings.Cut(name, " ")
		err := ValidateHostArgv(state, unit, bin, a)
		if err == nil {
			t.Errorf("%s: accepted %q", name, a)
		} else if strings.Contains(err.Error(), gbTestPW[:16]) {
			t.Errorf("%s: the refusal names the password: %v", name, err)
		}
	}
}

func TestGreenboneFeedServicesAreGreenbones(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "greenbone", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range append(slices.Clone(gbFeedServices), gbMustRun...) {
		if !bytes.Contains(b, []byte("\n  "+s+":\n")) {
			t.Errorf("Greenbone's compose.yaml has no service %s", s)
		}
	}
	for _, s := range gbFeedServices { // the ref the feed update inspects is the image line of the file
		if !bytes.Contains(b, []byte("\n    image: "+gbRegistry+s+"\n")) {
			t.Errorf("the image of %s is not %s%s", s, gbRegistry, s)
		}
	}
	if !bytes.Contains(b, []byte("\nname: "+gbProject+"\n")) {
		t.Errorf("the project is not %s", gbProject)
	}
}

// gbWorld is a fake podman, systemctl and apt-get for the OpenVAS commands.
type gbWorld struct {
	t         *testing.T
	o         *Ops
	base      string
	log       *bytes.Buffer
	logw      *syncWriter
	mu        sync.Mutex
	calls     []string
	version   string    // what podman compose version prints ("" fails, like a podman without a provider)
	install   string    // the version after apt-get install
	logins    int       // how many logins fail before one works (-1: never)
	locked    time.Time // until then gvmd holds its lock (it loads its feed): a login try is ended by the image's timeout (124)
	running   string    // what compose ps prints
	gone      bool      // gvmd's container no longer exists
	pws       []string  // the password of each login try
	socketOn  bool      // podman.socket is enabled
	upGate    chan struct{}
	upIn      chan struct{}
	psGate    chan struct{} // when set, compose ps waits for it (or its context)
	sleeps    int
	images    map[string]string // feed service -> image ID
	newImages map[string]string // what the pull changes
	pullCode  int
	// gbLean (D-593): the SCAP/CERT containers there are (service -> its label io.vedette.started-by), the volumes there are, what
	// the schema query prints (the schemas that hold data; a drop that works empties it), the exit codes of the drop tries in turn
	// (then 0; dropFail: always 2), and of compose stop gvmd, a volume rm that fails, image IDs whose rmi is refused, compose up
	// failing once gvmd was stopped (gvmd does not start again), a hook at compose stop gvmd, whether gvmd ran when the drop came,
	// and what compose ps printed before compose stop gvmd.
	ctrs        map[string]string
	volumes     map[string]bool
	schemas     string
	dropCodes   []int
	dropFail    bool
	stopCode    int
	volRmCode   int
	rmiRefused  map[string]bool
	restartFail bool
	onStopGvmd  func()
	dropLive    bool
	beforeOff   string
}

func newGBWorld(t *testing.T, osRelease string) *gbWorld {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "var", "lib", "vedette-host") // the shipped state directory under the fake root (compose names it)
	for _, d := range []string{state, filepath.Join(base, "run"), filepath.Join(base, "etc"), filepath.Join(base, gbFilesDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // the fake root of a test, like /run and /etc
			t.Fatal(err)
		}
	}
	for _, f := range []string{gbComposeFile, gbOverrideFile} {
		if err := os.WriteFile(filepath.Join(base, f), []byte("services: {}\n"), 0o644); err != nil { //nolint:gosec // a fake compose file
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "etc", "os-release"), []byte(osRelease), 0o644); err != nil { //nolint:gosec // a fake os-release
		t.Fatal(err)
	}
	w := &gbWorld{t: t, base: base, log: &bytes.Buffer{}, version: "2.40.3+ds1-0ubuntu1", install: "2.40.3",
		running: "gvmd\nospd-openvas\npg-gvm\nredis-server\nopenvasd\n", images: map[string]string{}, newImages: map[string]string{}}
	for i, s := range gbFeedServices {
		w.images[s] = strings.Repeat(string(rune('a'+i)), 64)
	}
	w.volumes, w.ctrs, w.rmiRefused = map[string]bool{}, map[string]string{}, map[string]bool{}
	w.logw = &syncWriter{w: w.log}
	logger := slog.New(slog.NewTextHandler(w.logw, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, err := NewWithDeps(Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), CoreGID: os.Getgid(), Logger: logger}, Deps{
		Root: base, ChainTop: base, GreenboneUID: os.Getuid(),
		LockHeld: func(string) (bool, error) { return false, nil },
		Sleep: func(ctx context.Context, _ time.Duration) bool {
			w.mu.Lock()
			w.sleeps++
			n := w.sleeps
			w.mu.Unlock()
			return ctx.Err() == nil && n < 5
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	o.gbExec = w.exec
	w.o = o
	return w
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// logs is what the host logged so far (the re-sync may write while a test reads).
func (w *gbWorld) logs() string {
	w.logw.mu.Lock()
	defer w.logw.mu.Unlock()
	return w.log.String()
}

func (w *gbWorld) exec(ctx context.Context, name string, _ io.Reader, args ...string) (vexec.Result, int, error) {
	if _, ok := ctx.Deadline(); !ok {
		w.t.Errorf("%s %q runs without a deadline", name, args)
	}
	if err := ValidateHostArgv(w.o.cfg.StateDir, "vedette-core.service", name, args); err != nil {
		w.t.Errorf("the host runner refuses %s %q: %v", name, args, err)
		return vexec.Result{}, -1, err
	}
	line := name + " " + strings.Join(args, " ")
	if strings.Contains(line, "--new-password=") {
		line = name + " exec gvmd --new-password"
	}
	w.mu.Lock()
	w.calls = append(w.calls, line)
	w.mu.Unlock()
	switch {
	case name == binPodman && slices.Equal(args, gbVersionArgv()):
		if w.version == "" {
			return vexec.Result{}, 125, nil
		}
		return vexec.Result{Stdout: []byte(w.version + "\n")}, 0, nil
	case name == binAptGet && slices.Equal(args, argsUpdate):
		return vexec.Result{}, 0, nil
	case name == binAptGet:
		w.version = w.install
		return vexec.Result{}, 0, nil
	case name == binSystemctl && slices.Equal(args, argsPodmanSocketEnabled):
		if w.socketOn {
			return vexec.Result{Stdout: []byte("enabled\n")}, 0, nil
		}
		return vexec.Result{Stdout: []byte("disabled\n")}, 1, nil
	case name == binSystemctl && slices.Equal(args, argsPodmanSocketEnable):
		w.socketOn = true
		return vexec.Result{}, 0, nil
	case name == binSystemctl && slices.Equal(args, argsPodmanSocketActive):
		return vexec.Result{Stdout: []byte("active\n")}, 0, nil
	case slices.Equal(args, gbUpArgv()):
		w.mu.Lock()
		if w.beforeOff != "" { // compose up starts the gvmd that compose stop gvmd stopped
			if w.restartFail {
				w.mu.Unlock()
				return vexec.Result{}, 1, nil
			}
			w.running, w.beforeOff = w.beforeOff, ""
		}
		w.mu.Unlock()
		if w.upIn != nil {
			w.upIn <- struct{}{}
		}
		if w.upGate != nil {
			select {
			case <-w.upGate:
			case <-ctx.Done():
				return vexec.Result{}, -1, ctx.Err()
			}
		}
		return vexec.Result{}, 0, nil
	case len(args) == 11 && args[0] == "exec" && args[1] == "-u": // the login (the drop is exec too)
		w.mu.Lock()
		defer w.mu.Unlock()
		w.pws = append(w.pws, strings.TrimPrefix(args[10], "--new-password="))
		if w.gone {
			return vexec.Result{}, 125, nil
		}
		if time.Now().Before(w.locked) {
			return vexec.Result{}, 124, nil
		}
		if w.logins != 0 {
			if w.logins > 0 {
				w.logins--
			}
			return vexec.Result{Stderr: []byte("Failed to modify user")}, 1, nil
		}
		return vexec.Result{}, 0, nil
	case slices.Equal(args, gbPsArgv()):
		if w.psGate != nil {
			select {
			case <-w.psGate:
			case <-ctx.Done():
				return vexec.Result{}, -1, ctx.Err()
			}
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		return vexec.Result{Stdout: []byte(w.running)}, 0, nil
	case slices.Equal(args, gbGvmdExistsArgv()):
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.gone {
			return vexec.Result{}, 1, nil
		}
		return vexec.Result{}, 0, nil
	case slices.Equal(args, gbStopArgv()):
		w.mu.Lock()
		// compose stop leaves the services whose profile is off (the old SCAP/CERT containers); ps still lists them
		w.running = strings.Join(slices.DeleteFunc(strings.Fields(w.running), func(x string) bool { return !slices.Contains(gbLeanServices, x) }), "\n")
		w.mu.Unlock()
		return vexec.Result{}, 0, nil
	case slices.Equal(args, gbStopGvmdArgv()):
		w.mu.Lock()
		hook := w.onStopGvmd
		if w.stopCode == 0 {
			w.beforeOff, w.running = w.running, strings.Replace(w.running, "gvmd\n", "", 1)
		}
		code := w.stopCode
		w.mu.Unlock()
		if hook != nil {
			hook()
		}
		return vexec.Result{}, code, nil
	case slices.Equal(args, gbSchemasArgv()):
		w.mu.Lock()
		defer w.mu.Unlock()
		return vexec.Result{Stdout: []byte(w.schemas)}, 0, nil
	case slices.Equal(args, gbDropArgv()):
		w.mu.Lock()
		defer w.mu.Unlock()
		w.dropLive = w.dropLive || slices.Contains(strings.Fields(w.running), "gvmd")
		code := 0
		switch {
		case w.dropFail:
			code = 2
		case len(w.dropCodes) > 0:
			code, w.dropCodes = w.dropCodes[0], w.dropCodes[1:]
		}
		if code == 0 {
			w.schemas = ""
		}
		return vexec.Result{}, code, nil
	case len(args) == 5 && args[0] == "container" && args[1] == "inspect":
		w.mu.Lock()
		defer w.mu.Unlock()
		label, ok := w.ctrs[strings.TrimSuffix(strings.TrimPrefix(args[4], gbProject+"-"), "-1")]
		if !ok {
			return vexec.Result{Stderr: []byte("Error: no such container")}, 125, nil
		}
		return vexec.Result{Stdout: []byte(label + "\n")}, 0, nil
	case len(args) == 4 && args[0] == "rm":
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.ctrs, strings.TrimSuffix(strings.TrimPrefix(args[3], gbProject+"-"), "-1"))
		return vexec.Result{}, 0, nil
	case len(args) == 3 && args[0] == "volume":
		w.mu.Lock()
		defer w.mu.Unlock()
		switch {
		case args[1] == "exists" && w.volumes[args[2]]:
			return vexec.Result{}, 0, nil
		case args[1] == "exists":
			return vexec.Result{}, 1, nil
		case w.volRmCode != 0:
			return vexec.Result{}, w.volRmCode, nil
		}
		delete(w.volumes, args[2])
		return vexec.Result{}, 0, nil
	case slices.Equal(args, gbPullFeedArgv()):
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.pullCode == 0 {
			for s, id := range w.newImages {
				w.images[s] = id
			}
		}
		return vexec.Result{}, w.pullCode, nil
	case slices.Equal(args, gbUpFeedArgv()):
		return vexec.Result{}, 0, nil
	case len(args) == 5 && args[0] == "image" && args[1] == "inspect":
		w.mu.Lock()
		defer w.mu.Unlock()
		id, ok := w.images[strings.TrimPrefix(args[4], gbRegistry)]
		if !ok {
			return vexec.Result{Stderr: []byte("Error: no such image")}, 125, nil
		}
		return vexec.Result{Stdout: []byte("sha256:" + id + "\n")}, 0, nil
	case len(args) == 2 && args[0] == "rmi":
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.rmiRefused[args[1]] {
			return vexec.Result{Stderr: []byte("Error: image is in use by a container")}, 2, nil
		}
		return vexec.Result{}, 0, nil
	}
	w.t.Errorf("unexpected call %s", line)
	return vexec.Result{}, -1, errors.New("unexpected")
}

func (w *gbWorld) Calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.calls)
}

// count is how many calls are line.
func (w *gbWorld) count(line string) int {
	n := 0
	for _, c := range w.Calls() {
		if c == line {
			n++
		}
	}
	return n
}

const gbLoginLine = "podman exec gvmd --new-password"

func (w *gbWorld) up(ctx context.Context) error {
	return w.o.gbOp(ctx, false, gbUpLimit, func(ctx context.Context) error { return w.o.gbUp(ctx, nolog, gbTestPW) })
}

func (w *gbWorld) down(ctx context.Context) error {
	return w.o.gbOp(ctx, true, gbDownLimit, func(ctx context.Context) error { return w.o.gbDown(ctx, nolog) })
}

const ubuntu2604 = "ID=ubuntu\nVERSION_ID=\"26.04\"\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\n"

func TestGreenboneUp_TheFirstStartInstallsTheProviderAndSetsTheLogin(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) { // synctest.Wait lets the background re-sync of the login end
		testGreenboneFirstStart(t)
	})
}

func testGreenboneFirstStart(t *testing.T) {
	w := newGBWorld(t, ubuntu2604)
	w.version, w.logins = "", 2 // no provider yet; gvmd takes the login again at the third try of the re-sync
	if err := w.up(t.Context()); err != nil {
		t.Fatal(err)
	}
	ps := "podman " + strings.Join(gbPsArgv(), " ")
	want := []string{
		"podman compose version --short",
		"apt-get -q update",
		"apt-get " + strings.Join(gbAptInstallArgv("docker-compose-v2"), " "),
		"podman compose version --short",
		"systemctl is-enabled podman.socket",
		"systemctl enable --now podman.socket",
		"systemctl is-active podman.socket",
		"podman " + strings.Join(gbUpArgv(), " "),
		ps, // up checks the services and returns: the login is gvmd's from the creation of its user (N42-4)
	}
	want = append(want, gbLeanFreshCalls()...) // a new box has no SCAP/CERT data to remove (D-593); once
	synctest.Wait()
	exists := "podman " + strings.Join(gbGvmdExistsArgv(), " ")
	want = append(want, gbLoginLine, exists, gbLoginLine, exists, gbLoginLine) // the re-sync in the background, until it takes
	if got := w.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls\n%q\nwant\n%q", got, want)
	}
	if !strings.Contains(w.logs(), "gvmd took Vedette's GMP login") {
		t.Fatalf("the re-sync is not in the log: %s", w.logs())
	}
	// review r1 M1: the parent is 0750, root's (here the test's uid) and core's group; gvmd's own folder 0755
	for d, mode := range map[string]os.FileMode{api.GreenboneRunDir: 0o750, api.GreenboneSocketDir: 0o755} {
		st, err := os.Lstat(filepath.Join(w.base, d))
		if err != nil || !st.IsDir() || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want a directory %o", d, st, err, mode)
		}
	}
	st, _ := os.Lstat(filepath.Join(w.base, api.GreenboneRunDir))
	if sys := st.Sys().(*syscall.Stat_t); int(sys.Uid) != os.Getuid() || int(sys.Gid) != os.Getgid() {
		t.Errorf("%s is %d:%d, want the owner uid and core's gid %d:%d", api.GreenboneRunDir, sys.Uid, sys.Gid, os.Getuid(), os.Getgid())
	}
	// review r1 L5: the host enabled podman.socket, so it says so for install.sh --uninstall
	marker := w.o.stateFile(gbSocketMarker)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("no marker after enabling podman.socket: %v", err)
	}
	// A second start finds the provider and the socket enabled: no apt-get, no enable, no new marker.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	w.calls = nil
	if err := w.up(t.Context()); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if c := w.Calls(); slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "apt-get") || strings.Contains(s, "enable --now") }) {
		t.Errorf("apt-get or enable ran again: %q", c)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a marker was written for a podman.socket that was already enabled")
	}
	if strings.Contains(w.logs(), gbTestPW) {
		t.Fatal("the password is in the log")
	}
}

// review r1 M1: a parent folder an earlier host made 0755 is narrowed at the next start.
func TestGreenboneAtStart_TheParentIsClosedToOthers(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	d := filepath.Join(w.base, api.GreenboneRunDir)
	if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // what an earlier host made
		t.Fatal(err)
	}
	w.o.gbAtStart()
	if st, err := os.Lstat(d); err != nil || st.Mode().Perm() != 0o750 {
		t.Fatalf("%v %v, want 0750", st, err)
	}
}

// N42-4 (D-590): on a first start gvmd holds its lock while it loads its feed, hours on the N100, and `gvmd --new-password` waits on
// it. Up does not wait for it and never stops the project because of it: it returns once the services run, and the re-sync keeps
// trying in the background, past the 20 minutes the earlier login wait gave up at, until gvmd takes it. The password is never logged.
func TestGreenboneUp_ReturnsWhileGvmdLoadsItsFeedAndTheLoginIsSetAfter(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newGBWorld(t, ubuntu2604)
		w.o.d.Sleep = sleepCtx // the fake clock of the bubble: the re-sync's pauses are real waits
		start := time.Now()
		w.locked = start.Add(3 * time.Hour)
		if err := w.up(t.Context()); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d != 0 {
			t.Fatalf("up returned after %s: it waited for gvmd's lock", d)
		}
		synctest.Wait()
		if n := w.count(gbLoginLine); n != 1 {
			t.Fatalf("%d login tries right after up, want the first one", n)
		}
		<-time.After(4 * time.Hour)
		synctest.Wait()
		// review r1 M3: the pause doubles from 10 s to 5 min, so 3 hours hold about 40 tries, not 1000; the log says it once an hour
		if n := w.count(gbLoginLine); n < int(3*time.Hour/gbLoginMax) || n > int(3*time.Hour/gbLoginMax)+10 {
			t.Fatalf("%d login tries in 3 hours, want about one every %s once backed off", n, gbLoginMax)
		}
		if n := strings.Count(w.logs(), "still does not take the GMP login"); n < 2 || n > 3 {
			t.Fatalf("%d hourly lines in 3 hours: %s", n, w.logs())
		}
		if w.count("podman "+strings.Join(gbStopArgv(), " ")) != 0 {
			t.Fatalf("the project was stopped: %q", w.Calls())
		}
		n := w.count(gbLoginLine)
		<-time.After(time.Hour)
		synctest.Wait()
		if w.count(gbLoginLine) != n || !strings.Contains(w.logs(), "gvmd took Vedette's GMP login") {
			t.Fatalf("the re-sync did not end once gvmd took the login: %d → %d tries; log %s", n, w.count(gbLoginLine), w.logs())
		}
		if strings.Contains(w.logs(), gbTestPW) || strings.Contains(w.logs(), gbTestPW[:12]) {
			t.Fatalf("the password leaked into the log: %s", w.logs())
		}
	})
}

// The re-sync ends at greenbone.down (it is cancelled with the operation that runs) and when gvmd's container is gone; a gvmd that
// restarts mid-load (not running for a while, its container still there) does not end it (review r1 M1).
func TestGreenboneUp_TheLoginReSyncEndsOnDownAndWhenGvmdIsGone(t *testing.T) {
	t.Parallel()
	for _, end := range []string{"down", "gvmd gone", "gvmd restarting"} {
		synctest.Test(t, func(t *testing.T) {
			w := newGBWorld(t, ubuntu2604)
			w.o.d.Sleep = sleepCtx
			w.logins = -1 // gvmd never takes it
			if err := w.up(t.Context()); err != nil {
				t.Fatal(err)
			}
			<-time.After(time.Minute)
			synctest.Wait()
			if w.count(gbLoginLine) < 2 {
				t.Fatalf("%s: the re-sync does not run: %q", end, w.Calls())
			}
			w.mu.Lock()
			switch end {
			case "gvmd gone":
				w.gone = true
			case "gvmd restarting":
				w.running = "pg-gvm\nredis-server\n"
			}
			w.mu.Unlock()
			if end == "down" {
				if err := w.down(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			<-time.After(10 * time.Minute) // the try that ran sees it
			synctest.Wait()
			n := w.count(gbLoginLine)
			<-time.After(time.Hour)
			synctest.Wait()
			if end == "gvmd restarting" {
				if w.count(gbLoginLine) <= n {
					t.Fatalf("the re-sync ended while gvmd's container was still there: %d tries", n)
				}
				w.mu.Lock()
				w.gone = true // the end of the bubble needs the re-sync to end
				w.mu.Unlock()
				<-time.After(10 * time.Minute)
				return
			}
			if w.count(gbLoginLine) != n {
				t.Fatalf("%s: the re-sync went on: %d → %d tries", end, n, w.count(gbLoginLine))
			}
			if end == "gvmd gone" && !strings.Contains(w.logs(), "gvmd's container is gone") {
				t.Fatalf("the end is not in the log: %s", w.logs())
			}
		})
	}
}

// Review r1 L5: a down that lands while an up is still checking its services ends that up, and no re-sync starts after it; and a
// re-sync is never started for an up whose context a down already cancelled.
func TestGreenboneUp_ADownDuringAnUpStartsNoReSync(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newGBWorld(t, ubuntu2604)
		w.o.d.Sleep = sleepCtx
		w.logins = -1
		w.psGate = make(chan struct{})
		queued := make(chan struct{}, 2)
		w.o.gbOnQueue = func() { queued <- struct{}{} }
		res := make(chan error, 1)
		go func() { res <- w.up(t.Context()) }()
		<-queued
		synctest.Wait() // the up waits in compose ps, after compose up
		downed := make(chan error, 1)
		go func() { downed <- w.down(t.Context()) }()
		var f *server.Failure
		if err := <-res; !errors.As(err, &f) || f.Code != api.CodeGreenboneCancelled {
			t.Fatalf("%v, want greenbone_cancelled", err)
		}
		close(w.psGate) // the down's own compose ps
		if err := <-downed; err != nil {
			t.Fatal(err)
		}
		<-time.After(time.Hour)
		synctest.Wait()
		if n := w.count(gbLoginLine); n != 0 {
			t.Fatalf("%d login tries after the down", n)
		}
		cctx, cancel := context.WithCancel(t.Context())
		cancel()
		w.o.gbResyncStart(func() bool { return cctx.Err() == nil }, gbTestPW)
		synctest.Wait()
		w.o.gbMu.Lock()
		started := w.o.gbResyncStop != nil
		w.o.gbMu.Unlock()
		if w.count(gbLoginLine) != 0 || started {
			t.Fatal("a re-sync started for a cancelled up")
		}
	})
}

// Review r1 L5: a second up replaces the re-sync of the first: only one runs, with the second up's password.
func TestGreenboneUp_ASecondUpReplacesTheReSync(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newGBWorld(t, ubuntu2604)
		w.o.d.Sleep = sleepCtx
		w.logins = -1
		if err := w.up(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-time.After(time.Minute)
		synctest.Wait()
		const pw2 = "fedcba9876543210fedcba9876543210fedcba9876543210"
		if err := w.o.gbOp(t.Context(), false, gbUpLimit, func(ctx context.Context) error { return w.o.gbUp(ctx, nolog, pw2) }); err != nil {
			t.Fatal(err)
		}
		w.mu.Lock()
		from := len(w.pws)
		w.mu.Unlock()
		<-time.After(2 * time.Hour)
		synctest.Wait()
		w.mu.Lock()
		later := slices.Clone(w.pws[from:])
		w.gone = true // the end of the bubble needs the re-sync to end
		w.mu.Unlock()
		if len(later) == 0 || slices.Contains(later, gbTestPW) {
			t.Fatalf("after the second up the tries used %d passwords, some the first up's: the first re-sync goes on", len(later))
		}
		if len(later) > int(2*time.Hour/gbLoginMax)+10 {
			t.Fatalf("%d tries in 2 hours: more than one re-sync runs", len(later))
		}
		<-time.After(10 * time.Minute)
	})
}

// Review r1 M1, L5: at the host's start, a project whose gvmd runs gets the re-sync again with the password of the file; a stopped
// project, or no file, gets nothing, and a resume never replaces the re-sync of an up that came first.
func TestGreenboneResume_AtTheHostsStart(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"gvmd runs", "stopped", "no file", "after an up"} {
		synctest.Test(t, func(t *testing.T) {
			w := newGBWorld(t, ubuntu2604)
			w.o.d.Sleep = sleepCtx
			if c != "no file" {
				if err := w.o.gbPasswordWrite(gbTestPW); err != nil {
					t.Fatal(err)
				}
			}
			if c == "stopped" {
				w.running = ""
			}
			w.logins = 1
			if c == "after an up" {
				w.logins = -1
				if err := w.up(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			w.mu.Lock()
			before := len(w.pws)
			w.mu.Unlock()
			w.o.gbResume(t.Context())
			<-time.After(time.Hour)
			synctest.Wait()
			w.mu.Lock()
			tries := slices.Clone(w.pws[before:])
			w.gone = true
			w.mu.Unlock()
			switch c {
			case "gvmd runs":
				if len(tries) != 2 || tries[0] != gbTestPW || !strings.Contains(w.logs(), "gvmd took Vedette's GMP login") {
					t.Fatalf("the re-sync did not resume: %d tries; %s", len(tries), w.logs())
				}
			case "after an up":
				if len(tries) > int(time.Hour/gbLoginMax)+10 {
					t.Fatalf("%d tries in an hour: the resume started a second re-sync", len(tries))
				}
			default:
				if len(tries) != 0 {
					t.Fatalf("%s: %d login tries", c, len(tries))
				}
			}
			if strings.Contains(w.logs(), gbTestPW) {
				t.Fatal("the password is in the log")
			}
			<-time.After(10 * time.Minute)
		})
	}
}

// N42-4 (D-590): the password reaches gvmd as a file only root and gvmd's uid read: the directory root's 0700, the file 0400 and
// gvmd's (here the test's uid), the password and a newline. A directory open to others is refused before compose up, without the
// password in the message or the log.
func TestGreenboneUp_ThePasswordFileIsGvmdsAlone(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newGBWorld(t, ubuntu2604)
		if err := w.up(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		dir, file := w.o.gbPasswordPath()
		if file != filepath.Join(w.base, gbPasswordShipped) {
			t.Fatalf("the file is %s, not the shipped path under the fake root", file)
		}
		if st, err := os.Lstat(dir); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v, want a directory 0700", dir, st, err)
		}
		st, err := os.Lstat(file)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o400 {
			t.Fatalf("%s: %v %v, want a file 0400", file, st, err)
		}
		if sys := st.Sys().(*syscall.Stat_t); int(sys.Uid) != os.Getuid() {
			t.Fatalf("%s is owned by %d, want gvmd's uid (here %d)", file, sys.Uid, os.Getuid())
		}
		if b, err := os.ReadFile(file); err != nil || string(b) != gbTestPW+"\n" { //nolint:gosec // the test's own file
			t.Fatalf("%s holds %q, %v", file, b, err)
		}
		if pw, err := w.o.gbPasswordRead(); err != nil || pw != gbTestPW {
			t.Fatalf("read back: %v", err)
		}
		// review r1 L1: a temp file a write cut short left behind is removed at the next write
		if err := os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte(gbTestPW), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := w.o.gbPasswordWrite(gbTestPW); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatalf("%s holds %v, want only the password file (no temp file left)", dir, entries)
		}
		w2 := newGBWorld(t, ubuntu2604)
		d2, _ := w2.o.gbPasswordPath()
		if err := os.MkdirAll(d2, 0o755); err != nil { //nolint:gosec // a directory open to others
			t.Fatal(err)
		}
		var f *server.Failure
		if err := w2.up(t.Context()); !errors.As(err, &f) || f.Code != api.CodeGreenboneFailed || !strings.Contains(f.Message, "/var/lib/vedette-host/greenbone") {
			t.Fatalf("%v, want greenbone_failed naming the directory", err)
		}
		if slices.Contains(w2.Calls(), "podman "+strings.Join(gbUpArgv(), " ")) {
			t.Fatalf("compose up ran without the password file: %q", w2.Calls())
		}
		if strings.Contains(f.Message, gbTestPW) || strings.Contains(w2.logs(), gbTestPW) {
			t.Fatalf("the password leaked: %q / %s", f.Message, w2.logs())
		}
		// review r1 L4: the file is in the state directory, which must be the shipped one the override names
		w3 := newGBWorld(t, ubuntu2604)
		w3.o.cfg.StateDir = filepath.Join(w3.base, "srv", "host-state")
		if err := w3.up(t.Context()); !errors.As(err, &f) || !strings.Contains(f.Message, "/var/lib/vedette-host") {
			t.Fatalf("%v, want a failure about the state directory", err)
		}
		if slices.Contains(w3.Calls(), "podman "+strings.Join(gbUpArgv(), " ")) {
			t.Fatalf("compose up ran with another state directory: %q", w3.Calls())
		}
	})
}

// The override gives gvmd the file the host writes (deploy/greenbone checks the rest of the command).
func TestGreenboneOverrideNamesThePasswordFile(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "greenbone", "compose.vedette.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("\nsecrets:\n  vedette-gmp-password:\n    file: "+gbPasswordShipped+"\n")) {
		t.Fatalf("compose.vedette.yaml does not give gvmd %s as the secret vedette-gmp-password", gbPasswordShipped)
	}
}

func TestGreenboneUp_AServiceThatDoesNotRunIsAFailure(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.running = "gvmd\npg-gvm\nredis-server\n"
	var f *server.Failure
	if err := w.up(t.Context()); !errors.As(err, &f) || !strings.Contains(f.Message, "ospd-openvas") {
		t.Fatalf("%v, want a failure naming ospd-openvas", err)
	}
}

func TestGreenboneUp_AnOSWithoutTheProviderSaysSo(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.version, w.install = "", "1.29.2" // the package installs, but podman compose does not find a v2
	var f *server.Failure
	if err := w.up(t.Context()); !errors.As(err, &f) || f.Code != api.CodeGreenboneNoProvider {
		t.Fatalf("%v, want greenbone_no_provider", err)
	}
	w2 := newGBWorld(t, "ID=debian\nVERSION_ID=\"13\"\n")
	w2.version = ""
	_ = w2.up(t.Context())
	if !slices.Contains(w2.Calls(), "apt-get "+strings.Join(gbAptInstallArgv("docker-compose"), " ")) {
		t.Errorf("Debian 13 did not install docker-compose without recommends: %q", w2.Calls())
	}
}

// Down ends an up that still pulls (OpenVAS turned off during the first start), and an up that waited behind it gives up instead of
// starting the project after the down (review r1 L1); then it stops the project; the volumes are never named.
func TestGreenboneDown_CancelsTheRunningUpAndOneThatWaits(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.upGate, w.upIn = make(chan struct{}), make(chan struct{}, 2)
	queuedAt := make(chan struct{}, 3)
	w.o.gbOnQueue = func() { queuedAt <- struct{}{} }
	first, queued := make(chan error, 1), make(chan error, 1)
	go func() { first <- w.up(t.Context()) }()
	<-queuedAt
	<-w.upIn // the first up runs compose up
	go func() { queued <- w.up(t.Context()) }()
	<-queuedAt // the second has taken its generation and waits for the slot
	if err := w.down(t.Context()); err != nil {
		t.Fatal(err)
	}
	var f *server.Failure
	for name, ch := range map[string]chan error{"the running up": first, "the queued up": queued} {
		if err := <-ch; !errors.As(err, &f) || f.Code != api.CodeGreenboneCancelled {
			t.Fatalf("%s: %v, want greenbone_cancelled", name, err)
		}
	}
	c := w.Calls()
	ups := 0
	for _, l := range c {
		if l == "podman "+strings.Join(gbUpArgv(), " ") {
			ups++
		}
		if strings.Contains(l, " down") || strings.Contains(l, " -v") || strings.Contains(l, "volume") || strings.Contains(l, " rm ") {
			t.Errorf("down touched more than the containers: %s", l)
		}
	}
	if ups != 1 || c[len(c)-2] != "podman "+strings.Join(gbStopArgv(), " ") {
		t.Fatalf("calls %q: want one compose up, then the stop last", c)
	}
}

// review r1 M4: a feed update removes the feed images it replaced, by ID, and only those; a failed pull removes nothing.
func TestGreenboneSyncFeed_PullsStartsAndRemovesTheReplacedFeedImages(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	oldVT, oldScap := w.images["vulnerability-tests"], w.images["notus-data"]
	w.newImages["vulnerability-tests"], w.newImages["notus-data"] = strings.Repeat("1", 64), strings.Repeat("2", 64)
	sync := func() error {
		return w.o.gbOp(t.Context(), false, gbSyncLimit, func(ctx context.Context) error { return w.o.gbSyncFeed(ctx, nolog) })
	}
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	var rmis []string
	for _, l := range w.Calls() {
		if strings.HasPrefix(l, "podman rmi ") {
			rmis = append(rmis, strings.TrimPrefix(l, "podman rmi "))
		}
	}
	slices.Sort(rmis)
	want := []string{oldVT, oldScap}
	slices.Sort(want)
	if !slices.Equal(rmis, want) {
		t.Fatalf("removed %q, want only the two replaced images %q", rmis, want)
	}
	c := w.Calls()
	if i, j := slices.Index(c, "podman "+strings.Join(gbPullFeedArgv(), " ")), slices.Index(c, "podman "+strings.Join(gbUpFeedArgv(), " ")); i < 0 || j < i {
		t.Fatalf("calls %q", c)
	}
	if got := strings.Join(gbPullFeedArgv()[7:], " "); got != "pull notus-data vulnerability-tests report-formats data-objects" { // no SCAP/CERT (D-593)
		t.Fatalf("the feed pull is %q", got)
	}
	w.calls, w.pullCode = nil, 1
	w.newImages["data-objects"] = strings.Repeat("3", 64)
	if err := sync(); err == nil {
		t.Fatal("a failed pull is not a failure")
	}
	if slices.ContainsFunc(w.Calls(), func(l string) bool { return strings.HasPrefix(l, "podman rmi") }) {
		t.Fatalf("a failed update removed images: %q", w.Calls())
	}
}

func TestGreenboneUpArgs_RefuseAPasswordOfAnotherShape(t *testing.T) {
	t.Parallel()
	for _, pw := range []string{"", "admin", strings.ToUpper(gbTestPW), gbTestPW + "0", gbTestPW[:47] + "g"} {
		err := gbArgs(api.GreenboneUpArgs{Password: pw})
		var ae *server.ArgsError
		if !errors.As(err, &ae) || ae.Details[0].Field != "args.password" {
			t.Errorf("%q: %v, want a refusal of args.password", pw, err)
		}
		if pw != "" && strings.Contains(err.Error(), pw) {
			t.Errorf("the refusal repeats the value %q", pw)
		}
	}
	if err := gbArgs(api.GreenboneUpArgs{Password: gbTestPW}); err != nil {
		t.Fatal(err)
	}
}

// gbLeanFreshCalls are gbLean's calls on a lean box: no SCAP/CERT container, no schema holding data, no volume: a few reads.
func gbLeanFreshCalls() []string {
	var c []string
	for _, s := range gbLeanServices {
		c = append(c, "podman "+strings.Join(gbLeanLabelArgv(s), " "))
	}
	c = append(c, "podman "+strings.Join(gbSchemasArgv(), " "))
	for _, v := range gbLeanVolumes {
		c = append(c, "podman "+strings.Join(gbVolumeExistsArgv(v), " "))
	}
	return c
}

// gbLeanWorld is a box whose OpenVAS ran the SCAP/CERT services under Vedette's label: their containers, both volumes, both schemas
// with data, the three images.
func gbLeanWorld(t *testing.T) *gbWorld {
	t.Helper()
	w := newGBWorld(t, ubuntu2604)
	for i, s := range gbLeanServices {
		w.ctrs[s] = "vedette-host"
		w.images[s] = strings.Repeat(string(rune('7'+i)), 64)
	}
	for _, v := range gbLeanVolumes {
		w.volumes[v] = true
	}
	w.schemas = "scap\ncert\n"
	w.o.d.Sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil } // every pause ends at once
	return w
}

func gbP(a []string) string { return "podman " + strings.Join(a, " ") }

// gbLeanCalls is what one gbLean pass ran (the login re-sync left out).
func (w *gbWorld) leanCalls() []string {
	c := w.Calls()
	i := slices.Index(c, gbP(gbLeanLabelArgv(gbLeanServices[0])))
	if i < 0 {
		return nil
	}
	return slices.DeleteFunc(c[i:], func(l string) bool { return l == gbLoginLine || l == gbP(gbGvmdExistsArgv()) })
}

// LEAN-1 stage A (D-593, review r1): on a box whose OpenVAS ran the SCAP/CERT data, the up removes the three containers first, then,
// while a schema holds data, stops gvmd, drops the schemas (PostgreSQL still starting is asked again) and starts gvmd again, then
// removes the volumes and the images of Vedette's containers. Each up decides from the box: once all is gone a pass only reads;
// what failed (or what an older build brought back) is done at the next up.
func TestGreenboneUp_RemovesTheSCAPAndCERTDataOfAnEarlierOpenVAS(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"upgraded", "postgres starting", "drop fails", "volume stays"} {
		synctest.Test(t, func(t *testing.T) {
			w := gbLeanWorld(t)
			switch c {
			case "postgres starting":
				w.dropCodes = []int{2, 2}
			case "drop fails":
				w.dropFail = true
			case "volume stays":
				w.volRmCode = 1
			}
			var said []string
			up := func() error {
				return w.o.gbOp(t.Context(), false, gbUpLimit, func(ctx context.Context) error {
					return w.o.gbUp(ctx, func(s string) { said = append(said, s) }, gbTestPW)
				})
			}
			if err := up(); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			drops := map[string]int{"upgraded": 1, "postgres starting": 3, "drop fails": gbDropTries, "volume stays": 1}[c]
			var want []string
			for _, s := range gbLeanServices {
				want = append(want, gbP(gbLeanLabelArgv(s)), gbP(gbLeanRmArgv(s)))
			}
			want = append(want, gbP(gbSchemasArgv()), gbP(gbStopGvmdArgv()))
			for range drops {
				want = append(want, gbP(gbDropArgv()))
			}
			want = append(want, gbP(gbUpArgv()), gbP(gbPsArgv()))
			for _, v := range gbLeanVolumes {
				want = append(want, gbP(gbVolumeExistsArgv(v)), gbP(gbVolumeRmArgv(v)))
			}
			for _, s := range gbLeanServices {
				want = append(want, gbP(gbImageIDArgv(s)), "podman rmi "+w.images[s])
			}
			if got := w.leanCalls(); !slices.Equal(got, want) {
				t.Fatalf("%s: calls\n%q\nwant\n%q", c, got, want)
			}
			if w.dropLive || !strings.Contains(w.running, "gvmd") || len(w.ctrs) != 0 {
				t.Fatalf("%s: dropped while gvmd ran %t, running %q, containers left %v", c, w.dropLive, w.running, w.ctrs)
			}
			wantSaid := map[string]string{"upgraded": "3 container(s), gvmd's schemas true, 2 volume(s), 3 image(s)", "postgres starting": "3 container(s), gvmd's schemas true, 2 volume(s), 3 image(s)",
				"drop fails": "3 container(s), gvmd's schemas false, 2 volume(s), 3 image(s)", "volume stays": "3 container(s), gvmd's schemas true, 0 volume(s), 3 image(s)"}[c]
			if !slices.ContainsFunc(said, func(s string) bool { return strings.Contains(s, wantSaid) }) {
				t.Fatalf("%s: the up said %q, want %q", c, said, wantSaid)
			}
			if c == "drop fails" || c == "volume stays" {
				if !strings.Contains(w.logs(), "the next start of OpenVAS tries again") {
					t.Fatalf("%s: the failure is not in the log: %s", c, w.logs())
				}
			}
			// the next up: only reads once all is gone; what is left is done again (gvmd stopped only while a schema holds data)
			w.mu.Lock()
			w.calls, w.dropFail = nil, false
			w.mu.Unlock()
			if err := up(); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			got := w.leanCalls()
			switch c {
			case "drop fails":
				if !slices.Contains(got, gbP(gbStopGvmdArgv())) || w.schemas != "" {
					t.Fatalf("%s: the second up did not drop: %q", c, got)
				}
			case "volume stays":
				if slices.Contains(got, gbP(gbStopGvmdArgv())) || !slices.Contains(got, gbP(gbVolumeRmArgv(gbLeanVolumes[0]))) {
					t.Fatalf("%s: the second up %q, want the volumes again and gvmd left alone", c, got)
				}
			default:
				if !slices.Equal(got, gbLeanFreshCalls()) {
					t.Fatalf("%s: second up %q, want only the reads", c, got)
				}
			}
		})
	}
}

// Review r1 L2: an older build brought the data back (rollback, then this build again): the next up removes it again.
func TestGreenboneUp_SCAPAndCERTDataBroughtBackAreRemovedAgain(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := gbLeanWorld(t)
		for range 2 {
			if err := w.up(t.Context()); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if w.schemas != "" || len(w.volumes) != 0 || len(w.ctrs) != 0 {
				t.Fatalf("left: schemas %q volumes %v containers %v", w.schemas, w.volumes, w.ctrs)
			}
			w.mu.Lock() // the rollback's OpenVAS
			w.schemas, w.volumes[gbLeanVolumes[0]], w.ctrs["scap-data"] = "scap\n", true, "vedette-host"
			w.mu.Unlock()
		}
	})
}

// Review r1 H1, L4, L7: an image is removed only when the container that used it carried Vedette's label (a customer's own
// Greenbone, or the supervisor's trial without the label, keeps it); a refused rmi is logged and the rest goes on.
func TestGreenboneUp_OnlyTheImagesOfVedettesContainersAreRemoved(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := gbLeanWorld(t)
		w.ctrs["scap-data"] = ""                        // not Vedette's
		delete(w.ctrs, "dfn-cert-data")                 // no container at all
		w.rmiRefused[w.images["cert-bund-data"]] = true // another container uses it
		if err := w.up(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		got := w.leanCalls()
		if slices.ContainsFunc(got, func(l string) bool {
			return strings.Contains(l, w.images["scap-data"]) || strings.Contains(l, w.images["dfn-cert-data"]) || l == gbP(gbImageIDArgv("scap-data"))
		}) {
			t.Fatalf("an image without Vedette's container was touched: %q", got)
		}
		if !slices.Contains(got, "podman rmi "+w.images["cert-bund-data"]) || !strings.Contains(w.logs(), "removing the image of cert-bund-data") {
			t.Fatalf("the refused rmi: %q; log %s", got, w.logs())
		}
		if len(w.volumes) != 0 || w.schemas != "" || len(w.ctrs) != 0 {
			t.Fatalf("the rest did not go on: volumes %v schemas %q containers %v", w.volumes, w.schemas, w.ctrs)
		}
	})
}

// Review r1 M1, L3, L7: a stop of gvmd that fails drops nothing (the containers are removed first anyway, so a down works); a gvmd
// that does not start again fails the up and nothing more is removed; a cancel between the stop and the drop ends the pass with the
// cancel, drops nothing and removes nothing more; a down right after deploy, before any up, ignores the old data containers.
func TestGreenboneUp_SCAPAndCERTCleanupFailures(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"stop fails", "gvmd does not restart", "cancel", "down first"} {
		synctest.Test(t, func(t *testing.T) {
			w := gbLeanWorld(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var err error
			switch c {
			case "stop fails":
				w.stopCode = 1
			case "gvmd does not restart":
				w.restartFail = true
			case "cancel":
				w.onStopGvmd = cancel
			case "down first":
				w.running += "scap-data\ncert-bund-data\ndfn-cert-data\n" // an upgraded box right after deploy, before any up
				if err := w.o.gbOp(ctx, true, gbDownLimit, func(ctx context.Context) error { return w.o.gbDown(ctx, nolog) }); err != nil {
					t.Fatalf("down with the old data containers running: %v", err)
				}
				return
			}
			err = w.o.gbLean(ctx, nolog)
			synctest.Wait()
			got := w.leanCalls()
			if w.dropLive || len(w.ctrs) != 0 {
				t.Fatalf("%s: dropped while gvmd ran %t, containers left %v", c, w.dropLive, w.ctrs)
			}
			switch c {
			case "stop fails":
				if err != nil || slices.Contains(got, gbP(gbDropArgv())) || w.schemas == "" || !slices.Contains(got, gbP(gbUpArgv())) || !strings.Contains(w.logs(), "stopping gvmd") {
					t.Fatalf("%s: %v %q", c, err, got)
				}
			case "gvmd does not restart":
				var f *server.Failure
				if !errors.As(err, &f) || f.Code != api.CodeGreenboneFailed || slices.ContainsFunc(got, func(l string) bool {
					return strings.HasPrefix(l, "podman volume") || strings.HasPrefix(l, "podman rmi")
				}) {
					t.Fatalf("%s: %v %q, want greenbone_failed and nothing more removed", c, err, got)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || slices.Contains(got, gbP(gbDropArgv())) || slices.ContainsFunc(got, func(l string) bool {
					return strings.HasPrefix(l, "podman volume") || strings.HasPrefix(l, "podman rmi")
				}) {
					t.Fatalf("%s: %v %q, want the cancel and nothing more", c, err, got)
				}
			}
		})
	}
}

// Review r1 M2: docker-compose 2.24.0-2.24.3 ignore the !override tag of compose.vedette.yaml, so the floor is 2.24.4.
func TestGreenboneProviderFloorIs2_24_4(t *testing.T) {
	t.Parallel()
	for v, ok := range map[string]bool{"2.24.3": false, "v2.24.3": false, "2.23.9": false, "1.29.2": false, "2.24.4": true, "2.24.6": true,
		"2.40.3+ds1-0ubuntu1": true, "2.26.1": true, "3.0.0": true, "": false} {
		w := newGBWorld(t, ubuntu2604)
		w.version = v
		if got := w.o.gbProviderOK(t.Context()); got != ok {
			t.Errorf("%q: accepted %t, want %t", v, got, ok)
		}
	}
}
