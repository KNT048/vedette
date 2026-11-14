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
		"podman inspect":    gbImageIDArgv("vulnerability-tests"),
		"podman rmi":        {"rmi", strings.Repeat("ab", 32)},
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
		"podman pull another":       swap(gbPullFeedArgv(), "scap-data", "gvmd"),
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
	mu        sync.Mutex
	calls     []string
	version   string // what podman compose version prints ("" fails, like a podman without a provider)
	install   string // the version after apt-get install
	logins    int    // how many logins fail before one works (-1: never)
	running   string // what compose ps prints
	socketOn  bool   // podman.socket is enabled
	upGate    chan struct{}
	upIn      chan struct{}
	sleeps    int
	images    map[string]string // feed service -> image ID
	newImages map[string]string // what the pull changes
	pullCode  int
}

func newGBWorld(t *testing.T, osRelease string) *gbWorld {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
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
	logger := slog.New(slog.NewTextHandler(&syncWriter{w: w.log}, &slog.HandlerOptions{Level: slog.LevelDebug}))
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
	case len(args) == 11 && args[0] == "exec":
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.logins != 0 {
			if w.logins > 0 {
				w.logins--
			}
			return vexec.Result{Stderr: []byte("Failed to modify user")}, 1, nil
		}
		return vexec.Result{}, 0, nil
	case slices.Equal(args, gbPsArgv()):
		w.mu.Lock()
		defer w.mu.Unlock()
		return vexec.Result{Stdout: []byte(w.running)}, 0, nil
	case slices.Equal(args, gbStopArgv()):
		w.mu.Lock()
		w.running = ""
		w.mu.Unlock()
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
		return vexec.Result{Stdout: []byte("sha256:" + w.images[strings.TrimPrefix(args[4], gbRegistry)] + "\n")}, 0, nil
	case len(args) == 2 && args[0] == "rmi":
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

func (w *gbWorld) up(ctx context.Context) error {
	return w.o.gbOp(ctx, false, gbUpLimit, func(ctx context.Context) error { return w.o.gbUp(ctx, nolog, gbTestPW) })
}

func (w *gbWorld) down(ctx context.Context) error {
	return w.o.gbOp(ctx, true, gbDownLimit, func(ctx context.Context) error { return w.o.gbDown(ctx, nolog) })
}

const ubuntu2604 = "ID=ubuntu\nVERSION_ID=\"26.04\"\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\n"

func TestGreenboneUp_TheFirstStartInstallsTheProviderAndSetsTheLogin(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.version, w.logins = "", 2 // no provider yet; gvmd takes the login at the third try
	if err := w.up(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"podman compose version --short",
		"apt-get -q update",
		"apt-get " + strings.Join(gbAptInstallArgv("docker-compose-v2"), " "),
		"podman compose version --short",
		"systemctl is-enabled podman.socket",
		"systemctl enable --now podman.socket",
		"systemctl is-active podman.socket",
		"podman " + strings.Join(gbUpArgv(), " "),
		"podman exec gvmd --new-password", "podman exec gvmd --new-password", "podman exec gvmd --new-password",
		"podman " + strings.Join(gbPsArgv(), " "),
	}
	if got := w.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls\n%q\nwant\n%q", got, want)
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
	marker := filepath.Join(w.base, "state", gbSocketMarker)
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
	if c := w.Calls(); slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "apt-get") || strings.Contains(s, "enable --now") }) {
		t.Errorf("apt-get or enable ran again: %q", c)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a marker was written for a podman.socket that was already enabled")
	}
	if strings.Contains(w.log.String(), gbTestPW) {
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

// review r1 L2: a login that never takes stops the project again, and the password is never logged nor in the message.
func TestGreenboneUp_ALoginThatNeverTakesStopsOpenVAS(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.logins = -1 // gvmd never takes it
	err := w.up(t.Context())
	var f *server.Failure
	if !errors.As(err, &f) || f.Code != api.CodeGreenboneFailed || !strings.Contains(f.Message, "did not take Vedette's login") || !strings.Contains(f.Message, "stopped again") {
		t.Fatalf("%v, want greenbone_failed about the login and the stop", err)
	}
	if c := w.Calls(); c[len(c)-1] != "podman "+strings.Join(gbStopArgv(), " ") {
		t.Fatalf("the project was not stopped after the login failed: %q", c)
	}
	if strings.Contains(f.Message, gbTestPW) || strings.Contains(w.log.String(), gbTestPW) || strings.Contains(w.log.String(), gbTestPW[:12]) {
		t.Fatalf("the password leaked: %q / %s", f.Message, w.log.String())
	}
	if !strings.Contains(w.log.String(), "setting the GMP login failed") {
		t.Fatalf("the failure is not in the log: %s", w.log.String())
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
	oldVT, oldScap := w.images["vulnerability-tests"], w.images["scap-data"]
	w.newImages["vulnerability-tests"], w.newImages["scap-data"] = strings.Repeat("1", 64), strings.Repeat("2", 64)
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
	if got := strings.Join(gbPullFeedArgv()[7:], " "); got != "pull notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects" {
		t.Fatalf("the feed pull is %q", got)
	}
	w.calls, w.pullCode = nil, 1
	w.newImages["notus-data"] = strings.Repeat("3", 64)
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
