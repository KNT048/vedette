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
		"podman up":       gbUpArgv(),
		"podman stop":     gbStopArgv(),
		"podman ps":       gbPsArgv(),
		"podman pull":     gbPullFeedArgv(),
		"podman upfeed":   gbUpFeedArgv(),
		"podman version":  gbVersionArgv(),
		"podman login":    gbLoginArgv(gbTestPW),
		"systemctl en":    argsPodmanSocketEnable,
		"systemctl act":   argsPodmanSocketActive,
		"apt-get ubuntu":  gbAptInstallArgv("docker-compose-v2"),
		"apt-get debian":  gbAptInstallArgv("docker-compose"),
		"apt-get update ": argsUpdate,
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
		"podman short password":     gbLoginArgv("abc"),
		"podman upper password":     gbLoginArgv(strings.ToUpper(gbTestPW)),
		"podman shell password":     gbLoginArgv(gbTestPW[:40] + "';reboot"),
		"podman another user":       swap(gbLoginArgv(gbTestPW), "--user=admin", "--user=root"),
		"podman another gvmd verb":  swap(gbLoginArgv(gbTestPW), "--user=admin", "--delete-user=admin"),
		"systemctl another socket":  {"enable", "--now", "docker.socket"},
		"apt-get another package":   gbAptInstallArgv("podman-compose"),
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
	if !bytes.Contains(b, []byte("\nname: "+gbProject+"\n")) {
		t.Errorf("the project is not %s", gbProject)
	}
}

// gbWorld is a fake podman, systemctl and apt-get for the OpenVAS commands.
type gbWorld struct {
	t       *testing.T
	o       *Ops
	base    string
	log     *bytes.Buffer
	mu      sync.Mutex
	calls   []string
	version string // what podman compose version prints ("" fails, like a podman without a provider)
	install string // the version after apt-get install
	logins  int    // how many logins fail before one works (-1: never)
	running string // what compose ps prints
	upGate  chan struct{}
	upIn    chan struct{}
	sleeps  int
}

func newGBWorld(t *testing.T, osRelease string) *gbWorld {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	for _, d := range []string{state, filepath.Join(base, "run"), filepath.Join(base, "etc"), filepath.Join(base, gbFilesDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
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
	w := &gbWorld{t: t, base: base, log: &bytes.Buffer{}, version: "2.40.3+ds1-0ubuntu1", install: "2.40.3", running: "gvmd\nospd-openvas\npg-gvm\nredis-server\nopenvasd\n"}
	logger := slog.New(slog.NewTextHandler(&syncWriter{w: w.log}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o, err := NewWithDeps(Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), Logger: logger}, Deps{
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
	case name == binSystemctl && slices.Equal(args, argsPodmanSocketEnable):
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
	case len(args) == 7 && args[0] == "exec":
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
	case slices.Equal(args, gbPullFeedArgv()), slices.Equal(args, gbUpFeedArgv()):
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
		"systemctl enable --now podman.socket",
		"systemctl is-active podman.socket",
		"podman " + strings.Join(gbUpArgv(), " "),
		"podman exec gvmd --new-password", "podman exec gvmd --new-password", "podman exec gvmd --new-password",
		"podman " + strings.Join(gbPsArgv(), " "),
	}
	if got := w.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls\n%q\nwant\n%q", got, want)
	}
	for _, d := range []string{api.GreenboneRunDir, api.GreenboneSocketDir} {
		st, err := os.Lstat(filepath.Join(w.base, d))
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v, want a directory 0755", d, st, err)
		}
	}
	// A second start finds the provider and installs nothing.
	w.calls = nil
	if err := w.up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c := w.Calls(); slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "apt-get") }) {
		t.Errorf("apt-get ran again: %q", c)
	}
	if strings.Contains(w.log.String(), gbTestPW) {
		t.Fatal("the password is in the log")
	}
}

func TestGreenboneUp_ThePasswordIsNeverLoggedNorInAnError(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.logins = -1 // gvmd never takes it
	err := w.up(t.Context())
	var f *server.Failure
	if !errors.As(err, &f) || f.Code != api.CodeGreenboneFailed || !strings.Contains(f.Message, "did not take Vedette's login") {
		t.Fatalf("%v, want greenbone_failed about the login", err)
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
		t.Errorf("Debian 13 did not install docker-compose: %q", w2.Calls())
	}
}

// Down ends an up that still pulls (OpenVAS turned off during the first start), then stops the project; the volumes are never named.
func TestGreenboneDown_CancelsAnUpThatRunsThenStops(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	w.upGate, w.upIn = make(chan struct{}), make(chan struct{}, 1)
	upErr := make(chan error, 1)
	go func() { upErr <- w.up(t.Context()) }()
	<-w.upIn
	if err := w.o.gbOp(t.Context(), true, gbDownLimit, func(ctx context.Context) error { return w.o.gbDown(ctx, nolog) }); err != nil {
		t.Fatal(err)
	}
	var f *server.Failure
	if err := <-upErr; !errors.As(err, &f) || f.Code != api.CodeGreenboneCancelled {
		t.Fatalf("up: %v, want greenbone_cancelled", err)
	}
	c := w.Calls()
	if !slices.Contains(c, "podman "+strings.Join(gbStopArgv(), " ")) {
		t.Fatalf("no stop: %q", c)
	}
	for _, l := range c {
		if strings.Contains(l, " down") || strings.Contains(l, "-v") || strings.Contains(l, "volume") || strings.Contains(l, " rm") {
			t.Errorf("down touched more than the containers: %s", l)
		}
	}
}

func TestGreenboneSyncFeed_PullsAndStartsTheSevenFeedServices(t *testing.T) {
	t.Parallel()
	w := newGBWorld(t, ubuntu2604)
	if err := w.o.gbOp(t.Context(), false, gbSyncLimit, func(ctx context.Context) error { return w.o.gbSyncFeed(ctx, nolog) }); err != nil {
		t.Fatal(err)
	}
	want := []string{"podman " + strings.Join(gbPullFeedArgv(), " "), "podman " + strings.Join(gbUpFeedArgv(), " ")}
	if got := w.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	if got := strings.Join(gbPullFeedArgv()[7:], " "); got != "pull notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects" {
		t.Fatalf("the feed pull is %q", got)
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
