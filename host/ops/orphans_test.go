package ops

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
)

// D-600: the host stops, at its start, the containers that run while the rootful podman no longer knows them, when their name is
// Vedette's or Greenbone's project's; a fake /proc and fake podman and systemctl answers, nothing runs.

type orphanCtr struct {
	pid      int
	name     string
	known    bool // podman container exists says yes
	uid      string
	bundle   string // conmon's -b; "" = the rootful podman's default for its id
	termDies bool   // ends at SIGTERM (otherwise only at SIGKILL)
	never    bool   // never ends
}

type orphanWorld struct {
	t      *testing.T
	o      *Ops
	root   string
	log    *syncWriter
	buf    *bytes.Buffer
	mu     sync.Mutex
	calls  []string
	ctrs   map[string]*orphanCtr // by id
	exists int                   // the exit code of every podman container exists (-1: podman's own answer above)
	umount []string
}

func orphanID(n int) string { return strings.Repeat(strconv.Itoa(n%10), 64) }

func newOrphanWorld(t *testing.T, ctrs []*orphanCtr) *orphanWorld {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	w := &orphanWorld{t: t, root: root, buf: &bytes.Buffer{}, ctrs: map[string]*orphanCtr{}, exists: -1}
	w.log = &syncWriter{w: w.buf}
	o, err := NewWithDeps(Config{StateDir: state, OwnerUID: os.Getuid(), Logger: slog.New(slog.NewTextHandler(w.log, nil))}, Deps{
		Root: root, ChainTop: root,
		Sleep: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	o.gbExec = w.exec
	o.orphanUnmount = func(p string) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.umount = append(w.umount, strings.TrimPrefix(p, root))
		return nil
	}
	w.o = o
	w.write("proc/stat", "cpu  1 2 3\nbtime 1794700000\n")
	var mounts strings.Builder
	for i, c := range ctrs {
		id := orphanID(i + 1)
		w.ctrs[id] = c
		if c.uid == "" {
			c.uid = "0"
		}
		if c.bundle == "" {
			c.bundle = orphanBundleDir + id + "/userdata"
		}
		dir := "proc/" + strconv.Itoa(c.pid)
		argv := []string{"/usr/bin/conmon", "--api-version", "1", "-c", id, "-u", id, "-r", "/usr/bin/crun", "-b", c.bundle,
			"-p", c.bundle + "/pidfile", "-n", c.name, "--exit-command-arg", "-n", "--exit-command-arg", "container", "-s"}
		w.write(dir+"/cmdline", strings.Join(argv, "\x00")+"\x00")
		w.write(dir+"/status", "Name:\tconmon\nUid:\t"+c.uid+"\t"+c.uid+"\t"+c.uid+"\t"+c.uid+"\n")
		w.write(dir+"/stat", strconv.Itoa(c.pid)+" (conmon) S 1 1 1 0 -1 4 0 0 0 0 0 0 0 0 20 0 1 0 6000 0 0\n")
		// the container's own process, which crun's state names
		cpid := c.pid + 1
		w.write("proc/"+strconv.Itoa(cpid)+"/cmdline", "/usr/local/bin/gvmd\x00")
		w.write("proc/"+strconv.Itoa(cpid)+"/stat", strconv.Itoa(cpid)+" (gvmd) S 1 1 1 0 -1 4 0 0 0 0 0 0 0 0 20 0 1 0 6100 0 0\n")
		w.write("run/crun/"+id+"/status", `{"pid":`+strconv.Itoa(cpid)+`,"rootfs":"/var/lib/containers/storage/overlay/`+strings.Repeat("e", 64)+`/merged"}`)
		mounts.WriteString("1 2 0:1 / " + orphanBundleDir + id + "/userdata/shm rw - tmpfs shm rw\n")
	}
	mounts.WriteString("3 2 0:2 / /var/lib/containers/storage/overlay/" + strings.Repeat("e", 64) + "/merged rw - overlay overlay rw\n")
	mounts.WriteString("4 2 0:3 / /home rw - ext4 /dev/sda2 rw\n")
	w.write("proc/self/mountinfo", mounts.String())
	// a process that is no conmon, and one whose cmdline is empty (a kernel thread)
	w.write("proc/7/cmdline", "/usr/sbin/sshd\x00-D\x00")
	w.write("proc/8/cmdline", "")
	return w
}

func (w *orphanWorld) write(rel, body string) {
	w.t.Helper()
	p := filepath.Join(w.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // the fake root of a test
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *orphanWorld) end(id string) {
	c := w.ctrs[id]
	_ = os.RemoveAll(filepath.Join(w.root, "proc", strconv.Itoa(c.pid)))
	_ = os.RemoveAll(filepath.Join(w.root, "proc", strconv.Itoa(c.pid+1)))
}

func (w *orphanWorld) exec(ctx context.Context, name string, _ io.Reader, args ...string) (vexec.Result, int, error) {
	if _, ok := ctx.Deadline(); !ok {
		w.t.Errorf("%s %q runs without a deadline", name, args)
	}
	if err := ValidateHostArgv(w.o.cfg.StateDir, "vedette-core.service", name, args); err != nil {
		w.t.Errorf("the host runner refuses %s %q: %v", name, args, err)
		return vexec.Result{}, -1, err
	}
	w.mu.Lock()
	w.calls = append(w.calls, name+" "+strings.Join(args, " "))
	w.mu.Unlock()
	switch {
	case name == binPodman && len(args) == 3 && args[1] == "exists":
		if w.exists >= 0 {
			return vexec.Result{}, w.exists, nil
		}
		if c := w.ctrs[args[2]]; c != nil && c.known {
			return vexec.Result{}, 0, nil
		}
		return vexec.Result{}, 1, nil
	case name == binSystemctl && args[0] == "kill":
		for _, u := range args[2:] {
			id := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(u, "libpod-"), "conmon-"), ".scope")
			c := w.ctrs[id]
			if c == nil || c.never || (args[1] == "--signal=SIGTERM" && !c.termDies) {
				continue
			}
			w.end(id)
		}
		return vexec.Result{}, 0, nil
	}
	w.t.Errorf("unexpected call %s %q", name, args)
	return vexec.Result{}, 1, nil
}

func (w *orphanWorld) killed() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, c := range w.calls {
		if strings.HasPrefix(c, "systemctl kill") {
			out = append(out, c)
		}
	}
	return out
}

func (w *orphanWorld) crunState(n int) bool {
	_, err := os.Lstat(filepath.Join(w.root, "run/crun", orphanID(n)))
	return err == nil
}

func TestOrphansStopsGreenbonesAndVedettesOrphansOnly(t *testing.T) {
	t.Parallel()
	w := newOrphanWorld(t, []*orphanCtr{
		{pid: 100, name: "greenbone-community-edition-gvmd-1", termDies: true},                            // 1: orphan, ends at SIGTERM
		{pid: 200, name: "vedette-core"},                                                                  // 2: orphan that ignores SIGTERM
		{pid: 300, name: "greenbone-community-edition-pg-gvm-1", known: true, termDies: true},             // 3: podman's own
		{pid: 400, name: "mydb", termDies: true},                                                          // 4: someone else's
		{pid: 500, name: "vedette-sensor", uid: "1000", termDies: true},                                   // 5: a rootless podman's
		{pid: 600, name: "vedette-scan", bundle: "/run/containers/storage/overlay-containers/x/userdata"}, // 6: not the rootful default
	})
	w.o.orphansAtStart(t.Context())

	id1, id2 := orphanID(1), orphanID(2)
	want := []string{
		"systemctl kill --signal=SIGTERM libpod-" + id1 + ".scope libpod-" + id2 + ".scope",
		"systemctl kill --signal=SIGKILL libpod-" + id2 + ".scope libpod-conmon-" + id2 + ".scope",
	}
	if got := w.killed(); !slices.Equal(got, want) {
		t.Fatalf("kills:\n%q\nwant:\n%q", got, want)
	}
	// podman was asked about the three candidates with Vedette's or Greenbone's name (not mydb, not the rootless one, not the other bundle)
	asked := 0
	for _, c := range w.calls {
		if strings.HasPrefix(c, "podman container exists ") {
			asked++
		}
	}
	if asked != 3 {
		t.Fatalf("podman asked %d times, want 3: %q", asked, w.calls)
	}
	if w.crunState(1) || w.crunState(2) || !w.crunState(3) || !w.crunState(4) {
		t.Fatal("crun's state: removed for the two orphans only")
	}
	wantUmount := []string{orphanBundleDir + id1 + "/userdata/shm", "/var/lib/containers/storage/overlay/" + strings.Repeat("e", 64) + "/merged"}
	if len(w.umount) < 2 || !slices.Contains(w.umount, wantUmount[0]) || !slices.Contains(w.umount, wantUmount[1]) || slices.Contains(w.umount, "/home") {
		t.Fatalf("unmounted %q", w.umount)
	}
	for _, s := range []string{
		`msg="orphaned container: it runs but podman does not know it; stopping it" container=greenbone-community-edition-gvmd-1 id=` + id1 + ` started=2026-11-14T23:47:40Z conmon_pid=100`,
		`msg="orphaned container stopped" container=greenbone-community-edition-gvmd-1 id=` + id1,
		`msg="orphaned container stopped" container=vedette-core id=` + id2,
		`msg="orphaned containers: done" stopped=2 still_running=0`,
	} {
		if !strings.Contains(w.buf.String(), s) {
			t.Errorf("the log has no %q:\n%s", s, w.buf.String())
		}
	}
	for _, s := range []string{"pg-gvm", "mydb", "vedette-sensor", "vedette-scan"} {
		if strings.Contains(w.buf.String(), s) {
			t.Errorf("the log names %s, which is not an orphan of Vedette's:\n%s", s, w.buf.String())
		}
	}
}

func TestOrphansNothingWhenPodmanDoesNotAnswer(t *testing.T) {
	t.Parallel()
	w := newOrphanWorld(t, []*orphanCtr{
		{pid: 100, name: "greenbone-community-edition-gvmd-1", termDies: true},
		{pid: 200, name: "vedette-core", termDies: true},
	})
	w.exists = 125
	w.o.orphansAtStart(t.Context())
	if k := w.killed(); len(k) != 0 {
		t.Fatalf("killed although podman did not answer: %q", k)
	}
	if !w.crunState(1) || !strings.Contains(w.buf.String(), "podman did not answer whether it knows a running container; none is stopped") {
		t.Fatalf("log:\n%s", w.buf.String())
	}
}

func TestOrphansStuckIsLoggedAndLeft(t *testing.T) {
	t.Parallel()
	w := newOrphanWorld(t, []*orphanCtr{{pid: 100, name: "greenbone-community-edition-ospd-openvas-1", never: true}})
	w.o.orphansAtStart(t.Context())
	if k := w.killed(); len(k) != 2 {
		t.Fatalf("kills %q, want SIGTERM then SIGKILL", k)
	}
	if !w.crunState(1) || len(w.umount) != 0 {
		t.Fatal("the state of a container that still runs was touched")
	}
	if !strings.Contains(w.buf.String(), "still running after SIGKILL") || !strings.Contains(w.buf.String(), "stopped=0 still_running=1") {
		t.Fatalf("log:\n%s", w.buf.String())
	}
}

func TestOrphansNoCandidateAsksNothing(t *testing.T) {
	t.Parallel()
	w := newOrphanWorld(t, []*orphanCtr{{pid: 100, name: "mydb"}, {pid: 200, name: "vedette-core", known: true}})
	w.o.orphansAtStart(t.Context())
	if k := w.killed(); len(k) != 0 {
		t.Fatalf("killed %q", k)
	}
	if strings.Contains(w.buf.String(), "orphaned") {
		t.Fatalf("log:\n%s", w.buf.String())
	}
}

func TestOrphanArgvIsValidated(t *testing.T) {
	t.Parallel()
	id := orphanID(3)
	for _, ok := range [][]string{
		{"kill", "--signal=SIGTERM", "libpod-" + id + ".scope"},
		{"kill", "--signal=SIGKILL", "libpod-" + id + ".scope", "libpod-conmon-" + id + ".scope"},
	} {
		if err := ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binSystemctl, ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range [][]string{
		{"kill", "--signal=SIGTERM"},
		{"kill", "--signal=SIGHUP", "libpod-" + id + ".scope"},
		{"kill", "--signal=SIGKILL", "vedette-core.service"},
		{"kill", "--signal=SIGKILL", "libpod-" + id[:63] + ".scope"},
		{"kill", "--signal=SIGKILL", "libpod-" + id + ".scope", "vedette-host.service"},
	} {
		if err := ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binSystemctl, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binPodman, []string{"container", "exists", id}); err != nil {
		t.Errorf("container exists refused: %v", err)
	}
	if err := ValidateHostArgv("/var/lib/vedette-host", "vedette-core.service", binPodman, []string{"container", "exists", "mydb"}); err == nil {
		t.Error("container exists of a name accepted")
	}
	for _, n := range []string{"vedette-core", "vedette-zap", "greenbone-community-edition-gvmd-1", "greenbone-community-edition-pg-gvm-migrator-1"} {
		if !orphanNameRE.MatchString(n) {
			t.Errorf("%s is not an orphan name", n)
		}
	}
	for _, n := range []string{"vedette-corex", "mydb", "greenbone-community-edition-", "greenbone-community-edition-gvmd", "k8s_POD"} {
		if orphanNameRE.MatchString(n) {
			t.Errorf("%s is an orphan name", n)
		}
	}
}
