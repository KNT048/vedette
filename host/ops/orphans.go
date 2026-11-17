package ops

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Orphaned containers (D-600). An orphan is a container that still runs while the rootful podman of the box no longer knows it: its
// conmon and its processes live on in their libpod scopes, but `podman container exists <id>` says no. On kien's N100 an
// install.sh --uninstall of 2026-11-13 purged podman and wiped /var/lib/containers under fourteen running Greenbone containers; they kept
// running for four days, gvmd aborting ~470 times a minute on its lost /var/lib/gvm, with nothing that could see or stop them (podman
// lists only what its database holds). The host looks for them at every start, which follows every install, upgrade, self-update and
// reboot, and stops the ones that are Vedette's or Greenbone's project that Vedette runs:
//
//  1. From the kernel's side: every process whose argv[0] is conmon, owned by root, that runs the main process of a container (-c and
//     -u the same 64 hex id) of the rootful podman's default storage (-b /var/lib/containers/storage/overlay-containers/<id>/userdata),
//     with a name (-n) of orphanNameRE. Anything else (another name, a rootless podman, CRI-O, an exec session) is never looked at again.
//  2. podman container exists <id>, for each: exit 0 (podman knows it) leaves it alone, exit 1 makes it an orphan; any other answer, or no
//     answer within a minute, and nothing at all is stopped (fail closed).
//  3. systemctl kill --signal=SIGTERM libpod-<id>.scope for all of them at once, 10 s for them to end (podman stop's own grace), then
//     systemctl kill --signal=SIGKILL on the container's and conmon's scopes of the ones left, 20 s more. systemd signals every process of
//     the scope; the empty scopes then go.
//  4. For each one that ended: its mounts the host can name by the id (the container's /dev/shm under its bundle, and the rootfs crun's
//     state names when it is an overlay "merged" folder), unmounted with MNT_DETACH, and crun's state folder /run/crun/<id>; and its
//     network namespace (review r1 M2): netavark keeps it as a bind mount /run/netns/netns-<uuid> that outlives the processes, with the
//     veth and the IP on the bridge. Its inode is read from the container's process (crun's state pid) before the kill; afterwards the
//     one /run/netns entry with that device and inode, when no process is left in it, is unmounted and removed.
//
// Each orphan is logged with its name, id and start time, and audited (host.start, orphan_container_stopped or orphan_container_stuck).
// It runs in the background after Start, holding the OpenVAS slot (gbSem), so a greenbone.up waits until Greenbone's orphans are gone.

const (
	orphanBundleDir = "/var/lib/containers/storage/overlay-containers/" // conmon's -b of the rootful podman: <this><id>/userdata
	orphanCrunDir   = "/run/crun"                                       // crun's state of a container of the rootful podman: <this>/<id>
	orphanMax       = 64                                                // the most orphans one start stops (one systemctl argv)
	orphanTermWait  = 10 * time.Second
	orphanKillWait  = 20 * time.Second
	orphanPoll      = 500 * time.Millisecond
	orphanAskWait   = time.Minute
	orphanRecheck   = 2 * time.Second // between the two questions to podman (review r1 M1)
	orphanCommand   = "host.start"    // the audit command of what the host does at its start
)

var (
	// orphanNameRE: the containers of Vedette's services and of the passive web scan, and docker-compose v2's names of the services of
	// Greenbone's project as vedette-host runs it (D-529: greenbone-community-edition-<service>-<n>).
	orphanNameRE   = regexp.MustCompile(`^(vedette-(core|sensor|scan|honeypot|greenbone|zap)|` + gbProject + `-[a-z0-9]+(-[a-z0-9]+)*-[0-9]{1,4})$`)
	orphanScopeRE  = regexp.MustCompile(`^libpod-(conmon-)?[0-9a-f]{64}\.scope$`)
	orphanRootfsRE = regexp.MustCompile(`^/var/lib/containers/storage/overlay/[0-9a-f]{64}/merged$`)
	orphanSignals  = []string{"--signal=SIGTERM", "--signal=SIGKILL"}
)

// conmonProc is one conmon of a container's main process, as /proc shows it.
type conmonProc struct {
	pid      int
	start    string // field 22 of /proc/<pid>/stat: tells the process apart from a later one with the same pid
	id, name string
	started  time.Time // zero when /proc/stat has no btime
}

func (c conmonProc) startedText() string {
	if c.started.IsZero() {
		return "unknown"
	}
	return c.started.UTC().Format(time.RFC3339)
}

// orphanKillArgv is systemctl kill of the scopes, all of which must be libpod scopes of a 64-hex id.
func orphanKillArgv(signal string, scopes []string) ([]string, error) {
	args := append([]string{"kill", signal}, scopes...)
	if !isOrphanKillArgv(args) {
		return nil, errors.New("not the fixed systemctl kill command line")
	}
	return args, nil
}

func isOrphanKillArgv(args []string) bool {
	if len(args) < 3 || len(args) > 2+2*orphanMax || args[0] != "kill" || (args[1] != orphanSignals[0] && args[1] != orphanSignals[1]) {
		return false
	}
	for _, u := range args[2:] {
		if !orphanScopeRE.MatchString(u) {
			return false
		}
	}
	return true
}

// containerExistsArgv asks podman whether it knows a container by its full id (exit 0 yes, 1 no).
func containerExistsArgv(id string) ([]string, error) {
	if !imageIDRE.MatchString(id) {
		return nil, errPodmanArgs
	}
	return []string{"container", "exists", id}, nil
}

// orphansAtStart finds and stops the orphans (the steps above). It never blocks the start: Start runs it in its own goroutine.
func (o *Ops) orphansAtStart(ctx context.Context) {
	// the slot first, then the look (review r1 M1): an OpenVAS operation that recreates Greenbone's containers ends before the snapshot
	select {
	case o.gbSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-o.gbSem }()
	var orphans []conmonProc
	for _, c := range o.conmons() {
		if !orphanNameRE.MatchString(c.name) {
			continue
		}
		orphan, ok := o.isOrphan(ctx, c)
		if !ok {
			return
		}
		if orphan {
			orphans = append(orphans, c)
		}
	}
	if len(orphans) == 0 {
		return
	}
	if len(orphans) > orphanMax {
		orphans = orphans[:orphanMax]
	}
	for _, c := range orphans {
		o.log.WarnContext(ctx, "orphaned container: it runs but podman does not know it; stopping it", "container", c.name, "id", c.id, "started", c.startedText(), "conmon_pid", c.pid)
	}
	netns := map[string]fileKey{}
	for _, c := range orphans {
		if k, ok := o.orphanNetns(c.id); ok {
			netns[c.id] = k
		}
	}
	o.orphanKill(ctx, orphanSignals[0], orphans, false)
	left := o.orphansWait(ctx, orphans, orphanTermWait)
	if len(left) > 0 && ctx.Err() == nil {
		o.orphanKill(ctx, orphanSignals[1], left, true)
		left = o.orphansWait(ctx, left, orphanKillWait)
	}
	stuck := map[string]bool{}
	for _, c := range left {
		stuck[c.id] = true
	}
	stopped := 0
	for _, c := range orphans {
		detail := map[string]any{"container": c.name, "id": c.id, "started": c.startedText()}
		if stuck[c.id] {
			o.log.ErrorContext(ctx, "orphaned container: still running after SIGKILL; left as it is (a reboot ends it)", "container", c.name, "id", c.id, "conmon_pid", c.pid)
			o.note(orphanCommand, "orphan_container_stuck", detail)
			continue
		}
		stopped++
		o.orphanLeftovers(ctx, c)
		if k, ok := netns[c.id]; ok {
			o.orphanNetnsRemove(ctx, c, k)
		}
		o.log.InfoContext(ctx, "orphaned container stopped", "container", c.name, "id", c.id, "started", c.startedText())
		o.note(orphanCommand, "orphan_container_stopped", detail)
	}
	o.log.InfoContext(ctx, "orphaned containers: done", "stopped", stopped, "still_running", len(left))
}

// isOrphan asks podman twice, orphanRecheck apart, whether it knows c, and looks after each answer that c's conmon still runs (review
// r1 M1): a container podman removes in the normal way (quadlet's --replace or --rm, a compose recreate during the deploy) has left its
// database while its conmon was ending; only a conmon that still runs while podman says no twice is an orphan. ok is false when podman
// did not answer (the pass then stops nothing).
func (o *Ops) isOrphan(ctx context.Context, c conmonProc) (orphan, ok bool) {
	args, err := containerExistsArgv(c.id)
	if err != nil {
		return false, true
	}
	for try := range 2 {
		if try > 0 && !o.d.Sleep(ctx, orphanRecheck) {
			return false, false
		}
		_, code, err := o.gbStep(ctx, orphanAskWait, binPodman, args...)
		switch {
		case err == nil && code == 0: // podman's own container: never touched here
			return false, true
		case err == nil && code == 1:
			if !o.procAlive(c.pid, c.start) {
				return false, true // it ended on its own: podman removed it, nothing to stop
			}
		default:
			attrs := []any{"container", c.name, "id", c.id, "exit_code", code}
			if err != nil {
				attrs = append(attrs, "error", err.Error())
			}
			o.log.WarnContext(ctx, "orphaned containers: podman did not answer whether it knows a running container; none is stopped", attrs...)
			return false, false
		}
	}
	return true, true
}

// orphanKill signals the container scopes of cs (and with conmon, conmon's too) in one systemctl call. Its exit code is not the
// answer (a scope that already went is "not loaded"): orphansWait looks at the processes themselves.
func (o *Ops) orphanKill(ctx context.Context, signal string, cs []conmonProc, conmon bool) {
	var scopes []string
	for _, c := range cs {
		scopes = append(scopes, "libpod-"+c.id+".scope")
		if conmon {
			scopes = append(scopes, "libpod-conmon-"+c.id+".scope")
		}
	}
	args, err := orphanKillArgv(signal, scopes)
	if err != nil {
		return
	}
	if _, code, err := o.gbStep(ctx, gbStepWait, binSystemctl, args...); err != nil || code != 0 {
		attrs := []any{"signal", signal, "exit_code", code}
		if err != nil {
			attrs = append(attrs, "error", err.Error())
		}
		o.log.InfoContext(ctx, "orphaned containers: systemctl kill did not reach every scope", attrs...)
	}
}

// orphansWait waits up to d for the conmons of cs to end and returns the ones still there.
func (o *Ops) orphansWait(ctx context.Context, cs []conmonProc, d time.Duration) []conmonProc {
	left := cs
	for range int(d / orphanPoll) {
		var still []conmonProc
		for _, c := range left {
			if o.procAlive(c.pid, c.start) {
				still = append(still, c)
			}
		}
		left = still
		if len(left) == 0 || !o.d.Sleep(ctx, orphanPoll) {
			return left
		}
	}
	return left
}

// procAlive says whether the process pid that started at start (field 22 of its stat) still runs.
func (o *Ops) procAlive(pid int, start string) bool {
	s, ok := procStart(filepath.Join(o.path("/proc"), strconv.Itoa(pid)))
	return ok && s == start
}

// conmons lists the conmon processes of step 1.
func (o *Ops) conmons() []conmonProc {
	proc := o.path("/proc")
	ents, err := os.ReadDir(proc)
	if err != nil {
		return nil
	}
	btime := bootTime(proc)
	var out []conmonProc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if c, ok := readConmon(filepath.Join(proc, e.Name()), pid, btime); ok {
			out = append(out, c)
		}
	}
	return out
}

// readConmon reads /proc/<pid>: conmon's argv, its owner and its start.
func readConmon(dir string, pid int, btime int64) (conmonProc, bool) {
	b, err := readSmall(filepath.Join(dir, "cmdline"), 64<<10)
	if err != nil || len(b) == 0 {
		return conmonProc{}, false
	}
	argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if filepath.Base(argv[0]) != "conmon" {
		return conmonProc{}, false
	}
	flags := map[string]string{}
	for i := 1; i+1 < len(argv); i++ {
		var key string
		switch argv[i] {
		case "-c", "--cid":
			key = "c"
		case "-u", "--cuuid":
			key = "u"
		case "-n", "--name":
			key = "n"
		case "-b", "--bundle":
			key = "b"
		case "--exit-command-arg", "--runtime-arg", "--runtime-opt", "-r", "--runtime", "-l", "--log-path", "-p", "--container-pidfile",
			"-P", "--conmon-pidfile", "--exit-dir", "--exit-command", "--socket-dir-path", "--log-level", "--log-tag", "--log-size-max",
			"--persist-dir":
			i++ // a value that is not one of ours, never read as a flag
			continue
		default:
			continue
		}
		if v, ok := flags[key]; ok && v != argv[i+1] {
			return conmonProc{}, false // the same flag twice with two values: not judged
		}
		flags[key] = argv[i+1]
		i++
	}
	id := flags["c"]
	if !imageIDRE.MatchString(id) || flags["u"] != id || flags["b"] != orphanBundleDir+id+"/userdata" || !rootOwned(dir) {
		return conmonProc{}, false
	}
	start, ok := procStart(dir)
	if !ok {
		return conmonProc{}, false
	}
	c := conmonProc{pid: pid, start: start, id: id, name: flags["n"]}
	if ticks, err := strconv.ParseInt(start, 10, 64); err == nil && btime > 0 {
		c.started = time.Unix(btime, 0).Add(time.Duration(ticks) * time.Second / 100) // USER_HZ is 100 on Linux
	}
	return c, true
}

// procStart is field 22 of /proc/<pid>/stat (after the command in parentheses, which may hold anything but ends at the last ")").
func procStart(dir string) (string, bool) {
	b, err := readSmall(filepath.Join(dir, "stat"), 4<<10)
	if err != nil {
		return "", false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return "", false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", false
	}
	return f[19], true
}

// rootOwned says whether the real uid of the process is 0 (/proc/<pid>/status, line Uid:).
func rootOwned(dir string) bool {
	b, err := readSmall(filepath.Join(dir, "status"), 16<<10)
	if err != nil {
		return false
	}
	for l := range strings.Lines(string(b)) {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "Uid:" {
			return f[1] == "0"
		}
	}
	return false
}

// bootTime is btime of /proc/stat (seconds since the epoch), 0 when it cannot be read.
func bootTime(proc string) int64 {
	b, err := readSmall(filepath.Join(proc, "stat"), 1<<20)
	if err != nil {
		return 0
	}
	for l := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func readSmall(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name) //nolint:gosec // G304: a file of /proc or crun's state, by a pid or a validated id
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return b, nil
}

// orphanLeftovers removes what an orphan that ended leaves (step 4). Nothing here can fail the start: each miss is logged.
func (o *Ops) orphanLeftovers(ctx context.Context, c conmonProc) {
	state := filepath.Join(o.path(orphanCrunDir), c.id)
	var st struct {
		Pid    int    `json:"pid"`
		Rootfs string `json:"rootfs"`
	}
	if b, err := readSmall(filepath.Join(state, "status"), 64<<10); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Pid > 0 {
		if _, err := os.Lstat(filepath.Join(o.path("/proc"), strconv.Itoa(st.Pid))); err == nil {
			o.log.WarnContext(ctx, "orphaned container: its process still shows in /proc; its mounts and crun's state are left", "container", c.name, "id", c.id, "pid", st.Pid)
			return
		}
	}
	want := map[string]bool{orphanBundleDir + c.id + "/userdata/shm": true}
	if orphanRootfsRE.MatchString(st.Rootfs) {
		want[st.Rootfs] = true
	}
	for _, mp := range o.mountPoints() {
		if !want[mp] {
			continue
		}
		if err := o.unmount(o.path(mp)); err != nil {
			o.log.WarnContext(ctx, "orphaned container: a mount could not be removed", "container", c.name, "mount", mp, "error", err.Error())
		}
	}
	if fi, err := os.Lstat(state); err == nil && fi.IsDir() {
		if err := os.RemoveAll(state); err != nil {
			o.log.WarnContext(ctx, "orphaned container: crun's state could not be removed", "container", c.name, "dir", orphanCrunDir+"/"+c.id, "error", err.Error())
		}
	}
}

// mountPoints are the mount points of /proc/self/mountinfo (field 5), unescaped only when plain (the ones wanted have no escapes).
func (o *Ops) mountPoints() []string {
	f, err := os.Open(o.path("/proc/self/mountinfo"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(io.LimitReader(f, 16<<20))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		if fl := strings.Fields(sc.Text()); len(fl) >= 5 && !strings.Contains(fl[4], `\`) {
			out = append(out, fl[4])
		}
	}
	return out
}

func (o *Ops) unmount(p string) error {
	if o.orphanUnmount != nil {
		return o.orphanUnmount(p)
	}
	return unmountDetach(p)
}

// fileKey is a file's device and inode (a network namespace's identity: /proc/<pid>/ns/net and its bind mount in /run/netns agree).
type fileKey struct{ dev, ino uint64 }

func statKey(p string) (fileKey, bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return fileKey{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert // Dev is int32 on darwin, uint64 on linux
}

// orphanNetnsRE: netavark's names of the namespaces it keeps (netns-<uuid>).
var orphanNetnsRE = regexp.MustCompile(`^netns-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// orphanNetns is the network namespace of the container's process that crun's state names (read before the kill).
func (o *Ops) orphanNetns(id string) (fileKey, bool) {
	var st struct {
		Pid int `json:"pid"`
	}
	b, err := readSmall(filepath.Join(o.path(orphanCrunDir), id, "status"), 64<<10)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Pid <= 0 {
		return fileKey{}, false
	}
	return statKey(filepath.Join(o.path("/proc"), strconv.Itoa(st.Pid), "ns", "net"))
}

// orphanNetnsRemove unmounts and removes the /run/netns entry of the namespace k, only when no process of the box is still in it.
func (o *Ops) orphanNetnsRemove(ctx context.Context, c conmonProc, k fileKey) {
	proc := o.path("/proc")
	if ents, err := os.ReadDir(proc); err == nil {
		for _, e := range ents {
			if _, err := strconv.Atoi(e.Name()); err != nil {
				continue
			}
			if pk, ok := statKey(filepath.Join(proc, e.Name(), "ns", "net")); ok && pk == k {
				o.log.WarnContext(ctx, "orphaned container: a process still uses its network namespace; it is left", "container", c.name, "pid", e.Name())
				return
			}
		}
	}
	dir := o.path("/run/netns")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !orphanNetnsRE.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if nk, ok := statKey(p); !ok || nk != k {
			continue
		}
		if err := o.unmount(p); err != nil {
			o.log.WarnContext(ctx, "orphaned container: its network namespace could not be unmounted", "container", c.name, "netns", e.Name(), "error", err.Error())
			return
		}
		if err := os.Remove(p); err != nil {
			o.log.WarnContext(ctx, "orphaned container: its network namespace entry could not be removed", "container", c.name, "netns", e.Name(), "error", err.Error())
			return
		}
		o.log.InfoContext(ctx, "orphaned container: its network namespace removed", "container", c.name, "netns", e.Name())
		return
	}
}
