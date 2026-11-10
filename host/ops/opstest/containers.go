package opstest

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/knt048/vedette/host/ops"
)

// The sensor ids the fake machine's Config carries (host.conf sensor_uid and sensor_gid).
const (
	SensorUID = 10002
	SensorGID = 10003
)

// UnitsDir is the Quadlet directory under the fake root.
func (m *Machine) UnitsDir() string { return filepath.Join(m.Root, "etc/containers/systemd") }

// MakeUnitsDir builds the Quadlet directory the way the installer does: root-owned (here: the test
// user), 0755, with parents closed to group and others.
func (m *Machine) MakeUnitsDir() {
	m.t.Helper()
	m.must(os.MkdirAll(m.UnitsDir(), 0o750))
	for _, d := range []string{filepath.Join(m.Root, "etc"), filepath.Join(m.Root, "etc/containers"), m.UnitsDir()} {
		m.must(os.Chmod(d, 0o755)) //nolint:gosec // a directory of the fake root, 0755 like /etc/containers/systemd
	}
}

// Digest builds a digest from one hex digit repeated 64 times ('a' to 'f', '0' to '9').
func Digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// InstallUnit writes the unit of a service as the installer's bootstrap (or an earlier start) would:
// built from the host's own template with the machine's host.conf ids.
func (m *Machine) InstallUnit(service, digest string, install bool) {
	m.t.Helper()
	m.MakeUnitsDir()
	cfg := m.Config()
	text, err := ops.RenderUnit(service, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID)
	m.must(err)
	m.must(os.WriteFile(filepath.Join(m.UnitsDir(), "vedette-"+service+".container"), text, 0o644)) //nolint:gosec // a unit file of the fake root, 0644 like the real ones
}

// Unit is the text of a service's unit file.
func (m *Machine) Unit(service string) (string, error) {
	b, err := os.ReadFile(filepath.Join(m.UnitsDir(), "vedette-"+service+".container")) //nolint:gosec // test support: a path under the fake root
	return string(b), err
}

// Prev is the saved previous text of a unit (containers/units/<service>.prev in the state dir).
func (m *Machine) Prev(service string) (string, error) {
	b, err := os.ReadFile(filepath.Join(m.State, "containers", "units", service+".prev")) //nolint:gosec // test support: a path under the fake state dir
	return string(b), err
}

// TransitionPath is containers/transition.json in the state dir.
func (m *Machine) TransitionPath() string {
	return filepath.Join(m.State, "containers", "transition.json")
}

// StatefulContainers makes the fake systemctl and podman remember what the container commands do
// (opt-in: the other tests keep the plain fakes). "systemctl restart vedette-<svc>.service" copies
// the unit file as the container's own record (the digest it runs) and marks the service active;
// "stop" clears that; "is-active" prints active (exit 0) or inactive (exit 3). "podman container
// inspect vedette-<svc>" prints the JSON of a container with the digest of that record, running, and
// the health word from SetHealth (default healthy), or "unhealthy" when the digest is one BadImage
// named. Rules added with Rule fire first and can make a call fail or lie. Markers: "restart-fails"
// makes every restart exit 1 without starting anything; "reload-fails" does the same for daemon-reload.
func (m *Machine) StatefulContainers() {
	m.t.Helper()
	root := "ROOT='" + m.Root + "'; STATE='" + m.State + "'\n"
	m.writeFakeWith("systemctl", root+`S="$REC/ctr"; mkdir -p "$S"
svc="${2#vedette-}"; svc="${svc%.service}"
[ -e "$STATE/containers/transition.json" ] && echo "$1 $2" >> "$S/withjournal"
case "$1" in
  daemon-reload)
    [ -e "$REC/mark.reload-fails" ] && exit 1
    ;;
  restart)
    [ -e "$REC/mark.restart-fails" ] && exit 1
    cp "$ROOT/etc/containers/systemd/vedette-$svc.container" "$S/$svc.unit" 2>/dev/null
    : > "$S/$svc.running"; : > "$S/$svc.active"
    ;;
  stop)
    rm -f "$S/$svc.running" "$S/$svc.active"
    ;;
  is-active)
    if [ -e "$S/$svc.active" ]; then echo active; exit 0; fi
    echo inactive; exit 3
    ;;
esac
`)
	m.writeFakeWith("podman", `S="$REC/ctr"; mkdir -p "$S"
svc="${3#vedette-}"
[ -e "$S/$svc.raw" ] && { cat "$S/$svc.raw"; exit 0; }
[ -e "$S/$svc.running" ] || { echo "Error: no such container $3" >&2; exit 125; }
digest=$(sed -n 's/^Image=.*@\(sha256:[0-9a-f]*\)$/\1/p' "$S/$svc.unit")
health=healthy
[ -e "$S/$svc.health" ] && health=$(cat "$S/$svc.health")
if [ -s "$S/$svc.seq" ]; then
  health=$(head -n 1 "$S/$svc.seq"); tail -n +2 "$S/$svc.seq" > "$S/$svc.seq.tmp"; mv "$S/$svc.seq.tmp" "$S/$svc.seq"
fi
[ -e "$S/bad.$digest" ] && health=unhealthy
printf '[{"Name":"%s","ImageDigest":"%s","State":{"Status":"running","Running":true,"Health":{"Status":"%s"}}}]\n' "$3" "$digest" "$health"
`)
}

// SetHealth sets the health word the fake podman prints for a service ("healthy", "starting", ...).
func (m *Machine) SetHealth(service, status string) {
	m.t.Helper()
	m.ctr()
	m.must(os.WriteFile(filepath.Join(m.Rec, "ctr", service+".health"), []byte(status), 0o600))
}

// SetHealthSequence makes the next looks at a service's container print these health words, one
// per look, before the word of SetHealth (default healthy) takes over.
func (m *Machine) SetHealthSequence(service string, words ...string) {
	m.t.Helper()
	m.ctr()
	m.must(os.WriteFile(filepath.Join(m.Rec, "ctr", service+".seq"), []byte(strings.Join(words, "\n")+"\n"), 0o600))
}

// CallsWithJournal lists the systemctl verbs (and units) that were called while
// containers/transition.json existed.
func (m *Machine) CallsWithJournal() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "ctr", "withjournal"))
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// BadImage makes every container of that digest report "unhealthy".
func (m *Machine) BadImage(digest string) {
	m.t.Helper()
	m.ctr()
	m.must(os.WriteFile(filepath.Join(m.Rec, "ctr", "bad."+digest), nil, 0o600))
}

// InspectRaw makes the fake podman print text for a service whatever the state (hostile output).
func (m *Machine) InspectRaw(service, text string) {
	m.t.Helper()
	m.ctr()
	m.must(os.WriteFile(filepath.Join(m.Rec, "ctr", service+".raw"), []byte(text), 0o600))
}

// SetRunning marks a service's container as running (or not) with the unit file it has now, as if
// it had been started earlier.
func (m *Machine) SetRunning(service string, on bool) {
	m.t.Helper()
	d := m.ctr()
	run, act := filepath.Join(d, service+".running"), filepath.Join(d, service+".active")
	if !on {
		_ = os.Remove(run)
		_ = os.Remove(act)
		return
	}
	b, err := os.ReadFile(filepath.Join(m.UnitsDir(), "vedette-"+service+".container")) //nolint:gosec // test support: a path under the fake root
	m.must(err)
	m.must(os.WriteFile(filepath.Join(d, service+".unit"), b, 0o600)) //nolint:gosec // test support: a path under the fake rec dir
	m.must(os.WriteFile(run, nil, 0o600))
	m.must(os.WriteFile(act, nil, 0o600))
}

// IsRunning says whether the fake machine runs the service.
func (m *Machine) IsRunning(service string) bool {
	_, err := os.Stat(filepath.Join(m.Rec, "ctr", service+".active"))
	return err == nil
}

func (m *Machine) ctr() string {
	m.t.Helper()
	d := filepath.Join(m.Rec, "ctr")
	m.must(os.MkdirAll(d, 0o750))
	return d
}
