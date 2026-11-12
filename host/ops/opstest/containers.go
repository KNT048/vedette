package opstest

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	text, err := ops.RenderUnitIn(service, digest, install, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID, cfg.CoreData)
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

// TransitionPath is containers/transition-<service>.json in the state dir.
func (m *Machine) TransitionPath(service string) string {
	return filepath.Join(m.State, "containers", "transition-"+service+".json")
}

// Deadlocked lists the services whose synchronous restart the fake refused because the host's own start
// job was pending (marker "host-starting") and the unit is ordered After=vedette-host.service.
func (m *Machine) Deadlocked() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "ctr", "deadlocked"))
	return strings.Fields(string(b))
}

// StatefulContainers makes the fake systemctl and podman remember what the container commands do
// (opt-in: the other tests keep the plain fakes). "systemctl restart vedette-<svc>.service" copies
// the unit file as the container's own record (the digest it runs) and marks the service active;
// "stop" clears that and "start" does what restart does (marker "start-fails": exit 1; slice 3-8b, the restore of
// backup.restore); "is-active" prints active (exit 0) or inactive (exit 3). "podman container
// inspect vedette-<svc>" prints the JSON of a container with the digest of that record, running, and
// the health word from SetHealth (default healthy), or "unhealthy" when the digest is one BadImage
// named. Rules added with Rule fire first and can make a call fail or lie. Markers: "restart-fails"
// makes every restart exit 1 without starting anything; "reload-fails" does the same for daemon-reload;
// "host-starting" models the host's own start job still pending: a restart of a unit that is After=
// vedette-host.service fails (a real one would wait for the job forever) and is listed by Deadlocked.
func (m *Machine) StatefulContainers() {
	m.t.Helper()
	root := "ROOT='" + m.Root + "'; STATE='" + m.State + "'; CORE='" + m.CoreData + "'\n"
	m.writeFakeWith("systemctl", root+ctrHelpers+`svc="${2#vedette-}"; svc="${svc%.service}"
for f in "$STATE"/containers/transition-*.json; do [ -e "$f" ] && { echo "$1 $2" >> "$S/withjournal"; break; }; done
case "$1" in
  daemon-reload)
    [ -e "$REC/mark.reload-fails" ] && exit 1
    ;;
  restart)
    [ -e "$REC/mark.restart-fails" ] && exit 1
    # While the host's own start job is pending, a synchronous restart of a unit ordered After= the host waits
    # for that job: it can never finish. The fake fails it at once and says so.
    if [ -e "$REC/mark.host-starting" ] && grep -q '^After=.*vedette-host.service' "$ROOT/etc/containers/systemd/vedette-$svc.container" 2>/dev/null; then
      echo "$svc" >> "$S/deadlocked"; exit 1
    fi
    unitdigest "$ROOT/etc/containers/systemd/vedette-$svc.container"; ud=$digest
    echo "$svc backups=$(ls "$STATE"/backups/*.tar.gz 2>/dev/null | wc -l | tr -d ' ') db=$(head -n 1 "$CORE/vedette.db" 2>/dev/null) digest=$ud" >> "$S/at-restart"
    [ "$svc" = core ] && [ -e "$REC/mark.migrate-db" ] && [ "$(cat "$REC/mark.migrate-db")" = "$ud" ] && printf 'db: migrated' > "$CORE/vedette.db"
    cp "$ROOT/etc/containers/systemd/vedette-$svc.container" "$S/$svc.unit" 2>/dev/null
    : > "$S/$svc.running"; : > "$S/$svc.active"
    readone "$S/$svc.gen" 0; echo $((one + 1)) > "$S/$svc.gen"
    [ -e "$REC/mark.lock-containers" ] && chmod 500 "$STATE/containers"
    [ -e "$REC/mark.plant-aside-dir" ] && { rm -f "$CORE/vedette.db.rollback"; mkdir -p "$CORE/vedette.db.rollback"; }
    ;;
  stop)
    rm -f "$S/$svc.running" "$S/$svc.active"
    ;;
  start)
    # backup.restore stops core and starts it again (a unit change restarts instead)
    [ -e "$REC/mark.start-fails" ] && exit 1
    cp "$ROOT/etc/containers/systemd/vedette-$svc.container" "$S/$svc.unit" 2>/dev/null
    : > "$S/$svc.running"; : > "$S/$svc.active"
    readone "$S/$svc.gen" 0; echo $((one + 1)) > "$S/$svc.gen"
    ;;
  is-active)
    if [ -e "$S/$svc.active" ]; then echo active; exit 0; fi
    echo inactive; exit 3
    ;;
esac
`)
	m.writeFakeWith("podman", containerPodman)
}

// ctrHelpers starts the container fakes with shell builtins only: every fork of these fakes runs under a -race test
// binary's waitid, and the fakes are called on every health look. unitdigest sets digest from the Image= line of a
// unit as the old sed pair did (Image=...@sha256:<hex>, else Image=<64 hex> as sha256:<hex>, else empty); readone
// sets one to the first line of a file, or to the default when the file is missing.
const ctrHelpers = `S="$REC/ctr"; [ -d "$S" ] || mkdir -p "$S"
unitdigest() {
  digest=""; d2=""
  [ -r "$1" ] || return 0
  while IFS= read -r l || [ -n "$l" ]; do
    case $l in
      Image=*@sha256:*) h=${l##*@sha256:}; case $h in *[!0-9a-f]*) ;; *) [ -n "$digest" ] || digest="sha256:$h" ;; esac ;;
      Image=*) h=${l#Image=}; case $h in *[!0-9a-f]*) ;; *) [ ${#h} -eq 64 ] && [ -z "$d2" ] && d2="sha256:$h" ;; esac ;;
    esac
  done < "$1"
  [ -n "$digest" ] || digest=$d2
}
readone() { one=$2; [ -r "$1" ] || return 0; IFS= read -r one < "$1" || [ -n "$one" ]; }
`

// containerPodman is the part of the fake podman that answers "container inspect".
const containerPodman = ctrHelpers + `svc="${3#vedette-}"
[ -e "$S/$svc.raw" ] && { cat "$S/$svc.raw"; exit 0; }
[ -e "$S/$svc.running" ] || { echo "Error: no such container $3" >&2; exit 125; }
unitdigest "$S/$svc.unit"
health=healthy
[ -e "$S/$svc.health" ] && readone "$S/$svc.health" "" && health=$one
if [ -s "$S/$svc.seq" ]; then
  { IFS= read -r health; while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done; } < "$S/$svc.seq" > "$S/$svc.seq.tmp"; mv "$S/$svc.seq.tmp" "$S/$svc.seq"
fi
[ -e "$S/bad.$digest" ] && health=unhealthy
readone "$S/$svc.gen" 0; gen=$one
cid=$(printf '%064x' "$gen"); started=$(printf '2026-11-11T00:00:00.%09dZ' "$gen")
printf '[{"Name":"%s","Id":"%s","ImageDigest":"%s","Image":"%s","State":{"Status":"running","Running":true,"StartedAt":"%s","Health":{"Status":"%s"}}}]\n' "$3" "$cid" "$digest" "${digest#sha256:}" "$started" "$health"
`

// MigratesDatabaseOn makes a restart of core with that image digest replace core's database file by
// "db: migrated", as a new release that migrates its schema does.
func (m *Machine) MigratesDatabaseOn(digest string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.Rec, "mark.migrate-db"), []byte(digest), 0o600))
}

// AtRestart lists, one line per restart of a unit the fake systemctl did, what the machine looked like at
// that moment: "<service> backups=<number of backup archives> db=<first line of core's database> digest=<the
// digest in the unit>". It proves the order of the steps of a switch.
func (m *Machine) AtRestart() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "ctr", "at-restart"))
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// RemoveImage makes the fake podman forget an image (and its tags), as if someone had removed it.
func (m *Machine) RemoveImage(digest string) {
	m.t.Helper()
	_ = os.Remove(filepath.Join(m.img(), "have."+digest))
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

// ContainerRestarted makes the fake podman report a new run (a new ID and StartedAt) of the service's container, as after a
// restart systemd did on its own; the unit file and the running state stay as they are.
func (m *Machine) ContainerRestarted(service string) {
	m.t.Helper()
	p := filepath.Join(m.ctr(), service+".gen")
	n := 0
	if b, err := os.ReadFile(p); err == nil { //nolint:gosec // test support: a path under the fake rec dir
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	m.must(os.WriteFile(p, []byte(strconv.Itoa(n+1)+"\n"), 0o600))
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

// StatefulImages makes the fake podman remember what container.pull does (opt-in; it replaces the
// podman of StatefulContainers, which a pull test does not need):
//
//	pull -q <ref@digest>                 records the digest as present, prints an image id; exit 125 and nothing
//	                                     recorded when the marker "pull-fails" exists
//	image inspect --format json <ref>    prints a one-image JSON array when the digest (for ref@digest) or the
//	                                     tag's digest (for a local tag) is present, else exit 125; the digest it
//	                                     shows is the one the marker file ctr/img.lie holds when that exists
//	tag <ref@digest> <local tag>         records the tag (exit 125 when the marker "tag-fails" exists)
//
// Present, tagged and the pull calls are read back with ImagePresent, ImageTag and Calls("podman").
func (m *Machine) StatefulImages() {
	m.t.Helper()
	m.writeFakeWith("podman", imagePodman)
}

// imagePodman is the part of the fake podman that answers pull, image inspect, image ls, tag and rmi.
const imagePodman = `S="$REC/img"; [ -d "$S" ] || mkdir -p "$S"
id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
key() { echo "$1" | tr '/:@' '___'; }
case "$1" in
  pull)
    [ -e "$REC/mark.pull-fails" ] && { echo "Error: pulling failed" >&2; exit 125; }
    ref="$3"; d="${ref#*@}"
    svc="${ref#ghcr.io/knt048/vedette-}"; svc="${svc%%@*}"
    echo "$svc" > "$S/have.$d"
    echo "$id"
    ;;
  rmi)
    d="sha256:$2"
    [ -e "$REC/mark.rmi-fails" ] && { echo "Error: rmi failed" >&2; exit 125; }
    [ -e "$S/used.$d" ] && { echo "Error: image is in use by a container" >&2; exit 2; }
    [ -e "$S/have.$d" ] || { echo "Error: no such image $d" >&2; exit 1; }
    rm -f "$S/have.$d"
    for f in "$S"/tag.*; do [ -e "$f" ] && [ "$(cat "$f")" = "$d" ] && rm -f "$f"; done
    grep -v " $d\$" "$S/tags" > "$S/tags.tmp" 2>/dev/null; mv "$S/tags.tmp" "$S/tags" 2>/dev/null
    echo "$d" >> "$S/removed"
    ;;
  image)
    if [ "$2" = ls ]; then
      : >> "$S/tags"
      printf '['
      first=1
      for f in "$S"/have.*; do
        [ -e "$f" ] || continue
        d="${f##*/have.}"; svc=$(cat "$f")
        [ $first = 1 ] || printf ','
        first=0
        printf '{"Id":"%s","Digest":"%s","Names":[' "${d#sha256:}" "$d"
        n=1
        while read -r ref dg; do
          [ "$dg" = "$d" ] || continue
          [ $n = 1 ] || printf ','
          n=0
          printf '"%s"' "$ref"
        done < "$S/tags" 2>/dev/null
        printf '],"RepoDigests":['
        [ -n "$svc" ] && [ "$svc" != scan-nmap ] && printf '"ghcr.io/knt048/vedette-%s@%s"' "$svc" "$d"
        c=0; [ -e "$S/used.$d" ] && c=1
        printf '],"Containers":%s}' "$c"
      done
      printf ']\n'
      exit 0
    fi
    x="$5"
    case "$x" in
      *@sha256:*) d="${x#*@}" ;;
      */*) d=$(cat "$S/tag.$(key "$x")" 2>/dev/null) ;;
      *) d="sha256:$x" ;; # a bare image ID
    esac
    { [ -n "$d" ] && [ -e "$S/have.$d" ]; } || { echo "Error: no such image $x" >&2; exit 125; }
    [ -e "$S/raw" ] && { cat "$S/raw"; exit 0; }
    # an image the fake built has its own ID; a pulled one shows the fixed one
    iid="$id"; [ "$(cat "$S/have.$d" 2>/dev/null)" = scan-nmap ] && iid="${d#sha256:}"
    shown="$d"; [ -e "$S/lie" ] && shown=$(cat "$S/lie")
    repo="$shown"
    svc="${x#ghcr.io/knt048/vedette-}"; svc="${svc#localhost/vedette-}"; svc="${svc%%[@:]*}"
    if [ -e "$S/repoonly" ]; then
      # an image index: Digest is the digest of a manifest inside it, RepoDigests names the pulled index
      shown=sha256:0000000000000000000000000000000000000000000000000000000000000000; repo="$d"
    fi
    printf '[{"Id":"%s","Digest":"%s","RepoDigests":["ghcr.io/knt048/vedette-%s@%s"],"Architecture":"amd64","Os":"linux"}]\n' "$iid" "$shown" "$svc" "$repo"
    ;;
  tag)
    [ -e "$REC/mark.tag-fails" ] && { echo "Error: tagging failed" >&2; exit 125; }
    case "$2" in
      *@sha256:*) d="${2#*@}" ;;
      *) [ -e "$REC/mark.tag-id-fails" ] && { echo "Error: tagging failed" >&2; exit 125; }
         d="sha256:$2" ;; # a bare image ID: the tag moves to it
    esac
    [ -e "$S/have.$d" ] || { echo "Error: no such image $2" >&2; exit 125; }
    grep -v "^$3 " "$S/tags" > "$S/tags.tmp" 2>/dev/null; mv "$S/tags.tmp" "$S/tags" 2>/dev/null
    echo "$d" > "$S/tag.$(key "$3")"
    echo "$3 $d" >> "$S/tags"
    ;;
  build)
    # the scan image built on the box (D-147): "build ... --build-arg BASE_IMAGE=<ref@digest> ... --tag <tag> <dir>"
    echo "$*" >> "$S/builds"
    [ -e "$REC/mark.build-fails" ] && { echo "Error: build failed" >&2; exit 125; }
    while [ $# -gt 0 ]; do
      case "$1" in
        --tag) tag="$2" ;;
        --iidfile) iidfile="$2" ;;
        BASE_IMAGE=*) base="${1#BASE_IMAGE=}" ;;
      esac
      shift
    done
    [ -e "$S/have.${base#*@}" ] || { echo "Error: the base image is not here (--pull=never)" >&2; exit 125; }
    n=$(cat "$S/buildn" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$S/buildn"
    nid=$(printf 'b%063x' "$n")
    echo scan-nmap > "$S/have.sha256:$nid"
    if [ ! -e "$REC/mark.build-no-tag" ]; then
      grep -v "^$tag " "$S/tags" > "$S/tags.tmp" 2>/dev/null; mv "$S/tags.tmp" "$S/tags" 2>/dev/null
      echo "sha256:$nid" > "$S/tag.$(key "$tag")"
      echo "$tag sha256:$nid" >> "$S/tags"
    fi
    [ -e "$REC/mark.build-no-iid" ] || printf 'sha256:%s' "$nid" > "$iidfile"
    [ -e "$REC/mark.build-bad-iid" ] && printf 'not an id' > "$iidfile"
    echo "$nid"
    ;;
  run)
    # "run --rm ... --entrypoint nmap <image id> --version": what the built image prints
    echo "$*" >> "$S/runs"
    shift 14
    [ -e "$S/have.sha256:$1" ] || { echo "Error: no such image $1" >&2; exit 125; }
    [ -e "$REC/mark.nmap-fails" ] && exit 125
    if [ -e "$REC/mark.nmap-garbage" ]; then echo "not nmap at all"; exit 0; fi
    v=7.95; [ -s "$S/nmapver" ] && v=$(cat "$S/nmapver")
    echo "Nmap version $v ( https://nmap.org )"
    echo "Platform: x86_64-pc-linux-gnu"
    ;;
esac
`

// StatefulPodman makes the fake podman answer both the container looks of StatefulContainers and the
// image calls of StatefulImages (pull, image inspect, tag, and also image ls and rmi): what a test of
// container.start with a version needs. "image ls --format json" lists every image the fake holds with
// its local tags and, when the service is known (a pull, or PresentImage), its pull reference; "rmi
// <digest>" removes it and its tags and records the digest (see ImageRemoved), exit 125 and nothing
// removed when the marker "rmi-fails" exists, exit 2 for an image MarkImageUsed named.
func (m *Machine) StatefulPodman() {
	m.t.Helper()
	m.writeFakeWith("podman", "if [ \"$1\" = container ]; then\n"+containerPodman+"\nexit 0\nfi\n"+imagePodman)
}

// PresentImage makes the fake podman hold an image of that digest for the service, with the pull
// reference and a local tag for version (empty: no tag), as if it had been pulled before.
func (m *Machine) PresentImage(service, digest, version string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "have."+digest), []byte(service+"\n"), 0o600))
	if version != "" {
		tag := "localhost/vedette-" + service + ":" + version
		m.must(os.WriteFile(filepath.Join(m.img(), "tag."+strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(tag)), []byte(digest+"\n"), 0o600))
		f, err := os.OpenFile(filepath.Join(m.img(), "tags"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		m.must(err)
		_, err = f.WriteString(tag + " " + digest + "\n")
		m.must(err)
		m.must(f.Close())
	}
}

// MarkImageUsed makes the fake podman report a container for the image and refuse to remove it.
func (m *Machine) MarkImageUsed(digest string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "used."+digest), nil, 0o600))
}

// ImageRemoved lists the digests the fake podman removed with rmi, in order.
func (m *Machine) ImageRemoved() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "img", "removed"))
	return strings.Fields(string(b))
}

func (m *Machine) img() string {
	m.t.Helper()
	d := filepath.Join(m.Rec, "img")
	m.must(os.MkdirAll(d, 0o750))
	return d
}

// SetImagePresent makes the fake podman hold an image of that digest, as if it had been pulled before.
func (m *Machine) SetImagePresent(digest string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "have."+digest), nil, 0o600))
}

// ImagePresent says whether the fake podman holds an image of that digest.
func (m *Machine) ImagePresent(digest string) bool {
	_, err := os.Stat(filepath.Join(m.Rec, "img", "have."+digest))
	return err == nil
}

// ImageTag is the digest a local tag points to in the fake podman ("" when the tag does not exist).
func (m *Machine) ImageTag(tag string) string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "img", "tag."+strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(tag)))
	return strings.TrimSpace(string(b))
}

// ImageLie makes every image inspect show this digest instead of the real one.
func (m *Machine) ImageLie(digest string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "lie"), []byte(digest), 0o600))
}

// ImageRaw makes every image inspect of an image that is present print text instead (hostile output).
func (m *Machine) ImageRaw(text string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "raw"), []byte(text), 0o600))
}

// BuiltID is the 64-hex ID the fake podman gives the n-th image it builds (n from 1) for the scan image (D-147).
func BuiltID(n int) string { return fmt.Sprintf("b%063x", n) }

// NmapVersion makes "nmap --version" in an image the fake builds print this version.
func (m *Machine) NmapVersion(v string) {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "nmapver"), []byte(v), 0o600))
}

// Builds lists the argv (joined by spaces) of every "podman build" the fake saw, in order.
func (m *Machine) Builds() []string { return m.lines(filepath.Join(m.Rec, "img", "builds")) }

// NmapRuns lists the argv (joined by spaces) of every "podman run" the fake saw, in order.
func (m *Machine) NmapRuns() []string { return m.lines(filepath.Join(m.Rec, "img", "runs")) }

func (m *Machine) lines(path string) []string {
	b, _ := os.ReadFile(path) //nolint:gosec // test support: a path under the fake rec dir
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// PresentBuilt makes the fake podman hold an image the host "built" with this 64-hex ID, tagged localhost/vedette-scan-nmap:<version>
// (empty: no tag), as if an earlier container.pull of scan had built it. Its "digest" in units and records is "sha256:" + id.
func (m *Machine) PresentBuilt(id, version string) {
	m.t.Helper()
	d := "sha256:" + id
	m.must(os.WriteFile(filepath.Join(m.img(), "have."+d), []byte("scan-nmap\n"), 0o600))
	if version != "" {
		tag := "localhost/vedette-scan-nmap:" + version
		m.must(os.WriteFile(filepath.Join(m.img(), "tag."+strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(tag)), []byte(d+"\n"), 0o600))
		f, err := os.OpenFile(filepath.Join(m.img(), "tags"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		m.must(err)
		_, err = f.WriteString(tag + " " + d + "\n")
		m.must(err)
		m.must(f.Close())
	}
}

// ImageRepoOnly makes image inspect show another Digest and the pulled digest only in RepoDigests, as an image index may.
func (m *Machine) ImageRepoOnly() {
	m.t.Helper()
	m.must(os.WriteFile(filepath.Join(m.img(), "repoonly"), nil, 0o600))
}

// ConntrackSays makes the fake conntrack print text on stderr (where the real one prints "N flow entries have been
// deleted") and exit with code.
func (m *Machine) ConntrackSays(code int, text string) {
	m.t.Helper()
	m.writeFakeWith(ops.BinConntrack, "printf '%s\\n' '"+strings.ReplaceAll(text, "'", "")+"' >&2\nexit "+strconv.Itoa(code)+"\n")
}
