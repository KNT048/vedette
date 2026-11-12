package ops

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/host/api"
)

// The Quadlet units of the services (docs/DEPLOYMENT.md sections 2 and 6.1, D-105, D-114, D-123).
// Each service has one constant Go template. A unit is built whole from it and never edited, and
// there are no drop-ins (Podman 4.9 on noble documents none). The only things that go into a template
// are the image digest, the host.conf uids and gids, and (appended after it, not part of it) the
// [Install] section that makes the service start at boot. Every one of them is checked before the
// template runs, so no value can add a line to the unit: there is no free text anywhere.

const (
	// unitsRel is the Quadlet directory of system (rootful) units, relative to Deps.Root (D-105 (4)).
	unitsRel = "etc/containers/systemd"
	// maxUnitSize bounds what is read back (the largest template is under 2 KiB).
	maxUnitSize = 16 << 10
	// hpHostDir is where the honeypot's config/ lives on the box (core writes it, the container reads it), D-89.
	// Core mounts it read-write and the honeypot container read-only, each at its -honeypot-dir default, at the
	// same absolute path in both, because opencanary.conf holds the log path (D-123 (1)). The honeypot's log/ is
	// not a folder of this directory any more: it is the size-capped tmpfs volume below (D-318).
	hpHostDir = "/var/lib/vedette-honeypot"
	// hpLogVolume is the volume of the honeypot's log/ (the container writes it, core reads it), D-89. It is a
	// tmpfs of at most hpLogSize bytes and hpLogInodes files, so whoever takes the honeypot over cannot fill the
	// disk of vedette.db with files in log/ (D-318). hpLogVolume + ".volume" is the Quadlet file.
	hpLogVolume = "vedette-hp-log"
	hpLogSize   = "64m"
	hpLogInodes = 1024
)

// HoneypotConfModule is the containers.conf module the honeypot unit loads (ContainersConfModule=, Podman >= 4.8): it
// clears default_sysctls (#486). The container joins the host-owned namespace vedette-hp from its own user namespace
// (UserNS=auto), where crun may not write a sysctl of that namespace, so a distribution default such as Ubuntu 26.04's
// net.ipv4.ping_group_range stops every start. The namespace's own sysctls are vedette-host's (INV-20 of honeypot).
// The file is constant text shipped in the vedette-host .deb (deploy/deb/nfpm.yaml), so dpkg installs and purges it
// with the binary. Exported for the package and contract tests.
const HoneypotConfModule = "/usr/lib/vedette/honeypot-containers.conf"

// installSection is what makes a service start at boot. Quadlet applies [Install] when it generates
// the unit (a generated unit cannot be enabled or disabled), so "persist" is its presence.
const installSection = "\n[Install]\nWantedBy=multi-user.target\n"

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// imageLineRE matches the Image= line of every template: a repository and a pinned digest.
	imageLineRE = regexp.MustCompile(`^Image=([a-z0-9./-]+)@(sha256:[0-9a-f]{64})$`)
)

// unitFill is everything a template may use.
type unitFill struct {
	Digest    string
	Install   bool
	CoreUID   int
	CoreGID   int
	SensorUID int
	SensorGID int
	// DataDir is host.conf's core_data, bound at /var/lib/vedette in core's unit (D-142 H1): the database and
	// the key core reads (its default -key) are then the files backup.* backs up and backup.restore puts back.
	DataDir string
}

// coreDataRE is a core_data the unit accepts: absolute, no empty, "." or ".." segment, no trailing slash,
// and only characters that cannot end a Volume= field or start an option, a specifier or a new line.
var coreDataRE = regexp.MustCompile(`^(/[A-Za-z0-9_-][A-Za-z0-9._-]*)+$`)

func validCoreData(p string) bool {
	return len(p) <= 200 && coreDataRE.MatchString(p)
}

// ID is the 64 hex digits of the digest: the image ID of a scan image, which the unit names instead of repository@digest (D-147).
func (f unitFill) ID() string { return strings.TrimPrefix(f.Digest, "sha256:") }

type serviceUnit struct {
	repo        string // the image repository, without the digest ("" when byID)
	tmpl        *template.Template
	needsCore   bool // uses core_uid and core_gid
	needsSensor bool // uses sensor_uid and sensor_gid
	// byID: the image is built on the box and has no registry digest, so Image= is the bare 64-hex image ID and the "digest" the host
	// keeps for the service is "sha256:" + that ID (D-147). Podman looks an image up by its full ID like by a name.
	byID bool
}

const (
	repoCore     = "ghcr.io/knt048/vedette-core"
	repoSensor   = "ghcr.io/knt048/vedette-sensor"
	repoHoneypot = "ghcr.io/knt048/vedette-honeypot"
)

func mustTemplate(name, text string) *template.Template {
	return template.Must(template.New(name).Option("missingkey=error").Parse(text))
}

// services holds the templates. greenbone has none: it is a group of upstream containers with no
// unit text anywhere in the spec (DEPLOYMENT.md 2.4), so the host refuses to make one (D-123 (2)).
var services = map[string]serviceUnit{
	api.ServiceCore:     {repo: repoCore, tmpl: mustTemplate("core", coreUnitText), needsCore: true, needsSensor: true},
	api.ServiceSensor:   {repo: repoSensor, tmpl: mustTemplate("sensor", sensorUnitText), needsSensor: true},
	api.ServiceHoneypot: {repo: repoHoneypot, tmpl: mustTemplate("honeypot", honeypotUnitText)},
	api.ServiceScan:     {tmpl: mustTemplate("scan", scanUnitText), needsSensor: true, byID: true},
}

const coreUnitText = `[Unit]
Description=Vedette core
After=network-online.target vedette-host.service
Wants=network-online.target

[Container]
ContainerName=vedette-core
HostName=vedette
Image=` + repoCore + `@{{.Digest}}
Pull=never
Network=vedette-int.network
PublishPort=8443:8443
PublishPort=127.0.0.1:8444:8444
PublishPort=514:5514/udp
PublishPort=514:5514/tcp
PublishPort=6514:5515/tcp
Volume={{.DataDir}}:/var/lib/vedette
Volume=` + hpHostDir + `/config:/var/lib/vedette/honeypot/config
Volume=` + hpLogVolume + `.volume:/var/lib/vedette/honeypot/log:ro,noexec
Volume=/run/vedette:/run/vedette
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds/passive
Volume=vedette-creds-active.volume:/var/lib/vedette-creds/active
ReadOnly=true
Tmpfs=/tmp:size=64m
NoNewPrivileges=true
DropCapability=ALL
User={{.CoreUID}}:{{.CoreGID}}
LogDriver=journald
PodmanArgs=--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 --group-add={{.SensorGID}}
Environment=GOMEMLIMIT=1800MiB
HealthCmd=["/vedette","healthcheck"]
HealthInterval=30s
HealthStartPeriod=60s
HealthRetries=3
Exec=-listen :8443 -sensor-listen :8444 -sensor-creds /var/lib/vedette-creds -syslog-port 5514

[Service]
Restart=always
TimeoutStartSec=300
`

const sensorUnitText = `[Unit]
Description=Vedette sensor (passive capture)
After=vedette-core.service
Wants=vedette-core.service

[Container]
ContainerName=vedette-sensor
Image=` + repoSensor + `@{{.Digest}}
Pull=never
Network=host
User={{.SensorUID}}:{{.SensorGID}}
DropCapability=ALL
AddCapability=NET_RAW
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds:ro
LogDriver=journald
PodmanArgs=--memory=512m --memory-swap=512m --cpus=1 --pids-limit=256
HealthCmd=["/vedette-sensor","healthcheck"]
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=passive --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem

[Service]
Restart=always
`

const honeypotUnitText = `[Unit]
Description=Vedette honeypot (all decoys, namespace vedette-hp)
After=vedette-host.service
Requires=vedette-host.service

[Container]
ContainerName=vedette-honeypot
Image=` + repoHoneypot + `@{{.Digest}}
Pull=never
Network=ns:/run/netns/vedette-hp
DropCapability=ALL
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
UserNS=auto
ContainersConfModule=` + HoneypotConfModule + `
Volume=` + hpHostDir + `/config:/var/lib/vedette/honeypot/config:ro
Volume=` + hpLogVolume + `.volume:/var/lib/vedette/honeypot/log:U,noexec
LogDriver=journald
PodmanArgs=--memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=128
HealthCmd=["/vedette","honeypot","healthcheck"]
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3

[Service]
Restart=always
`

const scanUnitText = `[Unit]
Description=Vedette scan (active scanning)
After=vedette-core.service
Wants=vedette-core.service

[Container]
ContainerName=vedette-scan
Image={{.ID}}
Pull=never
Network=host
User={{.SensorUID}}:{{.SensorGID}}
DropCapability=ALL
AddCapability=NET_RAW
NoNewPrivileges=true
RunInit=true
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-creds-active.volume:/var/lib/vedette-creds:ro
LogDriver=journald
PodmanArgs=--memory=1g --memory-swap=1g --cpus=2 --pids-limit=512 --cpu-shares=128
HealthCmd=["/vedette-sensor","healthcheck"]
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=active --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem

[Service]
Restart=always
`

// The two credential volumes (D-110 (4), D-114 (4), D-147): one per sensor role, each a Quadlet .volume unit that the host writes from
// the constant text below, with the same safe writer as the service units. core mounts both read-write; sensor mounts only passive and
// scan only active, read-only (the unit texts above), so a container sees the bundle of its own role and no other. Quadlet creates the
// volume on first use with User= as owner and Group= as group (Podman's .volume keys): core_uid, which writes the bundles, and
// sensor_gid, which reads them. The setgid bit (mode 2750) that makes every file core creates there belong to sensor_gid is core's to
// set on its own role folders at start: an owner keeps the bit on chmod only when it is in the file's group, which is why core's unit
// carries --group-add=<sensor_gid> and nothing else of that kind.
var credsRoles = []string{"passive", "active"}

const volumeUnitText = `[Unit]
Description=Vedette sensor credentials (%s role)

[Volume]
VolumeName=vedette-creds-%s
User=%d
Group=%d
`

func volumeFileName(role string) string { return "vedette-creds-" + role + ".volume" }

// renderVolume builds the .volume unit of a role. The role is from the closed list and the ids are checked like a unit's.
func renderVolume(role string, coreUID, sensorGID int) ([]byte, error) {
	if !slices.Contains(credsRoles, role) || !validID(coreUID) || !validID(sensorGID) {
		return nil, fmt.Errorf("%w: volume", errBadFill)
	}
	return fmt.Appendf(nil, volumeUnitText, role, role, coreUID, sensorGID), nil
}

// RenderVolume builds the .volume unit of a role ("passive" or "active"). Exported for the contract tests.
func RenderVolume(role string, coreUID, sensorGID int) ([]byte, error) {
	return renderVolume(role, coreUID, sensorGID)
}

// hpLogVolumeText is the .volume unit of the honeypot's log/ (D-318): constant text, no host.conf id (:U in the honeypot's unit gives
// the volume to the container's user at start; core reads it through the "other" bits that init.py sets, D-162). Podman's local
// driver mounts it as a tmpfs with these options when the first container that uses it starts. Podman's bind of the volume into a
// container has its own flags and does not carry noexec over (honeypot-check showed it), so both units also say noexec on the
// Volume= line: nothing in log/ is ever run.
var hpLogVolumeText = []byte(`[Unit]
Description=Vedette honeypot log (tmpfs, size-capped)

[Volume]
VolumeName=` + hpLogVolume + `
Type=tmpfs
Device=tmpfs
Options=size=` + hpLogSize + `,nr_inodes=` + fmt.Sprint(hpLogInodes) + `,nosuid,nodev,noexec
`)

// hpLogVolumeFileName is the Quadlet file of the honeypot log volume.
const hpLogVolumeFileName = hpLogVolume + ".volume"

// HpLogVolumeText is the text of the honeypot log volume unit. Exported for the contract tests.
func HpLogVolumeText() []byte { return slices.Clone(hpLogVolumeText) }

// validID is a uid or gid a unit may carry: 1 up to what host.conf accepts (31 bits). Never 0.
func validID(n int) bool { return n >= 1 && n <= 1<<31-1 }

// RenderUnit builds the text of a service's unit. Exported for the contract tests.
// It binds the default core_data /var/lib/vedette; RenderUnitIn names another.
func RenderUnit(service, digest string, install bool, coreUID, coreGID, sensorUID, sensorGID int) ([]byte, error) {
	return RenderUnitIn(service, digest, install, coreUID, coreGID, sensorUID, sensorGID, "/var/lib/vedette")
}

// RenderUnitIn is RenderUnit with the core_data of host.conf. Exported for the contract tests.
func RenderUnitIn(service, digest string, install bool, coreUID, coreGID, sensorUID, sensorGID int, coreData string) ([]byte, error) {
	return renderUnit(service, unitFill{Digest: digest, Install: install, CoreUID: coreUID, CoreGID: coreGID, SensorUID: sensorUID, SensorGID: sensorGID, DataDir: coreData})
}

var (
	errNoTemplate = errors.New("ops: this service has no unit template")
	errBadFill    = errors.New("ops: a value for the unit is not valid")
)

// renderUnit validates every fill-in, then runs the service's template. The check of the result is
// belt and braces: the digest line is the only place a fill-in with letters goes, and the whole text
// is plain ASCII with no carriage return.
func renderUnit(service string, f unitFill) ([]byte, error) {
	s, ok := services[service]
	if !ok {
		return nil, errNoTemplate
	}
	if !digestRE.MatchString(f.Digest) {
		return nil, fmt.Errorf("%w: digest", errBadFill)
	}
	if s.needsCore && (!validID(f.CoreUID) || !validID(f.CoreGID)) {
		return nil, fmt.Errorf("%w: core uid or gid", errBadFill)
	}
	if s.needsCore && !validCoreData(f.DataDir) {
		return nil, fmt.Errorf("%w: core_data", errBadFill)
	}
	if s.needsSensor && (!validID(f.SensorUID) || !validID(f.SensorGID)) {
		return nil, fmt.Errorf("%w: sensor uid or gid", errBadFill)
	}
	var b bytes.Buffer
	if err := s.tmpl.Execute(&b, f); err != nil {
		return nil, fmt.Errorf("ops: render %s unit: %w", service, err)
	}
	if f.Install {
		b.WriteString(installSection)
	}
	out := b.Bytes()
	pin := "@" + f.Digest
	if s.byID {
		pin = "\nImage=" + f.ID() + "\n"
	}
	if len(out) > maxUnitSize || bytes.ContainsAny(out, "\r\x00") || !utf8.Valid(out) || strings.Count(string(out), pin) != 1 {
		return nil, fmt.Errorf("%w: the unit came out wrong", errBadFill)
	}
	return out, nil
}

// ParseUnit reads back what the host's own template made: the digest of the Image= line (which must
// carry the service's repository) and whether the unit has [Install]. Anything else (a second
// Image= line, another repository, a short digest, a carriage return) is an error. Exported for
// fuzzing.
func ParseUnit(service string, text []byte) (digest string, install bool, err error) {
	return parseUnit(service, text)
}

func parseUnit(service string, text []byte) (digest string, install bool, err error) {
	s, ok := services[service]
	if !ok {
		return "", false, errNoTemplate
	}
	if len(text) == 0 || len(text) > maxUnitSize || bytes.ContainsAny(text, "\r\x00") || !utf8.Valid(text) {
		return "", false, errors.New("ops: the unit is empty, too large or not text")
	}
	for line := range strings.SplitSeq(string(text), "\n") {
		if !strings.HasPrefix(line, "Image=") {
			continue
		}
		if s.byID {
			id, ok := strings.CutPrefix(line, "Image=")
			if !ok || !imageIDRE.MatchString(id) || digest != "" {
				return "", false, errors.New("ops: the unit has no single Image= line of this service")
			}
			digest = "sha256:" + id
			continue
		}
		m := imageLineRE.FindStringSubmatch(line)
		if m == nil || m[1] != s.repo || digest != "" {
			return "", false, errors.New("ops: the unit has no single Image= line of this service")
		}
		digest = m[2]
	}
	if digest == "" {
		return "", false, errors.New("ops: the unit has no Image= line")
	}
	return digest, strings.HasSuffix(string(text), installSection), nil
}

// unitOf is the systemd unit Quadlet generates from vedette-<service>.container.
func unitOf(service string) string { return "vedette-" + service + ".service" }

// containerName is the ContainerName of the unit.
func containerName(service string) string { return "vedette-" + service }

func unitFileName(service string) string { return "vedette-" + service + ".container" }

// ourUnit is parseUnit plus identity: the bytes must be exactly what this host would write for that
// digest and [Install] state with the host.conf ids it has now (D-123 L2). A unit that differs in any
// byte (an older template, other ids, a hand edit) is not ours and is never read, restarted or
// rewritten by a container command; the bootstrap of slice 3-8 or the installer rewrites it.
func (o *Ops) ourUnit(service string, text []byte) (digest string, install bool, err error) {
	digest, install, err = parseUnit(service, text)
	if err != nil {
		return "", false, err
	}
	want, rerr := renderUnit(service, o.fillFor(digest, install))
	if rerr != nil || !bytes.Equal(want, text) {
		return "", false, errUnitNotOurs
	}
	return digest, install, nil
}

var errUnitNotOurs = errors.New("ops: the unit differs from what this host would write")

// startTimeoutOf is the time systemd gives the unit to start: TimeoutStartSec of the template (core:
// 300 s) or systemd's own default of 90 s when the template sets none. A test reads it from the templates.
func startTimeoutOf(service string) time.Duration {
	if service == api.ServiceCore {
		return 300 * time.Second
	}
	return 90 * time.Second
}

// restartLimitFor is how long the host waits for one "systemctl restart": the unit's own start
// timeout, so the host never gives up before systemd does, plus a margin.
func restartLimitFor(service string) time.Duration { return startTimeoutOf(service) + 30*time.Second }
