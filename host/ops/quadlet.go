package ops

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
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
	// hpHostDir is where the honeypot's two folders live on the box: config/ (core writes it, the
	// container reads it) and log/ (the container writes it, core reads it), D-89. Core mounts config
	// read-write and log read-only, each at its -honeypot-dir default, and the honeypot container mounts the
	// two folders at the same absolute paths, because opencanary.conf holds the log path (D-123 (1)).
	hpHostDir = "/var/lib/vedette-honeypot"
)

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
}

type serviceUnit struct {
	repo        string // the image repository, without the digest
	tmpl        *template.Template
	needsCore   bool // uses core_uid and core_gid
	needsSensor bool // uses sensor_uid and sensor_gid
}

const (
	repoCore     = "ghcr.io/knt048/vedette-core"
	repoSensor   = "ghcr.io/knt048/vedette-sensor"
	repoHoneypot = "ghcr.io/knt048/vedette-honeypot"
	// repoScan is the image built on the box from the signed base image (D-113 (7)); how a locally built
	// image is pinned is settled with the build in slice SP-6 (D-123 (4)).
	repoScan = "localhost/vedette-scan-nmap"
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
	api.ServiceScan:     {repo: repoScan, tmpl: mustTemplate("scan", scanUnitText), needsSensor: true},
}

const coreUnitText = `[Unit]
Description=Vedette core
After=network-online.target vedette-host.service
Wants=network-online.target

[Container]
ContainerName=vedette-core
Image=` + repoCore + `@{{.Digest}}
Pull=never
Network=vedette-int.network
PublishPort=8443:8443
PublishPort=127.0.0.1:8444:8444
Volume=vedette-data.volume:/var/lib/vedette
Volume=` + hpHostDir + `/config:/var/lib/vedette/honeypot/config
Volume=` + hpHostDir + `/log:/var/lib/vedette/honeypot/log:ro
Volume=/etc/vedette/master.key:/run/secrets/master.key:ro
Volume=/run/vedette:/run/vedette
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds/passive
Volume=vedette-creds-active.volume:/var/lib/vedette-creds/active
ReadOnly=true
Tmpfs=/tmp
NoNewPrivileges=true
DropCapability=ALL
User={{.CoreUID}}:{{.CoreGID}}
LogDriver=journald
PodmanArgs=--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 --group-add={{.SensorGID}}
HealthCmd=/vedette healthcheck
HealthInterval=30s
HealthStartPeriod=60s
HealthRetries=3
Exec=-listen :8443 -key /run/secrets/master.key

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
HealthCmd=/vedette-sensor healthcheck
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
Volume=` + hpHostDir + `/config:/var/lib/vedette/honeypot/config:ro
Volume=` + hpHostDir + `/log:/var/lib/vedette/honeypot/log
LogDriver=journald
PodmanArgs=--memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=128
HealthCmd=/vedette honeypot healthcheck
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
Image=` + repoScan + `@{{.Digest}}
Pull=never
Network=host
User={{.SensorUID}}:{{.SensorGID}}
DropCapability=ALL
AddCapability=NET_RAW
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-creds-active.volume:/var/lib/vedette-creds:ro
LogDriver=journald
PodmanArgs=--memory=1g --memory-swap=1g --cpus=2 --pids-limit=512 --cpu-shares=128
HealthCmd=/vedette-sensor healthcheck
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=active --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem

[Service]
Restart=always
`

// validID is a uid or gid a unit may carry: 1 up to what host.conf accepts (31 bits). Never 0.
func validID(n int) bool { return n >= 1 && n <= 1<<31-1 }

// RenderUnit builds the text of a service's unit. Exported for the contract tests.
func RenderUnit(service, digest string, install bool, coreUID, coreGID, sensorUID, sensorGID int) ([]byte, error) {
	return renderUnit(service, unitFill{Digest: digest, Install: install, CoreUID: coreUID, CoreGID: coreGID, SensorUID: sensorUID, SensorGID: sensorGID})
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
	if len(out) > maxUnitSize || bytes.ContainsAny(out, "\r\x00") || !utf8.Valid(out) || strings.Count(string(out), "@"+f.Digest) != 1 {
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
