package ops

import (
	"bytes"
	"context"
	"text/template"

	"github.com/knt048/vedette/host/api"
)

// Unit migration between host releases (D-316 (10)). vedette-host updates itself (host.self_update), so a new host can find on disk
// a unit that an earlier host wrote from an earlier template. Such a unit is still the host's own: ourUnit accepts it when its bytes
// are exactly what one of the earlier templates below makes for the same digest, the same [Install] state and the host.conf ids of
// now, the way dpkg replaces a conffile silently only while it still has the bytes of the version that shipped it. A unit edited by
// a person matches no template and stays "not ours" (unit_unsafe, unit_foreign).
//
// A unit on an earlier template is rewritten to the current one once per host start (migrateUnits, inside the one daemon-reload of
// Start's recoverTransitions, never in the retries after READY) or by the next command that writes the unit; the running container is never restarted for it: the new text
// takes effect at the next restart of the service (the image step of the same software run, D-340 (8), or a reboot).
//
// When a template changes, its text before the change is appended to its service's list here (TestUnitTemplatesArePinned fails
// until that is done), and the golden file the old test kept goes to testdata/units/legacy. A change that two units must make
// together (as D-318 did for core and honeypot) is never listed: migrating one without the other would be wrong, so such a change
// needs its own migration step. The lists start after D-318; a box with older units needs -bootstrap -force-units (RUNBOOK).
var legacyTemplates = map[string][]*template.Template{
	api.ServiceCore: {
		mustTemplate("core-1", coreUnitTextD318),     // D-318 (2026-11-12): the honeypot log volume, 514 only
		mustTemplate("core-2", coreUnitTextD214),     // D-214 (2026-11-12): 6514:5515/tcp published, no HostName yet
		mustTemplate("core-3", coreUnitTextHostName), // #489 (2026-11-12): HostName=vedette, no 127.0.0.1:8765 publish yet (D-395)
		mustTemplate("core-4", coreUnitTextBeforeD458), // D-395 (2026-11-13): Podman's default AppArmor profile (D-458)
	},
	api.ServiceSensor: {
		mustTemplate("sensor-1", sensorUnitTextBeforeD458), // before D-458 (2026-11-12): Podman's default AppArmor profile
	},
	api.ServiceHoneypot: {
		mustTemplate("honeypot-1", honeypotUnitTextD318),       // D-318 (2026-11-12): before ContainersConfModule (#486)
		mustTemplate("honeypot-2", honeypotUnitTextBeforeD458), // #486 (2026-11-12): Podman's default AppArmor profile (D-458)
	},
	api.ServiceScan: {
		mustTemplate("scan-1", scanUnitTextBeforeD458), // before D-458 (2026-11-12): Podman's default AppArmor profile
	},
}

// migrateUnits rewrites, once per start (recoverTransitions with atStart), every unit that is on an earlier template (ourUnitAge says stale) to the current template for the
// same digest and [Install] state, with the .volume units it mounts (writeUnitForStart; .prev keeps the old bytes), and says whether
// it wrote one: recoverTransitions then makes its one daemon-reload, before READY. It restarts nothing: systemd keeps a running
// service as it is until its next restart, which is where the new text takes effect. It skips:
//   - everything while a self-update journal is there: the new host is not committed and the previous one may be put back, which must
//     find the units it wrote (D-316 (6b)); the image steps of the run, after the commit, rewrite the units they start, and the next
//     host start the rest;
//   - a service whose unit change is still being recovered (a transition journal): that is the recovery's to settle;
//   - a unit whose current template publishes a host port the earlier one did not (D-455), busy or not: the earlier unit stays, one
//     unit_migration_deferred line per start names the ports, and the container.start that next restarts the service checks the
//     ports and writes the current template.
//
// A failure is logged and audited (unit_migration_failed) and changes nothing else: the unit stays ours on its earlier template, and
// the next start, or the next command that writes it, tries again.
func (o *Ops) migrateUnits(ctx context.Context) (wrote bool) {
	if _, st := o.loadSUJournal(); st != jAbsent {
		return false
	}
	for _, svc := range unitServices {
		if _, st, _ := o.loadJournal(svc); st != jAbsent {
			continue
		}
		text, fs := o.readUnit(svc)
		if fs != fileOK {
			continue
		}
		digest, install, stale, err := o.ourUnitAge(svc, text)
		if err != nil || !stale {
			continue
		}
		detail := map[string]any{"service": svc, "digest": digest}
		want, err := renderUnit(svc, o.fillFor(digest, install))
		if added := addedPorts(text, want); len(added) > 0 { // want is nil after an error: it adds no port
			// The migration never adds a host port (D-455): it runs at boot, before the programs that may hold the port have bound
			// it, and its text takes effect at the next restart with no health revert behind it. The container.start that restarts
			// the service checks the port and writes the current template.
			o.noteUnitDeferred(ctx, svc, digest, "", added)
			continue
		}
		if err == nil {
			err = o.writeUnitForStart(ctx, svc, want)
		}
		if err != nil {
			o.log.ErrorContext(ctx, "could not rewrite a unit of an earlier host release to the current template", "service", svc, "error", err.Error())
			o.note(api.CmdContainerStart, "unit_migration_failed", detail)
			continue
		}
		wrote = true
		o.note(api.CmdContainerStart, "unit_migrated", detail)
	}
	return wrote
}

// ownTemplate renders text's own template (the current one, or the earlier one an earlier host wrote it from) again for the same
// digest with install, so a change of [Install] alone never moves a unit to another template (D-455: the current one may add host
// ports). text must be ours with the [Install] state had.
func (o *Ops) ownTemplate(service string, text []byte, digest string, had, install bool) ([]byte, error) {
	s, ok := services[service]
	if !ok {
		return nil, errNoTemplate
	}
	f := o.fillFor(digest, had)
	for _, t := range append([]*template.Template{s.tmpl}, legacyTemplates[service]...) {
		if b, err := s.render(t, f); err == nil && bytes.Equal(b, text) {
			return s.render(t, o.fillFor(digest, install))
		}
	}
	return nil, errUnitNotOurs
}

// RenderLegacyUnits builds the unit of a service from each of its earlier templates, oldest first (none for a service whose template
// never changed since the lists start). Exported for the contract tests.
func RenderLegacyUnits(service, digest string, install bool, coreUID, coreGID, sensorUID, sensorGID int, coreData string) ([][]byte, error) {
	f := unitFill{Digest: digest, Install: install, CoreUID: coreUID, CoreGID: coreGID, SensorUID: sensorUID, SensorGID: sensorGID, DataDir: coreData}
	var out [][]byte
	for _, t := range legacyTemplates[service] {
		b, err := services[service].render(t, f)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// legacyUnit says whether text is exactly what an earlier template of service makes for f.
func legacyUnit(service string, f unitFill, text []byte) bool {
	s, ok := services[service]
	if !ok {
		return false
	}
	for _, t := range legacyTemplates[service] {
		if b, err := s.render(t, f); err == nil && bytes.Equal(b, text) {
			return true
		}
	}
	return false
}

const coreUnitTextD318 = `[Unit]
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
PublishPort=514:5514/udp
PublishPort=514:5514/tcp
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

const coreUnitTextD214 = `[Unit]
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

const honeypotUnitTextD318 = `[Unit]
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

// The four templates before D-458 (each unit loads the containers.conf module that selects the AppArmor profile vedette-container).

const coreUnitTextBeforeD458 = `[Unit]
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
PublishPort=127.0.0.1:8765:8765
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

const sensorUnitTextBeforeD458 = `[Unit]
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

const honeypotUnitTextBeforeD458 = `[Unit]
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

const scanUnitTextBeforeD458 = `[Unit]
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

const coreUnitTextHostName = `[Unit]
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
