package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The operating system's time zone (spec 6.15): read from the /etc/localtime link, set with "timedatectl set-timezone <zone>".
// timedated writes the link (and /etc/timezone where the distribution keeps one), tells the kernel and its D-Bus listeners; systemd
// re-reads the link for its calendar timers (apt-daily, apt-daily-upgrade) and journald stores UTC, so nothing is restarted.

const (
	localtimeFile = "etc/localtime"
	zoneinfoDir   = "usr/share/zoneinfo"
	// maxZoneFile bounds a zone file: the largest TZif file of the database is a few KiB.
	maxZoneFile = 1 << 20
)

// readZone is the zone the operating system uses: the name /etc/localtime links to, "" when it is no link into a zone database.
func (o *Ops) readZone() string {
	target, err := os.Readlink(o.path(localtimeFile))
	if err != nil {
		return ""
	}
	return api.ZoneOfLink(target)
}

// readTime is GET /v1/state/time.
func (o *Ops) readTime(context.Context) (any, error) {
	return api.TimeState{Timezone: o.readZone()}, nil
}

// errNoZoneFile is a name the zone database of the machine has no zone for.
var errNoZoneFile = errors.New("no zone file")

// checkZoneFile proves that the machine's zone database has a zone of that name: a regular TZif file, opened through an os.Root of
// the database directory (a link inside it, such as UTC -> Etc/UTC, is followed; one that leads outside it is refused), without
// blocking on a FIFO. timedatectl checks the name again itself.
func (o *Ops) checkZoneFile(name string) error {
	root, err := os.OpenRoot(o.path(zoneinfoDir))
	if err != nil {
		return fmt.Errorf("%w: the zone database cannot be opened: %w", errNoZoneFile, err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoZoneFile, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxZoneFile {
		return fmt.Errorf("%w: not a regular file of at most 1 MiB", errNoZoneFile)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head, []byte("TZif")) {
		return fmt.Errorf("%w: not a TZif file", errNoZoneFile)
	}
	return nil
}

// cmdTimezoneSet is os.timezone.set (spec 6.15).
func (o *Ops) cmdTimezoneSet() server.Command {
	return server.Define(server.Spec[api.OSTimezoneArgs]{
		Name: api.CmdOSTimezoneSet, Write: true, Timeout: time.Minute,
		Validate: func(a *api.OSTimezoneArgs) error {
			if !api.ValidZoneName(a.Zone) {
				return server.Invalid("zone", "must be an IANA time zone name such as Europe/Berlin or UTC")
			}
			return nil
		},
		Check: func(ctx context.Context, a api.OSTimezoneArgs) error {
			if err := o.checkZoneFile(a.Zone); err != nil {
				o.log.InfoContext(ctx, "os.timezone.set: zone refused", "zone", a.Zone, "error", err.Error())
				return refuse412(api.CodeZoneUnknown, "The operating system does not know the time zone "+a.Zone+".")
			}
			return nil
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.OSTimezoneArgs) (any, error) {
			if cur := o.readZone(); cur == a.Zone {
				rc.Log("The operating system already uses " + a.Zone + ".")
				return api.OSTimezoneResult{Zone: a.Zone}, nil
			}
			rc.Log("Setting the operating system time zone to " + a.Zone)
			res, code, err := o.exec(ctx, binTimedatectl, "set-timezone", a.Zone)
			if err != nil {
				return nil, err
			}
			if code != 0 {
				logOutput(rc, res.Stderr)
				return nil, fail(api.CodeTimezoneNotSet, "timedatectl could not set the time zone: "+clipText(strings.TrimSpace(string(res.Stderr)), 200))
			}
			if got := o.readZone(); got != a.Zone {
				return nil, fail(api.CodeEffectNotVerified, fmt.Sprintf("/etc/localtime names %q after timedatectl, not %q.", clipText(got, 64), a.Zone))
			}
			return api.OSTimezoneResult{Zone: a.Zone, Changed: true}, nil
		},
	})
}
