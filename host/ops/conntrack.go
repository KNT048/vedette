package ops

import (
	"context"
	"errors"
	"io/fs"
	"regexp"
	"strconv"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Stale syslog flows after core restarts (D-268). core publishes the syslog port 514 -> 5514 (udp and tcp) through
// netavark's DNAT. A device that sends UDP from one fixed source port and never pauses keeps hitting the conntrack entry
// made before core restarted; a stale entry (one that DNATs to the old container, or one created without DNAT while
// core's rules were gone) keeps the flow, so nothing reaches the new core, and it never times out while the device
// keeps sending (measured, review M1 of D-167; which of the two it is, the rootful lab run will say). TCP opens new
// connections and is not affected. Like kube-proxy for UDP services, the host deletes the UDP entries whose original
// destination port is the published one, once, right after it sees core run again; that clears both kinds.
//
// The host sees core run again in two ways: the health wait of a start it ran itself (coreLooked from waitHealthy),
// and a look at core's container every coreWatchEvery (watchCore), which also covers a systemd restart after a crash
// and a start by backup.restore. A "run" is the container's ID plus StartedAt. The FIRST look after the host starts
// always deletes once: at boot core starts after vedette-host, and a core that restarted while the host was down is
// unseen; a correct entry that is deleted is re-created by the next datagram, so the cost is one log line.
//
// ponytail: IPv4 only (-f ipv4: netavark publishes through IPv4 DNAT here), one fixed port; the port is the constant
// of core's unit (quadlet.go PublishPort=514:5514), not read from it.

const (
	binConntrack = "conntrack"
	// syslogPublishedPort is the host port core's unit publishes for syslog (PublishPort=514:5514/udp and /tcp).
	syslogPublishedPort = "514"
	// coreWatchEvery is how often the host looks at core's container for a new run (Deps.CoreWatch overrides it).
	coreWatchEvery = 30 * time.Second
)

// argsConntrackSyslog is the one conntrack command line: delete the UDP flows of IPv4 whose original destination port
// is the published syslog port. "conntrack" prints "N flow entries have been deleted" on stderr and exits 1 when N is 0.
// The literal "udp" is a reviewed exception of the network-literal guard in modules/host (FORBID-2): it is an argv word.
var argsConntrackSyslog = []string{"-D", "-f", "ipv4", "-p", "udp", "--orig-port-dst", syslogPublishedPort}

var (
	// validateConntrack accepts exactly argsConntrackSyslog and nothing else: no other filter, no -F (flush all), no -U.
	validateConntrack = exactly(argsConntrackSyslog...)

	ctrIDRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	startedAtRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,20}(Z|[+-][0-9]{2}:[0-9]{2})$`)
	ctDeletedRE = regexp.MustCompile(`([0-9]{1,9}) flow entries have been deleted`)
)

// runIdentity is the identity of one run of a container from the two fields Podman prints; a field of another shape is
// ignored, and "" means the host cannot tell runs apart.
func runIdentity(id, startedAt string) string {
	if !ctrIDRE.MatchString(id) {
		id = ""
	}
	if !startedAtRE.MatchString(startedAt) {
		startedAt = ""
	}
	if id == "" && startedAt == "" {
		return ""
	}
	return id + "@" + startedAt
}

// ObserveCore looks at core's container once and clears the stale syslog flows when it runs again. The watch loop
// calls it; it is also the seam of tests.
func (o *Ops) ObserveCore(ctx context.Context) { o.observeCore(ctx) }

func (o *Ops) observeCore(ctx context.Context) {
	info, err := o.inspect(ctx, api.ServiceCore)
	if err != nil {
		return // no container, or output the host cannot read: nothing to compare
	}
	o.coreLooked(ctx, info)
}

// coreLooked takes what a look at core's container showed: a run not seen before (the first look included) clears.
func (o *Ops) coreLooked(ctx context.Context, info inspectInfo) {
	if !info.Running || info.Started == "" {
		return
	}
	o.ctMu.Lock()
	defer o.ctMu.Unlock()
	prev := o.ctSeen
	o.ctSeen = info.Started
	if prev == info.Started {
		return
	}
	o.clearSyslogFlows(ctx)
}

// clearSyslogFlows runs the conntrack delete once and logs once. A missing binary is logged once per host run and
// nothing else happens; exit 1 is "0 entries" only when conntrack says so on stderr (it also exits 1 on real errors).
// Called under ctMu.
func (o *Ops) clearSyslogFlows(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	defer cancel()
	res, code, err := o.exec(cctx, binConntrack, argsConntrackSyslog...)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !o.ctMissingLogged {
			o.ctMissingLogged = true
			o.log.ErrorContext(ctx, "ops: conntrack is not installed; stale UDP syslog flows are not cleared after core restarts (install the conntrack package)", "path", prodPaths[binConntrack])
		}
	case err != nil:
		o.log.ErrorContext(ctx, "conntrack could not clear the stale syslog flows", "error", err.Error())
	case code > 1, code == 1 && !ctDeletedRE.Match(res.Stderr):
		o.log.ErrorContext(ctx, "conntrack failed while clearing the stale syslog flows", "exit_code", code)
	default:
		n := 0
		if m := ctDeletedRE.FindSubmatch(res.Stderr); m != nil {
			n, _ = strconv.Atoi(string(m[1]))
		}
		o.log.InfoContext(ctx, "core runs again: deleted the UDP conntrack entries of the syslog port", "port", syslogPublishedPort, "deleted", n)
	}
}

// watchCore looks at core's container every Deps.CoreWatch until ctx ends.
func (o *Ops) watchCore(ctx context.Context) {
	t := time.NewTicker(o.d.CoreWatch)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.observeCore(ctx)
		}
	}
}
