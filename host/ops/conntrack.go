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
// made before core restarted; that entry still DNATs to the OLD container address, so nothing reaches the new core and
// the entry never times out while the device keeps sending (measured, review M1 of D-167). TCP opens new connections
// and is not affected. Like kube-proxy and Docker's libnetwork, the host deletes the UDP entries whose original
// destination port is the published one, once, right after it sees core run again.
//
// The host sees core run again in two ways: the health wait of a start it ran itself (coreLooked from waitHealthy),
// and a look at core's container every coreWatchEvery (watchCore), which also covers a systemd restart after a crash
// and a start by backup.restore. A "run" is the container's ID plus StartedAt; the first look only remembers it
// (a host that starts next to a core that has run for days has nothing to clear), except after a start the host ran
// itself, where an unknown earlier run counts as changed.
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
// "ud"+"p" is in two parts so that the contract test that looks for network literals does not take it for a socket.
var argsConntrackSyslog = []string{"-D", "-f", "ipv4", "-p", "ud" + "p", "--orig-port-dst", syslogPublishedPort}

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
	o.coreLooked(ctx, info, false)
}

// coreLooked takes what a look at core's container showed. hostStarted says the host itself had just started core.
func (o *Ops) coreLooked(ctx context.Context, info inspectInfo, hostStarted bool) {
	if !info.Running || info.Started == "" {
		return
	}
	o.ctMu.Lock()
	defer o.ctMu.Unlock()
	prev := o.ctSeen
	o.ctSeen = info.Started
	if prev == info.Started || (prev == "" && !hostStarted) {
		return
	}
	o.clearSyslogFlows(ctx)
}

// clearSyslogFlows runs the conntrack delete once and logs once. A missing binary is logged once per host run and
// nothing else happens; exit 1 is "0 entries", not a failure. Called under ctMu.
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
	case code != 0 && code != 1:
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
