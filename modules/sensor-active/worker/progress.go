package worker

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// Progress of a running job (#830, sensor-protocol.md 6.6). The worker reads what nmap and nuclei print anyway: nmap's
// <taskprogress> lines, which --stats-every adds to its XML (nmapargv), and nuclei's -ms lines, one per template and target that
// ran. Nothing else is asked of either tool. The output is the device's and the tool's, so it is read as untrusted: a line over
// its cap is skipped whole, a line that does not have the exact shape is ignored, and every number is checked before it is sent
// (core checks it again). Only the latest state is kept; it is posted at most once every sensorlink.ProgressEvery per job, never
// retried, and never after the job's result.

const (
	maxNmapProgressLine = 512      // a <taskprogress> element is about 120 bytes
	maxNucleiLine       = 64 << 10 // a -ms line without a match is under 2 KiB; a longer one (a match with its evidence) is not counted
)

// lines splits what a process prints into lines and hands each complete one, without its newline, to onLine. A line longer than
// max is dropped whole. It never fails and keeps at most max bytes.
type lines struct {
	buf    []byte
	max    int
	over   bool
	onLine func([]byte)
}

func (l *lines) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		if !l.over {
			if len(l.buf)+len(chunk) > l.max {
				l.over, l.buf = true, l.buf[:0]
			} else {
				l.buf = append(l.buf, chunk...)
			}
		}
		if i < 0 {
			break
		}
		if !l.over {
			l.onLine(l.buf)
		}
		l.buf, l.over = l.buf[:0], false
		p = p[i+1:]
	}
	return n, nil
}

// nmapPhase maps the task names of nmap 7.9x (scantype2str, the "Service scan" and "NSE" meters) to the phases of the protocol.
// A task that is not here (traceroute, OS detection, idle scan) reports nothing.
var nmapPhase = map[string]string{
	"Ping Scan": "discovery", "ARP Ping Scan": "discovery", "Host Discovery": "discovery",
	"SYN Stealth Scan": "ports", "Connect Scan": "ports", "UDP Scan": "ports", "ACK Scan": "ports", "Window Scan": "ports",
	"FIN Scan": "ports", "NULL Scan": "ports", "XMAS Scan": "ports", "Maimon Scan": "ports", "IPProto Scan": "ports",
	"SCTP INIT Scan": "ports", "SCTP COOKIE-ECHO Scan": "ports",
	"Service scan": "services",
	"NSE":          "scripts", "Script Pre-Scan": "scripts", "Script Post-Scan": "scripts",
}

var (
	// taskRE is a whole <taskprogress> or <taskbegin> element as nmap writes it: name="value" attributes of plain characters.
	taskRE = regexp.MustCompile(`^<(taskprogress|taskbegin)((?: [a-z]{1,16}="[A-Za-z0-9 .:+-]{0,64}"){1,8}) ?/>$`)
	attrRE = regexp.MustCompile(` ([a-z]{1,16})="([^"]*)"`)
	pctRE  = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,2})?$`)
	secRE  = regexp.MustCompile(`^[0-9]{1,7}$`)
)

// nmapProgress reads one line of nmap's XML: a <taskprogress> gives the phase, its percent and nmap's estimate of the seconds left;
// a <taskbegin> (only printed with -v, which Vedette does not pass) a phase at 0 %. ok is false for every other line.
func nmapProgress(line []byte) (p sensorlink.JobProgress, ok bool) {
	m := taskRE.FindSubmatch(bytes.TrimSpace(line))
	if m == nil {
		return p, false
	}
	attrs := map[string]string{}
	for _, a := range attrRE.FindAllSubmatch(m[2], -1) {
		if _, dup := attrs[string(a[1])]; dup {
			return p, false
		}
		attrs[string(a[1])] = string(a[2])
	}
	phase, known := nmapPhase[attrs["task"]]
	if !known {
		return p, false
	}
	p = sensorlink.JobProgress{Phase: phase}
	if string(m[1]) == "taskbegin" {
		return p, true
	}
	if !pctRE.MatchString(attrs["percent"]) {
		return p, false
	}
	pct, err := strconv.ParseFloat(attrs["percent"], 64)
	if err != nil || pct > 100 {
		return p, false
	}
	p.Percent = pct
	if r, has := attrs["remaining"]; has {
		if !secRE.MatchString(r) {
			return p, false
		}
		n, _ := strconv.Atoi(r)
		if n <= sensorlink.MaxProgressRemaining { // nmap's "over 10 days" is no estimate
			p.RemainingS = n
		}
	}
	return p, true
}

// nucleiCounter counts the template and target pairs a nuclei run has finished from its -ms lines: each line that reads as a result
// of the job (nucleiout, the same reader core uses) is one pair, counted once. A target nuclei gives up (its error log reached the
// job's max_host_errors timeouts: nuclei's -mhe stops sending to it) keeps only the pairs it finished in the total, so the bar does
// not stall on checks that will never run (review r1 #6). The pairs are one map; the stdout and stderr readers share the counter
// under mu.
type nucleiCounter struct {
	mu                 sync.Mutex
	templates, targets []string
	maxErrors          int
	seen               map[string]bool
	perTarget, errors  []int
	dead               []bool
}

func newNucleiCounter(nj *sensorlink.NucleiJob) *nucleiCounter {
	c := &nucleiCounter{templates: nj.Templates, maxErrors: nj.MaxHostErrors, seen: map[string]bool{}}
	for _, t := range nj.Targets {
		c.targets = append(c.targets, t.Host+":"+strconv.Itoa(t.Port))
	}
	c.perTarget, c.errors, c.dead = make([]int, len(c.targets)), make([]int, len(c.targets)), make([]bool, len(c.targets))
	return c
}

// line counts one -ms line; it says whether the count changed.
func (c *nucleiCounter) line(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	res, _, err := nucleiout.Read(raw, c.templates, c.targets)
	if err != nil || len(res) != 1 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := res[0].Template + "\x00" + res[0].Target
	if c.seen[k] {
		return false
	}
	c.seen[k] = true
	if i := slices.Index(c.targets, res[0].Target); i >= 0 {
		c.perTarget[i]++
	}
	return true
}

// errorLine reads one line of nuclei's error log; it says whether a target was given up just now.
func (c *nucleiCounter) errorLine(raw []byte) bool {
	i := nucleiout.TimeoutTarget(raw, c.targets)
	if i < 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors[i]++
	if c.dead[i] || c.maxErrors < 1 || c.errors[i] < c.maxErrors {
		return false
	}
	c.dead[i] = true
	return true
}

// publish hands the current count to rep. It holds mu while it does, so the two readers never hand over their counts out of order.
func (c *nucleiCounter) publish(rep *reporter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rep.set(c.progressLocked())
}

// progressLocked is the current count. The caller holds mu.
func (c *nucleiCounter) progressLocked() sensorlink.JobProgress {
	var total int64
	for i := range c.targets {
		if c.dead[i] {
			total += int64(c.perTarget[i])
		} else {
			total += int64(len(c.templates))
		}
	}
	return sensorlink.JobProgress{Phase: "vulns", Percent: -1, Done: int64(len(c.seen)), Total: total}
}

// reporter keeps the latest progress of one job between two posts.
type reporter struct {
	mu     sync.Mutex
	latest sensorlink.JobProgress
	dirty  bool
}

func (r *reporter) set(p sensorlink.JobProgress) {
	r.mu.Lock()
	r.latest, r.dirty = p, true
	r.mu.Unlock()
}

func (r *reporter) take() (sensorlink.JobProgress, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.latest, r.dirty
	r.dirty = false
	return p, ok
}

// runReporting runs an allowlisted binary like runner.Run while watch reads its output into rep, and posts rep's latest state every
// progressEvery until the process ends. It returns after the last post, so no report of the job follows its result.
func (w *Worker) runReporting(ctx context.Context, id, name string, argv []string, watch exec.Watch, rep *reporter) (exec.Result, error) {
	pctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if p, ok := rep.take(); ok { // the phase the tool starts with (nmapWatch), at once: the next comes progressEvery later
			w.postProgress(pctx, id, &p)
		}
		tk := time.NewTicker(w.progressEvery)
		defer tk.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-tk.C:
				if p, ok := rep.take(); ok {
					w.postProgress(pctx, id, &p)
				}
			}
		}
	}()
	out, err := w.runner.RunWatch(ctx, name, argv, nil, watch)
	stop()
	<-done
	return out, err
}

// postProgress makes one attempt. A refusal is only logged: a core of before #830 answers 404 unknown_job (or 403 forbidden_route:
// it has no such route, review r1 #4), and a lost report is replaced by the next.
func (w *Worker) postProgress(ctx context.Context, id string, p *sensorlink.JobProgress) {
	err := w.link.PostProgress(ctx, id, p)
	var e *sensorlink.Error
	switch {
	case err == nil, ctx.Err() != nil:
	case errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Status == http.StatusForbidden || e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable):
		w.log.DebugContext(ctx, "sensor_active_progress_not_taken", "id", id, "error", err)
	default:
		w.log.WarnContext(ctx, "sensor_active_progress_not_taken", "id", id, "error", err)
	}
}

// phaseRank orders the phases of one nmap run: nmap scans a host group in this order.
var phaseRank = map[string]int{"discovery": 0, "ports": 1, "services": 2, "scripts": 3}

// firstPhase is the phase an nmap command line starts with: host discovery, unless -Pn skips it (the external shapes).
func firstPhase(argv []string) string {
	if slices.Contains(argv, "-Pn") {
		return "ports"
	}
	return "discovery"
}

// hosthintRE is the start of nmap's <hosthint> element: written (and flushed) during host discovery of a port scan as soon as a
// target is found up (scan_engine.cc ultrascan_host_pspec_update, nmap >= 7.80), so the port scan of that host starts next.
var hosthintRE = regexp.MustCompile(`^<hosthint>`)

// nmapWatch is the Watch of an nmap run: its stdout (the XML) into rep. The phase of the command line is set before nmap starts,
// and the phase moves on by itself when nmap's XML shows the next stage begins (a <hosthint>: discovery found the host, the port
// scan comes next), so the page moves through the phases even when nmap prints no <taskprogress> (no terminal: core/exec could
// not open one). Those guesses only ever move forward; a <taskprogress> is nmap's own word and is taken as it is.
func nmapWatch(argv []string, rep *reporter) exec.Watch {
	cur := firstPhase(argv)
	rep.set(sensorlink.JobProgress{Phase: cur, Percent: -1})
	sweep := slices.Contains(argv, "-sn") // no port scan follows the discovery of a sweep
	// onLine runs on one goroutine, the copier of stdout: cur needs no lock
	return exec.Watch{Stdout: &lines{max: maxNmapProgressLine, onLine: func(l []byte) {
		if p, ok := nmapProgress(l); ok {
			cur = p.Phase
			rep.set(p)
			return
		}
		if !sweep && hosthintRE.Match(bytes.TrimSpace(l)) && phaseRank["ports"] > phaseRank[cur] {
			cur = "ports"
			rep.set(sensorlink.JobProgress{Phase: cur, Percent: -1})
		}
	}}}
}

// nucleiWatch is the Watch of a nuclei run: its stdout (the -ms lines) and its stderr (the error log, for the targets nuclei gives
// up) through a nucleiCounter into rep. The count starts at 0 of the total, so the page shows the checks to come from the first
// report on.
func nucleiWatch(nj *sensorlink.NucleiJob, rep *reporter) exec.Watch {
	c := newNucleiCounter(nj)
	c.publish(rep)
	return exec.Watch{
		Stdout: &lines{max: maxNucleiLine, onLine: func(l []byte) {
			if c.line(l) {
				c.publish(rep)
			}
		}},
		Stderr: &lines{max: nucleiout.MaxErrorLogLine, onLine: func(l []byte) {
			if c.errorLine(l) {
				c.publish(rep)
			}
		}},
	}
}
