package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.active (host-api §6.15a, exposure INV-24): ZAP's active scan of one page, after the passive baseline of the same page. Every
// fence of zap.baseline holds unchanged (the arguments, one run at a time, the host's own re-check of ownership, the network fence
// that lets the container reach only IP:Port, the read-only container, the cleanup on every path). What differs is what ZAP is told
// to do: instead of zap-baseline.py, the Automation Framework runs a plan the host writes itself from the validated page (never
// text from core), with
//
//   - one context whose only include path is the page's own origin, anchored: ^scheme://host(:port)?(/ or ? …)?$, so the spider and
//     the active scan never leave it, whatever a page links or redirects to (the network fence stops it anyway);
//   - a spider bounded in time, depth and children per node, that submits forms only with GET unless the disruptive rules run;
//   - the passive rules off (the baseline already ran them on this page: no alert counted twice);
//   - the active scan bounded per rule and per page, at two threads with a delay between requests, with the rule split below;
//   - the report as the traditional JSON report, read by exposure's ParseZAPReport like the baseline's.

// The bounds of one active page. The page's own limit holds everything up to the end of podman run: about a minute of JVM start, the
// spider's minutes, the active scan's own cap, the report; exposure waits a little longer (ActiveScanTimeout) so it never gives up
// on a run the host still runs.
const (
	zapSpiderMinutes    = 2  // the spider's own cap (maxDuration)
	zapSpiderDepth      = 5  // links followed from the page (maxDepth)
	zapSpiderChildren   = 20 // children crawled per node (maxChildren)
	zapActiveMinutes    = 12 // the active scan's own cap for the page (maxScanDurationInMins): reached = cut short, the report keeps what it found
	zapRuleMinutes      = 2  // one rule's cap (maxRuleDurationInMins)
	zapThreadsPerHost   = 2  // concurrent requests (threadPerHost)
	zapDelayMs          = 100
	zapMaxAlertsPerRule = 10

	zapActivePageLimit = 20 * time.Minute
	zapActiveTimeout   = 22 * time.Minute // the command: the page's 20 minutes and the cleanup after it
	zapStopTimeout     = 3 * time.Minute  // zap.stop: the run's cleanup (podman rm, its proof, nft delete) after the cancel

	// zapActiveMemory is the container's memory and swap cap (the JVM heap is half of it, the home tmpfs counts against it): the
	// active scan keeps every request it sends in ZAP's session database, more than the baseline's.
	zapActiveMemory = "2g"
	zapActiveHeap   = "-Xmx1g"
	zapActiveTmpfs  = "/home/zap:rw,size=512m,mode=1777"
	zapActivePids   = "--pids-limit=512"
	zapPlanName     = "plan.yaml"
)

// The rule split of the active scan (ZAP plugin ids, https://www.zaproxy.org/docs/alerts/). The plan turns every rule off
// (defaultThreshold off) and then names each rule it runs: a rule a future image adds stays off until it is classified here
// (TestZapActiveRulesCoverTheImage holds the table equal to the image's own list, testdata/zap-2.17.0-active-rules.txt).
const (
	zapRuleOn         = iota // the active scan proper: runs on every page of the active pass
	zapRuleDisruptive        // only with Disruptive: the box's own proven IP, in a person's scan that allows the disruptive checks
	zapRuleOff               // never
)

type zapRule struct {
	id    int
	class int
	why   string
}

// zapActiveRules classifies every active rule of the pinned image. Disruptive = ZAP's denial-of-service style checks (oversized or
// malformed input meant to crash a parser or server, a memory read of the TLS library), checks that store data in the site or call
// other actions of a service, and checks that make the server reach its hosting provider's own infrastructure. ZAP's active rules
// guess no password and try no login: none is brute force, and the forced-browse add-on is not run. SQL Injection (40018) runs on
// every page at strength low (error and expression payloads: a quote or an arithmetic value, never "OR 1=1"); its boolean and UNION
// payloads (strength medium), which in an UPDATE or DELETE would touch every row, run only with Disruptive.
var zapActiveRules = []zapRule{
	{0, zapRuleOn, "Directory Browsing"},
	{6, zapRuleOn, "Path Traversal (reads files)"},
	{7, zapRuleOn, "Remote File Inclusion"},
	{10045, zapRuleOn, "Source Code Disclosure - /WEB-INF Folder"},
	{10047, zapRuleOn, "HTTPS Content Available via HTTP"},
	{10048, zapRuleOn, "Remote Code Execution - Shell Shock (a harmless marker)"},
	{10058, zapRuleOn, "GET for POST"},
	{10104, zapRuleOn, "User Agent Fuzzer"},
	{10106, zapRuleOn, "HTTP Only Site"},
	{20015, zapRuleDisruptive, "Heartbleed: reads the server's memory, may crash it"},
	{20017, zapRuleOn, "Source Code Disclosure - CVE-2012-1823"},
	{20018, zapRuleOn, "Remote Code Execution - CVE-2012-1823 (a harmless marker)"},
	{20019, zapRuleOn, "External Redirect"},
	{30001, zapRuleDisruptive, "Buffer Overflow: oversized input meant to crash the server"},
	{30002, zapRuleDisruptive, "Format String Error: input meant to crash a C server"},
	{40003, zapRuleOn, "CRLF Injection"},
	{40008, zapRuleOn, "Parameter Tampering"},
	{40009, zapRuleOn, "Server Side Include"},
	{40012, zapRuleOn, "Cross Site Scripting (Reflected)"},
	{40014, zapRuleDisruptive, "Cross Site Scripting (Persistent): stores script in the site, shown to its visitors"},
	{40016, zapRuleDisruptive, "Cross Site Scripting (Persistent) - Prime: stores data in the site"},
	{40017, zapRuleDisruptive, "Cross Site Scripting (Persistent) - Spider: stores data in the site"},
	{40018, zapRuleOn, "SQL Injection: strength low, medium with Disruptive"},
	{40019, zapRuleOn, "SQL Injection - MySQL (Time Based)"},
	{40020, zapRuleOn, "SQL Injection - Hypersonic SQL (Time Based)"},
	{40021, zapRuleOn, "SQL Injection - Oracle (Time Based)"},
	{40022, zapRuleOn, "SQL Injection - PostgreSQL (Time Based)"},
	{40026, zapRuleOff, "Cross Site Scripting (DOM Based): drives a browser in the container, beyond its memory cap"},
	{40027, zapRuleOn, "SQL Injection - MsSQL (Time Based)"},
	{40028, zapRuleOn, "ELMAH Information Leak"},
	{40029, zapRuleOn, "Trace.axd Information Leak"},
	{40032, zapRuleOn, ".htaccess Information Leak"},
	{40034, zapRuleOn, ".env Information Leak"},
	{40035, zapRuleOn, "Hidden File Finder"},
	{40042, zapRuleOn, "Spring Actuator Information Leak"},
	{40043, zapRuleOff, "Log4Shell: needs a third-party callback server (OAST)"},
	{40044, zapRuleDisruptive, "Exponential Entity Expansion (Billion Laughs): a denial of service of the XML parser"},
	{40045, zapRuleOn, "Spring4Shell"},
	{40048, zapRuleOn, "Remote Code Execution (React2Shell) (a harmless marker)"},
	{50000, zapRuleOff, "Script Active Scan Rules: no script is installed"},
	{90017, zapRuleOn, "XSLT Injection"},
	{90019, zapRuleOn, "Server Side Code Injection"},
	{90020, zapRuleOn, "Remote OS Command Injection (reads a file)"},
	{90021, zapRuleOn, "XPath Injection"},
	{90023, zapRuleOn, "XML External Entity Attack (reads a file)"},
	{90024, zapRuleOn, "Generic Padding Oracle"},
	{90026, zapRuleDisruptive, "SOAP Action Spoofing: calls other actions of a SOAP service"},
	{90029, zapRuleOn, "SOAP XML Injection"},
	{90034, zapRuleDisruptive, "Cloud Metadata Potentially Exposed: makes the server fetch its hosting provider's metadata service"},
	{90035, zapRuleOn, "Server Side Template Injection"},
	{90036, zapRuleOn, "Server Side Template Injection (Blind)"},
	{90037, zapRuleOn, "Remote OS Command Injection (Time Based)"},
	{100043, zapRuleOff, "Swagger UI Secret & Vulnerability Detector: an alpha rule"},
}

// zapSQLi is the SQL Injection rule whose strength follows Disruptive.
const zapSQLi = 40018

// zapActivePlan is the Automation Framework plan of one active page: built from the validated page and the fixed bounds above, never
// from text core sent.
func zapActivePlan(p zapPage, disruptive bool) string {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) } // a JSON string is a YAML double-quoted scalar
	var b strings.Builder
	w := func(s ...string) {
		for _, l := range s {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	w("env:",
		"  contexts:",
		"    - name: page",
		"      urls:",
		"        - "+q(p.url),
		"      includePaths:",
		"        - "+q(zapScopeRE(p.url)),
		"  parameters:",
		"    failOnError: false",
		"    failOnWarning: false",
		"    progressToStdout: true",
		"jobs:",
		"  - type: passiveScan-config",
		"    parameters:",
		"      disableAllRules: true",
		"      scanOnlyInScope: true",
		"  - type: spider",
		"    parameters:",
		"      context: page",
		"      url: "+q(p.url),
		"      maxDuration: "+strconv.Itoa(zapSpiderMinutes),
		"      maxDepth: "+strconv.Itoa(zapSpiderDepth),
		"      maxChildren: "+strconv.Itoa(zapSpiderChildren),
		"      threadCount: "+strconv.Itoa(zapThreadsPerHost),
		"      processForm: true",
		"      postForm: "+strconv.FormatBool(disruptive),
		"      acceptCookies: true",
		"  - type: activeScan",
		"    parameters:",
		"      context: page",
		"      maxRuleDurationInMins: "+strconv.Itoa(zapRuleMinutes),
		"      maxScanDurationInMins: "+strconv.Itoa(zapActiveMinutes),
		"      threadPerHost: "+strconv.Itoa(zapThreadsPerHost),
		"      delayInMs: "+strconv.Itoa(zapDelayMs),
		"      maxAlertsPerRule: "+strconv.Itoa(zapMaxAlertsPerRule),
		"      addQueryParam: false",
		"      injectPluginIdInHeader: false",
		"      scanHeadersAllRequests: false",
		"      handleAntiCSRFTokens: true",
		"    policyDefinition:",
		"      defaultStrength: medium",
		"      defaultThreshold: \"off\"",
		"      rules:")
	for _, r := range zapActiveRules {
		if r.class == zapRuleOff || r.class == zapRuleDisruptive && !disruptive {
			continue
		}
		strength := "medium"
		if r.id == zapSQLi && !disruptive {
			strength = "low"
		}
		w("        - id: "+strconv.Itoa(r.id), "          strength: "+strength, "          threshold: medium")
	}
	w("  - type: report",
		"    parameters:",
		"      template: traditional-json",
		"      reportDir: "+q(zapWorkDir),
		"      reportFile: "+q(zapReportName))
	return b.String()
}

// zapScopeRE is the one include path of the plan's context: the page's scheme, host and port, anchored at both ends, then nothing or
// a path or query. ZAP writes a URL without the scheme's own port, so the default port may be there or not; any other port must be.
func zapScopeRE(pageURL string) string {
	scheme, rest, _ := strings.Cut(pageURL, "://")
	hostport := strings.TrimSuffix(rest, "/")
	host, port, hasPort := strings.Cut(hostport, ":")
	origin := regexp.QuoteMeta(scheme + "://" + strings.ToLower(host))
	if hasPort {
		origin += ":" + port
	} else {
		origin += "(?::" + map[string]string{"http": "80", "https": "443"}[scheme] + ")?"
	}
	return "^" + origin + "(?:[/?].*)?$"
}

// zapActiveArgv is the one podman run of zap.active: the container of zap.baseline with the active pass's memory, heap, tmpfs and pid
// caps, and ZAP's own runner (zap.sh -cmd) on the plan the host wrote into the work folder.
func zapActiveArgv(addHost, wrk string) []string {
	a := []string{"--module", AppArmorConfModule, "run", "--rm", "--pull=never", "--name", zapContainer, "--label", zapLabel, "--network", zapNetwork, "--dns", "none"}
	if addHost != "" {
		a = append(a, "--add-host", addHost)
	}
	return append(a, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", zapActiveTmpfs,
		"--volume", wrk+":"+zapWorkDir+zapMountOpts, "--user", "1000:1000", "--memory="+zapActiveMemory, "--memory-swap="+zapActiveMemory, zapActivePids, "--no-healthcheck",
		"--workdir", zapCwd,
		zapImage, "zap.sh", "-cmd", "-silent", zapActiveHeap, "-autorun", zapWorkDir+"/"+zapPlanName)
}

func (p zapPage) activeArgv(wrk string) []string {
	addHost := ""
	if p.kind == api.ZapKindDomain {
		addHost = p.host + ":" + p.ip.String()
	}
	return zapActiveArgv(addHost, wrk)
}

// isZapActiveArgv: the add-host (a name pinned to a public IPv4) and the work folder (exactly <stateDir>/zap/wrk) pass their own
// check, and the argv is then exactly what zapActiveArgv builds of them. The page's URL is in the plan, which zapRun writes from the
// validated page.
func isZapActiveArgv(stateDir string, a []string) bool {
	if len(a) < 4 || a[0] != "--module" || a[2] != "run" || !slices.Contains(a, "-autorun") {
		return false
	}
	addHost := ""
	if i := slices.Index(a, "--add-host"); i > 0 && i+1 < len(a) {
		addHost = a[i+1]
		name, ip, ok := strings.Cut(addHost, ":")
		addr, err := netip.ParseAddr(ip)
		if !ok || len(name) > 253 || !zapHostRE.MatchString(name) || err != nil || !egressip.IsPublicIPv4(addr) || addr.String() != ip {
			return false
		}
	}
	i := slices.Index(a, "--volume")
	if i < 0 || i+1 >= len(a) {
		return false
	}
	wrk, ok := strings.CutSuffix(a[i+1], ":"+zapWorkDir+zapMountOpts)
	if !ok || !validBuildDir(wrk) || wrk != filepath.Join(stateDir, "zap", "wrk") {
		return false
	}
	return slices.Equal(a, zapActiveArgv(addHost, wrk))
}

// zapActiveArgs validates the args of zap.active: those of zap.baseline, and Disruptive only for the box's own IP (kind ip, not typed).
func zapActiveArgs(a api.ZapActiveArgs) (zapPage, error) {
	p, err := zapArgs(a.ZapBaselineArgs)
	if err != nil {
		return zapPage{}, err
	}
	if a.Disruptive && (a.Kind != api.ZapKindIP || a.Typed != nil) {
		return zapPage{}, server.Invalid("disruptive", "is for the box's own IP only (kind ip, not a typed IP)")
	}
	return p, nil
}

func (o *Ops) cmdZapActive() server.Command {
	// Not a write command, as zap.baseline: it shares its one-run-at-a-time and touches only its own things.
	return server.Define(server.Spec[api.ZapActiveArgs]{
		Name: api.CmdZapActive, Write: false, Timeout: zapActiveTimeout,
		Validate: func(a *api.ZapActiveArgs) error { _, err := zapActiveArgs(*a); return err },
		Run: func(ctx context.Context, rc *server.RunContext, a api.ZapActiveArgs) (any, error) {
			p, err := zapActiveArgs(a)
			if err != nil {
				return nil, err
			}
			return o.zapRun(ctx, rc.Log, p, zapPass{active: true, disruptive: a.Disruptive})
		},
	})
}

func (o *Ops) cmdZapStop() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdZapStop, Write: false, Timeout: zapStopTimeout,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return o.zapStopRun(ctx, rc.Log)
		},
	})
}

// errZapStopped is the cause of a run's context that zap.stop cancelled.
var errZapStopped = errors.New("zap: stopped")

// zapStopRun cancels the ZAP run that runs now and waits until its cleanup is over (the container proven gone, then the fence
// deleted); without one it answers that nothing ran.
func (o *Ops) zapStopRun(ctx context.Context, logf func(string)) (any, error) {
	o.zapMu.Lock()
	stop, done := o.zapStop, o.zapDone
	o.zapMu.Unlock()
	if stop == nil {
		logf("no web scan (ZAP) was running")
		return api.ZapStopResult{}, nil
	}
	stop()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, fail(api.CodeZapCleaningUp, "The web scan (ZAP) was told to stop, but its cleanup did not end in time; the next run cleans up first.")
	}
	logf("the web scan (ZAP) was stopped and its container removed")
	return api.ZapStopResult{Stopped: true}, nil
}

// zapJobEndRE is the Automation Framework's line at the end of the active scan job (progressToStdout), with the time it took.
var zapJobEndRE = regexp.MustCompile(`Job activeScan finished, time taken: (\d{1,3}):(\d{2}):(\d{2})`)

// zapCutShort reads ZAP's output: the active scan was cut short when the framework terminated the job, when it took its whole time
// cap (ZAP's own maxScanDurationInMins ends it there), or when it started and never said it finished.
func zapCutShort(out []byte) bool {
	if bytes.Contains(out, []byte("Job activeScan terminated")) {
		return true
	}
	m := zapJobEndRE.FindSubmatch(out)
	if m == nil {
		return bytes.Contains(out, []byte("Job activeScan started"))
	}
	h, _ := strconv.Atoi(string(m[1]))
	mi, _ := strconv.Atoi(string(m[2]))
	s, _ := strconv.Atoi(string(m[3]))
	return time.Duration(h)*time.Hour+time.Duration(mi)*time.Minute+time.Duration(s)*time.Second >= zapActiveMinutes*time.Minute-5*time.Second
}
