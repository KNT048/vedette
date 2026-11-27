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
//   - one context with the page's own origin as its include path, anchored: ^scheme://host(:port)?(/ or ? …)?$. The Automation
//     Framework also includes the context's URL followed by ".*" by itself, unescaped (each dot of the host then matches any
//     character, so a look-alike name such as wwwxexample.com is in the context too). The context keeps the spider and the active
//     scan on the page's site in practice; the boundary is the network fence: only IP:Port, no DNS, the one name pinned to IP;
//   - a spider bounded in time, depth and children per node, that submits forms only with GET unless the disruptive rules run;
//   - the passive rules off (the baseline already ran them on this page: no alert counted twice);
//   - the active scan bounded per rule and per page, at two threads with a delay between requests, with the rule split below;
//   - the report as the traditional JSON report, read by exposure's ParseZAPReport like the baseline's.
//
// With Passive (api.ZapActiveArgs.Passive) the one run does the page's passive pass too, so ZAP starts once and spiders once: the
// passive rules stay on (as zap.baseline's, at most 10 alerts a rule), the plan waits for them after the spider, writes their report
// (passive.json), and only then runs the active scan and writes its report. The spider, the active scan, the rule split and every
// bound are those of the active plan above.

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
	// The gentle speed of a target's deep-scan settings: one thread (the spider's too) and 500 ms between requests, fixed here, never
	// a number of core's. The active scan's own cap stays: a gentle page reaches it sooner and says so (cut_short).
	zapGentleThreads = 1
	zapGentleDelayMs = 500
	// The passive plan of a page with paths to skip (zapPassivePlan): the baseline's spider minute and passive wait (-m 1 -T 5, less
	// the plan's own start), inside zapPageLimit.
	zapPassiveSpiderMinutes = 1
	zapPassiveWaitMinutes   = 4

	zapActivePageLimit = 20 * time.Minute
	// zapCombinedPageLimit is the page's limit with the passive pass in the same run: the active page's 20 minutes and the passive
	// rules' wait after the spider (zapPassiveWaitMinutes); exposure waits a minute more (CombinedScanTimeout).
	zapCombinedPageLimit = zapActivePageLimit + zapPassiveWaitMinutes*time.Minute
	zapActiveTimeout     = 26 * time.Minute // the command: the longest page (zapCombinedPageLimit) and the cleanup after it
	zapStopTimeout       = 3 * time.Minute  // zap.stop: the run's cleanup (podman rm, its proof, nft delete) after the cancel

	// zapActiveMemory is the container's memory and swap cap (the JVM heap is half of it, the home tmpfs counts against it): the
	// active scan keeps every request it sends in ZAP's session database, more than the baseline's.
	zapActiveMemory = "2g"
	zapActiveHeap   = "-Xmx1g"
	zapActiveTmpfs  = "/home/zap:rw,size=512m,mode=1777"
	zapActivePids   = "--pids-limit=512"
	zapPlanName     = "plan.yaml"
	// zapPassiveReportName is the report of the passive pass of a run with Passive, written before its active scan starts.
	zapPassiveReportName = "passive.json"
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
// other actions of a service, and checks that make the server fetch something itself (its hosting provider's own infrastructure,
// a third-party URL). ZAP's active rules
// guess no password and try no login: none is brute force, and the forced-browse add-on is not run. SQL Injection (40018) runs on
// every page at strength low (error and expression payloads: a quote or an arithmetic value, never "OR 1=1"); its boolean and UNION
// payloads (strength medium), which in an UPDATE or DELETE would touch every row, run only with Disruptive.
var zapActiveRules = []zapRule{
	{0, zapRuleOn, "Directory Browsing"},
	{6, zapRuleOn, "Path Traversal (reads files)"},
	{7, zapRuleDisruptive, "Remote File Inclusion: makes the server fetch a third-party URL"},
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

// zapDenialRules are the disruptive rules of denial of service (api.ZapSettings.NoDoS turns them off); every other disruptive rule
// may change data or makes the server fetch something elsewhere (NoChange turns them off, with form posting and SQL Injection's
// stronger payloads).
var zapDenialRules = []int{20015, 30001, 30002, 40044}

// zapFixedFileRules request fixed file names under a page's folders (.env, .htaccess, ELMAH, trace.axd, hidden files, Spring
// actuators, /WEB-INF), not a URL the spider found: ZAP does not apply the context's excludes to them, so a page with paths to skip
// leaves them out.
var zapFixedFileRules = []int{10045, 40028, 40029, 40032, 40034, 40035, 40042}

// zapActiveOpts are how one active page runs: with the disruptive rules or not (after the host's own checks), and the deep-scan
// settings of the target, which only narrow. passive runs the page's passive pass in the same run.
type zapActiveOpts struct {
	disruptive, noDoS, noChange, gentle bool
	passive                             bool
}

// postsForms says whether the spider posts forms: only with the disruptive rules and the checks that may change data.
func (o zapActiveOpts) postsForms() bool { return o.disruptive && !o.noChange }

// zapRuleRuns says whether rule r runs on page p under o, and at which strength.
func zapRuleRuns(p zapPage, r zapRule, o zapActiveOpts) (bool, string) {
	denial := slices.Contains(zapDenialRules, r.id)
	switch {
	case r.class == zapRuleOff,
		r.class == zapRuleDisruptive && !o.disruptive,
		r.class == zapRuleDisruptive && denial && o.noDoS,
		r.class == zapRuleDisruptive && !denial && o.noChange,
		len(p.skip) > 0 && slices.Contains(zapFixedFileRules, r.id):
		return false, ""
	case r.id == zapSQLi && !o.postsForms():
		return true, "low"
	}
	return true, "medium"
}

// zapSkippedRules are the rules page p does not run under o, or runs with weaker payloads, that it would run with the same disruptive
// rules and no deep-scan settings (api.ZapActiveResult.SkippedRules).
func zapSkippedRules(p zapPage, o zapActiveOpts) []int {
	wide := p
	wide.skip = nil
	var out []int
	for _, r := range zapActiveRules {
		on, strength := zapRuleRuns(p, r, o)
		wideOn, wideStrength := zapRuleRuns(wide, r, zapActiveOpts{disruptive: o.disruptive})
		if wideOn && (!on || strength != wideStrength) {
			out = append(out, r.id)
		}
	}
	return out
}

// zapPlanRules are the ZAP plugin ids of the active rules page p's plan runs under o (api.ZapActiveResult.Rules).
func zapPlanRules(p zapPage, o zapActiveOpts) []int {
	var out []int
	for _, r := range zapActiveRules {
		if on, _ := zapRuleRuns(p, r, o); on {
			out = append(out, r.id)
		}
	}
	return out
}

// zapPace is the threads and the delay between requests of an active page.
func zapPace(o zapActiveOpts) (threads, delayMs int) {
	if o.gentle {
		return zapGentleThreads, zapGentleDelayMs
	}
	return zapThreadsPerHost, zapDelayMs
}

// zapSettingsNote is what the run log says of the deep-scan settings of a page ("" for none).
func zapSettingsNote(p zapPage, o zapActiveOpts) string {
	var parts []string
	if o.disruptive && o.noDoS {
		parts = append(parts, "denial-of-service rules off")
	}
	if o.disruptive && o.noChange {
		parts = append(parts, "rules that may change data off")
	}
	if o.gentle {
		parts = append(parts, "gentle")
	}
	if len(p.skip) > 0 {
		parts = append(parts, strconv.Itoa(len(p.skip))+" web paths skipped")
	}
	if len(parts) == 0 {
		return ""
	}
	return "; the target's settings: " + strings.Join(parts, ", ")
}

// zapDisruptiveRuleIDs are the rules a run without Disruptive does not run as a run with it does: the disruptive class, and SQL
// Injection (its stronger payloads). ZapActiveResult carries them to core, which closes an issue of one of them only after a run
// with Disruptive.
func zapDisruptiveRuleIDs() []int {
	var ids []int
	for _, r := range zapActiveRules {
		if r.class == zapRuleDisruptive || r.id == zapSQLi {
			ids = append(ids, r.id)
		}
	}
	return ids
}

// zapActivePlan is the Automation Framework plan of one active page with or without the disruptive rules and no deep-scan settings.
func zapActivePlan(p zapPage, disruptive bool) string {
	return zapPlanActive(p, zapActiveOpts{disruptive: disruptive})
}

// zapPlanWriter writes a plan line by line; zapQuote quotes a value (a JSON string is a YAML double-quoted scalar).
type zapPlanWriter struct{ b strings.Builder }

func (z *zapPlanWriter) w(s ...string) {
	for _, l := range s {
		z.b.WriteString(l)
		z.b.WriteByte('\n')
	}
}

func zapQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

// env writes the plan's one context: the page's origin as its include path, and an exclude for each path to skip.
func (z *zapPlanWriter) env(p zapPage) {
	z.w("env:",
		"  contexts:",
		"    - name: page",
		"      urls:",
		"        - "+zapQuote(p.url),
		"      includePaths:",
		"        - "+zapQuote(zapScopeRE(p.url)))
	if len(p.skip) > 0 {
		z.w("      excludePaths:")
		for _, prefix := range p.skip {
			z.w("        - " + zapQuote(zapExcludeRE(p.url, prefix)))
		}
	}
	z.w("  parameters:",
		"    failOnError: false",
		"    failOnWarning: false",
		"    progressToStdout: true",
		"jobs:")
}

// spiderSeeds writes the spider's reading of robots.txt and sitemap.xml off when a path to skip covers the file: the spider fetches
// them as seeds, not as URLs it found.
func (z *zapPlanWriter) spiderSeeds(p zapPage) {
	for _, f := range []struct{ path, param string }{{"/robots.txt", "parseRobotsTxt"}, {"/sitemap.xml", "parseSitemapXml"}} {
		if slices.ContainsFunc(p.skip, func(prefix string) bool { return strings.HasPrefix(f.path, strings.ToLower(prefix)) }) {
			z.w("      " + f.param + ": false")
		}
	}
}

func (z *zapPlanWriter) report() { z.reportAs(zapReportName) }

func (z *zapPlanWriter) reportAs(name string) {
	z.w("  - type: report",
		"    parameters:",
		"      template: traditional-json",
		"      reportDir: "+zapQuote(zapWorkDir),
		"      reportFile: "+zapQuote(name))
}

// zapPlanActive is the Automation Framework plan of one active page: built from the validated page, the fixed bounds above and the
// settings o, never from text core sent.
func zapPlanActive(p zapPage, o zapActiveOpts) string {
	threads, delay := zapPace(o)
	var z zapPlanWriter
	z.env(p)
	if o.passive { // the passive rules at their defaults, as the baseline's
		z.w("  - type: passiveScan-config",
			"    parameters:",
			"      maxAlertsPerRule: "+strconv.Itoa(zapMaxAlertsPerRule),
			"      scanOnlyInScope: true")
	} else { // the baseline already ran them on this page: no alert counted twice
		z.w("  - type: passiveScan-config",
			"    parameters:",
			"      disableAllRules: true",
			"      scanOnlyInScope: true")
	}
	z.w("  - type: spider",
		"    parameters:",
		"      context: page",
		"      url: "+zapQuote(p.url),
		"      maxDuration: "+strconv.Itoa(zapSpiderMinutes),
		"      maxDepth: "+strconv.Itoa(zapSpiderDepth),
		"      maxChildren: "+strconv.Itoa(zapSpiderChildren),
		"      threadCount: "+strconv.Itoa(threads),
		"      processForm: true",
		"      postForm: "+strconv.FormatBool(o.postsForms()),
		"      acceptCookies: true")
	z.spiderSeeds(p)
	if o.passive { // the passive rules read every page the spider found, then their report is written before any attack request
		z.w("  - type: passiveScan-wait",
			"    parameters:",
			"      maxDuration: "+strconv.Itoa(zapPassiveWaitMinutes))
		z.reportAs(zapPassiveReportName)
	}
	z.w("  - type: activeScan",
		"    parameters:",
		"      context: page",
		"      maxRuleDurationInMins: "+strconv.Itoa(zapRuleMinutes),
		"      maxScanDurationInMins: "+strconv.Itoa(zapActiveMinutes),
		"      threadPerHost: "+strconv.Itoa(threads),
		"      delayInMs: "+strconv.Itoa(delay),
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
		if on, strength := zapRuleRuns(p, r, o); on {
			z.w("        - id: "+strconv.Itoa(r.id), "          strength: "+strength, "          threshold: medium")
		}
	}
	z.report()
	return z.b.String()
}

// zapPassivePlan is the passive pass of a page with paths to skip, as an Automation Framework plan (zap-baseline.py has no exclude):
// zap-baseline.py's own run with the page's context and its excludes. The passive rules at their defaults (core applies its own rule
// list to the report, as for the baseline), a spider of one minute on one thread that neither handles nor posts a form, the wait for
// the passive rules, and the same report.
func zapPassivePlan(p zapPage) string {
	var z zapPlanWriter
	z.env(p)
	z.w("  - type: passiveScan-config",
		"    parameters:",
		"      maxAlertsPerRule: "+strconv.Itoa(zapMaxAlertsPerRule),
		"      scanOnlyInScope: true",
		"  - type: spider",
		"    parameters:",
		"      context: page",
		"      url: "+zapQuote(p.url),
		"      maxDuration: "+strconv.Itoa(zapPassiveSpiderMinutes),
		"      threadCount: 1",
		"      processForm: false",
		"      postForm: false")
	z.spiderSeeds(p)
	z.w("  - type: passiveScan-wait",
		"    parameters:",
		"      maxDuration: "+strconv.Itoa(zapPassiveWaitMinutes))
	z.report()
	return z.b.String()
}

// zapOriginRE is the page's scheme, host and port as a pattern. ZAP writes a URL without the scheme's own port, so the default port
// may be there or not; any other port must be.
func zapOriginRE(pageURL string) string {
	scheme, rest, _ := strings.Cut(pageURL, "://")
	hostport := strings.TrimSuffix(rest, "/")
	host, port, hasPort := strings.Cut(hostport, ":")
	origin := regexp.QuoteMeta(scheme + "://" + strings.ToLower(host))
	if hasPort {
		return origin + ":" + port
	}
	return origin + "(?::" + map[string]string{"http": "80", "https": "443"}[scheme] + ")?"
}

// zapScopeRE is the include path the plan gives its context (ZAP adds the context URL's own unescaped "<url>.*"; see the top): the
// page's origin, anchored at both ends, then nothing or a path or query.
func zapScopeRE(pageURL string) string { return "^" + zapOriginRE(pageURL) + "(?:[/?].*)?$" }

// zapExcludeRE is the exclude of a path to skip: the page's origin, then the prefix as written (QuoteMeta: never a pattern), then
// anything; in any case, so a server that ignores case (IIS) is not reached under another spelling of the prefix.
func zapExcludeRE(pageURL, prefix string) string {
	return "(?i)^" + zapOriginRE(pageURL) + regexp.QuoteMeta(prefix) + ".*$"
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
	if a.Grant != "" && (!a.Disruptive || !zapGrantRE.MatchString(a.Grant)) {
		return zapPage{}, server.Invalid("grant", "must be the grant of zap.authorize (32 hex characters), with disruptive")
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
			pass := zapPass{active: true, disruptive: a.Disruptive, req: rc.RequestID, actor: rc.Actor, grant: a.Grant, passive: a.Passive}
			if st := a.Settings; st != nil {
				pass.noDoS, pass.noChange, pass.gentle = st.NoDoS, st.NoChange, st.Gentle
			}
			return o.zapRun(ctx, rc.Log, p, pass)
		},
	})
}

func (o *Ops) cmdZapStop() server.Command {
	return server.Define(server.Spec[api.ZapStopArgs]{
		Name: api.CmdZapStop, Write: false, Timeout: zapStopTimeout,
		Validate: zapStopArgs,
		Run: func(ctx context.Context, rc *server.RunContext, a api.ZapStopArgs) (any, error) {
			if err := zapStopArgs(&a); err != nil {
				return nil, err
			}
			return o.zapStopRun(ctx, rc.Log, a.RequestID)
		},
	})
}

// zapReqRE is a request id as the host takes it (the X-Request-Id header, lower case): a UUID v4.
var zapReqRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// zapStopArgs validates the args of zap.stop (and writes the request id in lower case, as the host keeps it).
func zapStopArgs(a *api.ZapStopArgs) error {
	a.RequestID = strings.ToLower(a.RequestID)
	if !zapReqRE.MatchString(a.RequestID) {
		return server.Invalid("request_id", "must be the request id (a UUID v4) of a zap.baseline or zap.active run")
	}
	return nil
}

// errZapStopped is the cause of a run's context that zap.stop cancelled.
var errZapStopped = errors.New("zap: stopped")

// zapStopsKept bounds the stops kept for runs that had not started: a run starts within seconds of its request, so a stop older
// than one run's command timeout names a run that never came; at most zapStopsMax are kept.
const (
	zapStopsKept = zapActiveTimeout
	zapStopsMax  = 64
)

// zapStopRun stops the run of request id req. When it runs, it is cancelled and zapStopRun waits until its cleanup is over (the
// container proven gone, then the fence deleted). Otherwise the stop is kept, so the run refuses to start if its request arrives
// after the stop (the scan gave up while its zap.baseline or zap.active was on its way); a run of another request is left alone.
func (o *Ops) zapStopRun(ctx context.Context, logf func(string), req string) (any, error) {
	o.zapMu.Lock()
	if !o.zapBusy || o.zapReq != req {
		now := o.d.Now()
		if o.zapStopped == nil {
			o.zapStopped = map[string]time.Time{}
		}
		for k, until := range o.zapStopped {
			if now.After(until) {
				delete(o.zapStopped, k)
			}
		}
		if len(o.zapStopped) < zapStopsMax {
			o.zapStopped[req] = now.Add(zapStopsKept)
		}
		o.zapMu.Unlock()
		logf("the web scan (ZAP) of request " + req + " is not running: it will not start")
		return api.ZapStopResult{}, nil
	}
	stop, done := o.zapStop, o.zapDone
	o.zapMu.Unlock()
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
