package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// Active web scan of the pages the passive baseline scanned (S-EXP-2, CONTRACT INV-24): ZAP's spider and active scan rules, which send
// attack requests (SQL injection, cross-site scripting, path traversal, command injection, …) to the one page's origin. It is the
// dangerous class of the web step, so it runs only when every one of these holds, and says why on the scan when it does not:
//
//   - a scan a person started (Scan now or Run once now): a scan the box runs by itself on its schedule keeps the passive baseline
//     only, and says so (notActiveScheduled);
//   - the target's testing terms are accepted (ScanTarget.Mode.Full), read again right before each page (ModeNow);
//   - the page was scanned by the passive baseline of this run (ZAP answered for it): the same page, address and port, through the
//     host's same fences (ownership re-checked by the host, the network fence that lets the container reach that address and port
//     only, ZAP's own context anchored to the page's scheme, host and port);
//   - the run's time for the active pass is not used up (ActiveRunLimit), each page bounded by ActiveScanTimeout.
//
// The disruptive rules of the host's rule split (denial of service, checks that may change data heavily) and form posting run only on
// the box's own proven public IP (an IP target that is not a typed IP, the page on exactly that address) when the mode read right
// before the page allows the disruptive checks (runMode: a person's scan, the terms include them, the gateway not in 100.64.0.0/10).
// Every other page, a domain's on a CDN or hosting address among them, gets the active scan with them off.

// ActiveWebScanner runs ZAP's active scan against one page and returns its JSON report. t.Mode.Disruptive says whether the disruptive
// rules run. Errors as WebScanner: *Unavailable for a reason that holds for the other pages, *PageSkipped for this page only. When ctx
// ends before the run does, the scanner stops ZAP (the container removed) before it returns.
type ActiveWebScanner interface {
	Active(ctx context.Context, t ScanTarget, page WebPage) (WebScan, error)
}

// Limits of the active web scan (INV-24). The host bounds one page itself at 20 minutes (spider 2 minutes, active rules 12 minutes, 2
// threads, 100 ms between requests, depth 5, 20 children per node, a 2 GiB container); exposure waits a minute more.
const (
	ActiveScanTimeout = 21 * time.Minute
	ActiveRunLimit    = 60 * time.Minute // the active pass of one scan: a page starts only while a whole page still fits

	passActive = "active"

	webActiveTool           = "ZAP active scan: spider 2 minutes, depth 5, forms sent with GET only; active rules 12 minutes, 2 threads, 100 ms between requests; disruptive rules off"
	webActiveToolDisruptive = "ZAP active scan: spider 2 minutes, depth 5, forms posted; active rules 12 minutes, 2 threads, 100 ms between requests; disruptive rules on (the box's own IP)"
	// The tools of a page whose passive and active scans run in one ZAP run (CombinedWebScanner): one probe-log row for both.
	webCombinedTool           = "ZAP passive and active scan in one run: spider 2 minutes, depth 5, forms sent with GET only; passive rules; then active rules 12 minutes, 2 threads, 100 ms between requests; disruptive rules off"
	webCombinedToolDisruptive = "ZAP passive and active scan in one run: spider 2 minutes, depth 5, forms posted; passive rules; then active rules 12 minutes, 2 threads, 100 ms between requests; disruptive rules on (the box's own IP)"
)

// The lines of the active web scan.
const (
	// notActiveScheduled is the line of every scheduled scan of a target whose testing terms are accepted: the passive web scan ran, the
	// active one waits for a person.
	notActiveScheduled = "Active web checks run when a person presses Scan now; scheduled scans read the pages without attacking them."
	notActiveNoScanner = "Active web scan (ZAP) is not set up on this box."
	notActiveNoLog     = "Active web scan (ZAP) did not run: the probe log is not available, and nothing is sent without it."
	notActiveTerms     = "Active web scan (ZAP) did not run: the testing terms of this target are no longer accepted."
	notActiveFail      = "Active web scan (ZAP) failed, so the page was not attacked. The box log has the error."
	notActiveSlow      = "Active web scan (ZAP) did not finish within 21 minutes, so the page's active results are not known."
	notActiveHostSlow  = "Active web scan (ZAP) did not finish within the box's time limit for a page, so the page's active results are not known; its passive results are kept."
	notActiveUnread    = "Active web scan (ZAP) returned a report that could not be read, so the page's active results are not known."
	notActiveCut       = "Active web scan (ZAP) reached its limit of 12 minutes on this page: the alerts it found until then are kept, and some rules did not run."
	notActiveRunLimit  = "Active web scan (ZAP): %s not attacked: the active pass of one scan takes at most 60 minutes. Scan again to check %s."
	notActiveDisrupt   = "Active web scan (ZAP) ran without its disruptive rules (denial of service, checks that may change data) on %s: they run only on this box's own public IP, in a scan a person starts."
	// notActiveSettings is the line of the pages whose disruptive rules this target's settings removed: ZAP's disruptive rules are
	// denial-of-service rules and rules that may change data (the host runs the class of each group allowed), so with both groups off
	// none runs.
	notActiveSettings = "Active web scan (ZAP) ran without its disruptive rules on %s. " + notSettings + " Its disruptive rules are denial-of-service checks and exploit checks that may change data, and both are off."
	// notActiveOff is the line of an active web scan this target's settings turned off.
	notActiveOff = "Active web scan (ZAP): " + notSettings
	// notActiveHostRefused is a page the step asked the disruptive rules for and the host ran without them: its own check of the
	// person's press or of the box's gateway (zapgrant.go), with the host's reason.
	notActiveHostRefused = "Active web scan (ZAP) ran without its disruptive rules on %s: %s"
)

// activeTally is what the active pass did, for its run step's note.
type activeTally struct {
	pages, alerts int
	disruptive    bool
	cut           []string
	note          string   // why it ended early (a reason that held for the rest)
	refused       []string // the host ran pages without the disruptive rules: how many, and its reason
}

// hostRefusal is the pages the host ran without the disruptive rules for one reason.
type hostRefusal struct {
	why   string
	pages []string
}

func addRefused(rs []hostRefusal, why, page string) []hostRefusal {
	for i := range rs {
		if rs[i].why == why {
			rs[i].pages = append(rs[i].pages, page)
			return rs
		}
	}
	return append(rs, hostRefusal{why: why, pages: []string{page}})
}

// activeEnd is how the active pass's run step ends, and its note: the pages attacked of those it takes, with or without the
// disruptive rules, the alerts, the pages cut short at their limit.
func activeEnd(ok, failed, left int, t activeTally) (corerun.Status, string) {
	how := corerun.Done
	switch {
	case ok == 0 && failed > 0:
		how = corerun.Failed
	case failed > 0 || left > 0 || t.note != "":
		how = corerun.Partial
	}
	rules := "without the disruptive rules"
	if t.disruptive {
		rules = "with the disruptive rules on the box's own IP"
	}
	note := fmt.Sprintf("ZAP attacked %d of %s %s, %s.", ok, plural(t.pages, "page"), rules, plural(t.alerts, "alert"))
	if ok == 0 {
		note = fmt.Sprintf("ZAP attacked none of %s.", plural(t.pages, "page"))
	}
	if len(t.cut) > 0 {
		note += " Cut short at its time limit (12 minutes) on " + strings.Join(t.cut, ", ") + ": what it found until then is kept."
	}
	if left > 0 {
		note += " " + plural(left, "page") + " not attacked."
	}
	for _, r := range t.refused { // the pass ran, with less than asked: said, not a partial step
		note += " " + r
	}
	if t.note != "" {
		note += " " + t.note
	}
	return how, note
}

// ownProvenPage says the page is on the box's own proven public IP: an IP target that is not a typed IP (the gate took it as the box's
// own egress, inside its proof), and the page on exactly that address.
func ownProvenPage(st ScanTarget, page WebPage) bool {
	if st.Kind != KindIP || st.Typed {
		return false
	}
	ip, err := netip.ParseAddr(st.Value)
	return err == nil && ip.Unmap() == page.IP.Unmap()
}

// activeCall is how the active scan of one page runs, decided right before it: the target it runs with (the mode read now, the
// settings of the page's address when that is an IP target too, the disruptive rules only on the box's own proven IP, the host's
// grant), the tool of its probe-log row, and whether the settings narrowed its disruptive rules. A page that does not run has its
// "Not checked" line; stop, with it, says no page after it runs either and is the step's note.
type activeCall struct {
	st         ScanTarget
	tool       string
	narrowed   bool
	line, stop string
}

// activeTarget decides the active scan of page in the scan of st (see activeCall). Its error is only the run's end.
func (s *Service) activeTarget(ctx context.Context, st ScanTarget, page WebPage) (activeCall, error) {
	mode, err := s.ModeNow(ctx, st.User, st.ID) // the terms and the gate as they are now, with the run's own rules (runMode)
	if ctx.Err() != nil {
		return activeCall{}, ctx.Err() // the run's end stops its step
	}
	if err != nil || !mode.Full {
		if err != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the terms before the active web scan failed", "target", st.Value, "error", err)
		}
		return activeCall{line: notActiveTerms, stop: notActiveTerms}, nil
	}
	if !mode.WebActive { // the settings turned the active web scan off while the run ran
		return activeCall{line: notActiveOff, stop: notSettings}, nil
	}
	pst := st
	pst.Mode = mode.And(st.Mode) // never more than the run started with
	if st.Kind == KindDomain {   // a page on an address that is an IP target too: that target's settings narrow it as well
		it, found, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), page.IP.Unmap().String())
		switch {
		case err != nil:
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the settings of a page's address failed", "target", st.Value, "page", page.URL, "error", err)
			return activeCall{line: clipText(page.URL+": "+notActiveFail, maxLineText)}, nil
		case found && (it.Deep.Problem != nil || !it.Deep.WebActive || slices.Contains(it.Deep.SkipPorts, page.Port)):
			return activeCall{line: clipText(page.URL+": "+notActiveOff+" (the settings of "+it.Value+")", maxLineText)}, nil
		case found:
			pst = withSettings(pst, it.Deep)
		}
		if !s.webKeepsPaths(pst) { // that target's web paths to skip, which this box's ZAP cannot leave out
			return activeCall{line: clipText(page.URL+": "+notWebPaths, maxLineText)}, nil
		}
	}
	call := activeCall{}
	switch own := ownProvenPage(st, page); {
	case own && pst.Mode.WebDisruptive():
	case own && pst.Mode.Disruptive: // the box's own page, and the settings keep one of the two groups of ZAP's disruptive rules off
		call.narrowed = true
		pst.Mode = pst.Mode.withoutDisruptive()
	default:
		pst.Mode = pst.Mode.withoutDisruptive()
	}
	call.tool = webActiveTool
	if pst.Mode.Disruptive {
		call.tool = webActiveToolDisruptive
		pst.Grant = s.grantOf(ctx, RunIDOf(ctx)) // the host's grant of the press that started this scan: it checks it itself
	}
	call.st = pst
	return call, nil
}

// webActive is the active pass of the web step, after webPassive, on the pages it scanned (c.webOK). See the comment at the top. A
// page whose active scan already ran in the same ZAP run as its passive scan (c.webAhead) is taken as it ran: its checks were made
// right before that run, and it is never attacked twice.
func (s *Service) webActive(ctx context.Context, st ScanTarget, c Content) (Content, error) {
	pages := c.webOK
	rs := runStepsOf(ctx) // its run step (stepKeyZAPActive), in the plan of a deep scan
	ahead := map[string]*aheadRun{}
	for _, p := range pages {
		if run := c.webAhead[p.URL]; run != nil {
			ahead[p.URL] = run
		}
	}
	if st.Mode.Full && len(ahead) == 0 && s.skipIfGone(ctx, st, c, stepKeyZAPActive) { // the target stopped answering earlier in the run
		return c, nil
	}
	switch {
	case !st.Mode.Full: // a surface scan has no active pass (a typed IP without its live proof runs at that depth)
		rs.skip(ctx, stepKeyZAPActive, "The active web scan runs only in a deep scan.")
		return c, nil
	case !st.Mode.WebActive: // the target's settings turned the active web scan off
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveOff})
		rs.skip(ctx, stepKeyZAPActive, notSettings)
		return c, nil
	case !s.webKeepsPaths(st): // its spider and rules would request the paths to skip (the passive step's line says so)
		rs.skip(ctx, stepKeyZAPActive, notWebPaths)
		return c, nil
	case len(pages) == 0:
		rs.skip(ctx, stepKeyZAPActive, "No web page was read by the passive web scan, so there is nothing to attack.")
		return c, nil
	case st.User == SystemUser:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveScheduled})
		rs.skip(ctx, stepKeyZAPActive, notActiveScheduled)
		return c, nil
	}
	pages = slices.DeleteFunc(slices.Clone(pages), func(p WebPage) bool { return st.Skips(p.Port) }) // never a port the settings skip
	aw, _ := s.cfg.Web.(ActiveWebScanner)
	if aw == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoScanner})
		rs.skip(ctx, stepKeyZAPActive, notActiveNoScanner)
		return c, nil
	}
	plog, _ := s.cfg.Probes.(WebProbeLog)
	if plog == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoLog})
		rs.skip(ctx, stepKeyZAPActive, notActiveNoLog)
		return c, nil
	}
	if len(ahead) == 0 {
		// The ports seen open earlier must still answer (probes.go): a page on a port that stopped answering is not attacked
		if !s.beforeEngine(ctx, st, &c, stepKeyZAPActive, stepNameZAPAct, "web") {
			return c, nil
		}
		if pages = slices.DeleteFunc(slices.Clone(pages), func(p WebPage) bool { return s.lostPort(ctx, p.IP.String(), p.Port) }); len(pages) == 0 {
			rs.skip(ctx, stepKeyZAPActive, "Not run. "+s.lostText(ctx, st, s.observerOf(ctx).lostOf()))
			return c, nil
		}
	} else {
		// The pages attacked with their passive scan were checked right before it (the passive step's check that the ports answer); a
		// page still to attack here is held to the ports seen lost since.
		pages = slices.DeleteFunc(slices.Clone(pages), func(p WebPage) bool { return ahead[p.URL] == nil && s.lostPort(ctx, p.IP.String(), p.Port) })
	}
	rs.start(ctx, stepKeyZAPActive)
	step := activeTally{pages: len(pages)}
	steps := stepsOf(ctx)
	start := s.clock()
	if !c.webAheadAt.IsZero() { // the active pass began with the first page attacked with its passive scan
		start = c.webAheadAt
	}
	var scanned, gentle, narrowed []string
	var refused []hostRefusal // pages the host ran without the disruptive rules, by its reason
	ok, failed, left := 0, 0, 0
	halt := false                       // no page still to attack runs any more (the pass's time, the terms, the settings, the probe log, ZAP unavailable)
	notYet := func(from int) []string { // the pages from index from on that were not attacked with their passive scan
		var out []string
		for _, p := range pages[from:] {
			if ahead[p.URL] == nil {
				out = append(out, p.URL)
			}
		}
		return out
	}
	for i, page := range pages {
		run := ahead[page.URL]
		if run == nil && halt {
			continue
		}
		var pst ScanTarget
		var res WebScan
		var err error
		slow := false
		if run != nil {
			pst = run.st
			if run.narrowed {
				narrowed = append(narrowed, page.URL)
			}
			if !pst.Mode.Disruptive {
				gentle = append(gentle, page.URL)
			}
			steps.begin(StepZAPActive, pst.Mode.Disruptive)
			res, err = run.res, run.err
		} else {
			if s.clock().Sub(start)+ActiveScanTimeout > ActiveRunLimit {
				rest := notYet(i)
				left, halt = len(rest), true
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveRunLimit, plural(len(rest), "page"), strings.Join(rest, ", ")), maxLineText)})
				continue
			}
			call, cerr := s.activeTarget(ctx, st, page)
			if cerr != nil {
				return c, cerr
			}
			if call.line != "" {
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: call.line})
				if call.stop != "" {
					left, step.note, halt = len(notYet(i)), call.stop, true
				}
				continue
			}
			pst = call.st
			if call.narrowed {
				narrowed = append(narrowed, page.URL)
			}
			if !pst.Mode.Disruptive {
				gentle = append(gentle, page.URL)
			}
			if err := plog.RecordWebProbe(ctx, WebProbe{ID: store.NewID("pb"), IP: page.IP.String(), Port: page.Port, URL: page.URL, Tool: call.tool}); err != nil { // LEGAL §3: logged before ZAP starts
				if ctx.Err() != nil {
					return c, err
				}
				s.cfg.Log.ErrorContext(ctx, "exposure: writing the probe log of the active web step failed", "target", st.Value, "page", page.URL, "error", err)
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoLog})
				left, step.note, halt = len(notYet(i)), notActiveNoLog, true
				continue
			}
			rs.say(stepKeyZAPActive, fmt.Sprintf("page %d of %d: %s", i+1, len(pages), page.URL))
			wctx, cancel := context.WithTimeout(ctx, ActiveScanTimeout)
			steps.begin(StepZAPActive, pst.Mode.Disruptive)
			res, err = aw.Active(wctx, pst, page)
			slow = wctx.Err() != nil
			cancel()
		}
		if err == nil {
			rough := pst.Mode.Disruptive && res.DisruptiveRefused == "" // asked for and not refused by the host; a refused page counts as one without them
			if pst.Mode.Disruptive && !rough {
				refused = addRefused(refused, res.DisruptiveRefused, page.URL)
			}
			rows, perr := parseZAPWithRules(res.Report, page.URL)
			if run != nil { // one ZAP session: its active report holds the passive alerts too, read by the passive step
				rows = slices.DeleteFunc(rows, func(r WebFindingRow) bool { return !slices.Contains(res.Rules, r.PluginID) })
			}
			switch {
			case perr == nil || errors.Is(perr, ErrNoPage):
				for i := range rows {
					rows[i].Pass = passActive
					rows[i].Disruptive = rough && (len(res.DisruptiveRules) == 0 || slices.Contains(res.DisruptiveRules, rows[i].PluginID))
				}
				c.WebFindings = mergeWebRows(c.WebFindings, rows)
				for _, r := range res.SkippedRules { // a rule the settings left out of the page did not look at it again
					c.WebSkippedRules = append(c.WebSkippedRules, r+"@"+siteOf(page.URL))
				}
				c.WebSkippedPaths = addSkippedPaths(c.WebSkippedPaths, page.URL, pst.SkipPaths)
				if !res.CutShort { // a page cut short did not run every rule: an active alert it no longer reports is not "gone"
					c.WebActivePages = append(c.WebActivePages, page.URL)
					if rough {
						c.WebDisruptivePages = append(c.WebDisruptivePages, page.URL)
					}
				}
				scanned = append(scanned, page.URL)
				ok++
				step.alerts += len(rows)
				step.disruptive = step.disruptive || rough
				if res.CutShort {
					step.cut = append(step.cut, page.URL)
					c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveCut, maxLineText)})
				}
				steps.end(StepZAPActive, callRan, len(rows), s.clock())
			default:
				s.cfg.Log.ErrorContext(ctx, "exposure: unreadable ZAP report of the active scan", "target", st.Value, "page", page.URL, "error", perr)
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveUnread, maxLineText)})
				failed++
				steps.end(StepZAPActive, callFailed, 0, s.clock())
			}
			continue
		}
		var un *Unavailable
		var skip *PageSkipped
		switch {
		case ctx.Err() != nil: // the run was stopped: the scanner stopped ZAP; the run's end stops the step
			return c, err
		case errors.As(err, &skip), errors.As(err, &un):
			steps.end(StepZAPActive, callSkipped, 0, s.clock())
		default:
			failed++
			steps.end(StepZAPActive, callFailed, 0, s.clock())
		}
		switch {
		case errors.As(err, &un):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText("Active web scan (ZAP) did not run: "+un.Reason, maxLineText)})
			left, step.note, halt = len(notYet(i+1)), "Did not run: "+un.Reason, true
		case errors.As(err, &skip):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": active web scan (ZAP) did not run: "+skip.Reason, maxLineText)})
		case slow:
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveSlow, maxLineText)})
		case errors.Is(err, ErrActiveTimedOut):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveHostSlow, maxLineText)})
		default:
			s.cfg.Log.ErrorContext(ctx, "exposure: active web scan failed", "target", st.Value, "page", page.URL, "error", err)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveFail, maxLineText)})
		}
	}
	if gentle = slices.DeleteFunc(gentle, func(u string) bool { return slices.Contains(narrowed, u) }); len(gentle) > 0 && st.Mode.Disruptive {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveDisrupt, strings.Join(gentle, ", ")), maxLineText)})
	}
	if len(narrowed) > 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveSettings, strings.Join(narrowed, ", ")), maxLineText)})
	}
	for _, r := range refused {
		line := fmt.Sprintf(notActiveHostRefused, strings.Join(r.pages, ", "), r.why)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(line, maxLineText)})
		step.refused = append(step.refused, fmt.Sprintf("Without the disruptive rules on %s: %s", plural(len(r.pages), "page"), r.why))
	}
	if len(scanned) > 0 {
		text := fmt.Sprintf("Active web scan (ZAP: spider and active rules, attack requests to the page's own address only) of %s: %s. %s.",
			plural(len(scanned), "page"), strings.Join(scanned, ", "), plural(step.alerts, "alert"))
		if len(step.cut) > 0 {
			text += " Cut short at its time limit on " + strings.Join(step.cut, ", ") + "."
		}
		c.Checks = append(c.Checks, CheckRow{Kind: "web", At: store.FormatTS(s.clock()), Text: clipText(text, maxLineText)})
	}
	how, note := activeEnd(ok, failed, left, step)
	rs.end(ctx, stepKeyZAPActive, how, note)
	return c, nil
}

// The passive and active scans of one page in one ZAP run (INV-24): ZAP starts once and spiders once, its passive rules read the
// pages the spider found and their report is written before the active scan starts, so the passive results stand also when the
// active part ends without its report. The web step asks for it, from the passive pass, only for a page whose active scan this run
// takes anyway, decided by the same checks the active pass makes (aheadCall), right before the run.

// CombinedWebScanner is implemented by an ActiveWebScanner that runs a page's passive and active scans in one ZAP run. t is the
// active scan's target (activeCall.st, with NoTech). passive is the passive report as Baseline returns it; active is the active
// scan's outcome as Active returns it, with Rules (the ids of the rules it ran: the alerts of its report that are not of these are
// the passive ones of the same run), or activeErr when the active part ended without its report (ErrActiveTimedOut when the host's
// time ran out; the passive report stands either way). err is the run's own error, as Baseline's (no report at all); ErrNoCombined
// says the host cannot run both in one run (an older host): nothing was started, and the step runs Baseline, then Active.
type CombinedWebScanner interface {
	Combined(ctx context.Context, t ScanTarget, page WebPage) (passive, active WebScan, activeErr, err error)
}

var (
	// ErrNoCombined says the host cannot run a page's passive and active scans in one run (it is older than that); nothing was started.
	ErrNoCombined = errors.New("exposure: the host cannot run the passive and active web scans of a page in one run")
	// ErrActiveTimedOut says the host's time for a page ran out during its active scan; the passive report of the same run stands.
	ErrActiveTimedOut = errors.New("exposure: the active web scan did not finish within the host's time for a page")
)

// CombinedScanTimeout is how long the web step waits for a page's passive and active scans in one run: the host's own bound of such a
// page (24 minutes: the active page's 20 and the passive rules' wait of 4 after the spider) and a minute more.
const CombinedScanTimeout = ActiveScanTimeout + 4*time.Minute

// aheadRun is a page's active scan that ran in the same ZAP run as its passive scan: how it was decided and what it gave.
type aheadRun struct {
	st       ScanTarget
	narrowed bool
	res      WebScan
	err      error
}

// aheadCall says whether the active scan of page runs in the same ZAP run as its passive scan, and how: only when the scanner can
// (CombinedWebScanner) and the active pass would take the page anyway, by the same checks and in the same order (webActive's and
// activeTarget's, made now, right before the run), its time (ActiveRunLimit, which the whole run of CombinedScanTimeout must fit in)
// counted from at (the first such page; zero: none yet), and the passive pass's web paths to skip the same as the active one's (one
// run, one context). passive is the target of the page's passive scan. The call's NoTech are what this run positively identified the page as not running on (webTechAbsent).
func (s *Service) aheadCall(ctx context.Context, st, passive ScanTarget, c Content, page WebPage, at time.Time) (activeCall, bool, error) {
	_, combined := s.cfg.Web.(CombinedWebScanner)
	_, active := s.cfg.Web.(ActiveWebScanner)
	_, logs := s.cfg.Probes.(WebProbeLog)
	switch {
	case !combined || !active || !logs, !st.Mode.Full, !st.Mode.WebActive, !s.webKeepsPaths(st), st.User == SystemUser, st.Skips(page.Port),
		!at.IsZero() && s.clock().Sub(at)+CombinedScanTimeout > ActiveRunLimit: // the whole run, its passive part included, must fit
		return activeCall{}, false, nil
	}
	call, err := s.activeTarget(ctx, st, page)
	if err != nil || call.line != "" || !slices.Equal(call.st.SkipPaths, passive.SkipPaths) {
		return activeCall{}, false, err
	}
	call.st.NoTech = webTechAbsent(c, page)
	call.tool = webCombinedTool
	if call.st.Mode.Disruptive {
		call.tool = webCombinedToolDisruptive
	}
	if len(call.st.NoTech) > 0 {
		call.tool += "; rules of " + strings.Join(call.st.NoTech, ", ") + " left out (identified as not this site's)"
	}
	return call, true, nil
}

// mergeWebRows adds rows to have, one row per alert and site (ZAP's plugin id and the page's scheme, host and port): an alert both
// passes reported, or one report listed twice, is one row, whose sample pages and count are joined. It never counts an alert twice.
func mergeWebRows(have, rows []WebFindingRow) []WebFindingRow {
	at := map[string]int{}
	for i, r := range have {
		at[r.PluginID+"@"+siteOf(r.Site)] = i
	}
	for _, r := range rows {
		k := r.PluginID + "@" + siteOf(r.Site)
		i, dup := at[k]
		if !dup {
			at[k] = len(have)
			have = append(have, r)
			continue
		}
		h := &have[i]
		for _, u := range r.URLs {
			if len(h.URLs) < maxWebURLs && !containsStr(h.URLs, u) {
				h.URLs = append(h.URLs, u)
			}
		}
		h.Count = max(h.Count, r.Count, len(h.URLs))
		if h.Pass == passActive && r.Pass == passActive { // a rule a pass without the disruptive rules ran too can close it
			h.Disruptive = h.Disruptive && r.Disruptive
		}
		if riskRank(r.Risk) > riskRank(h.Risk) {
			h.Risk = r.Risk
		}
	}
	return have
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func riskRank(r string) int {
	for i, x := range zapRisks {
		if x == r {
			return i
		}
	}
	return -1
}
