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

// webActive is the active pass of the web step, after webPassive, on the pages it scanned (c.webOK). See the comment at the top.
func (s *Service) webActive(ctx context.Context, st ScanTarget, c Content) (Content, error) {
	pages := c.webOK
	rs := runStepsOf(ctx)                                           // its run step (stepKeyZAPActive), in the plan of a deep scan
	if st.Mode.Full && s.skipIfGone(ctx, st, c, stepKeyZAPActive) { // the target stopped answering earlier in the run
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
	// The ports seen open earlier must still answer (probes.go): a page on a port that stopped answering is not attacked
	if !s.beforeEngine(ctx, st, &c, stepKeyZAPActive, stepNameZAPAct, "web") {
		return c, nil
	}
	if pages = slices.DeleteFunc(slices.Clone(pages), func(p WebPage) bool { return s.lostPort(ctx, p.IP.String(), p.Port) }); len(pages) == 0 {
		rs.skip(ctx, stepKeyZAPActive, "Not run. "+s.lostText(ctx, st, s.observerOf(ctx).lostOf()))
		return c, nil
	}
	rs.start(ctx, stepKeyZAPActive)
	step := activeTally{pages: len(pages)}
	steps := stepsOf(ctx)
	start := s.clock()
	var scanned, gentle, narrowed []string
	var refused []hostRefusal // pages the host ran without the disruptive rules, by its reason
	ok, failed, left := 0, 0, 0
	for i, page := range pages {
		if s.clock().Sub(start)+ActiveScanTimeout > ActiveRunLimit {
			rest := make([]string, 0, len(pages)-i)
			for _, p := range pages[i:] {
				rest = append(rest, p.URL)
			}
			left = len(rest)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveRunLimit, plural(len(rest), "page"), strings.Join(rest, ", ")), maxLineText)})
			break
		}
		mode, err := s.ModeNow(ctx, st.User, st.ID) // the terms and the gate as they are now, with the run's own rules (runMode)
		if ctx.Err() != nil {
			return c, ctx.Err() // the run's end stops its step
		}
		if err != nil || !mode.Full {
			if err != nil {
				s.cfg.Log.ErrorContext(ctx, "exposure: reading the terms before the active web scan failed", "target", st.Value, "error", err)
			}
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveTerms})
			left, step.note = len(pages)-i, notActiveTerms
			break
		}
		if !mode.WebActive { // the settings turned the active web scan off while the run ran
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveOff})
			left, step.note = len(pages)-i, notSettings
			break
		}
		pst := st
		pst.Mode = mode.And(st.Mode) // never more than the run started with
		if st.Kind == KindDomain {   // a page on an address that is an IP target too: that target's settings narrow it as well
			it, found, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), page.IP.Unmap().String())
			switch {
			case err != nil:
				s.cfg.Log.ErrorContext(ctx, "exposure: reading the settings of a page's address failed", "target", st.Value, "page", page.URL, "error", err)
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveFail, maxLineText)})
				continue
			case found && (it.Deep.Problem != nil || !it.Deep.WebActive || slices.Contains(it.Deep.SkipPorts, page.Port)):
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveOff+" (the settings of "+it.Value+")", maxLineText)})
				continue
			case found:
				pst = withSettings(pst, it.Deep)
			}
			if !s.webKeepsPaths(pst) { // that target's web paths to skip, which this box's ZAP cannot leave out
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notWebPaths, maxLineText)})
				continue
			}
		}
		switch own := ownProvenPage(st, page); {
		case own && pst.Mode.WebDisruptive():
		case own && pst.Mode.Disruptive: // the box's own page, and the settings keep one of the two groups of ZAP's disruptive rules off
			narrowed = append(narrowed, page.URL)
			pst.Mode = pst.Mode.withoutDisruptive()
		default:
			pst.Mode = pst.Mode.withoutDisruptive()
		}
		tool := webActiveTool
		if pst.Mode.Disruptive {
			tool = webActiveToolDisruptive
			pst.Grant = s.grantOf(ctx, RunIDOf(ctx)) // the host's grant of the press that started this scan: it checks it itself
		} else {
			gentle = append(gentle, page.URL)
		}
		if err := plog.RecordWebProbe(ctx, WebProbe{ID: store.NewID("pb"), IP: page.IP.String(), Port: page.Port, URL: page.URL, Tool: tool}); err != nil { // LEGAL §3: logged before ZAP starts
			if ctx.Err() != nil {
				return c, err
			}
			s.cfg.Log.ErrorContext(ctx, "exposure: writing the probe log of the active web step failed", "target", st.Value, "page", page.URL, "error", err)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoLog})
			left, step.note = len(pages)-i, notActiveNoLog
			break
		}
		rs.say(stepKeyZAPActive, fmt.Sprintf("page %d of %d: %s", i+1, len(pages), page.URL))
		wctx, cancel := context.WithTimeout(ctx, ActiveScanTimeout)
		steps.begin(StepZAPActive, pst.Mode.Disruptive)
		res, err := aw.Active(wctx, pst, page)
		slow := wctx.Err() != nil
		cancel()
		if err == nil {
			rough := pst.Mode.Disruptive && res.DisruptiveRefused == "" // asked for and not refused by the host; a refused page counts as one without them
			if pst.Mode.Disruptive && !rough {
				refused = addRefused(refused, res.DisruptiveRefused, page.URL)
			}
			rows, perr := parseZAPWithRules(res.Report, page.URL)
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
			left, step.note = len(pages)-i-1, "Did not run: "+un.Reason
		case errors.As(err, &skip):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": active web scan (ZAP) did not run: "+skip.Reason, maxLineText)})
			continue
		case slow:
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveSlow, maxLineText)})
			continue
		default:
			s.cfg.Log.ErrorContext(ctx, "exposure: active web scan failed", "target", st.Value, "page", page.URL, "error", err)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveFail, maxLineText)})
			continue
		}
		break
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
