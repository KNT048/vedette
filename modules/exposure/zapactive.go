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
)

// activeTally is what the active pass did, for its run step's note.
type activeTally struct {
	pages, alerts int
	disruptive    bool
	cut           []string
	note          string // why it ended early (a reason that held for the rest)
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
	rs := runStepsOf(ctx) // its run step (stepKeyZAPActive), in the plan of a deep scan
	switch {
	case !st.Mode.Full: // a surface scan has no active pass (a typed IP without its live proof runs at that depth)
		rs.skip(ctx, stepKeyZAPActive, "The active web scan runs only in a deep scan.")
		return c, nil
	case len(pages) == 0:
		rs.skip(ctx, stepKeyZAPActive, "No web page was read by the passive web scan, so there is nothing to attack.")
		return c, nil
	case st.User == SystemUser:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveScheduled})
		rs.skip(ctx, stepKeyZAPActive, notActiveScheduled)
		return c, nil
	}
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
	rs.start(ctx, stepKeyZAPActive)
	step := activeTally{pages: len(pages)}
	steps := stepsOf(ctx)
	start := s.clock()
	var scanned, gentle []string
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
		pst := st
		pst.Mode = ScanMode{Full: true, Disruptive: mode.Disruptive && st.Mode.Disruptive && ownProvenPage(st, page)}
		tool := webActiveTool
		if pst.Mode.Disruptive {
			tool = webActiveToolDisruptive
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
			rows, perr := parseZAPWithRules(res.Report, page.URL)
			switch {
			case perr == nil || errors.Is(perr, ErrNoPage):
				for i := range rows {
					rows[i].Pass = passActive
					rows[i].Disruptive = pst.Mode.Disruptive && (len(res.DisruptiveRules) == 0 || slices.Contains(res.DisruptiveRules, rows[i].PluginID))
				}
				c.WebFindings = mergeWebRows(c.WebFindings, rows)
				if !res.CutShort { // a page cut short did not run every rule: an active alert it no longer reports is not "gone"
					c.WebActivePages = append(c.WebActivePages, page.URL)
					if pst.Mode.Disruptive {
						c.WebDisruptivePages = append(c.WebDisruptivePages, page.URL)
					}
				}
				scanned = append(scanned, page.URL)
				ok++
				step.alerts += len(rows)
				step.disruptive = step.disruptive || pst.Mode.Disruptive
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
	if len(gentle) > 0 && st.Mode.Disruptive {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveDisrupt, strings.Join(gentle, ", ")), maxLineText)})
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
