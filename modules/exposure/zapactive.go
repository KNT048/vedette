package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

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

// The web steps of a run as the run page reads them (contract.ts WebStep), kept in exp_scan.summary as they go.
const (
	WebStepPassive = "zap_passive"
	WebStepActive  = "zap_active"

	WebRunning = "running"
	WebDone    = "done"
	WebPartial = "partial"
	WebFailed  = "failed"
	WebStopped = "stopped"
	WebSkipped = "skipped"
)

// WebStep is one ZAP pass of a run: its state, the pages done of the pages it takes, the alerts it kept, whether a page was cut short
// at its time limit, whether the disruptive rules ran on a page, and a line saying why it was skipped or how it ended.
type WebStep struct {
	Step       string `json:"step"`
	State      string `json:"state"`
	PagesDone  int    `json:"pages_done"`
	PagesTotal int    `json:"pages_total"`
	Alerts     int    `json:"alerts"`
	CutShort   bool   `json:"cut_short"`
	Disruptive bool   `json:"disruptive"`
	Note       string `json:"note"`
}

// webTracker keeps the web steps of one run and writes them into its summary each time one changes; nil outside a run.
type webTracker struct {
	mu    sync.Mutex
	run   string
	steps []WebStep
}

type webStepsKey struct{}

func withWebSteps(ctx context.Context, t *webTracker) context.Context {
	return context.WithValue(ctx, webStepsKey{}, t)
}

// webStepSet records step (by its name) and writes the run's web steps; a write that fails is logged and the scan goes on.
func (s *Service) webStepSet(ctx context.Context, step WebStep) {
	t, _ := ctx.Value(webStepsKey{}).(*webTracker)
	if t == nil {
		return
	}
	step.Note = clipText(step.Note, maxLineText)
	t.mu.Lock()
	found := false
	for i := range t.steps {
		if t.steps[i].Step == step.Step {
			t.steps[i], found = step, true
		}
	}
	if !found {
		t.steps = append(t.steps, step)
	}
	steps := append([]WebStep(nil), t.steps...)
	t.mu.Unlock()
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		return updateSummary(wctx, tx, t.run, func(sum *scanSummary) { sum.WebSteps = steps })
	}); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the web step of a scan", "run", t.run, "error", err)
	}
}

// webStepEnd is the state a pass ends in from what its pages did.
func webStepEnd(ok, failed, left int) string {
	switch {
	case ok == 0 && failed > 0:
		return WebFailed
	case failed > 0 || left > 0:
		return WebPartial
	}
	return WebDone
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
	if !st.Mode.Full || len(pages) == 0 {
		return c, nil // a surface scan has no active pass; with no page scanned there is nothing to attack
	}
	if st.User == SystemUser {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveScheduled})
		s.webStepSet(ctx, WebStep{Step: WebStepActive, State: WebSkipped, PagesTotal: len(pages), Note: notActiveScheduled})
		return c, nil
	}
	aw, _ := s.cfg.Web.(ActiveWebScanner)
	if aw == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoScanner})
		return c, nil
	}
	plog, _ := s.cfg.Probes.(WebProbeLog)
	if plog == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveNoLog})
		return c, nil
	}
	step := WebStep{Step: WebStepActive, State: WebRunning, PagesTotal: len(pages)}
	s.webStepSet(ctx, step)
	steps := stepsOf(ctx)
	start := s.clock()
	var scanned, cut, gentle []string
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
			s.webStepSet(ctx, WebStep{Step: WebStepActive, State: WebStopped, PagesDone: step.PagesDone, PagesTotal: step.PagesTotal, Alerts: step.Alerts, CutShort: step.CutShort, Disruptive: step.Disruptive})
			return c, ctx.Err()
		}
		if err != nil || !mode.Full {
			if err != nil {
				s.cfg.Log.ErrorContext(ctx, "exposure: reading the terms before the active web scan failed", "target", st.Value, "error", err)
			}
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: notActiveTerms})
			left = len(pages) - i
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
			left = len(pages) - i
			break
		}
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
				}
				c.WebFindings = mergeWebRows(c.WebFindings, rows)
				if !res.CutShort { // a page cut short did not run every rule: an active alert it no longer reports is not "gone"
					c.WebActivePages = append(c.WebActivePages, page.URL)
				}
				scanned = append(scanned, page.URL)
				ok++
				step.Alerts += len(rows)
				step.Disruptive = step.Disruptive || pst.Mode.Disruptive
				if res.CutShort {
					cut, step.CutShort = append(cut, page.URL), true
					c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveCut, maxLineText)})
				}
				steps.end(StepZAPActive, callRan, len(rows), s.clock())
			default:
				s.cfg.Log.ErrorContext(ctx, "exposure: unreadable ZAP report of the active scan", "target", st.Value, "page", page.URL, "error", perr)
				c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveUnread, maxLineText)})
				failed++
				steps.end(StepZAPActive, callFailed, 0, s.clock())
			}
			step.PagesDone++
			s.webStepSet(ctx, step)
			continue
		}
		var un *Unavailable
		var skip *PageSkipped
		switch {
		case ctx.Err() != nil: // the run was stopped: the scanner stopped ZAP; the step reads as stopped
			step.State = WebStopped
			s.webStepSet(ctx, step)
			return c, err
		case errors.As(err, &skip), errors.As(err, &un):
			steps.end(StepZAPActive, callSkipped, 0, s.clock())
		default:
			failed++
			steps.end(StepZAPActive, callFailed, 0, s.clock())
		}
		step.PagesDone++
		switch {
		case errors.As(err, &un):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText("Active web scan (ZAP) did not run: "+un.Reason, maxLineText)})
			left = len(pages) - i - 1
			step.Note = clipText("Did not run: "+un.Reason, maxLineText)
		case errors.As(err, &skip):
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": active web scan (ZAP) did not run: "+skip.Reason, maxLineText)})
			s.webStepSet(ctx, step)
			continue
		case slow:
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveSlow, maxLineText)})
			s.webStepSet(ctx, step)
			continue
		default:
			s.cfg.Log.ErrorContext(ctx, "exposure: active web scan failed", "target", st.Value, "page", page.URL, "error", err)
			c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(page.URL+": "+notActiveFail, maxLineText)})
			s.webStepSet(ctx, step)
			continue
		}
		break
	}
	if len(gentle) > 0 && st.Mode.Disruptive {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "web", Text: clipText(fmt.Sprintf(notActiveDisrupt, strings.Join(gentle, ", ")), maxLineText)})
	}
	if len(scanned) > 0 {
		text := fmt.Sprintf("Active web scan (ZAP: spider and active rules, attack requests to the page's own address only) of %s: %s. %s.",
			plural(len(scanned), "page"), strings.Join(scanned, ", "), plural(step.Alerts, "alert"))
		if len(cut) > 0 {
			text += " Cut short at its time limit on " + strings.Join(cut, ", ") + "."
		}
		c.Checks = append(c.Checks, CheckRow{Kind: "web", At: store.FormatTS(s.clock()), Text: clipText(text, maxLineText)})
	}
	step.State = webStepEnd(ok, failed, left)
	if step.Note == "" && step.CutShort {
		step.Note = "Cut short at the time limit on " + strings.Join(cut, ", ")
	}
	s.webStepSet(ctx, step)
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
