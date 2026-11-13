package feeds

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"
)

// NVD pull robustness (W3-1, D-500). Measured from the N100 on 2026-11-13: one page answered in 3.1 s, the next
// only started its answer after 20.6 s, an earlier one after more than 30 s, and NVD answers 503 when it is busy (its
// documentation asks clients to retry with a back-off). So one page waits longer, is tried again, and a pull that
// could not finish keeps its pages and goes on from there at the next tick instead of starting over.
const (
	// nvdPageTimeout bounds one request; nvdHeaderTimeout is how long NVD may take before it starts to answer.
	nvdPageTimeout   = 3 * time.Minute
	nvdHeaderTimeout = 2 * time.Minute
	// nvdMaxRetryAfter caps a Retry-After NVD sends: a longer one ends the pull, which goes on at the next tick.
	nvdMaxRetryAfter = 15 * time.Minute
	// nvdResumeKeep: pages kept longer than this without a new page are dropped, and the next pull starts again.
	nvdResumeKeep = 24 * time.Hour
)

// nvdFeedID is the built-in feed of the NVD affected versions.
const nvdFeedID = "nvd-kev"

// nvdRetryWaits are the waits before the second, third and fourth try of one page; a longer Retry-After wins.
var nvdRetryWaits = []time.Duration{6 * time.Second, 30 * time.Second, 2 * time.Minute}

// errNVDPaused ends a pull of nvd-kev that kept its pages to go on later (nvdRun): nothing is written, it is not a
// failure of the feed (no error status, no back-off, no fetch.failed), and the feed row tells how far it got.
var errNVDPaused = errors.New("feeds: the NVD pull is paused and goes on later")

// nvdRun is one pull of the NVD affected versions, kept between ticks while it is not finished. Only the pulling
// goroutine (it holds the feed lock) touches the pages; the progress fields are read by the handlers under nvdMu.
type nvdRun struct {
	url      string
	full     bool
	from, to time.Time
	affected map[string][]AffectedRow
	st       Stats
	bytes    int

	start, total, pages int       // records and pages done; total is NVD's count (0 until the first page)
	running             bool      // a pull is working on it now
	busy                string    // why the last try failed ("NVD was busy (HTTP 503)"), "" after a good page
	retryAt             time.Time // the next try of the page (running) or the next pull (paused)
	stalls              int       // pulls in a row that ended without a new page
	updated             time.Time // the last good page
}

// nvdState is the run of the Service (one NVD feed per box).
func (s *Service) nvdState() *nvdRun {
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	return s.nvd
}

// nvdResumeAt says when a paused pull of nvd-kev goes on (ok false: none is paused). RunPull uses it instead of the
// feed's stored state, which still says what the last finished pull did.
func (s *Service) nvdResumeAt() (time.Time, bool) {
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	if s.nvd == nil || s.nvd.running {
		return time.Time{}, false
	}
	return s.nvd.retryAt, true
}

// live is the feed row as the GUI shows it: while the NVD versions load (or wait to go on), the row says how far
// the pull got and why it waits, instead of the last error or "not fetched yet" alone (W3-1). A feed that never
// finished a pull stays "never": its versions are not loaded yet.
func (s *Service) live(r sourceRow) sourceRow {
	if r.ID != nvdFeedID {
		return r
	}
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	run := s.nvd
	if run == nil || run.url != r.URL {
		return r
	}
	text := run.text(s.now())
	r.Error = &text
	if r.Records == nil {
		r.Status = "never"
	}
	return r
}

// text is the progress line: "Loading version ranges from NVD: page 8 of 18. NVD was busy (HTTP 503); trying page 8
// again in 30 s." Called under nvdMu.
func (r *nvdRun) text(now time.Time) string {
	verb := "Updating"
	if r.full {
		verb = "Loading"
	}
	of := ""
	if r.total > 0 {
		of = fmt.Sprintf(" of %d", (r.total+NVDPageSize-1)/NVDPageSize)
	}
	if !r.running {
		t := fmt.Sprintf("%s version ranges from NVD: %d%s pages done.", verb, r.pages, of)
		if r.busy != "" {
			t += " " + r.busy + "."
		}
		if wait := r.retryAt.Sub(now); wait > 0 {
			return t + " Vedette goes on in " + roughly(wait) + "."
		}
		return t + " Vedette goes on at the next check (every 5 minutes)."
	}
	t := fmt.Sprintf("%s version ranges from NVD: page %d%s.", verb, r.pages+1, of)
	if r.busy != "" {
		t += fmt.Sprintf(" %s; trying page %d again", r.busy, r.pages+1)
		if wait := r.retryAt.Sub(now); wait > 0 {
			t += " in " + roughly(wait)
		}
		t += "."
	}
	return t
}

// roughly writes a wait as people say it: "30 s", "2 min".
func roughly(d time.Duration) string {
	if d < 90*time.Second {
		return fmt.Sprintf("%d s", int(d.Round(time.Second)/time.Second))
	}
	return fmt.Sprintf("%d min", int(d.Round(time.Minute)/time.Minute))
}

// nvdBusy is the reason of a failed try as the feed row says it.
func nvdBusy(err error) string {
	var se *StatusError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("NVD was busy (HTTP %d)", se.Code)
	case errors.Is(err, context.DeadlineExceeded):
		return "NVD did not answer in time"
	}
	return "NVD could not be reached"
}

// nvdRetryable says whether a failed request is worth trying again: NVD busy or slow, or the connection broke. An
// answer Vedette refuses (too large, unreadable, a refused address or redirect) is not.
func nvdRetryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	var fe *Error
	return !errors.As(err, &fe) && !errors.Is(err, ErrBlockedAddress) && !errors.Is(err, ErrBoxAddrsUnknown) &&
		!errors.Is(err, ErrRedirect) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrInvalidURL)
}

// sleep waits d or until ctx ends; tests replace it (Service.wait) so no test waits for real.
func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.wait != nil {
		return s.wait(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// nvdPage fetches one page, trying again after nvdRetryWaits (or NVD's Retry-After when longer) while NVD is busy or
// slow. A wait that would not end before the pull's deadline is not started: the pull pauses and goes on later.
func (s *Service) nvdPage(ctx context.Context, run *nvdRun, u string) (*Response, error) {
	for try := 0; ; try++ {
		rctx, cancel := context.WithTimeout(ctx, nvdPageTimeout)
		resp, err := s.Fetcher.Fetch(rctx, Request{URL: u, HeaderTimeout: nvdHeaderTimeout})
		cancel()
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil || !nvdRetryable(err) {
			return nil, err
		}
		wait := time.Duration(0)
		if try < len(nvdRetryWaits) {
			wait = nvdRetryWaits[try]
		}
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > wait {
			wait = min(se.RetryAfter, nvdMaxRetryAfter)
		}
		s.nvdMu.Lock()
		run.busy, run.retryAt = nvdBusy(err), s.now().Add(wait)
		s.nvdMu.Unlock()
		if try >= len(nvdRetryWaits) {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait {
			return nil, err // the pull's budget ends first: pause here, go on after the wait
		}
		s.Log.InfoContext(ctx, "NVD is busy; trying the page again", "page", run.pages+1, "wait", wait, "error", err)
		if err := s.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// buildNVD asks the NVD CVE API 2.0 for the affected versions of the CVEs CISA lists (?hasKev, D-500), NVDPageSize
// per request with nvdPause between requests. After a good pull less than nvdIncrementalDays old, only the CVEs NVD
// changed since one day before that pull are asked for; otherwise everything, and CVEs NVD no longer lists go.
//
// Nothing is written until every page is in, so a pull that never finished never deletes or half updates anything.
// A pull that got some pages and then stopped (NVD busy after every try, its Retry-After, the pull budget) keeps
// them and returns errNVDPaused; the next pull goes on from the next page (W3-1). One that got no page fails.
func (s *Service) buildNVD(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	now := s.now()
	run := s.nvdState()
	if run != nil && (run.url != src.URL || now.Sub(run.updated) > nvdResumeKeep) {
		run = nil // the address changed, or the pages are too old to finish with
	}
	if run == nil {
		have, err := s.st.affectedCount(ctx)
		if err != nil {
			return p, err
		}
		var from, to time.Time
		if have > 0 && src.Status == "ok" && src.LastSuccess != nil && now.Sub(*src.LastSuccess) < nvdIncrementalDays*24*time.Hour {
			from, to = src.LastSuccess.Add(-24*time.Hour), now
		}
		run = &nvdRun{url: src.URL, full: from.IsZero(), from: from, to: to, affected: map[string][]AffectedRow{}, updated: now}
	}
	s.nvdMu.Lock()
	run.running, run.busy, s.nvd = true, "", run
	s.nvdMu.Unlock()
	pagesBefore := run.pages

	err := s.nvdPages(ctx, run)
	s.nvdMu.Lock()
	defer s.nvdMu.Unlock()
	run.running = false
	switch {
	case err == nil:
		s.nvd = nil
	case run.pages == 0:
		s.nvd = nil // nothing to go on from: a plain failure, recorded on the feed
		if nvdRetryable(err) && ctx.Err() == nil {
			why := run.busy
			if why == "" {
				why = nvdBusy(err)
			}
			return p, &Error{Err: err, Detail: why + " for the first page, after every try. Vedette tries again later; the versions loaded before are kept."}
		}
		return p, err
	default:
		if run.pages > pagesBefore {
			run.stalls = 0
		} else {
			run.stalls++
		}
		switch now := s.now(); {
		case run.busy == "": // the pull's budget ran out between good pages: go on at the next tick
			run.retryAt = now
		case run.retryAt.Before(now.Add(BackoffBase)): // NVD stayed busy: wait at least 5 min, longer while no page comes
			run.retryAt = now.Add(max(Backoff(run.stalls), BackoffBase))
		}
		s.Log.InfoContext(ctx, "the NVD pull paused; it goes on later", "pages", run.pages, "total", run.total, "at", run.retryAt, "error", err)
		return p, errNVDPaused
	}

	p.out = outcome{OK: true, Bytes: run.bytes}
	p.hasAffected, p.affectedFull, p.affected = true, run.full, run.affected
	st := run.st
	if len(st.Reasons) > 3 {
		st.Reasons = st.Reasons[:3]
	}
	if run.full && len(run.affected) == 0 {
		return p, accepted(st) // a full pull with nothing never empties the table
	}
	p.out.fill(st, len(run.affected))
	return p, nil
}

// nvdPages fetches the pages of run from run.start on.
func (s *Service) nvdPages(ctx context.Context, run *nvdRun) error {
	for first := true; ; first = false {
		if run.pages >= nvdMaxPages {
			return fail(ErrBadSample, "NVD answered more than %d pages; Vedette stopped and kept the versions it had.", nvdMaxPages)
		}
		if !first || run.pages > 0 {
			if err := s.sleep(ctx, nvdPause); err != nil {
				return err
			}
		}
		u, err := NVDPageURL(run.url, run.start, run.from, run.to)
		if err != nil {
			return err
		}
		resp, err := s.nvdPage(ctx, run, u)
		if err != nil {
			return err
		}
		d, err := ParseNVD(resp.Body)
		if err != nil {
			return err
		}
		if d.Returned == 0 && run.start < d.Total { // review M3: a short answer must not end a full pull (it would delete the rest)
			return fail(ErrBadSample, "NVD answered an empty page at record %d of %d; Vedette kept the versions it had.", run.start, d.Total)
		}
		run.bytes += len(resp.Body)
		run.st.Accepted += d.Accepted
		run.st.Rejected += d.Rejected
		if len(run.st.Reasons) < 3 {
			run.st.Reasons = append(run.st.Reasons, d.Reasons...)
		}
		maps.Copy(run.affected, d.Affected)
		s.nvdMu.Lock()
		run.start += d.Returned
		run.total = d.Total
		run.pages++
		run.busy, run.updated = "", s.now()
		s.nvdMu.Unlock()
		if run.start >= d.Total {
			return nil
		}
	}
}
