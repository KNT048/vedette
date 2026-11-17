package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/knt048/vedette/core/store"
)

// D-629 (kien G13): a failing CISA list is never silent. The admins get one alert (critical) when both copies of the list failed at two
// scheduled checks in a row at least one interval apart (D-91 as amended: cisa.gov and CISA's GitHub copy are both asked every check;
// one failed check, a blip of the box's own network, stays quiet; a person's "Fetch now" does not count), or when the list has not been
// refreshed for six of its checks (six hours at the hourly default; a list at an admin's own address has only this rule), whichever
// comes first; and one "up to date again" when a pull works after that. One copy failing alone is a note on the feed, never an alert.
// Nothing in between. The state lives on the cisa-kev row (migration 0016) and is recorded before the notice is queued, so a restart
// neither repeats nor forgets an alert.

// kevFeedID is the CISA list.
const kevFeedID = "cisa-kev"

// KEVStaleChecks is how many checks of the CISA list may pass without a good pull before the admins are told (D-629).
const KEVStaleChecks = 6

// kevBothFailedChecks is how many scheduled checks in a row both copies of the CISA list must fail, at least one interval apart, before
// the admins are told (D-629).
const kevBothFailedChecks = 2

// ErrAlertOff is what Deps.Alert answers while nothing can be sent (the notify module is off): the watch tries again at its next run,
// quietly, and records nothing as sent.
var ErrAlertOff = errors.New("feeds: alerts are off")

// kevStaleAfter is how old the last good pull of the CISA list may be before the stale alert: KEVStaleChecks of its interval.
func kevStaleAfter(hours int) time.Duration {
	return time.Duration(KEVStaleChecks*max(hours, 1)) * time.Hour
}

// kevWatchState is the watch of the CISA list as stored (feeds_source.stale_*).
type kevWatchState struct {
	From         *time.Time // when the watch first saw the list on
	Alerted      *time.Time // when the open alert was recorded; nil: none open
	FailedSince  *time.Time // when the current run of scheduled checks where both copies failed began
	FailedChecks int        // how many such checks in a row
}

// watchKEV is the watch of the CISA list, run after the pulls of every tick of the pull job (so a box that was off pulls before it
// judges). pulled is the CISA list as this tick's own pull left it, nil when the tick did not pull it: only scheduled checks count
// toward the run of both-failed checks. It does nothing without Deps.Alert, and nothing but forget its state while the list is off.
// A time in the future (a clock that was wrong, #946 r1) is never trusted: a future last good pull is ignored, a future watch time is
// taken as now.
func (s *Service) watchKEV(ctx context.Context, pulled *sourceRow) error {
	if s.Alert == nil {
		return nil
	}
	r, err := s.st.source(ctx, kevFeedID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	w, err := s.st.kevWatch(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	if !r.Enabled { // turned off: no alert, and the next "on" counts from then (updateSettings clears it too)
		if !w.same(kevWatchState{}) {
			return s.st.setKEVWatch(ctx, kevWatchState{})
		}
		return nil
	}
	before := w
	clamp := func(t *time.Time) *time.Time {
		if t != nil && t.After(now) {
			return &now
		}
		return t
	}
	w.From, w.Alerted, w.FailedSince = clamp(w.From), clamp(w.Alerted), clamp(w.FailedSince)
	if w.From == nil { // the first look while it is on: the six checks count from here at the latest
		w.From = &now
	}
	builtin := r.URL == s.kevPrimary()
	switch {
	case r.Status == "ok" || !builtin:
		w.FailedSince, w.FailedChecks = nil, 0
	case pulled != nil && pulled.Status == "error": // this tick's own check: both copies failed
		if w.FailedSince == nil {
			w.FailedSince = &now
		}
		w.FailedChecks++
	}
	since := *w.From
	if r.LastSuccess != nil && r.LastSuccess.After(since) && !r.LastSuccess.After(now) {
		since = *r.LastSuccess
	}
	iv := interval(r.IntervalHours)
	bothFailed := w.FailedChecks >= kevBothFailedChecks && w.FailedSince != nil && now.Sub(*w.FailedSince) >= iv
	switch {
	case w.Alerted == nil && (bothFailed || now.Sub(since) >= kevStaleAfter(r.IntervalHours)):
		// recorded first: a stop between the two leaves an alert unsent rather than sent twice
		id := "feeds-kev-stale-" + since.UTC().Format("20060102T150405Z")
		w.Alerted = &now
		if err := s.st.setKEVWatch(ctx, w); err != nil {
			return err
		}
		title, text := kevStaleTitle, s.kevStaleNotice(ctx, r, since)
		if err := s.Alert(ctx, id, title, text, true); err != nil {
			w.Alerted = nil
			if rerr := s.st.setKEVWatch(ctx, w); rerr != nil {
				return errors.Join(quietOff(err), rerr)
			}
			return quietOff(err)
		}
		return nil
	case w.Alerted != nil && r.Status == "ok" && r.LastSuccess != nil && r.LastSuccess.After(*w.Alerted):
		id := "feeds-kev-fresh-" + w.Alerted.UTC().Format("20060102T150405Z")
		alerted := w.Alerted
		w.Alerted = nil
		if err := s.st.setKEVWatch(ctx, w); err != nil {
			return err
		}
		title, text := kevFreshNotice(r)
		if err := s.Alert(ctx, id, title, text, false); err != nil {
			w.Alerted = alerted
			if rerr := s.st.setKEVWatch(ctx, w); rerr != nil {
				return errors.Join(quietOff(err), rerr)
			}
			return quietOff(err)
		}
		return nil
	}
	if !w.same(before) {
		return s.st.setKEVWatch(ctx, w)
	}
	return nil
}

// same reports whether two watch states hold the same values.
func (w kevWatchState) same(o kevWatchState) bool {
	eq := func(a, b *time.Time) bool { return (a == nil) == (b == nil) && (a == nil || a.Equal(*b)) }
	return eq(w.From, o.From) && eq(w.Alerted, o.Alerted) && eq(w.FailedSince, o.FailedSince) && w.FailedChecks == o.FailedChecks
}

// quietOff drops ErrAlertOff: notify being off is not a failure of the pull job, the alert waits for it.
func quietOff(err error) error {
	if errors.Is(err, ErrAlertOff) {
		return nil
	}
	return fmt.Errorf("feeds: send the alert about the CISA list: %w", err)
}

// stamp is a time in an alert: UTC, said so (an alert is read away from the box's own screen).
func stamp(t time.Time) string { return t.UTC().Format("2 Jan 2006, 15:04") + " UTC" }

// kevStaleTitle is the title of the alert.
const kevStaleTitle = "Vedette cannot update the list of exploited vulnerabilities"

// kevStaleNotice is the text of the alert: what failed, since when the list is not fresh, what it means, what to check
// (the two hosts of the built-in address, or the admin's own host, #946 r1).
func (s *Service) kevStaleNotice(ctx context.Context, r sourceRow, since time.Time) (text string) {
	if r.Status == "error" && r.Error != nil && r.LastFetch != nil {
		if e := oneLine(*r.Error, 300); e != nil {
			text = fmt.Sprintf("The check at %s failed: %s. ", stamp(*r.LastFetch), *e)
		}
	}
	if r.LastSuccess != nil {
		text += "The list on the box is from the last good pull, at " + stamp(*r.LastSuccess) + "."
	} else {
		text += fmt.Sprintf("No pull has worked since %s, so the box has no list yet.", stamp(since))
	}
	reach := "www.cisa.gov or raw.githubusercontent.com"
	if r.URL == s.kevPrimary() { // a clock far from the servers' is the cause to name, not the network (#946 r2)
		if cs, _, err := s.st.kevCopies(ctx); err == nil {
			if clock := skewText(cs.SkewSecs); clock != "" {
				return text + " Until it works again, vulnerabilities CISA newly lists do not reach your alerts. " + clock +
					" You get one more message when the list is up to date again."
			}
		}
	}
	if r.URL != s.kevPrimary() {
		reach = "the address set for this list"
		if u, err := url.Parse(r.URL); err == nil && u.Hostname() != "" {
			reach = u.Hostname() + ", the address set for this list"
		}
	}
	return text + " Until it works again, vulnerabilities CISA newly lists do not reach your alerts. Vedette keeps trying " +
		every(r.IntervalHours) + ". Check that this box can reach " + reach + " (Settings, Feeds). " +
		"You get one more message when the list is up to date again."
}

// kevFreshNotice is the title and text of the "up to date again" message.
func kevFreshNotice(r sourceRow) (title, text string) {
	text = "CISA's list of exploited vulnerabilities was checked again at " + stamp(*r.LastSuccess)
	if r.AnsweredBy != nil {
		text += "; the newest list on the box came from " + copyLabel(*r.AnsweredBy)
	}
	return "The list of exploited vulnerabilities is up to date again", text + ". Vulnerabilities it added in the meantime are matched against your devices now."
}

func every(hours int) string {
	if hours <= 1 {
		return "every hour"
	}
	return fmt.Sprintf("every %d hours", hours)
}

// kevWatch reads the watch of the CISA list.
func (s *Store) kevWatch(ctx context.Context) (kevWatchState, error) {
	var f, a, fs *string
	var w kevWatchState
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT stale_watch_from, stale_alerted_at, stale_failed_since, stale_failed_checks FROM feeds_source WHERE id = ?`,
		kevFeedID).Scan(&f, &a, &fs, &w.FailedChecks); err != nil {
		return w, fmt.Errorf("feeds: read the watch of the CISA list: %w", err)
	}
	var err error
	for _, x := range []struct {
		raw *string
		out **time.Time
	}{{f, &w.From}, {a, &w.Alerted}, {fs, &w.FailedSince}} {
		if *x.out, err = optTS(x.raw); err != nil {
			return w, fmt.Errorf("feeds: stored watch time: %w", err)
		}
	}
	return w, nil
}

func (s *Store) setKEVWatch(ctx context.Context, w kevWatchState) error {
	ts := func(t *time.Time) any {
		if t == nil {
			return nil
		}
		return store.FormatTS(*t)
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET stale_watch_from = ?, stale_alerted_at = ?, stale_failed_since = ?, stale_failed_checks = ? WHERE id = ?`,
			ts(w.From), ts(w.Alerted), ts(w.FailedSince), w.FailedChecks, kevFeedID); err != nil {
			return fmt.Errorf("feeds: keep the watch of the CISA list: %w", err)
		}
		return nil
	})
}
