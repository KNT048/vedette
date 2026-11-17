package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// D-629 (kien G13): a failing CISA list is never silent. The admins get one alert when the list has not been refreshed for six of its
// checks (six hours at the hourly default), so a short outage stays quiet, and one "up to date again" when a pull works after that.
// Nothing in between. The state lives on the cisa-kev row (migration 0016), so a restart neither repeats nor forgets an alert.

// kevFeedID is the CISA list.
const kevFeedID = "cisa-kev"

// KEVStaleChecks is how many checks of the CISA list may pass without a good pull before the admins are told (D-629).
const KEVStaleChecks = 6

// ErrAlertOff is what Deps.Alert answers while nothing can be sent (the notify module is off): the watch tries again at its next run,
// quietly, and records nothing as sent.
var ErrAlertOff = errors.New("feeds: alerts are off")

// kevStaleAfter is how old the last good pull of the CISA list may be before the stale alert: KEVStaleChecks of its interval.
func kevStaleAfter(hours int) time.Duration {
	return time.Duration(KEVStaleChecks*max(hours, 1)) * time.Hour
}

// watchKEV is the stale watch of the CISA list, run after the pulls of every tick of the pull job (so a box that was off pulls before
// it judges). It does nothing without Deps.Alert, and nothing but forget its state while the list is turned off.
func (s *Service) watchKEV(ctx context.Context) error {
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
	from, alerted, err := s.st.kevWatch(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	if !r.Enabled { // turned off: no alert, and the next "on" counts from then (updateSettings clears it too)
		if from != nil || alerted != nil {
			return s.st.setKEVWatch(ctx, nil, nil)
		}
		return nil
	}
	if from == nil { // the first look while it is on: the six checks count from here at the latest
		from = &now
		if err := s.st.setKEVWatch(ctx, from, alerted); err != nil {
			return err
		}
	}
	since := *from
	if r.LastSuccess != nil && r.LastSuccess.After(since) {
		since = *r.LastSuccess
	}
	switch {
	case alerted == nil && now.Sub(since) >= kevStaleAfter(r.IntervalHours):
		title, text := kevStaleNotice(r, since)
		if err := s.Alert(ctx, "feeds-kev-stale-"+since.UTC().Format("20060102T150405Z"), title, text); err != nil {
			return quietOff(err)
		}
		return s.st.setKEVWatch(ctx, from, &now)
	case alerted != nil && r.LastSuccess != nil && r.LastSuccess.After(*alerted):
		why, err := s.st.answeredWhy(ctx)
		if err != nil {
			return err
		}
		title, text := kevFreshNotice(r, why)
		if err := s.Alert(ctx, "feeds-kev-fresh-"+alerted.UTC().Format("20060102T150405Z"), title, text); err != nil {
			return quietOff(err)
		}
		return s.st.setKEVWatch(ctx, from, nil)
	}
	return nil
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

// kevStaleNotice is the title and text of the stale alert: since when, the last error, what it means for the alerts, what to check.
func kevStaleNotice(r sourceRow, since time.Time) (title, text string) {
	title = "Vedette cannot update the list of exploited vulnerabilities"
	last := "it has not been pulled yet"
	if r.LastSuccess != nil {
		last = "the last good pull was at " + stamp(*r.LastSuccess)
	}
	text = fmt.Sprintf("CISA's list of exploited vulnerabilities has not been refreshed since %s: %s.", stamp(since), last)
	if r.Status == "error" && r.Error != nil {
		if e := oneLine(*r.Error, 300); e != nil {
			text += " The last check failed: " + *e + "."
		}
	}
	return title, text + " Until it works again, vulnerabilities CISA newly lists do not reach your alerts. Vedette keeps trying " +
		every(r.IntervalHours) + ". Check that this box can reach www.cisa.gov or raw.githubusercontent.com (Settings, Feeds). " +
		"You get one more message when the list is up to date again."
}

// kevFreshNotice is the title and text of the "up to date again" message.
func kevFreshNotice(r sourceRow, why *string) (title, text string) {
	text = "CISA's list of exploited vulnerabilities was refreshed at " + stamp(*r.LastSuccess)
	switch {
	case r.AnsweredBy != nil && *r.AnsweredBy == AnsweredMirror && why != nil:
		text += ", from CISA's GitHub copy, because " + *why
	case r.AnsweredBy != nil && *r.AnsweredBy == AnsweredMirror:
		text += ", from CISA's GitHub copy"
	}
	return "The list of exploited vulnerabilities is up to date again", text + ". Vulnerabilities it added in the meantime are matched against your devices now."
}

func every(hours int) string {
	if hours <= 1 {
		return "every hour"
	}
	return fmt.Sprintf("every %d hours", hours)
}

// answeredWhy is why cisa.gov did not answer when CISA's GitHub copy answered the last good pull of the CISA list (kien G13), nil when
// cisa.gov answered or the reason is not known. Read on its own, not with sourceCols, so code that reads the feed rows still works on
// the schema of the migrations before 0016 (the migration tests run it there).
func (s *Store) answeredWhy(ctx context.Context) (*string, error) {
	var why *string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT answered_why FROM feeds_source WHERE id = ?`, kevFeedID).Scan(&why)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feeds: read why the CISA GitHub copy answered: %w", err)
	}
	return why, nil
}

// kevWatch reads the stale watch of the CISA list: since when it was seen on, and when the stale alert went out (nil: none open).
func (s *Store) kevWatch(ctx context.Context) (from, alerted *time.Time, err error) {
	var f, a *string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT stale_watch_from, stale_alerted_at FROM feeds_source WHERE id = ?`, kevFeedID).Scan(&f, &a); err != nil {
		return nil, nil, fmt.Errorf("feeds: read the watch of the CISA list: %w", err)
	}
	if from, err = optTS(f); err != nil {
		return nil, nil, fmt.Errorf("feeds: stored watch time: %w", err)
	}
	if alerted, err = optTS(a); err != nil {
		return nil, nil, fmt.Errorf("feeds: stored alert time: %w", err)
	}
	return from, alerted, nil
}

func (s *Store) setKEVWatch(ctx context.Context, from, alerted *time.Time) error {
	ts := func(t *time.Time) any {
		if t == nil {
			return nil
		}
		return store.FormatTS(*t)
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET stale_watch_from = ?, stale_alerted_at = ? WHERE id = ?`, ts(from), ts(alerted), kevFeedID); err != nil {
			return fmt.Errorf("feeds: keep the watch of the CISA list: %w", err)
		}
		return nil
	})
}
