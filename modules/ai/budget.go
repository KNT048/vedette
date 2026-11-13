package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/jobs"
)

// The monthly AI budget (D-531, beta item 23). There is no daily cap and no per-job quota: the box spends up to the budget the
// administrator set for the month, warns loudly at 80 % (Home and the alert channels) and stops every AI job at 100 % with a message
// that says why and how to go on. What is left per job is a fuse against a loop: more than fuseCalls calls of one job in one minute is
// not a real workload, so the rest of that minute is refused and the trip is written to the audit log.

const (
	budgetWarnPct = 80 // the early warning
	// scheduledPausePct is where scheduled AI jobs (today the response plans, Actor "system") stop for the month, so one background
	// job cannot drain the budget: questions, explanations and the other jobs a person starts keep the last 20 % (review of #688).
	scheduledPausePct = 80
	heldRetry         = 15              // seconds a call refused by the holds of calls in flight is told to wait (ErrBudgetHeld)
	budgetWatch       = 5 * time.Minute // how often the alert job compares the meter with the budgets
	fuseCalls         = 30              // calls of one job in one minute before the fuse trips: no person or schedule makes that many
	fuseSpan          = time.Minute
)

// renewDay is the day the budget starts again, as people read it ("1 December 2026").
func (s *Service) renewDay() string { return s.meter.Renews().Format("2 January 2006") }

// budgetStop is the sentence for the shared budget being used up; it starts with a lower-case letter so it can follow a clause.
func (s *Service) budgetStop() string {
	return fmt.Sprintf("this month's AI budget of %s tokens is used up, so AI jobs are stopped until it renews on %s. An administrator can raise the budget in Settings, AI assistant.",
		number(s.snap.Load().cfg.MonthlyBudget), s.renewDay())
}

// budgetReached is the 429 of a budget that is used up (or of the scheduled-job pause), with retry_after: the seconds until it renews.
func (s *Service) budgetReached(msg string) error {
	wait := max(int(math.Ceil(s.meter.Renews().Sub(s.cfg.Clock()).Seconds())), 1)
	return apierr.New(http.StatusTooManyRequests, "budget_reached", msg).With("retry_after", wait)
}

// budgetHeld is the 429 of a call that the holds of other calls in flight refused: the budget is not used up, so it never says so. A
// non-empty lead is what happened first ("The AI's answer was cut off …"); it is followed by ", and".
func (s *Service) budgetHeld(lead string) error {
	msg := "Other AI calls running now are holding the rest of this month's AI budget, so nothing was sent. Try again in a few seconds."
	if lead != "" {
		msg = lead + ", and other AI calls running now are holding the rest of this month's AI budget, so it was not asked again. Try again in a few seconds."
	}
	return apierr.New(http.StatusTooManyRequests, "rate_limited", msg).With("retry_after", heldRetry)
}

// scheduledPause stops a scheduled call (Actor "system") before anything is done or recorded: when the shared budget is used up (one
// 429 budget_reached, no capped row every 5 minutes for the rest of the month) or past scheduledPausePct. The first stop of a month
// writes one box log line; the rest are silent.
func (s *Service) scheduledPause(ctx context.Context, job Job) error {
	var msg, why string
	switch {
	case s.meter.UsedUp():
		msg, why = capitalize(s.budgetStop()), "used up"
	case s.meter.Reached(scheduledPausePct):
		msg, why = fmt.Sprintf("Scheduled AI jobs such as response plans pause at %d %% of this month's AI budget, so questions and explanations keep the rest. They start again when the budget renews on %s or an administrator raises it in Settings, AI assistant.",
			scheduledPausePct, s.renewDay()), "paused"
	default:
		return nil
	}
	s.noteScheduledStop(ctx, job, why)
	return s.budgetReached(msg)
}

// noteScheduledStop writes the one box log line a month per reason for a scheduled job that is stopped by a budget; the rest are silent.
func (s *Service) noteScheduledStop(ctx context.Context, job Job, why string) {
	key := s.cfg.Clock().In(s.loc).Format("2006-01") + " " + why
	s.fuseMu.Lock()
	note := s.pauseNoted != key
	s.pauseNoted = key
	s.fuseMu.Unlock()
	if note {
		s.cfg.Log.InfoContext(ctx, "ai: scheduled AI jobs stop for this month's budget", "job", string(job), "reason", why)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ErrAlertOff is what Config.Alert answers (wrapped) when the alert channels are switched off (the notify module is off): nothing can
// be sent, which is no failure of the budget watch; it sends the notice once notify is on again, if the budget is still past it.
var ErrAlertOff = errors.New("ai: the alert channels are off")

// fuseWindow counts the calls of one job in the current minute.
type fuseWindow struct {
	start time.Time
	n     int
	noted bool // the trip of this window is in the audit log
}

// checkFuse counts one call of the job and refuses it when the job has made fuseCalls calls in this minute already. The first refusal
// of a window writes one audit line (ai.fuse) and one log line; later ones of the same window only refuse. Nothing is sent and no
// activity row is written: no call was made.
func (s *Service) checkFuse(ctx context.Context, job Job) error {
	now := s.cfg.Clock()
	s.fuseMu.Lock()
	if s.fuse == nil {
		s.fuse = map[Job]*fuseWindow{}
	}
	w := s.fuse[job]
	if w == nil || now.Sub(w.start) >= fuseSpan || now.Before(w.start) {
		w = &fuseWindow{start: now}
		s.fuse[job] = w
	}
	if w.n < fuseCalls {
		w.n++
		s.fuseMu.Unlock()
		return nil
	}
	note := !w.noted
	w.noted = true
	wait := max(int(math.Ceil(w.start.Add(fuseSpan).Sub(now).Seconds())), 1)
	s.fuseMu.Unlock()
	msg := fmt.Sprintf("The AI job %s asked for the AI more than %d times in one minute, which looks like a loop, so Vedette stopped it for the rest of the minute. Nothing was sent. If it keeps happening, the audit log and the box log name the job.", job.Name(), fuseCalls)
	if note {
		s.cfg.Log.WarnContext(ctx, "ai: the runaway fuse stopped a job", "job", string(job), "calls_per_minute", fuseCalls)
		detail := fmt.Sprintf("More than %d calls of %s in one minute: the rest of the minute is refused (runaway fuse, D-531).", fuseCalls, job)
		wctx := context.WithoutCancel(ctx) // the caller may be gone; the trip is still recorded
		if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
			return s.auditTx(wctx, tx, "system", "ai.fuse", string(job), detail)
		}); err != nil {
			s.cfg.Log.WarnContext(ctx, "ai: could not write the audit line of the runaway fuse", "error", err)
		}
	}
	return apierr.New(http.StatusTooManyRequests, "rate_limited", msg).With("retry_after", wait)
}

// BudgetView is this month's use of one budget: the box's shared one or a profile's own.
type BudgetView struct {
	Scope  string `json:"scope"` // "box" or "profile"
	ID     string `json:"id"`    // the profile id; "" for the box
	Name   string `json:"name"`  // the profile name; "" for the box
	Used   int    `json:"used"`
	Budget int    `json:"budget"`
}

// pct is the share of the budget used, rounded down.
func (b BudgetView) pct() int {
	if b.Budget <= 0 {
		return 0
	}
	return int(min(int64(b.Used)*100/int64(b.Budget), 1000))
}

// budgets lists the box's budget and every profile's, with this month's use from the meter.
func (s *Service) budgets() []BudgetView {
	sn := s.snap.Load()
	out := []BudgetView{{Scope: "box", Used: s.meter.Used(), Budget: sn.cfg.MonthlyBudget}}
	for _, p := range sn.profiles {
		out = append(out, BudgetView{Scope: "profile", ID: p.ID, Name: p.Name, Used: s.meter.ProfileUsed(p.ID), Budget: p.MonthlyBudget})
	}
	return out
}

// budgetAlerts is what ai_setting key `budget_alerts` keeps: the month and the alerts already sent in it. A key names the scope, the
// threshold and the budget it was sent for ("box:80:6000000"), so raising a budget arms its alerts again.
type budgetAlerts struct {
	Month string   `json:"month"`
	Sent  []string `json:"sent"`
}

// BudgetJobs is the alert job of the monthly budget, offered only when Alert is wired (it calls out to notify, so it is no
// housekeeping and runs only while the module is on).
func (s *Service) budgetJobs() []jobs.Job {
	if s.cfg.Alert == nil {
		return nil
	}
	return []jobs.Job{{Module: "ai", Name: "budget-watch", Every: budgetWatch, Run: s.watchBudget}}
}

// watchBudget sends one notice per budget and threshold and month: medium at 80 %, high at 100 %. A notice that could not be sent is
// tried again at the next run (notify off: quietly, ErrAlertOff); one that was sent is remembered in ai_setting, so a restart does not
// send it again.
func (s *Service) watchBudget(ctx context.Context) error {
	month := s.cfg.Clock().In(s.loc).Format("2006-01")
	var st budgetAlerts
	var raw string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'budget_alerts'`).Scan(&raw)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return fmt.Errorf("ai: read the budget alerts: %w", err)
	default:
		_ = json.Unmarshal([]byte(raw), &st) // a value that cannot be read only means alerts may be sent again
	}
	if st.Month != month {
		st = budgetAlerts{Month: month}
	}
	renew := s.renewDay()
	var sendErr error
	sent := false
	for _, b := range s.budgets() {
		pct := b.pct()
		for _, th := range []int{100, budgetWarnPct} {
			if pct < th {
				continue
			}
			who := "box"
			if b.Scope == "profile" {
				who = b.ID
			}
			key := fmt.Sprintf("%s:%d:%d", who, th, b.Budget)
			if slices.Contains(st.Sent, key) {
				break // the higher threshold was sent: the lower one adds nothing
			}
			title, text := budgetNotice(b, th, renew)
			if err := s.cfg.Alert(ctx, "ai-budget-"+month+"-"+key, title, text, th >= 100); err != nil {
				if !errors.Is(err, ErrAlertOff) { // notify off: nothing to send, not an error of the job every 5 minutes
					sendErr = err
				}
				break
			}
			st.Sent = append(st.Sent, key)
			if th == 100 { // 100 % says all that 80 % would: do not send both
				st.Sent = append(st.Sent, fmt.Sprintf("%s:%d:%d", who, budgetWarnPct, b.Budget))
			}
			sent = true
			break
		}
	}
	if sent {
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			return upsertSetting(ctx, tx, "budget_alerts", st, s.cfg.Clock(), "system")
		}); err != nil {
			return err
		}
	}
	if sendErr != nil {
		return fmt.Errorf("ai: send the budget alert: %w", sendErr)
	}
	return nil
}

// budgetNotice is the title and text of a budget alert. Names of profiles are the administrator's own; no key, no content.
func budgetNotice(b BudgetView, th int, renew string) (title, text string) {
	what := "The box's monthly AI budget"
	if b.Scope == "profile" {
		what = fmt.Sprintf("The monthly budget of the AI profile %q", clipRunes(b.Name, 60))
	}
	use := fmt.Sprintf("%s of %s tokens used this month (%d %%)", number(b.Used), number(b.Budget), b.pct())
	if th >= 100 {
		stop := "AI jobs are stopped"
		if b.Scope == "profile" {
			stop = "Jobs of this profile go to their fallback profile, or stop when they have none"
		}
		return what + " is used up", fmt.Sprintf("%s is used up: %s. %s until the budget renews on %s. An administrator can raise it in Settings, AI assistant.", what, use, stop, renew)
	}
	if b.Scope == "box" {
		return what + " is at 80 %", fmt.Sprintf("%s is nearly used up: %s. Response plans are paused, so questions and explanations keep the rest; at 100 %% every AI job stops until the budget renews on %s. An administrator can raise it in Settings, AI assistant.", what, use, renew)
	}
	return what + " is at 80 %", fmt.Sprintf("%s is nearly used up: %s. At 100 %% AI jobs stop until the budget renews on %s. An administrator can raise it in Settings, AI assistant.", what, use, renew)
}
