package run

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"
)

// summary is the one line of words a run's state reads as on every page (Run.Summary): the Runs tab, the run page and every
// "Open the run" place show it instead of putting it together from the columns themselves.
func (m *Manager) summary(ctx context.Context, r Run) string {
	k, known := m.kind(r.Module, r.Kind)
	count := ""
	if r.Total > 0 {
		count = Count(r.Done, r.Total, k.Unit)
	}
	estimate := func() string {
		if !known || k.Estimate == nil {
			return ""
		}
		return k.Estimate(ctx, r)
	}
	switch r.Status {
	case Queued:
		switch {
		case r.BlockedBy != nil:
			return m.queuedBehind(ctx, r)
		case m.cfg.Gate != nil && !m.cfg.Gate.Enabled(r.Module):
			return "Queued; it starts when its module is turned on again"
		case r.StartedAt != nil:
			return join("Queued to go on where it stopped", count)
		}
		return "Queued; it starts in a moment"
	case Waiting:
		what := "a person to resume it"
		if r.WaitingFor != nil {
			what = *r.WaitingFor
		}
		return join("Waiting for "+what, count, estimate())
	case Running:
		if count == "" {
			return "Running"
		}
		return join(count, estimate())
	case Stopping:
		return join("Stopping: "+deref(r.StopReason, "a stop was asked"), count)
	case Done:
		if r.Total > 0 {
			return "Done: " + Count(r.Done, r.Total, k.Unit)
		}
		return "Done"
	case Partial:
		return join("Partly done: "+deref(r.Error, "part of the work was not done"), count)
	case Failed:
		return "Failed: " + deref(r.Error, "the run did not finish")
	case Stopped:
		s := deref(r.StopReason, "a stop was asked")
		if !strings.HasPrefix(s, "Stopped") { // "Stopped by ann@example.com" says it already
			s = "Stopped: " + s
		}
		if r.Total > 0 && r.Done < r.Total {
			s = join(s, count+" done")
		}
		return s
	}
	return string(r.Status)
}

// queuedBehind is the summary of a queued run whose lane another run holds: the run in its way, the runs queued ahead of it (its place
// in line) and, as far as their kinds can tell (Kind.Hold), when it starts: "Queued behind “LAN sweep of 10.20.0.0/16” and 2 runs
// queued before it (3rd in line); it starts in about 25 minutes".
func (m *Manager) queuedBehind(ctx context.Context, r Run) string {
	head := "Queued behind " + quote(r.BlockedBy.Title)
	var wait time.Duration
	unknown := 0
	if d, ok := m.holdOf(ctx, r.BlockedBy.ID, nil); ok {
		wait += d
	} else {
		unknown++
	}
	ahead := m.queuedAhead(ctx, r)
	for i := range ahead {
		if d, ok := m.holdOf(ctx, "", &ahead[i]); ok {
			wait += d
		} else {
			unknown++
		}
	}
	if len(ahead) == 0 {
		if unknown == 0 {
			return head + "; it starts in " + about(wait)
		}
		if left := m.blockerLeft(ctx, r.BlockedBy.ID); left != "" { // its kind tells its time left in words only
			return head + ", which has " + left + "; it starts when that run ends"
		}
		return head + "; it starts when that run ends"
	}
	runs := "1 run"
	if len(ahead) > 1 {
		runs = strconv.Itoa(len(ahead)) + " runs"
	}
	head += " and " + runs + " queued before it (" + ordinal(len(ahead)+1) + " in line)"
	switch {
	case unknown == 0:
		return head + "; it starts in " + about(wait)
	case unknown < len(ahead)+1 && wait >= time.Minute:
		return head + "; it starts in more than " + durationWords(wait, math.Floor)
	}
	return head + "; it starts when they end"
}

// queuedAhead are the runs that start before queued run r in its lane, in the order the dispatcher starts them (the oldest queued
// first), leaving out those that wait for their module to be turned on or whose kind this process does not know. Read without their
// own summaries.
func (m *Manager) queuedAhead(ctx context.Context, r Run) []Run {
	rows, err := m.cfg.DB.Reader().QueryContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.status = 'queued' AND r.lane = ?1 AND r.id <> ?2
		AND (r.queued_at < ?3 OR (r.queued_at = ?3 AND r.rowid < (SELECT rowid FROM core_run WHERE id = ?2)))
		ORDER BY r.queued_at, r.rowid LIMIT ?4`, r.Lane, r.ID, r.QueuedAt, MaxPage)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []Run
	for rows.Next() {
		a, err := m.scanBare(rows)
		if err != nil {
			return nil
		}
		if _, ok := m.kind(a.Module, a.Kind); !ok || (m.cfg.Gate != nil && !m.cfg.Gate.Enabled(a.Module)) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// holdOf is Kind.Hold of run a, or of run id read now when a is nil; ok is false when its kind gives none or it cannot be read.
func (m *Manager) holdOf(ctx context.Context, id string, a *Run) (time.Duration, bool) {
	if a == nil {
		r, err := m.scanBare(m.cfg.DB.Reader().QueryRowContext(ctx, `SELECT `+runCols+` FROM core_run r WHERE r.id = ?`, id))
		if err != nil {
			return 0, false
		}
		a = &r
	}
	k, ok := m.kind(a.Module, a.Kind)
	if !ok || k.Hold == nil {
		return 0, false
	}
	return k.Hold(ctx, *a)
}

// about writes a wait: "about a minute", "about 25 minutes", "about 3 hours".
func about(d time.Duration) string {
	if d < 90*time.Second {
		return "about a minute"
	}
	return "about " + durationWords(d, math.Ceil)
}

// durationWords writes d in minutes below an hour and a half, else in hours, rounded by round: "25 minutes", "3 hours".
func durationWords(d time.Duration, round func(float64) float64) string {
	n, unit := int(round(d.Minutes())), "minute"
	if d >= 90*time.Minute {
		n, unit = int(round(d.Hours())), "hour"
	}
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// ordinal writes n as "1st", "2nd", "3rd", "4th", "11th", "22nd".
func ordinal(n int) string {
	suffix := "th"
	if n%100 < 11 || n%100 > 13 {
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		}
	}
	return strconv.Itoa(n) + suffix
}

// blockerLeft is the estimate of the run that holds a queued run's lane ("about 12 minutes left at 100 packets/s"), "" when its kind
// gives none or it cannot be read. The holder is running, so its own summary never reads another run in turn.
func (m *Manager) blockerLeft(ctx context.Context, id string) string {
	var module, kind string
	if err := m.cfg.DB.Reader().QueryRowContext(ctx, `SELECT module, kind FROM core_run WHERE id = ?`, id).Scan(&module, &kind); err != nil {
		return ""
	}
	if k, ok := m.kind(module, kind); !ok || k.Estimate == nil {
		return ""
	}
	b, err := m.Read(ctx, id)
	if err != nil || (b.Status != Running && b.Status != Stopping) {
		return ""
	}
	k, _ := m.kind(module, kind)
	return k.Estimate(ctx, b)
}

// Count is "6,272 of 65,792 addresses": done of total, with the unit when there is one.
func Count(done, total int, unit string) string {
	s := Number(done) + " of " + Number(total)
	if unit != "" {
		s += " " + unit
	}
	return s
}

// Number writes n with a comma between thousands (12,345).
func Number(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// join joins the non-empty parts with "; ".
func join(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

func quote(s string) string { return "“" + s + "”" }

func deref(s *string, def string) string {
	if s == nil || strings.TrimSpace(*s) == "" {
		return def
	}
	return *s
}
