package run

import (
	"context"
	"strconv"
	"strings"
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
			// how long the run in its way has left, when its kind can tell: the queued one starts roughly then
			if left := m.blockerLeft(ctx, r.BlockedBy.ID); left != "" {
				return "Queued behind " + quote(r.BlockedBy.Title) + ", which has " + left + "; it starts when that run ends"
			}
			return "Queued behind " + quote(r.BlockedBy.Title) + "; it starts when that run ends"
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
