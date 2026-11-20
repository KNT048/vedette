package agentintake

import (
	"testing"
	"time"
)

func TestNodeHealth_Rules(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	m := time.Minute
	for _, c := range []struct {
		name  string
		c     Cadence
		state string
	}{
		{"5-minute osquery, 14 minutes silent", Cadence{Enrolled: ago(time.Hour * 5), LastCall: ago(14 * m), LastResult: ago(30 * m), CallEvery: 5 * m, CallGap: 5 * m}, StateReporting},
		{"5-minute osquery, 16 minutes silent", Cadence{Enrolled: ago(time.Hour * 5), LastCall: ago(16 * m), LastResult: ago(30 * m), CallEvery: 5 * m, CallGap: 5 * m}, StateQuiet},
		{"it fetches its config every 20 minutes: 50 minutes silent", Cadence{Enrolled: ago(time.Hour * 5), LastCall: ago(50 * m), LastResult: ago(50 * m), CallEvery: 5 * m, CallGap: 20 * m}, StateReporting},
		{"never fetched its config twice: judged by its hourly schedule", Cadence{Enrolled: ago(5 * time.Hour), LastCall: ago(170 * m), LastResult: ago(170 * m), CallEvery: 5 * m, ReportEvery: time.Hour}, StateReporting},
		{"never fetched its config twice, 3 hours and a minute silent", Cadence{Enrolled: ago(5 * time.Hour), LastCall: ago(181 * m), LastResult: ago(181 * m), CallEvery: 5 * m, ReportEvery: time.Hour}, StateQuiet},
		{"the package reporter, 3 hours silent", Cadence{Enrolled: ago(9 * time.Hour), LastCall: ago(180 * m), LastResult: ago(180 * m), CallEvery: reporterEvery, ReportEvery: time.Hour}, StateReporting},
		{"a daily Wazuh pull, 2 days silent", Cadence{LastCall: ago(48 * time.Hour), LastResult: ago(48 * time.Hour), CallEvery: 24 * time.Hour}, StateReporting},
		{"a daily Wazuh pull, 3 days and a minute silent", Cadence{LastCall: ago(72*time.Hour + m), LastResult: ago(72*time.Hour + m), CallEvery: 24 * time.Hour}, StateQuiet},
		{"calls, never delivered, past its first hour", Cadence{Enrolled: ago(61 * m), LastCall: ago(m), CallEvery: 5 * m, CallGap: 5 * m}, StateNeverReported},
		{"calls, never delivered, in its first hour", Cadence{Enrolled: ago(59 * m), LastCall: ago(m), CallEvery: 5 * m, CallGap: 5 * m}, StateReporting},
		{"silent and never delivered: quiet wins", Cadence{Enrolled: ago(3 * time.Hour), LastCall: ago(2 * time.Hour), CallEvery: 5 * m, CallGap: 5 * m}, StateQuiet},
		{"replaced wins", Cadence{Enrolled: ago(3 * time.Hour), LastCall: ago(2 * time.Hour), CallEvery: 5 * m, ReplacedBy: "node-new"}, StateReplaced},
	} {
		got, since := NodeHealth(c.c, now)
		if got != c.state || (got == StateQuiet) != !since.IsZero() || got == StateQuiet && !since.Equal(c.c.LastCall) {
			t.Errorf("%s: %s since %v, want %s", c.name, got, since, c.state)
		}
	}
}

func TestNextGap_Learning(t *testing.T) {
	t.Parallel()
	m, sec := time.Minute, time.Second
	every := 5 * m
	for _, c := range []struct {
		name           string
		old, gap, want time.Duration
	}{
		{"the first refresh", 0, 300 * sec, 300 * sec},
		{"a refresh a few seconds late is learned at once", 300 * sec, 304 * sec, 304 * sec},
		{"a shorter one by an eighth", 308 * sec, 300 * sec, 307 * sec},
		{"two service starts 4 minutes 45 seconds apart", 0, 285 * sec, 0},
		{"two service starts 5 minutes 15 seconds apart", 0, 315 * sec, 0},
		{"a repeated call is no refresh", 5 * m, 20 * sec, 5 * m},
		{"two service starts 2 minutes apart", 0, 2 * m, 0},
		{"two service starts 10 minutes apart", 0, 10 * m, 0},
		{"two service starts 14 minutes apart, after a learned refresh", 5 * m, 14 * m, 5 * m},
		{"an outage is not learned", 5 * m, 16 * m, 5 * m},
	} {
		if got := nextGap(c.old, c.gap, every); got != c.want {
			t.Errorf("%s: nextGap(%v, %v) = %v, want %v", c.name, c.old, c.gap, got, c.want)
		}
	}
}
