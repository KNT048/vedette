package run

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Status is the state of a run, and of a step of a run. The same eight words for every engine (web/src/lib/statusCodes.ts
// RUN_STATUSES); core_run.status is an open vocabulary checked by shape only, and this type is its one owner.
type Status string

// The run states, in the order the web lists them.
const (
	Queued   Status = "queued"   // waits for its lane; the queue is these rows, so it survives a restart
	Waiting  Status = "waiting"  // paused with work left until something it names (WaitingFor) happens; its lane is free
	Running  Status = "running"  // holds its lane
	Stopping Status = "stopping" // a stop was asked; it still holds its lane until the work ends
	Done     Status = "done"
	Partial  Status = "partial" // ended with part of the work done ("Partly done")
	Failed   Status = "failed"
	Stopped  Status = "stopped" // stopped by a person or by a restart (StopReason says which)
)

// Statuses lists every status.
var Statuses = []Status{Queued, Waiting, Running, Stopping, Done, Partial, Failed, Stopped}

// Skipped is a ninth state for a step only (web/src/lib/statusCodes.ts STEP_STATUSES): the step did not run, and its note says why
// (an engine turned off, nothing for it to check, or the run ended before it). A run is never skipped.
const Skipped Status = "skipped"

// StepStatuses lists every state a step can be in: the run states and Skipped.
var StepStatuses = append(slices.Clone(Statuses), Skipped)

// Valid reports whether s is one of Statuses.
func (s Status) Valid() bool { return slices.Contains(Statuses, s) }

// Live reports whether a run in s holds its lane (core_run_live).
func (s Status) Live() bool { return s == Running || s == Stopping }

// Ended reports whether s is final: the run has an ended_at and never runs again unless it is resumed.
func (s Status) Ended() bool { return s == Done || s == Partial || s == Failed || s == Stopped }

// Trigger is what started a run (core_run.trigger, a closed vocabulary).
type Trigger string

// The triggers.
const (
	Manual   Trigger = "manual"   // a person asked
	Schedule Trigger = "schedule" // a schedule came due
	Event    Trigger = "event"    // something the box saw (a new device, a finished sweep)
)

// Valid reports whether t is one of the three triggers.
func (t Trigger) Valid() bool { return t == Manual || t == Schedule || t == Event }

// Level is the level of a log line (core_run_log.level).
type Level string

// The levels.
const (
	Info  Level = "info"
	Warn  Level = "warn"
	Error Level = "error"
)

// Valid reports whether l is one of the three levels.
func (l Level) Valid() bool { return l == Info || l == Warn || l == Error }

// wordRE is the shape of the open vocabularies: kind, lane, subject kinds, item outcomes.
var wordRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// clip cuts s to at most n characters (runes), after trimming its spaces.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// nullable is clip, and nil for an empty result (the CHECKs refuse empty text).
func nullable(s string, n int) *string {
	s = clip(s, n)
	if s == "" {
		return nil
	}
	return &s
}
