package ai

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// ActivityResult is how a call ended.
type ActivityResult string

// The four results (contract.ts `ActivityResult`).
const (
	ResultOK            ActivityResult = "ok"
	ResultBlockedByHook ActivityResult = "blocked_by_hook"
	ResultFallbackUsed  ActivityResult = "fallback_used"
	ResultError         ActivityResult = "error"
)

// ActivityTool is a tool call as recorded: the arguments are a short summary without secrets.
type ActivityTool struct {
	Name   string `json:"name"`
	Access Access `json:"access"`
	Args   string `json:"args"`
}

// NewActivityTool records a tool call. Access other than "read" is recorded as "write" (fail closed), and the
// arguments are summarised by SummarizeArgs.
func NewActivityTool(name string, access Access, args string) ActivityTool {
	if access != AccessRead {
		access = AccessWrite
	}
	return ActivityTool{Name: name, Access: access, Args: SummarizeArgs(args)}
}

// ActivityLink points to a response proposal or action this call produced.
type ActivityLink struct {
	Kind string `json:"kind"` // proposal or action
	ID   string `json:"id"`
}

// ActivityEntry is one row of `ai_activity` (INV-17). It holds hashes of what was sent and received, never the
// content. Hash and PrevHash form the chain (INV-18); see Seal.
type ActivityEntry struct {
	ID         string         `json:"id"`
	TS         string         `json:"ts"` // FormatTS
	Job        string         `json:"job"`
	Profile    string         `json:"profile"` // "" when no profile was reached (blocked, capped)
	Model      string         `json:"model"`
	Trigger    string         `json:"trigger"` // user:<email> or system:<what>
	Hooks      []string       `json:"hooks"`   // names of hooks that acted
	Tools      []ActivityTool `json:"tools"`
	InputHash  string         `json:"input_hash"`
	OutputHash string         `json:"output_hash"`
	Summary    string         `json:"summary"`
	TokensIn   int            `json:"tokens_in"`
	TokensOut  int            `json:"tokens_out"`
	Result     ActivityResult `json:"result"`
	Links      []ActivityLink `json:"links,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// FormatTS formats a time the way every ts column is stored: UTC, milliseconds, trailing Z.
func FormatTS(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

var (
	idRE = regexp.MustCompile(`^[\w.-]{1,96}$`)
	tsRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
)

// ErrInvalidEntry is wrapped by Seal when an entry breaks the INV-17 shape.
var ErrInvalidEntry = errors.New("ai: invalid activity entry")

func (e ActivityEntry) validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalidEntry, what) }
	switch {
	case !idRE.MatchString(e.ID):
		return bad("id")
	case !tsRE.MatchString(e.TS):
		return bad("ts must be UTC with milliseconds, like 2026-11-09T05:00:00.000Z")
	case e.Job == "" || e.Trigger == "":
		return bad("job and trigger are required")
	case !hashRE.MatchString(e.InputHash) || !hashRE.MatchString(e.OutputHash):
		return bad("input_hash and output_hash must be SHA-256 hex (the content itself is not stored)")
	case e.TokensIn < 0 || e.TokensOut < 0:
		return bad("token counts cannot be negative")
	}
	switch e.Result {
	case ResultOK, ResultBlockedByHook, ResultFallbackUsed, ResultError:
	default:
		return bad("result")
	}
	for _, t := range e.Tools {
		if t.Name == "" || (t.Access != AccessRead && t.Access != AccessWrite) {
			return bad("every tool needs a name and access read or write")
		}
	}
	for _, l := range e.Links {
		if (l.Kind != "proposal" && l.Kind != "action") || !idRE.MatchString(l.ID) {
			return bad("links must be a proposal or action with an id")
		}
	}
	return nil
}

// Seal checks an entry, sets its PrevHash and computes its Hash from prev (INV-18). hooks and tools are
// stored as empty lists rather than null, and an empty links list is dropped, so the same entry always
// hashes the same.
func Seal(prev string, e ActivityEntry) (ActivityEntry, error) {
	e = e.normalized()
	if err := e.validate(); err != nil {
		return ActivityEntry{}, err
	}
	e.PrevHash = prev
	h, err := ChainHash(prev, e)
	if err != nil {
		return ActivityEntry{}, err
	}
	e.Hash = h
	return e, nil
}

// normalized gives an entry its stored shape: hooks and tools as empty lists rather than null, no empty links.
func (e ActivityEntry) normalized() ActivityEntry {
	if e.Hooks == nil {
		e.Hooks = []string{}
	}
	if e.Tools == nil {
		e.Tools = []ActivityTool{}
	}
	if len(e.Links) == 0 {
		e.Links = nil
	}
	return e
}

// VerifyResult is the answer of `GET /ai/activity/verify`. BrokenAt is 1-based; 0 means intact.
type VerifyResult struct {
	OK       bool
	Count    int
	BrokenAt int
	EntryID  string
}

// VerifyChain walks entries oldest first. Each entry must link to the one before it and its hash must match a
// recomputation. anchor is the expected prev_hash of the first entry: Genesis for a chain that was never
// pruned, the hash of the last pruned entry otherwise (`core_chain_anchor`), or "" to trust the first link.
func VerifyChain(entries []ActivityEntry, anchor string) VerifyResult {
	for i, e := range entries {
		e = e.normalized()
		linked := e.PrevHash == anchor || anchor == ""
		if i > 0 {
			linked = e.PrevHash == entries[i-1].Hash
		}
		if linked {
			if h, err := ChainHash(e.PrevHash, e); err == nil && h == e.Hash {
				continue
			}
		}
		return VerifyResult{Count: len(entries), BrokenAt: i + 1, EntryID: e.ID}
	}
	return VerifyResult{OK: true, Count: len(entries)}
}

// ActivityLog is an in-memory chain: the reference behaviour for the table and a ready fake for tests of
// code that records activity. The database version appends in the same transaction as the business change.
// There is no way to edit or remove an entry.
type ActivityLog struct {
	mu      sync.Mutex
	entries []ActivityEntry
}

// Append seals e after the last entry and stores it.
func (l *ActivityLog) Append(e ActivityEntry) (ActivityEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := Genesis
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Hash
	}
	s, err := Seal(prev, e)
	if err != nil {
		return ActivityEntry{}, err
	}
	l.entries = append(l.entries, s)
	return s, nil
}

// Entries returns a copy, oldest first.
func (l *ActivityLog) Entries() []ActivityEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ActivityEntry(nil), l.entries...)
}

// Verify checks the whole log against Genesis.
func (l *ActivityLog) Verify() VerifyResult { return VerifyChain(l.Entries(), Genesis) }
