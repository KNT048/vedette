package ai

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/knt048/vedette/core/chain"
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
	ID      string `json:"id"`
	TS      string `json:"ts"` // FormatTS
	Job     string `json:"job"`
	Profile string `json:"profile"` // "" when no profile was reached (blocked, capped)
	// ProfileID is the id of that profile. It is stored beside the row but is not part of the hash and not shown: it only lets the
	// meter count the tokens of a profile after a restart even if the profile has been renamed.
	ProfileID  string         `json:"-"`
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

// Seal checks an entry, sets its PrevHash and computes its Hash from prev (INV-18) with core/chain. hooks and
// tools are stored as empty lists rather than null, and an empty links list is dropped, so the same entry always
// hashes the same.
func Seal(prev string, e ActivityEntry) (ActivityEntry, error) {
	e = e.normalized()
	if !hashRE.MatchString(prev) {
		return ActivityEntry{}, fmt.Errorf("%w: prev_hash must be 64 lowercase hex characters", ErrChainLink)
	}
	if err := e.validate(); err != nil {
		return ActivityEntry{}, err
	}
	e.PrevHash = prev
	h, err := entryHash(e)
	if err != nil {
		return ActivityEntry{}, err
	}
	e.Hash = h
	return e, nil
}

// ErrChainLink means a prev_hash is not a hash.
var ErrChainLink = errors.New("ai: invalid chain link")

// entryMap is the entry as core/chain hashes it: every column except hash. Strings must be valid UTF-8 (core/chain
// refuses anything else instead of letting two different texts collapse to one), and the numbers are plain
// integers. An empty links list is left out, like an absent column.
func entryMap(e ActivityEntry) map[string]any {
	hooks := make([]any, len(e.Hooks))
	for i, h := range e.Hooks {
		hooks[i] = h
	}
	tools := make([]any, len(e.Tools))
	for i, t := range e.Tools {
		tools[i] = map[string]any{"name": t.Name, "access": string(t.Access), "args": t.Args}
	}
	m := map[string]any{
		"id": e.ID, "ts": e.TS, "job": e.Job, "profile": e.Profile, "model": e.Model, "trigger": e.Trigger,
		"hooks": hooks, "tools": tools, "input_hash": e.InputHash, "output_hash": e.OutputHash, "summary": e.Summary,
		"tokens_in": e.TokensIn, "tokens_out": e.TokensOut, "result": string(e.Result), "prev_hash": e.PrevHash,
	}
	if len(e.Links) > 0 {
		links := make([]any, len(e.Links))
		for i, l := range e.Links {
			links[i] = map[string]any{"kind": l.Kind, "id": l.ID}
		}
		m["links"] = links
	}
	return m
}

func entryHash(e ActivityEntry) (string, error) {
	return chain.HashCanonical(e.PrevHash, entryMap(e))
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

// VerifyResult is the answer of `GET /ai/activity/verify`: BrokenAt is 1-based, 0 when intact.
type VerifyResult = chain.Result

// ChainHead is the tail of the chain as core records it: the hash of the newest entry and how many entries the
// chain holds. core must update it in the same transaction as every append and every prune, and keep it where
// the application cannot edit it (core_chain_anchor records the other end, the last pruned hash). Without it,
// deleting the newest entries is invisible.
type ChainHead struct {
	Hash  string
	Count int
}

// VerifyChain walks entries oldest first with core/chain's verifier: each entry must link to the one before it and
// its hash must match a recomputation. anchor is the expected prev_hash of the first entry: the hash of the last
// pruned entry (`core_chain_anchor`), or "" for a chain that was never pruned (Genesis). head, when given, also
// catches missing newest entries: the count must match and the last hash must be head.Hash; a missing tail is
// reported as broken at the first missing position. A nil head skips that check and so cannot see a cut tail.
func VerifyChain(entries []ActivityEntry, anchor string, head *ChainHead) VerifyResult {
	v := chain.NewVerifier(anchor)
	last := anchor
	if last == "" {
		last = Genesis
	}
	for _, e := range entries {
		e = e.normalized()
		recomputed, err := entryHash(e)
		if err != nil {
			recomputed = ""
		}
		v.Add(e.ID, e.PrevHash, e.Hash, recomputed)
		last = e.Hash
	}
	res := v.Result()
	if res.OK && head != nil && (len(entries) != head.Count || last != head.Hash) {
		res.OK, res.BrokenAt, res.EntryID = false, len(entries)+1, ""
	}
	return res
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

// Head returns the head record core would keep for this log.
func (l *ActivityLog) Head() ChainHead {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := ChainHead{Hash: Genesis, Count: len(l.entries)}
	if n := len(l.entries); n > 0 {
		h.Hash = l.entries[n-1].Hash
	}
	return h
}

// Verify checks the whole log against Genesis and its own head.
func (l *ActivityLog) Verify() VerifyResult {
	h := l.Head()
	return VerifyChain(l.Entries(), "", &h)
}
