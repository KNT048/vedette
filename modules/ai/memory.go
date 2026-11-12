package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/store"
)

// Slice 4b of WP-25 (S-AI-7, INV-8): what an administrator told the box about the network (ai_memory), what the AI proposes to
// remember (ai_memory_suggestion, never part of a prompt), and the switch that lets the AI propose (ai_setting key `memory`).
// Nothing is cached: a prompt reads the rows when the call starts, so an edit, a switch-off or a delete takes effect on the next call.

// Limits of the memory (the mock is the contract).
const (
	MaxMemories    = 100 // memories a box holds
	MaxSuggestions = 50  // suggestions waiting for an answer; the AI stops suggesting when the list is full
	memoryMin      = 3
	memoryMax      = 300
	evidenceMax    = 200
)

// Errors of SuggestMemory. The producers of suggestions (the log digest, Ask) treat them as "nothing to do", not as failures.
var (
	ErrSuggestionsOff     = errors.New("ai: memory suggestions are off")
	ErrTooManySuggestions = errors.New("ai: too many suggestions are waiting")
)

// MemoryItem is a memory as the API shows it. LastUsedAt is null until a call carried it to the provider.
type MemoryItem struct {
	ID         string  `json:"id"`
	Text       string  `json:"text"`
	Source     string  `json:"source"` // "user" or "ai" (accepted from a suggestion)
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	Enabled    bool    `json:"enabled"`
}

// SuggestionItem is a suggestion waiting for an answer. Evidence says where the AI noticed it.
type SuggestionItem struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	CreatedAt string `json:"created_at"`
	Evidence  string `json:"evidence"`
}

// MemoryView is `GET /ai/memory`; the arrays are never null.
type MemoryView struct {
	SuggestEnabled bool             `json:"suggest_enabled"`
	Items          []MemoryItem     `json:"items"`
	Suggestions    []SuggestionItem `json:"suggestions"`
}

// MemoryPatch is the body of `PUT /ai/memory/{id}`: a nil field is left as it is.
type MemoryPatch struct {
	Text    *string `json:"text"`
	Enabled *bool   `json:"enabled"`
}

// checkMemoryText tidies a memory (one line, single spaces) and checks it: 3..300 characters, no control or invisible characters.
func checkMemoryText(text string) (string, error) {
	text = tidy(text)
	if auth.HasInvisible(text) {
		return "", badInput("invalid_memory", "A memory may not contain control or invisible characters. Retype it as plain text.")
	}
	if n := utf8.RuneCountInString(text); n < memoryMin || n > memoryMax {
		return "", badInput("invalid_memory", `Write what the AI should remember in 3 to 300 characters, for example "NAS-PHOTOS is reachable from the Internet".`)
	}
	return text, nil
}

// hookRefuses runs the before-AI hooks on a memory text. A text a hook blocks or holds, or that cannot be checked, would never be
// sent (fail closed), so it is not saved either: ok is false and why says which hook and what it said. A mask is fine: the text is
// sent masked.
func (s *Service) hookRefuses(ctx context.Context, hooks *HookRunner, text string) (why string, refused bool) {
	ctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	r, err := hooks.Run(ctx, BeforeAI, text)
	switch {
	case err != nil:
		return "it could not be checked against the hooks in time", true
	case r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld:
		return fmt.Sprintf("the hook %s stopped it: %s", strings.Join(r.Names(), ", "), r.Text), true
	}
	return "", false
}

func memoryBlocked(why string) error {
	return badInput("invalid_memory", "This memory cannot be saved, because %s Take out what the hook objects to and save it again.", strings.TrimSuffix(why, ".")+".")
}

func tooManyMemories() error {
	return badInput("too_many", "A box holds up to %d memories. Delete the ones that are out of date.", MaxMemories)
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func suggestOn(ctx context.Context, q queryer) (bool, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'memory'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // never set: off. Nothing makes suggestions yet, and a person turns it on knowing it.
	}
	if err != nil {
		return false, fmt.Errorf("ai: read memory setting: %w", err)
	}
	var v struct {
		SuggestEnabled bool `json:"suggest_enabled"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return false, fmt.Errorf("ai: memory setting: %w", err)
	}
	return v.SuggestEnabled, nil
}

// MemoryView returns the memories (newest first), the waiting suggestions (oldest first) and the switch (`GET /ai/memory`, admin).
func (s *Service) MemoryView(ctx context.Context) (MemoryView, error) {
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true}) // one snapshot for the switch and both lists
	if err != nil {
		return MemoryView{}, fmt.Errorf("ai: memory: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := tx
	v := MemoryView{Items: []MemoryItem{}, Suggestions: []SuggestionItem{}}
	if v.SuggestEnabled, err = suggestOn(ctx, q); err != nil {
		return MemoryView{}, err
	}
	rows, err := q.QueryContext(ctx, `SELECT id, text, source, created_at, last_used_at, enabled FROM ai_memory ORDER BY rowid DESC`)
	if err != nil {
		return MemoryView{}, fmt.Errorf("ai: memory: %w", err)
	}
	for rows.Next() {
		var m MemoryItem
		var used sql.NullString
		var on int
		if err := rows.Scan(&m.ID, &m.Text, &m.Source, &m.CreatedAt, &used, &on); err != nil {
			_ = rows.Close()
			return MemoryView{}, fmt.Errorf("ai: memory: %w", err)
		}
		if used.Valid {
			m.LastUsedAt = &used.String
		}
		m.Enabled = on == 1
		v.Items = append(v.Items, m)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return MemoryView{}, fmt.Errorf("ai: memory: %w", err)
	}
	_ = rows.Close()
	ss, err := q.QueryContext(ctx, `SELECT id, text, created_at, evidence FROM ai_memory_suggestion ORDER BY rowid`)
	if err != nil {
		return MemoryView{}, fmt.Errorf("ai: suggestions: %w", err)
	}
	defer func() { _ = ss.Close() }()
	for ss.Next() {
		var g SuggestionItem
		if err := ss.Scan(&g.ID, &g.Text, &g.CreatedAt, &g.Evidence); err != nil {
			return MemoryView{}, fmt.Errorf("ai: suggestions: %w", err)
		}
		v.Suggestions = append(v.Suggestions, g)
	}
	if err := ss.Err(); err != nil {
		return MemoryView{}, fmt.Errorf("ai: suggestions: %w", err)
	}
	return v, nil
}

func (s *Service) memoryItem(ctx context.Context, q queryer, id string) (MemoryItem, error) {
	var m MemoryItem
	var used sql.NullString
	var on int
	err := q.QueryRowContext(ctx, `SELECT id, text, source, created_at, last_used_at, enabled FROM ai_memory WHERE id = ?`, id).Scan(&m.ID, &m.Text, &m.Source, &m.CreatedAt, &used, &on)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryItem{}, harnessNotFound("memory")
	}
	if err != nil {
		return MemoryItem{}, fmt.Errorf("ai: memory: %w", err)
	}
	if used.Valid {
		m.LastUsedAt = &used.String
	}
	m.Enabled = on == 1
	return m, nil
}

func memoryCount(ctx context.Context, tx *sql.Tx) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_memory`).Scan(&n); err != nil {
		return 0, fmt.Errorf("ai: count memory: %w", err)
	}
	return n, nil
}

// AddMemory saves a memory typed by an administrator (`POST /ai/memory`, admin). At most MaxMemories.
func (s *Service) AddMemory(ctx context.Context, who, text string) (MemoryItem, error) {
	if err := s.harnessGuard(); err != nil {
		return MemoryItem{}, err
	}
	text, err := checkMemoryText(text)
	if err != nil {
		return MemoryItem{}, err
	}
	if why, bad := s.hookRefuses(ctx, s.Hooks(), text); bad {
		return MemoryItem{}, memoryBlocked(why)
	}
	id, now := store.NewID("mem"), store.FormatTS(s.cfg.Clock())
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if n, err := memoryCount(ctx, tx); err != nil {
			return err
		} else if n >= MaxMemories {
			return tooManyMemories()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_memory (id, text, source, created_at, enabled) VALUES (?, ?, 'user', ?, 1)`, id, text, now); err != nil {
			return fmt.Errorf("ai: save memory: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.memory.add", id, "")
	})
	if err != nil {
		return MemoryItem{}, err
	}
	return MemoryItem{ID: id, Text: text, Source: "user", CreatedAt: now, Enabled: true}, nil
}

// EditMemory changes the text and the switch of a memory (`PUT /ai/memory/{id}`, admin). A nil field stays as it is.
func (s *Service) EditMemory(ctx context.Context, who, id string, p MemoryPatch) (MemoryItem, error) {
	if err := s.harnessGuard(); err != nil {
		return MemoryItem{}, err
	}
	var text string
	if p.Text != nil {
		var err error
		if text, err = checkMemoryText(*p.Text); err != nil {
			return MemoryItem{}, err
		}
		if why, bad := s.hookRefuses(ctx, s.Hooks(), text); bad {
			return MemoryItem{}, memoryBlocked(why)
		}
	}
	var out MemoryItem
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := s.memoryItem(ctx, tx, id)
		if err != nil {
			return err
		}
		if p.Text != nil {
			cur.Text = text
		}
		if p.Enabled != nil {
			cur.Enabled = *p.Enabled
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_memory SET text = ?, enabled = ? WHERE id = ?`, cur.Text, b2i(cur.Enabled), id); err != nil {
			return fmt.Errorf("ai: save memory: %w", err)
		}
		out = cur
		return s.auditTx(ctx, tx, who, "ai.memory.edit", id, "")
	})
	return out, err
}

// DeleteMemory removes a memory (`DELETE /ai/memory/{id}`, admin).
func (s *Service) DeleteMemory(ctx context.Context, who, id string) error {
	if err := s.harnessGuard(); err != nil {
		return err
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM ai_memory WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("ai: delete memory: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return harnessNotFound("memory")
		}
		return s.auditTx(ctx, tx, who, "ai.memory.remove", id, "")
	})
}

// SetSuggest allows or forbids the AI to suggest memories (`PUT /ai/memory/settings`, admin). Suggestions already waiting stay.
func (s *Service) SetSuggest(ctx context.Context, who string, on bool) (MemoryView, error) {
	if err := s.harnessGuard(); err != nil {
		return MemoryView{}, err
	}
	state := "off"
	if on {
		state = "on"
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := upsertSetting(ctx, tx, "memory", struct {
			SuggestEnabled bool `json:"suggest_enabled"`
		}{on}, s.cfg.Clock(), who); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, who, "ai.memory.settings", "suggest", state)
	})
	if err != nil {
		return MemoryView{}, err
	}
	return s.MemoryView(ctx)
}

// AcceptSuggestion turns a waiting suggestion into a memory (`POST /ai/memory/suggestions/{id}/accept`, admin). The delete and the
// insert are one transaction on the single writer, so two accepts of one suggestion make one memory and the second is 404. A text
// the before-AI hooks would stop is refused (400 invalid_memory) and the suggestion stays; a text that is already a memory is not
// added twice: the suggestion goes and the existing memory is returned.
func (s *Service) AcceptSuggestion(ctx context.Context, who, id string) (MemoryItem, error) {
	if err := s.harnessGuard(); err != nil {
		return MemoryItem{}, err
	}
	// The hooks run before the write transaction, so a slow hook does not hold the one writer; the text is read again inside it and
	// the accept is refused if the suggestion is not the one that was checked.
	var checked string
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT text FROM ai_memory_suggestion WHERE id = ?`, id).Scan(&checked); errors.Is(err, sql.ErrNoRows) {
		return MemoryItem{}, harnessNotFound("suggestion")
	} else if err != nil {
		return MemoryItem{}, fmt.Errorf("ai: suggestion: %w", err)
	}
	if why, bad := s.hookRefuses(ctx, s.Hooks(), checked); bad {
		return MemoryItem{}, memoryBlocked(why)
	}
	mid, now := store.NewID("mem"), store.FormatTS(s.cfg.Clock())
	var text string
	var out MemoryItem
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT text FROM ai_memory_suggestion WHERE id = ?`, id).Scan(&text); errors.Is(err, sql.ErrNoRows) {
			return harnessNotFound("suggestion")
		} else if err != nil {
			return fmt.Errorf("ai: suggestion: %w", err)
		}
		if text != checked {
			return harnessNotFound("suggestion") // replaced since it was checked: nothing is accepted
		}
		var have string
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM ai_memory WHERE text = ?`, text).Scan(&have); {
		case err == nil:
			if _, err := tx.ExecContext(ctx, `DELETE FROM ai_memory_suggestion WHERE id = ?`, id); err != nil {
				return fmt.Errorf("ai: delete suggestion: %w", err)
			}
			if out, err = s.memoryItem(ctx, tx, have); err != nil {
				return err
			}
			return s.auditTx(ctx, tx, who, "ai.memory.accept", have, "from "+id)
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("ai: memory: %w", err)
		}
		if n, err := memoryCount(ctx, tx); err != nil {
			return err
		} else if n >= MaxMemories {
			return tooManyMemories() // the suggestion stays: nothing is lost
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_memory_suggestion WHERE id = ?`, id); err != nil {
			return fmt.Errorf("ai: delete suggestion: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_memory (id, text, source, created_at, enabled) VALUES (?, ?, 'ai', ?, 1)`, mid, text, now); err != nil {
			return fmt.Errorf("ai: save memory: %w", err)
		}
		out = MemoryItem{ID: mid, Text: text, Source: "ai", CreatedAt: now, Enabled: true}
		return s.auditTx(ctx, tx, who, "ai.memory.accept", mid, "from "+id)
	})
	if err != nil {
		return MemoryItem{}, err
	}
	return out, nil
}

// rejectedFor is how long the text of a rejected suggestion is remembered (as a digest) so the AI does not propose it again.
const rejectedFor = 30 * 24 * time.Hour

func (s *Service) forgetOldRejections(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM ai_memory_rejected WHERE rejected_at < ?`, store.FormatTS(s.cfg.Clock().Add(-rejectedFor))); err != nil {
		return fmt.Errorf("ai: purge rejected suggestions: %w", err)
	}
	return nil
}

// RejectSuggestion deletes a waiting suggestion (`POST /ai/memory/suggestions/{id}/reject`, admin) and keeps a hash of its text for
// 30 days, so SuggestMemory does not bring the same text back at once.
func (s *Service) RejectSuggestion(ctx context.Context, who, id string) error {
	if err := s.harnessGuard(); err != nil {
		return err
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var text string
		if err := tx.QueryRowContext(ctx, `SELECT text FROM ai_memory_suggestion WHERE id = ?`, id).Scan(&text); errors.Is(err, sql.ErrNoRows) {
			return harnessNotFound("suggestion")
		} else if err != nil {
			return fmt.Errorf("ai: suggestion: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_memory_suggestion WHERE id = ?`, id); err != nil {
			return fmt.Errorf("ai: delete suggestion: %w", err)
		}
		if err := s.forgetOldRejections(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_memory_rejected (digest, rejected_at) VALUES (?, ?) ON CONFLICT (digest) DO UPDATE SET rejected_at = excluded.rejected_at`, HashContent(text), store.FormatTS(s.cfg.Clock())); err != nil {
			return fmt.Errorf("ai: remember rejection: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.memory.reject", id, "")
	})
}

// SuggestMemory stores a suggestion of the AI (INV-8). It is the only way a suggestion enters the box: it does nothing unless an
// administrator allowed suggestions (ErrSuggestionsOff), at most MaxSuggestions wait (ErrTooManySuggestions), and a text that is
// already remembered or already waiting is not stored again. The log digest (D-223) and Ask (D-225) call it. The suggestion is
// not memory: it reaches no prompt until an administrator accepts it.
func (s *Service) SuggestMemory(ctx context.Context, text, evidence string) error {
	_, err := s.suggestMemory(ctx, text, evidence)
	return err
}

// suggestMemory is SuggestMemory that also says whether a new suggestion was stored.
func (s *Service) suggestMemory(ctx context.Context, text, evidence string) (bool, error) {
	if err := s.harnessGuard(); err != nil {
		return false, err
	}
	text = tidy(text)
	evidence = tidy(evidence)
	if n := utf8.RuneCountInString(text); n < memoryMin || n > memoryMax || auth.HasInvisible(text) {
		return false, fmt.Errorf("%w: a suggestion must be 3 to 300 characters", ErrInvalidPromptInput)
	}
	if n := utf8.RuneCountInString(evidence); n < 1 || n > evidenceMax || auth.HasInvisible(evidence) {
		return false, fmt.Errorf("%w: the evidence of a suggestion must be 1 to 200 characters", ErrInvalidPromptInput)
	}
	if _, bad := s.hookRefuses(ctx, s.Hooks(), text); bad {
		return false, nil // a text the hooks would stop could never be sent, so it is not worth asking about
	}
	stored := false
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		on, err := suggestOn(ctx, tx)
		if err != nil {
			return err
		}
		if !on {
			return ErrSuggestionsOff
		}
		var dup int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM ai_memory WHERE text = ?) + (SELECT COUNT(*) FROM ai_memory_suggestion WHERE text = ?)`, text, text).Scan(&dup); err != nil {
			return fmt.Errorf("ai: suggestion: %w", err)
		}
		if dup > 0 {
			return nil
		}
		if err := s.forgetOldRejections(ctx, tx); err != nil {
			return err
		}
		var refused int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_memory_rejected WHERE digest = ?`, HashContent(text)).Scan(&refused); err != nil {
			return fmt.Errorf("ai: suggestion: %w", err)
		}
		if refused > 0 {
			return nil // an administrator rejected this text less than 30 days ago
		}
		var waiting int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_memory_suggestion`).Scan(&waiting); err != nil {
			return fmt.Errorf("ai: suggestion: %w", err)
		}
		if waiting >= MaxSuggestions {
			return ErrTooManySuggestions
		}
		id := store.NewID("sg")
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_memory_suggestion (id, text, created_at, evidence) VALUES (?, ?, ?, ?)`, id, text, store.FormatTS(s.cfg.Clock()), evidence); err != nil {
			return fmt.Errorf("ai: save suggestion: %w", err)
		}
		stored = true
		return s.auditTx(ctx, tx, "system", "ai.memory.suggest", id, "")
	})
	return stored && err == nil, err
}

// memCall is the memory of one call: the block to send, the ids it carries, the memories left out and the hooks that acted on it.
type memCall struct {
	block DataBlock
	ids   []string
	left  []string // ids of memories a hook stopped (or that could not be checked): not sent
	// leftNames are the hooks that stopped them, for the activity row.
	leftNames []string
	names     []string // hooks that acted on the lines that were sent (a mask)
}

// memoryForCall reads the enabled memories and runs the before-AI hooks on each line alone (INV-8): a line a hook blocks or holds is
// left out, and every other line is sent, masked where a hook masked it, so one memory cannot stop every call. A job that sends
// public text only gets none (the privacy rule keeps internal data from the cloud profile that may run it). Nothing waiting or
// rejected is in ai_memory.
func (s *Service) memoryForCall(ctx context.Context, hooks *HookRunner, job Job) (memCall, error) {
	var mc memCall
	if !job.CarriesInternalData() {
		return mc, nil
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, text FROM ai_memory WHERE enabled = 1 ORDER BY rowid`)
	if err != nil {
		return mc, fmt.Errorf("ai: memory: %w", err)
	}
	type line struct{ id, text string }
	var all []line
	for rows.Next() {
		var l line
		if err := rows.Scan(&l.id, &l.text); err != nil {
			_ = rows.Close()
			return mc, fmt.Errorf("ai: memory: %w", err)
		}
		if n := utf8.RuneCountInString(l.text); n < memoryMin || n > memoryMax {
			_ = rows.Close()
			return mc, fmt.Errorf("%w: a memory entry must be 3 to 300 characters", ErrInvalidPromptInput)
		}
		all = append(all, l)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return mc, fmt.Errorf("ai: memory: %w", err)
	}
	_ = rows.Close()
	hctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	var lines strings.Builder
	for _, l := range all {
		r, err := hooks.Run(hctx, BeforeAI, oneLine(l.text))
		if err != nil || r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld {
			mc.left = append(mc.left, l.id)
			mc.leftNames = append(mc.leftNames, r.Names()...)
			continue
		}
		mc.names = append(mc.names, r.Names()...)
		mc.ids = append(mc.ids, l.id)
		lines.WriteString("- " + r.Text + "\n")
	}
	if len(mc.ids) > 0 {
		mc.block = DataBlock{Kind: DataMemory, Source: "notes kept by an administrator", Text: strings.TrimSuffix(lines.String(), "\n")}
	}
	return mc, nil
}

// touchMemory records that the memories were carried to a provider.
func touchMemory(ctx context.Context, tx *sql.Tx, ids []string, now string) error {
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE ai_memory SET last_used_at = ? WHERE id = ?`, now, id); err != nil {
			return fmt.Errorf("ai: memory use: %w", err)
		}
	}
	return nil
}
