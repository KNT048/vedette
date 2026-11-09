// Package audit appends to and verifies core_audit, the hash-chained audit log
// (docs/DATA_MODEL.md section 5.3, core CONTRACT INV-2, POST-3).
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// chainName is the core_chain_anchor key for this log.
const chainName = "core_audit"

// verifyPage is how many rows Verify reads per query.
const verifyPage int64 = 500

// ErrInvalid is wrapped by Entry validation failures.
var ErrInvalid = errors.New("audit: invalid entry")

var actionRE = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9_.-]+$`)

const (
	maxUser   = 320 // an email address
	maxTarget = 500
	maxDetail = 2000 // characters
)

// Entry is what a handler records. User is an email or "system".
type Entry struct {
	User   string
	Action string // "<module>.<what>"; the part before the first dot is the group
	Target string
	Detail string // optional, at most 2000 characters
}

func (e Entry) validate() error {
	if err := text("user", e.User, 1, maxUser, true); err != nil {
		return err
	}
	if !actionRE.MatchString(e.Action) {
		return fmt.Errorf("%w: action %q must match %s", ErrInvalid, e.Action, actionRE)
	}
	if err := text("target", e.Target, 1, maxTarget, true); err != nil {
		return err
	}
	return text("detail", e.Detail, 0, maxDetail, false)
}

func text(field, s string, minChars, maxChars int, bytesLimit bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalid, field)
	}
	if strings.ContainsRune(s, 0) {
		return fmt.Errorf("%w: %s contains NUL", ErrInvalid, field)
	}
	n := utf8.RuneCountInString(s)
	if bytesLimit {
		n = len(s)
	}
	if n < minChars {
		return fmt.Errorf("%w: %s is empty", ErrInvalid, field)
	}
	if n > maxChars {
		return fmt.Errorf("%w: %s is longer than %d", ErrInvalid, field, maxChars)
	}
	return nil
}

// Log writes core_audit rows.
type Log struct {
	now func() time.Time
}

// New returns a Log. clock may be nil (time.Now).
func New(clock func() time.Time) *Log {
	if clock == nil {
		clock = time.Now
	}
	return &Log{now: clock}
}

// hashEntry computes a row's hash (chain.HashCanonical adds prev_hash to the entry). The hashed
// entry is every column except hash and seq; a NULL detail is hashed as null. Append stores NULL
// for an empty detail, so an empty detail and a missing one are the same thing.
func hashEntry(prev, id, ts, user, action, target string, detail *string) (string, error) {
	m := map[string]any{"id": id, "ts": ts, "user": user, "action": action, "target": target, "detail": nil}
	if detail != nil {
		m["detail"] = *detail
	}
	return chain.HashCanonical(prev, m)
}

// Append adds one row inside the caller's transaction, so a failure here rolls the caller's change back (POST-3).
// The caller must hold the write transaction from store.DB.Write: that serialises chain appends.
func (l *Log) Append(ctx context.Context, tx *sql.Tx, e Entry) error {
	if err := e.validate(); err != nil {
		return err
	}
	q := coredb.New(tx)
	prev, err := q.LastAuditHash(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		a, aerr := q.GetChainAnchor(ctx, chainName)
		switch {
		case errors.Is(aerr, sql.ErrNoRows):
			prev = chain.Genesis
		case aerr != nil:
			return fmt.Errorf("audit: read anchor: %w", aerr)
		default:
			prev = a.LastPrunedHash
		}
	} else if err != nil {
		return fmt.Errorf("audit: read last hash: %w", err)
	}

	id := store.NewID("au")
	ts := store.FormatTS(l.now())
	var detail *string
	if e.Detail != "" {
		detail = &e.Detail
	}
	hash, err := hashEntry(prev, id, ts, e.User, e.Action, e.Target, detail)
	if err != nil {
		return fmt.Errorf("audit: hash entry: %w", err)
	}
	err = q.InsertAudit(ctx, coredb.InsertAuditParams{
		ID: id, PrevHash: prev, Hash: hash, Ts: ts, User: e.User, Action: e.Action, Target: e.Target, Detail: detail,
	})
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	// The head moves in the same transaction, so deleting the newest rows later is detectable (issue #17).
	return chainhead.Advance(ctx, tx, chainName, hash, l.now())
}

// Verify walks core_audit in seq order, a page at a time, and returns the chain verdict.
// The first row must link to the core_chain_anchor hash when the log was pruned, else to Genesis.
// The anchor, the head and every page are read in one read transaction, so appends that commit meanwhile
// cannot make a healthy chain look broken (nor hide a break).
func Verify(ctx context.Context, db *sql.DB) (chain.Result, error) {
	return verify(ctx, db, verifyPage, nil)
}

// verify is Verify with a page size and a hook called after each page (tests append rows from it).
func verify(ctx context.Context, db *sql.DB, page int64, afterPage func()) (chain.Result, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return chain.Result{}, fmt.Errorf("audit: begin read: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only: nothing to commit
	cq := coredb.New(tx)
	anchor := ""
	a, err := cq.GetChainAnchor(ctx, chainName)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return chain.Result{}, fmt.Errorf("audit: read anchor: %w", err)
	default:
		anchor = a.LastPrunedHash
	}
	head, err := chainhead.Load(ctx, tx, chainName)
	if err != nil {
		return chain.Result{}, err
	}
	v := chain.NewVerifierWithHead(anchor, head)
	var after int64
	for {
		rows, err := cq.ListAuditAfter(ctx, coredb.ListAuditAfterParams{Seq: after, Limit: page})
		if err != nil {
			return chain.Result{}, fmt.Errorf("audit: read rows: %w", err)
		}
		for _, r := range rows {
			// A hash that cannot be recomputed (a column holding invalid UTF-8) counts as a broken row.
			recomputed, herr := hashEntry(r.PrevHash, r.ID, r.Ts, r.User, r.Action, r.Target, r.Detail)
			if herr != nil {
				recomputed = ""
			}
			v.Add(r.ID, r.PrevHash, r.Hash, recomputed)
			after = r.Seq
		}
		if afterPage != nil {
			afterPage()
		}
		if int64(len(rows)) < page {
			return v.Result(), nil
		}
	}
}
