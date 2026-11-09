package response

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// The block list the customer's firewall pulls (INV-17, docs/specs/blocklist-format.md): plain text, one address per line,
// on an address that holds a token. The token is the only credential. Its SHA-256 matches a request; the token itself is
// sealed in core_secret so an admin can copy the address again. Regenerating it kills the old address at once.

const (
	tokenPurpose  = "response.blocklist.token"
	apiPrefix     = "/api/v1"
	fetchPerMin   = 60 // pulls per source address per minute
	badTokenPerMi = 20 // wrong tokens per source address per minute before 429
)

var tokenRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("response: token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ensureToken returns the token, creating the first one when there is none. tx is a write transaction.
func (s *Service) ensureToken(ctx context.Context, tx *sql.Tx) (token, last4 string, err error) {
	var secretID string
	err = tx.QueryRowContext(ctx, `SELECT secret_id, token_last4 FROM resp_blocklist WHERE id = 1`).Scan(&secretID, &last4)
	if err == nil {
		pt, oerr := s.cfg.Secrets.Open(ctx, tx, secretID, tokenPurpose)
		if oerr != nil {
			return "", "", fmt.Errorf("response: open the block list token: %w", oerr)
		}
		return string(pt), last4, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("response: read the block list token: %w", err)
	}
	return s.newTokenRow(ctx, tx, "")
}

// newTokenRow makes a token and stores it, replacing the old secret when oldSecret is set.
func (s *Service) newTokenRow(ctx context.Context, tx *sql.Tx, oldSecret string) (string, string, error) {
	token, err := newToken()
	if err != nil {
		return "", "", err
	}
	id, _, err := s.cfg.Secrets.Seal(ctx, tx, tokenPurpose, []byte(token), false)
	if err != nil {
		return "", "", fmt.Errorf("response: seal the block list token: %w", err)
	}
	last4 := token[len(token)-4:]
	if _, err := tx.ExecContext(ctx, `INSERT INTO resp_blocklist (id, token_hash, secret_id, token_last4) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, secret_id = excluded.secret_id, token_last4 = excluded.token_last4, last_fetch_at = NULL, last_fetch_from = NULL`,
		hashToken(token), id, last4); err != nil {
		return "", "", fmt.Errorf("response: save the block list token: %w", err)
	}
	if oldSecret != "" {
		if err := s.cfg.Secrets.Delete(ctx, tx, oldSecret); err != nil {
			return "", "", fmt.Errorf("response: delete the old block list token: %w", err)
		}
	}
	return token, last4, nil
}

func (s *Service) blockURL(token string) string {
	return strings.TrimRight(s.cfg.BaseURL, "/") + apiPrefix + "/response/blocklist/" + token + ".txt"
}

// blockEntries are the entries in force, newest first. An entry whose time to live ended no longer counts, whether or
// not the sweep has removed it, and an entry on the never-touch list is never listed (INV-10, FORBID-7).
func (s *Service) blockEntries(ctx context.Context, q dbq) ([]BlockEntry, error) {
	never, err := s.neverTouch(ctx, q)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT value, source, reason, added_at, expires_at FROM resp_block_entries WHERE expires_at IS NULL OR expires_at > ? ORDER BY added_at DESC, rowid DESC`, store2(s.now()))
	if err != nil {
		return nil, fmt.Errorf("response: read the block list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []BlockEntry{}
	for rows.Next() {
		var e BlockEntry
		var exp sql.NullString
		if err := rows.Scan(&e.Value, &e.Source, &e.Reason, &e.AddedAt, &exp); err != nil {
			return nil, err
		}
		e.ExpiresAt = ptrOrNilNS(exp)
		if _, hit := firstTouched(never, []string{e.Value}); hit {
			continue
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Blocklist is GET /response/blocklist (admin): the address with its token, the entries, the last pull.
func (s *Service) Blocklist(ctx context.Context) (BlocklistView, error) {
	var v BlocklistView
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		token, last4, err := s.ensureToken(ctx, tx)
		if err != nil {
			return err
		}
		v.URL, v.TokenLast4 = s.blockURL(token), last4
		if v.Entries, err = s.blockEntries(ctx, tx); err != nil {
			return err
		}
		var at, from sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT last_fetch_at, last_fetch_from FROM resp_blocklist WHERE id = 1`).Scan(&at, &from); err != nil {
			return err
		}
		if at.Valid {
			v.LastFetch = &LastFetch{At: at.String, From: from.String}
		}
		return nil
	})
	return v, err
}

// RegenerateToken is POST /response/blocklist/token: the old address stops working at once.
func (s *Service) RegenerateToken(ctx context.Context, who Actor) (BlocklistView, error) {
	s.mu.Lock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM resp_blocklist WHERE id = 1`).Scan(&old); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, _, err := s.newTokenRow(ctx, tx, old); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.blocklist.token", "response", LogBlocklistToken, "The block list token was regenerated; the old address no longer works", who.Email)
	})
	s.mu.Unlock()
	if err != nil {
		return BlocklistView{}, err
	}
	return s.Blocklist(ctx)
}

// addBlockEntry puts the address of an executed blocklist_add item on the list, in the transaction that records the item.
func (s *Service) addBlockEntry(ctx context.Context, tx *sql.Tx, r request, it itemRec) error {
	ip := it.Values[PIP]
	if _, ok := CheckValue(PIP, ip); !ok {
		return fmt.Errorf("response: a block list item has no valid address")
	}
	source := "AI request"
	if r.Source == "rule" {
		source = "Rule: " + deref2(r.RuleName)
	}
	_, reason, _ := strings.Cut(it.Change.After, "Reason: ")
	if reason == "" {
		reason = r.Title
	}
	_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO resp_block_entries (value, request_id, item_id, source, reason, added_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ip, r.ID, it.ID, cleanComment(source, 120), cleanComment(reason, 200), deref2(it.ExecutedAt), deref(it.RemoveAt))
	if err != nil {
		return fmt.Errorf("response: add a block list entry: %w", err)
	}
	return nil
}

// cleanComment makes text safe for a comment line of the list: every control character becomes a space and "|" becomes
// "/", so a reason built from attacker data can never start a new line (blocklist-format 4.2).
func cleanComment(s string, limit int) string {
	return strings.ReplaceAll(oneLine(s, limit), "|", "/")
}

// RenderBlocklist is the plain-text list (one address or range per line). Domains never appear in it.
func (s *Service) renderBlocklist(entries []BlockEntry) []byte {
	var b strings.Builder
	b.WriteString("# Vedette block list, " + store2(s.now()) + ". One IP address per line. Lines starting with # are comments.\n")
	seen := map[string]bool{}
	for _, e := range entries {
		a, err := netip.ParseAddr(e.Value)
		if err != nil || seen[e.Value] {
			continue
		}
		seen[e.Value] = true
		exp := "never"
		if e.ExpiresAt != nil {
			exp = *e.ExpiresAt
		}
		b.WriteString("# " + cleanComment(e.Source, 120) + " | " + cleanComment(e.Reason, 200) + " | expires " + exp + "\n")
		b.WriteString(a.String() + "\n")
	}
	return []byte(b.String())
}

// FetchBlocklist answers a pull of the public address. A wrong token is a plain 404 (it looks like a wrong path);
// a source address that pulls too often, or guesses tokens, gets 429. from is the source address of the request.
func (s *Service) FetchBlocklist(ctx context.Context, token, from string) ([]byte, error) {
	if !s.allowFetch("bad:"+from, badTokenPerMi, false) || !s.allowFetch("ok:"+from, fetchPerMin, false) {
		return nil, fail(http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again in a minute.").With("retry_after", 60)
	}
	var stored string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT token_hash FROM resp_blocklist WHERE id = 1`).Scan(&stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !tokenRE.MatchString(token) || errors.Is(err, sql.ErrNoRows) || subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(stored)) != 1 {
		s.allowFetch("bad:"+from, badTokenPerMi, true)
		return nil, fail(http.StatusNotFound, "not_found", "This item no longer exists.")
	}
	s.allowFetch("ok:"+from, fetchPerMin, true)
	var out []byte
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE resp_blocklist SET last_fetch_at = ?, last_fetch_from = ? WHERE id = 1`, s.ts(), oneLine(from, 64)); err != nil {
			return err
		}
		es, err := s.blockEntries(ctx, tx)
		out = s.renderBlocklist(es)
		return err
	})
	return out, err
}

// allowFetch is a sliding one-minute window per key: it reports whether another event still fits; record adds one.
func (s *Service) allowFetch(key string, limit int, record bool) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := s.now()
	keep := s.fetchTimes[key][:0]
	for _, t := range s.fetchTimes[key] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= limit {
		s.fetchTimes[key] = keep
		return false
	}
	if record {
		keep = append(keep, now)
	}
	s.fetchTimes[key] = keep
	return true
}
