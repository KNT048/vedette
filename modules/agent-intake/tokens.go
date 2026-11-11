package agentintake

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

const (
	tokenPrefix   = "vdt_osquery_"                     //nolint:gosec // the fixed start of every token, not a credential
	tokenAlphabet = "abcdefghijkmnpqrstuvwxyz23456789" // 32 letters: a byte & 31 picks one without bias
	tokenChars    = 32                                 // 32 × 5 bits = 160 bits
	maxTokenName  = 64
)

// Token is a token as the list shows it: the secret is never here.
type Token struct {
	ID           string
	Name         string
	Kind         string
	Last4        string
	CreatedAt    time.Time
	ExpiresAt    time.Time // zero = never
	LastReceived time.Time // zero = never
	Hosts        int
}

// newSecret makes a token secret: tokenPrefix + 32 characters of a 32-letter alphabet from crypto/rand (160 bits).
func newSecret() (string, error) {
	b := make([]byte, tokenChars)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentintake: token secret: %w", err)
	}
	for i := range b {
		b[i] = tokenAlphabet[b[i]&31]
	}
	return tokenPrefix + string(b), nil
}

// IssueToken makes an enrolment token (S-INV-4). ttlDays is 0..365, 0 = never expires. The secret is returned here and nowhere else: the
// table keeps its SHA-256 and the last four characters. At most MaxTokens tokens exist at once.
func (s *Service) IssueToken(ctx context.Context, actor, name string, ttlDays int) (Token, string, error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > maxTokenName || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '<' || r == '>' }) {
		return Token{}, "", apierr.New(400, "bad_name", "Name the token so you remember which machines use it, up to 64 characters.")
	}
	if ttlDays < 0 || ttlDays > 365 {
		return Token{}, "", apierr.New(400, "bad_expiry", "The expiry is 0 to 365 days; 0 means it never expires.")
	}
	secret, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	now := s.now()
	t := Token{ID: store.NewID("tok"), Name: name, Kind: "osquery", Last4: secret[len(secret)-4:], CreatedAt: now}
	if ttlDays > 0 {
		t.ExpiresAt = now.Add(time.Duration(ttlDays) * 24 * time.Hour)
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM intake_agent_tokens`).Scan(&n); err != nil {
			return fmt.Errorf("agentintake: count tokens: %w", err)
		}
		if n >= MaxTokens {
			return apierr.New(409, "too_many_tokens", fmt.Sprintf("There are already %d enrollment tokens. Revoke one you no longer use.", MaxTokens))
		}
		var exp any
		if !t.ExpiresAt.IsZero() {
			exp = store.FormatTS(t.ExpiresAt)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_agent_tokens (id, name, kind, token_hash, last4, created_at, expires_at) VALUES (?, ?, 'osquery', ?, ?, ?, ?)`,
			t.ID, t.Name, hashHex(secret), t.Last4, store.FormatTS(now), exp); err != nil {
			return fmt.Errorf("agentintake: insert token: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_token_create", t.Name, "last4 "+t.Last4) // the name and the last four only, never the secret
	})
	if err != nil {
		return Token{}, "", err
	}
	return t, secret, nil
}

// RevokeToken deletes a token and, with it, its nodes: their next call gets node_invalid (POST-3). What they already delivered stays in
// the inventory.
func (s *Service) RevokeToken(ctx context.Context, actor, id string) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `SELECT name FROM intake_agent_tokens WHERE id = ?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.NotFound()
		}
		if err != nil {
			return fmt.Errorf("agentintake: read token: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE id = ?`, id); err != nil { // the foreign key cascades to the nodes
			return fmt.Errorf("agentintake: delete token: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_token_revoke", name, "")
	})
}

// ListTokens returns the tokens, newest first, with the number of nodes each has.
func (s *Service) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT t.id, t.name, t.kind, t.last4, t.created_at, t.expires_at, t.last_received,
		(SELECT count(*) FROM intake_osquery_nodes n WHERE n.token_id = t.id) FROM intake_agent_tokens t ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, fmt.Errorf("agentintake: list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Token{}
	for rows.Next() {
		var t Token
		var created string
		var exp, rec sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind, &t.Last4, &created, &exp, &rec, &t.Hosts); err != nil {
			return nil, fmt.Errorf("agentintake: list tokens: %w", err)
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		t.ExpiresAt, t.LastReceived = parseTS(exp), parseTS(rec)
		out = append(out, t)
	}
	return out, rows.Err()
}
