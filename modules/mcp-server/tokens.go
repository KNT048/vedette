package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// MaxTokens is how many tokens a box holds (D-231): one per tool that connects, few on a small appliance. It also bounds the
// audit rows the call limits allow (D-232).
const MaxTokens = 10

var (
	tokenRE = regexp.MustCompile(`^vmcp_[0-9a-f]{32}$`)
	nameRE  = regexp.MustCompile(`^[\p{L}\p{N} _.'-]{1,64}$`)
)

// Token is a token as the API shows it: never the token itself (INV-3).
type Token struct {
	ID        string
	Name      string
	Scopes    []string
	Last4     string
	CreatedAt time.Time
	LastUsed  *time.Time
}

// Has reports whether the token holds scope.
func (t Token) Has(scope string) bool { return slices.Contains(t.Scopes, scope) }

func hashToken(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("mcpserver: stored time %q: %w", s, err)
	}
	return t, nil
}

const tokenCols = `id, name, scopes, last4, created_at, last_used`

type scanner interface{ Scan(dest ...any) error }

func scanToken(r scanner) (Token, error) {
	var (
		t               Token
		scopes, created string
		used            sql.NullString
	)
	if err := r.Scan(&t.ID, &t.Name, &scopes, &t.Last4, &created, &used); err != nil {
		return Token{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
		return Token{}, fmt.Errorf("mcpserver: stored scopes: %w", err)
	}
	var err error
	if t.CreatedAt, err = parseTS(created); err != nil {
		return Token{}, err
	}
	if used.Valid {
		u, err := parseTS(used.String)
		if err != nil {
			return Token{}, err
		}
		t.LastUsed = &u
	}
	return t, nil
}

// Tokens lists the tokens, oldest first.
func (s *Service) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+tokenCols+` FROM mcp_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("mcpserver: read tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CleanScopes checks the scopes of a new token (INV-2): at least one, each known; duplicates are dropped and the order is the
// GUI's. 400 invalid_scopes otherwise.
func CleanScopes(in []string) ([]string, error) {
	out := []string{}
	for _, sc := range AllScopes {
		if slices.Contains(in, sc) {
			out = append(out, sc)
		}
	}
	for _, sc := range in {
		if !slices.Contains(AllScopes, sc) {
			out = nil
			break
		}
	}
	if len(out) == 0 {
		return nil, apierr.New(http.StatusBadRequest, "invalid_scopes", "Choose at least one read scope: devices, findings or vulnerability feeds.")
	}
	return out, nil
}

// Create makes a token and returns it in full, the only time it is ever shown (INV-3, POST-2). The row and the audit row are
// one transaction (INV-8).
func (s *Service) Create(ctx context.Context, actor, name string, scopes []string) (string, Token, error) {
	name = strings.TrimSpace(name)
	if !nameRE.MatchString(name) {
		return "", Token{}, apierr.New(http.StatusBadRequest, "invalid_name", "The token name is 1 to 64 characters: letters, digits, spaces, apostrophes, dashes.")
	}
	scopes, err := CleanScopes(scopes)
	if err != nil {
		return "", Token{}, err
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never returns an error (Go 1.24+)
	secret := "vmcp_" + hex.EncodeToString(raw[:])
	sc, _ := json.Marshal(scopes) //nolint:errchkjson // a []string always encodes
	t := Token{ID: store.NewID("mcpt"), Name: name, Scopes: scopes, Last4: secret[len(secret)-4:], CreatedAt: s.now().UTC().Truncate(time.Millisecond)}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_tokens`).Scan(&n); err != nil {
			return fmt.Errorf("mcpserver: count tokens: %w", err)
		}
		if n >= MaxTokens {
			return apierr.New(http.StatusBadRequest, "too_many", fmt.Sprintf("A box holds up to %d MCP tokens. Revoke one you no longer use.", MaxTokens))
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_tokens (id, name, scopes, token_hash, last4, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			t.ID, t.Name, string(sc), hashToken(secret), t.Last4, store.FormatTS(t.CreatedAt)); err != nil {
			return fmt.Errorf("mcpserver: insert token: %w", err)
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "mcp.token_create", Target: t.Name, Detail: "scopes " + strings.Join(scopes, ",") + ", last 4 " + t.Last4})
	})
	if err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

// Revoke deletes a token: the next request that carries it gets 401 (INV-4). 404 when there is no such token.
func (s *Service) Revoke(ctx context.Context, actor, id string) error {
	defer s.limits.forget(id)
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		t, err := scanToken(tx.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM mcp_tokens WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.NotFound()
		}
		if err != nil {
			return fmt.Errorf("mcpserver: read token: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_tokens WHERE id = ?`, id); err != nil {
			return fmt.Errorf("mcpserver: delete token: %w", err)
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "mcp.token_revoke", Target: t.Name, Detail: "last 4 " + t.Last4})
	})
}

// authenticate returns the token a bearer secret names. ok is false for a malformed, unknown or revoked token; the shape is
// checked before the database is read.
func (s *Service) authenticate(ctx context.Context, secret string) (Token, bool, error) {
	if !tokenRE.MatchString(secret) {
		return Token{}, false, nil
	}
	t, err := scanToken(s.db.Reader().QueryRowContext(ctx, `SELECT `+tokenCols+` FROM mcp_tokens WHERE token_hash = ?`, hashToken(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, fmt.Errorf("mcpserver: read token: %w", err)
	}
	return t, true, nil
}

// lastUsedEvery is how stale last_used may get before a request that is not a tool call writes it (INV-4: tool calls always do).
const lastUsedEvery = time.Minute

// touch writes last_used when it is older than lastUsedEvery.
func (s *Service) touch(ctx context.Context, t Token) error {
	now := s.now()
	if t.LastUsed != nil && now.Sub(*t.LastUsed) < lastUsedEvery {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE mcp_tokens SET last_used = ? WHERE id = ?`, store.FormatTS(now), t.ID)
		return err
	})
}

// recordCall writes last_used and one audit row for a tool call (D-232): the token's name, the tool and the outcome. The
// arguments are never written (INV-8): they are what the agent asked about.
func (s *Service) recordCall(ctx context.Context, t Token, tool, outcome string, rows int) error {
	detail := fmt.Sprintf("tool %s, %s", tool, outcome)
	if outcome == "ok" {
		detail += fmt.Sprintf(", %d results", rows)
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		// a token revoked while the call ran updates no row; the call is still written down
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_tokens SET last_used = ? WHERE id = ?`, store.FormatTS(s.now()), t.ID); err != nil {
			return fmt.Errorf("mcpserver: last_used: %w", err)
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: "mcp:" + t.Name, Action: "mcp.call", Target: t.Name, Detail: detail})
	})
}
