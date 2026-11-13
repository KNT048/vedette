package honeypot

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

const secretPurpose = "hp_token.password"

// maxHostIPs is the limit of the host (host-api 6.6): it holds at most this many decoy addresses, so there are at most
// this many Trap IPs.
const maxHostIPs = 32

func bad(code, msg string) error         { return apierr.New(400, code, msg) }
func conflictErr(code, msg string) error { return apierr.New(409, code, msg) }
func notFound(msg string) error          { return apierr.New(404, apierr.CodeNotFound, msg) }

// ---- tokens ----

func randText(n int, alphabet string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("honeypot: random: %w", err)
	}
	out := make([]byte, n)
	for i, x := range b {
		out[i] = alphabet[int(x)%len(alphabet)]
	}
	return string(out), nil
}

const (
	letters = "abcdefghijklmnopqrstuvwxyz"
	lower   = "abcdefghijklmnopqrstuvwxyz0123456789"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

type tokenRow struct {
	Token
	secretID string
}

func (s *Service) loadTokens(ctx context.Context, q querier) ([]tokenRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.id, t.type, t.name, t.value, t.secret_id, t.plant_at, t.created_at,
		(SELECT max(ts) FROM hp_hits h WHERE h.token_id = t.id),
		(SELECT count(*) FROM hp_hits h WHERE h.token_id = t.id AND h.is_test = 0)
		FROM hp_tokens t ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []tokenRow
	for rows.Next() {
		var t tokenRow
		var sec, last sql.NullString
		if err := rows.Scan(&t.ID, &t.Type, &t.Name, &t.Value, &sec, &t.PlantAt, &t.CreatedAt, &last, &t.Triggers); err != nil {
			return nil, fmt.Errorf("honeypot: read tokens: %w", err)
		}
		t.secretID = sec.String
		if last.Valid {
			t.LastTriggeredAt = ptr(last.String)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Tokens is GET /honeypot/tokens; the bait password of a credential token is opened here (INV-10).
func (s *Service) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.loadTokens(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		t := r.Token
		if r.secretID != "" {
			pw, err := s.cfg.Secrets.Open(ctx, s.db.Reader(), r.secretID, secretPurpose)
			if err != nil { // one stored secret that cannot be opened (wrong key, damaged row) must not hide the other tokens
				s.cfg.Log.ErrorContext(ctx, "honeypot: open bait password", "token", r.ID, "error", err)
			} else {
				t.Password = ptr(string(pw))
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// MaskTokens returns l with every bait password hidden except its last 4 characters (D-189, L14): what a viewer sees.
// A password shorter than 8 characters shows no tail at all (the rule of secrets.Value.Last4). The input is not changed.
func MaskTokens(l []Token) []Token {
	out := make([]Token, len(l))
	for i, t := range l {
		out[i] = t
		if t.Password != nil {
			out[i].Password = ptr(maskPassword(*t.Password))
		}
	}
	return out
}

func maskPassword(pw string) string {
	r := []rune(pw)
	if len(r) < 8 {
		return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
	}
	return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" + string(r[len(r)-4:])
}

func (s *Service) token(ctx context.Context, id string) (Token, error) {
	all, err := s.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	for _, t := range all {
		if t.ID == id {
			return t, nil
		}
	}
	return Token{}, notFound("No such token.")
}

// AddToken is POST /honeypot/tokens (INV-10, POST-4, INV-13).
func (s *Service) AddToken(ctx context.Context, actor string, in TokenInput) (Token, error) {
	switch in.Type {
	case TokenFile, TokenCredential, TokenURL, TokenDNS:
	default:
		return Token{}, bad("bad_type", "Choose a token type: decoy file, fake credentials, URL or DNS name.")
	}
	name := strings.TrimSpace(in.Name)
	plant := strings.TrimSpace(in.PlantAt)
	if r := []rune(plant); len(r) > 120 {
		plant = strings.TrimSpace(string(r[:120]))
	}
	if !tokenNameRE.MatchString(name) {
		return Token{}, bad("bad_name", "The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: Payroll-2026-Q4.")
	}
	if plant == "" {
		return Token{}, bad("bad_plant_at", `Say where you will plant it, for example \\SRV-FILE\HR or "Password manager". This reminds you where to look when it fires.`)
	}
	if in.Type == TokenFile && in.Ext != "docx" && in.Ext != "xlsx" {
		return Token{}, bad("bad_ext", "Choose the file type: .docx or .xlsx.")
	}
	rnd, err := randText(10, lower)
	if err != nil {
		return Token{}, err
	}
	var value, password string
	switch in.Type {
	case TokenFile:
		value = strings.Join(strings.Fields(name), "-") + "." + in.Ext
	case TokenCredential:
		// The bait account is a generated, plausible service account (svc_ plus six letters), never the display name of the
		// token and never a common one like admin: ordinary brute force does not fire it, only a stolen list does (D-90 (3)).
		acct, err := randText(6, letters)
		if err != nil {
			return Token{}, err
		}
		value = "svc_" + acct
		a, err1 := randText(4, lower)
		b, err2 := randText(6, upper)
		if err := errors.Join(err1, err2); err != nil {
			return Token{}, err
		}
		password = "Bk!" + a + "-" + b + "x9"
	case TokenURL:
		box, err := s.cfg.Inventory.Box(ctx)
		if err != nil {
			return Token{}, fmt.Errorf("honeypot: read box: %w", err)
		}
		value = "https://" + box.Name + ":8443/t/" + rnd
	case TokenDNS:
		sl := slug(name)
		if sl == "" {
			sl = "token"
		}
		value = sl[:min(20, len(sl))] + "-" + rnd[:4] + ".vedette.internal"
	}
	t := Token{ID: store.NewID("tok"), Type: in.Type, Name: name, Value: value, PlantAt: plant, CreatedAt: store.FormatTS(s.now())}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var secretID any
		if in.Type == TokenCredential {
			id, _, err := s.cfg.Secrets.Seal(ctx, tx, secretPurpose, []byte(password), false)
			if err != nil {
				return fmt.Errorf("honeypot: seal bait password: %w", err)
			}
			secretID = id
			t.Password = ptr(password)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_tokens (id, type, name, value, secret_id, plant_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.ID, string(t.Type), t.Name, t.Value, secretID, t.PlantAt, t.CreatedAt); err != nil {
			if store.IsUniqueViolation(err) {
				return conflictErr("duplicate", "A token of this type with this name already exists.")
			}
			return fmt.Errorf("honeypot: add token: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.token_add", t.Value, string(t.Type))
	})
	if err != nil {
		return Token{}, err
	}
	if t.Type == TokenFile {
		s.Kick() // the share needs the new file name
	}
	return t, nil
}

// DeleteToken is DELETE /honeypot/tokens/{id}: the planted copy stops alerting (INV-10, POST-5), old hits stay.
func (s *Service) DeleteToken(ctx context.Context, actor, id string) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var value, typ string
		var sec sql.NullString
		err := tx.QueryRowContext(ctx, `DELETE FROM hp_tokens WHERE id = ? RETURNING value, type, secret_id`, id).Scan(&value, &typ, &sec)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such token.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: delete token: %w", err)
		}
		if sec.Valid {
			if err := s.cfg.Secrets.Delete(ctx, tx, sec.String); err != nil {
				return fmt.Errorf("honeypot: delete bait password: %w", err)
			}
		}
		return s.auditTx(ctx, tx, actor, "honeypot.token_delete", value, typ)
	})
	if err == nil {
		s.Kick()
	}
	return err
}
