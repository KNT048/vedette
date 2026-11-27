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
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/observe"
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
	CreatedBy    string
	ExpiresAt    time.Time // zero = never
	LastReceived time.Time // zero = never
	Hosts        int
	DeviceID     string // the device a person made it for ("" = any machine)
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
	return s.IssueTokenFor(ctx, actor, name, ttlDays, "")
}

// IssueTokenFor is IssueToken for one device (device "" = any machine): the device's agent row then shows the token under Show setup
// until a machine enrols with it. An unknown device is 404 not_found; the box is 409 box_device (it reads its own packages).
func (s *Service) IssueTokenFor(ctx context.Context, actor, name string, ttlDays int, device string) (Token, string, error) {
	if device != "" {
		devs, ok := s.cfg.Approver.(observe.AgentDevices)
		if !ok {
			return Token{}, "", apierr.NotFound()
		}
		d, found, err := devs.AgentDevice(ctx, device)
		if err != nil {
			return Token{}, "", err
		}
		if !found {
			return Token{}, "", apierr.NotFound()
		}
		if d.IsBox {
			return Token{}, "", apierr.New(409, "box_device", "This is the Vedette box itself: it reads its own packages and needs no agent.")
		}
	}
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
	t := Token{ID: store.NewID("tok"), Name: name, Kind: "osquery", Last4: secret[len(secret)-4:], CreatedAt: now, CreatedBy: actor, DeviceID: device}
	if ttlDays > 0 {
		t.ExpiresAt = now.Add(time.Duration(ttlDays) * 24 * time.Hour)
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM intake_agent_tokens`).Scan(&n); err != nil {
			return fmt.Errorf("agentintake: count tokens: %w", err)
		}
		if n >= MaxTokens { // expired tokens with no machine first: they do not count against the limit
			if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE NOT EXISTS (SELECT 1 FROM intake_osquery_nodes n WHERE n.token_id = intake_agent_tokens.id)
				AND ((expires_at IS NOT NULL AND expires_at < ?) OR (first_enrolled_at IS NULL AND created_at < ?))`, store.FormatTS(now), store.FormatTS(now.Add(-unusedTokenLife))); err != nil {
				return fmt.Errorf("agentintake: drop dead tokens: %w", err)
			}
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM intake_agent_tokens`).Scan(&n); err != nil {
				return fmt.Errorf("agentintake: count tokens: %w", err)
			}
		}
		if n >= MaxTokens {
			return apierr.New(409, "too_many_tokens", fmt.Sprintf("There are already %d enrollment tokens, the most there can be. Use Remove unused tokens (every token with no machine, made over an hour ago) or revoke a token you no longer need, then create the install command again.", MaxTokens))
		}
		var exp any
		if !t.ExpiresAt.IsZero() {
			exp = store.FormatTS(t.ExpiresAt)
		}
		// created_by: the enrolment approves its machines in this person's name.
		if _, err := tx.ExecContext(ctx, `INSERT INTO intake_agent_tokens (id, name, kind, token_hash, last4, created_at, expires_at, created_by, device_id) VALUES (?, ?, 'osquery', ?, ?, ?, ?, NULLIF(substr(?, 1, 256), ''), NULLIF(?, ''))`,
			t.ID, t.Name, hashHex(secret), t.Last4, store.FormatTS(now), exp, actor, device); err != nil {
			return fmt.Errorf("agentintake: insert token: %w", err)
		}
		detail := "last4 " + t.Last4 // the name and the last four only, never the secret
		if device != "" {
			detail += ", for device " + device
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_token_create", t.Name, detail)
	})
	if err != nil {
		return Token{}, "", err
	}
	return t, secret, nil
}

// RevokeToken deletes a token and, with it, its nodes: their next call gets node_invalid (POST-3). What they already delivered stays in
// the inventory.
func (s *Service) RevokeToken(ctx context.Context, actor, id string) error {
	var nodes []string
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `SELECT name FROM intake_agent_tokens WHERE id = ?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.NotFound()
		}
		if err != nil {
			return fmt.Errorf("agentintake: read token: %w", err)
		}
		var err2 error
		if nodes, err2 = nodeIDs(ctx, tx, `SELECT id FROM intake_osquery_nodes WHERE token_id = ?`, id); err2 != nil {
			return err2
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE id = ?`, id); err != nil { // the foreign key cascades to the nodes
			return fmt.Errorf("agentintake: delete token: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_token_revoke", name, "")
	})
	if err == nil {
		s.releaseNodes(ctx, nodes) // Their devices may be bound by the next node
	}
	return err
}

// RemoveUnusedTokens deletes every token that has no machine enrolled now, including one whose machines were all removed. A token with a
// machine is left alone, so no node_key is cut. A token made in the last hour is left alone too: its command may be on screen. It returns how many went.
func (s *Service) RemoveUnusedTokens(ctx context.Context, actor string) (int, error) {
	var n int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM intake_osquery_nodes n WHERE n.token_id = intake_agent_tokens.id)`, store.FormatTS(s.now().Add(-freshTokenAge)))
		if err != nil {
			return fmt.Errorf("agentintake: remove unused tokens: %w", err)
		}
		n, _ = r.RowsAffected()
		return s.auditTx(ctx, tx, actor, "inventory.agent_tokens_remove_unused", "unused tokens", fmt.Sprintf("%d removed", n))
	})
	return int(n), err
}

// nodeIDs lists node ids by a query.
func nodeIDs(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("agentintake: read nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("agentintake: read nodes: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListTokens returns the tokens, newest first, with the number of nodes each has.
func (s *Service) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+tokenCols+` FROM intake_agent_tokens t ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, fmt.Errorf("agentintake: list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("agentintake: list tokens: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

//nolint:gosec // G101: column names of the token table, no secret (the hash is not among them)
const tokenCols = `t.id, t.name, t.kind, t.last4, t.created_at, t.expires_at, t.last_received, t.first_enrolled_at, coalesce(t.created_by, ''), coalesce(t.device_id, ''),
	(SELECT count(*) FROM intake_osquery_nodes n WHERE n.token_id = t.id)`

func scanToken(sc interface{ Scan(...any) error }) (Token, error) {
	var t Token
	var created string
	var exp, rec, first sql.NullString
	if err := sc.Scan(&t.ID, &t.Name, &t.Kind, &t.Last4, &created, &exp, &rec, &first, &t.CreatedBy, &t.DeviceID, &t.Hosts); err != nil {
		return Token{}, err
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	t.ExpiresAt, t.LastReceived = parseTS(exp), parseTS(rec)
	t.ExpiresAt = effectiveExpiry(t.ExpiresAt, t.CreatedAt.UTC(), first.Valid)
	return t, nil
}

// setupToken is the token Show setup shows for a device (ReportState.Setup): the token tokenID its agent enrolled with when set, else the
// newest token a person made for this device that still enrols machines; nil when none.
func (s *Service) setupToken(ctx context.Context, device, tokenID string) (*Token, error) {
	q, args := `SELECT `+tokenCols+` FROM intake_agent_tokens t WHERE t.id = ?`, []any{tokenID}
	if tokenID == "" {
		q, args = `SELECT `+tokenCols+` FROM intake_agent_tokens t WHERE t.device_id = ? ORDER BY t.created_at DESC, t.id`, []any{device}
	}
	rows, err := s.db.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("agentintake: read the device's token: %w", err)
	}
	defer func() { _ = rows.Close() }()
	now := s.now()
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("agentintake: read the device's token: %w", err)
		}
		if tokenID != "" || t.ExpiresAt.IsZero() || t.ExpiresAt.After(now) {
			return &t, nil
		}
	}
	return nil, rows.Err()
}

// DeviceMerged is agent-intake's part of a device merge (core/lifecycle): the tokens made for the device that joined are the kept
// device's now.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if _, err := tx.ExecContext(ctx, `UPDATE intake_agent_tokens SET device_id = ? WHERE device_id = ?`, m.Into, m.From); err != nil {
		return fmt.Errorf("agentintake: move the device's tokens: %w", err)
	}
	return nil
}

// EnrolKey names a machine's enrolment on a token: the token and the host_identifier it enrols under. A removal keeps it when the
// person stopped the agent of a device whose token other machines share (DeviceDeleted), so that machine cannot enrol again with it.
func EnrolKey(token, hostIdentifier string) string {
	return "osquery-host:" + token + "/" + hostIdentifier
}

// DeviceDeleted is agent-intake's part of a device delete (core/lifecycle). With the person's choice to stop the device's agent
// (d.StopAgent, INV-27): the node of the device goes, so its next call gets node_invalid. Its token goes with it only when the token was
// made for this device and no other machine uses it; a token other machines share is never revoked, and the machine's enrolment on it
// is handed to the inventory's removal (Block), which refuses it at the next enrol. Without the choice nothing changes here (the token
// made for the device is released by its foreign key).
func (s *Service) DeviceDeleted(ctx context.Context, tx *sql.Tx, d lifecycle.Delete) error {
	if d.StopAgent == nil {
		return nil
	}
	node, ok := strings.CutPrefix(d.StopAgent.Key, "osquery:")
	if !ok {
		return nil
	}
	var tokenID, tokenName, host string
	var forDevice sql.NullString
	var others int
	err := tx.QueryRowContext(ctx, `SELECT n.token_id, t.name, n.host_identifier, t.device_id,
		(SELECT count(*) FROM intake_osquery_nodes o WHERE o.token_id = n.token_id AND o.id <> n.id)
		FROM intake_osquery_nodes n JOIN intake_agent_tokens t ON t.id = n.token_id WHERE n.id = ?`, node).Scan(&tokenID, &tokenName, &host, &forDevice, &others)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // its record is gone already: nothing reports for it
	}
	if err != nil {
		return fmt.Errorf("agentintake: read the device's node: %w", err)
	}
	if forDevice.String == d.Device && others == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_agent_tokens WHERE id = ?`, tokenID); err != nil { // cascades to the node
			return fmt.Errorf("agentintake: revoke the device's token: %w", err)
		}
		d.StopAgent.Token = tokenName
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE id = ?`, node); err != nil {
			return fmt.Errorf("agentintake: delete the device's node: %w", err)
		}
		d.StopAgent.Block = EnrolKey(tokenID, host)
	}
	d.StopAgent.Stopped = true
	return nil
}
