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
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Approver identities (S-RESP-2, D-191, WP-31 R3). An administrator types each approver's address or ID on a notify channel; a button
// press or an email link counts as that person only after the person proved the address themselves: a code mailed to it (email), or a code
// answered privately to a button press from that ID (chat). The code is typed in My account by the person signed in. A proof is held to the
// exact address: a list changed by an administrator, or a changed sign-in email, is not linked any more. Approving in the app is not touched.

// LinkMailer mails a link code to an address (cmd/vedette adapts notify's code mailer, the SMTP path of the sign-in codes). nil = no code can be
// mailed: Send code answers 503 email_not_ready.
type LinkMailer interface {
	Available(ctx context.Context) bool
	SendLinkCode(ctx context.Context, to, code string) error
}

// Identity is one approval channel whose list names the person, as My account shows it.
type Identity struct {
	Channel     string  `json:"channel"`
	Label       string  `json:"label"`
	Address     string  `json:"address"`
	Linked      bool    `json:"linked"`
	LinkedAt    *string `json:"linked_at"`
	Method      string  `json:"method"` // email_code, chat_code, or unavailable (no private answer on this channel yet)
	CodeWaiting bool    `json:"code_waiting"`
}

// CodeSent answers Send code: the address masked and when a new code may be asked for.
type CodeSent struct {
	SentTo      string `json:"sent_to"`
	ResendAfter int    `json:"resend_after"`
}

const (
	linkCodeTTL      = 10 * time.Minute
	linkCodeTries    = 5
	linkCodeResend   = 60 * time.Second
	linkCodesPerHour = 5
)

var chatNames = map[string]string{"slack": "Slack", "telegram": "Telegram", "zalo-personal": "Zalo"}

// privateAnswer lists the chat channels whose listener in notify answers a press so that only the person who pressed sees it (Telegram:
// answerCallbackQuery with show_alert). Only these get a link code in the answer: a code shown in a shared conversation would let the listed
// person link a stranger's mistyped ID (L7 again). A Slack or Zalo listener is added here once notify guarantees the same (ephemeral, 1:1).
var privateAnswer = []string{"telegram"}

// linkable says whether a person can prove an address on the channel at all: email by a mailed code, a chat channel by a press. The Zalo OA
// channel has neither (its approvals are links, which notify makes for email only, D-124 (2)), so it is not listed.
func linkable(channel string) bool {
	_, chat := chatVia(channel)
	return channel == "email" || chat
}

// linkCodeHash is the stored form of a link code: it is held to the person, the channel and the address it was made for.
func linkCodeHash(userID, channel, address, code string) string {
	sum := sha256.Sum256([]byte("vedette-link-code-v1\n" + userID + "\n" + channel + "\n" + address + "\n" + code))
	return hex.EncodeToString(sum[:])
}

func newLinkCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("response: link code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// sameAddress compares an address as its channel does: an email address without case, a platform id exactly.
func sameAddress(channel, a, b string) bool {
	if channel == "email" {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return a == b
}

func maskEmail(e string) string {
	local, domain, ok := strings.Cut(e, "@")
	r := []rune(local)
	if !ok || len(r) == 0 {
		return "•••"
	}
	return string(r[0]) + "•••@" + domain
}

// isLinked says whether the person proved exactly this address on the channel. On email the address must still be the sign-in email too.
func (s *Service) isLinked(ctx context.Context, u User, channel, address string) (bool, error) {
	if channel == "email" && !strings.EqualFold(strings.TrimSpace(address), u.Email) {
		return false, nil
	}
	var got string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT address FROM resp_identity WHERE user_id = ? AND channel = ?`, u.ID, channel).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("response: read identity: %w", err)
	}
	return sameAddress(channel, got, address), nil
}

// Linked says whether the person proved exactly this address on the channel (D-191). notify asks it before it mails an approval link to an
// approver (notify INV-13, Config.ApproverLinks): an unproved address gets no mail. The error never holds the address (notify logs it).
func (s *Service) Linked(ctx context.Context, userID, channel, address string) (bool, error) {
	if s.cfg.Users == nil {
		return false, nil
	}
	u, ok, err := s.cfg.Users.Lookup(ctx, userID)
	if err != nil {
		return false, errors.New("response: the user directory could not be read")
	}
	if !ok {
		return false, nil
	}
	linked, err := s.isLinked(ctx, u, channel, address)
	if err != nil {
		return false, errors.New("response: the approver identities could not be read")
	}
	return linked, nil
}

// noteLinkCode counts a code made for (person, channel) and says whether it is within linkCodesPerHour. ponytail: the count lives in memory, a restart
// starts it again; a restart is not something a sender can cause.
func (s *Service) noteLinkCode(userID, channel string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.identSends == nil {
		s.identSends = map[string][]time.Time{}
	}
	k, now := userID+"|"+channel, s.now()
	kept := slices.DeleteFunc(s.identSends[k], func(t time.Time) bool { return now.Sub(t) >= time.Hour })
	if len(kept) >= linkCodesPerHour {
		s.identSends[k] = kept
		return false
	}
	s.identSends[k] = append(kept, now)
	return true
}

// person reads the signed-in person again: active and operator or admin (the route says operator, the account may have changed since).
func (s *Service) person(ctx context.Context, who Actor) (User, error) {
	if s.cfg.Users == nil {
		return User{}, apierr.Forbidden()
	}
	u, ok, err := s.cfg.Users.Lookup(ctx, who.ID)
	if err != nil {
		return User{}, err
	}
	if !ok || u.Disabled || (u.Role != "operator" && u.Role != "admin") {
		return User{}, apierr.Forbidden()
	}
	return u, nil
}

// mine lists the approval channels whose saved list names the person.
func (s *Service) mine(ctx context.Context, u User) ([]Identity, error) {
	out := []Identity{}
	if s.cfg.Notifier == nil {
		return out, nil
	}
	chans, err := s.channels(ctx)
	if err != nil {
		return nil, err
	}
	waiting := map[string]string{} // channel -> address of a code that has not ended
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT channel, address FROM resp_link_codes WHERE user_id = ? AND expires_at > ?`, u.ID, s.ts())
	if err != nil {
		return nil, fmt.Errorf("response: read link codes: %w", err)
	}
	for rows.Next() {
		var ch, addr string
		if err := rows.Scan(&ch, &addr); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("response: read link codes: %w", err)
		}
		waiting[ch] = addr
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("response: read link codes: %w", err)
	}
	for _, t := range approvalTypes {
		i := slices.IndexFunc(chans, func(c NotifyChannel) bool { return c.Type == t && c.Configured })
		if i < 0 || !linkable(t) {
			continue
		}
		list, err := s.cfg.Notifier.Approvers(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, a := range list {
			if a.UserID != u.ID {
				continue
			}
			linked, err := s.isLinked(ctx, u, t, a.Address)
			if err != nil {
				return nil, err
			}
			row := Identity{Channel: t, Label: chans[i].Label, Address: a.Address, Linked: linked, Method: "unavailable"}
			switch {
			case t == "email":
				row.Method = "email_code"
			case slices.Contains(privateAnswer, t):
				row.Method = "chat_code"
			}
			if linked {
				var at string
				if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT linked_at FROM resp_identity WHERE user_id = ? AND channel = ?`, u.ID, t).Scan(&at); err != nil {
					return nil, fmt.Errorf("response: read identity: %w", err)
				}
				row.LinkedAt = &at
			} else if w, ok := waiting[t]; ok && sameAddress(t, w, a.Address) {
				row.CodeWaiting = true
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// MyIdentities is GET /response/me/identities (operator).
func (s *Service) MyIdentities(ctx context.Context, who Actor) ([]Identity, error) {
	u, err := s.person(ctx, who)
	if err != nil {
		return nil, err
	}
	return s.mine(ctx, u)
}

// putCode stores a new code for (person, channel, address), in place of any code waiting.
func (s *Service) putCode(ctx context.Context, tx *sql.Tx, userID, channel, address, code string) error {
	now := s.now()
	_, err := tx.ExecContext(ctx, `INSERT INTO resp_link_codes (user_id, channel, address, code_hash, expires_at, sent_at, tries) VALUES (?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT (user_id, channel) DO UPDATE SET address = excluded.address, code_hash = excluded.code_hash, expires_at = excluded.expires_at,
		sent_at = excluded.sent_at, tries = 0`, userID, channel, address, linkCodeHash(userID, channel, address, code), store.FormatTS(now.Add(linkCodeTTL)), store.FormatTS(now))
	if err != nil {
		return fmt.Errorf("response: store link code: %w", err)
	}
	return nil
}

// SendLinkCode is POST /response/me/identities/{channel}/code (operator): a code mailed to the person's address on the email approval channel.
func (s *Service) SendLinkCode(ctx context.Context, who Actor, channel string) (CodeSent, error) {
	u, err := s.person(ctx, who)
	if err != nil {
		return CodeSent{}, err
	}
	rows, err := s.mine(ctx, u)
	if err != nil {
		return CodeSent{}, err
	}
	i := slices.IndexFunc(rows, func(r Identity) bool { return r.Channel == channel })
	switch {
	case i < 0:
		return CodeSent{}, fail(http.StatusNotFound, "not_listed", "You are not on the approver list of this channel.")
	case rows[i].Method == "unavailable":
		return CodeSent{}, fail(http.StatusBadRequest, "chat_channel", "This channel cannot be linked yet. Approve in Vedette.")
	case rows[i].Method != "email_code":
		return CodeSent{}, fail(http.StatusBadRequest, "chat_channel", "Press Approve or Reject on the next approval message in this channel; Vedette answers you privately with a code.")
	case rows[i].Linked:
		return CodeSent{}, fail(http.StatusConflict, "already_linked", "This address is already linked.")
	case !strings.EqualFold(strings.TrimSpace(rows[i].Address), u.Email):
		return CodeSent{}, fail(http.StatusConflict, "address_mismatch", "The address on the email approval list is not your sign-in email. Ask an administrator to correct the list.")
	case s.cfg.Mailer == nil || !s.cfg.Mailer.Available(ctx):
		return CodeSent{}, fail(http.StatusServiceUnavailable, "email_not_ready", "Email is not set up, so no code can be sent. Ask an administrator to set up the email channel.")
	}
	addr := rows[i].Address
	var sent string
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT sent_at FROM resp_link_codes WHERE user_id = ? AND channel = ?`, u.ID, channel).Scan(&sent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return CodeSent{}, fmt.Errorf("response: read link code: %w", err)
	}
	if at, perr := time.Parse(time.RFC3339Nano, sent); err == nil && perr == nil {
		if wait := linkCodeResend - s.now().Sub(at); wait > 0 {
			secs := int((wait + time.Second - 1) / time.Second)
			return CodeSent{}, fail(http.StatusTooManyRequests, "resend_too_soon", fmt.Sprintf("Wait %d seconds before asking for a new code.", secs)).With("retry_after", secs)
		}
	}
	if !s.noteLinkCode(u.ID, channel) {
		return CodeSent{}, fail(http.StatusTooManyRequests, "too_many_codes", "Too many codes were sent in the last hour. Try again later.")
	}
	code, err := newLinkCode()
	if err != nil {
		return CodeSent{}, err
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.putCode(ctx, tx, u.ID, channel, addr, code) }); err != nil {
		return CodeSent{}, err
	}
	if err := s.cfg.Mailer.SendLinkCode(ctx, addr, code); err != nil {
		s.cfg.Log.WarnContext(ctx, "response: a link code could not be mailed", "user", u.ID, "error", err.Error())
		return CodeSent{}, fail(http.StatusBadGateway, "send_failed", "The code could not be sent. Check the email channel, then try again.")
	}
	return CodeSent{SentTo: maskEmail(addr), ResendAfter: int(linkCodeResend / time.Second)}, nil
}

// ConfirmLink is POST /response/me/identities/{channel}/confirm (operator): the code proves the address it was made for, if that address is
// still the person's on the channel's list.
func (s *Service) ConfirmLink(ctx context.Context, who Actor, channel, code string) (Identity, error) {
	u, err := s.person(ctx, who)
	if err != nil {
		return Identity{}, err
	}
	rows, err := s.mine(ctx, u)
	if err != nil {
		return Identity{}, err
	}
	noCode := fail(http.StatusBadRequest, "no_code", "No code is waiting for this channel. Ask for a new code.")
	var addr string
	var refused *apierr.Error
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var hash, expires string
		var tries int
		err := tx.QueryRowContext(ctx, `SELECT address, code_hash, expires_at, tries FROM resp_link_codes WHERE user_id = ? AND channel = ?`, u.ID, channel).Scan(&addr, &hash, &expires, &tries)
		if errors.Is(err, sql.ErrNoRows) {
			refused = noCode
			return nil
		}
		if err != nil {
			return fmt.Errorf("response: read link code: %w", err)
		}
		drop := func() error {
			_, err := tx.ExecContext(ctx, `DELETE FROM resp_link_codes WHERE user_id = ? AND channel = ?`, u.ID, channel)
			return err
		}
		if !slices.ContainsFunc(rows, func(r Identity) bool { return r.Channel == channel && sameAddress(channel, r.Address, addr) }) {
			refused = noCode // the list changed after the code was made: it proves an address that is not the person's any more
			return drop()
		}
		if at, perr := time.Parse(time.RFC3339Nano, expires); perr != nil || !at.After(s.now()) {
			refused = fail(http.StatusBadRequest, "code_expired", "This code has expired. Ask for a new code.")
			return drop()
		}
		c := strings.TrimSpace(code)
		if len(c) != 6 || strings.Trim(c, "0123456789") != "" {
			refused = fail(http.StatusBadRequest, "invalid_code", "The code is 6 digits.")
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(linkCodeHash(u.ID, channel, addr, c)), []byte(hash)) != 1 {
			tries++
			if tries >= linkCodeTries {
				refused = fail(http.StatusBadRequest, "too_many_tries", "Too many wrong codes. Ask for a new code.")
				return drop()
			}
			refused = fail(http.StatusBadRequest, "wrong_code", fmt.Sprintf("Wrong code. %d %s left.", linkCodeTries-tries, map[bool]string{true: "try", false: "tries"}[linkCodeTries-tries == 1]))
			_, err := tx.ExecContext(ctx, `UPDATE resp_link_codes SET tries = ? WHERE user_id = ? AND channel = ?`, tries, u.ID, channel)
			return err
		}
		if err := drop(); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO resp_identity (user_id, channel, address, linked_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (user_id, channel) DO UPDATE SET address = excluded.address, linked_at = excluded.linked_at`, u.ID, channel, addr, s.ts()); err != nil {
			return fmt.Errorf("response: store identity: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: u.Email, Action: "response.identity_link", Target: channel, Detail: truncRunes(cleanLine(u.Email+" linked "+addr), 400)})
	})
	if err != nil {
		return Identity{}, err
	}
	if refused != nil {
		return Identity{}, refused
	}
	rows, err = s.mine(ctx, u)
	if err != nil {
		return Identity{}, err
	}
	for _, r := range rows {
		if r.Channel == channel && sameAddress(channel, r.Address, addr) {
			return r, nil
		}
	}
	return Identity{}, noCode
}

// Unlink is DELETE /response/me/identities/{channel} (operator).
func (s *Service) Unlink(ctx context.Context, who Actor, channel string) error {
	u, err := s.person(ctx, who)
	if err != nil {
		return err
	}
	var gone bool
	s.mu.Lock() // a press or a link that passed its re-check under the lock decides before the proof goes, never after
	defer s.mu.Unlock()
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var addr string
		err := tx.QueryRowContext(ctx, `DELETE FROM resp_identity WHERE user_id = ? AND channel = ? RETURNING address`, u.ID, channel).Scan(&addr)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("response: delete identity: %w", err)
		}
		gone = true
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_link_codes WHERE user_id = ? AND channel = ?`, u.ID, channel); err != nil {
			return fmt.Errorf("response: delete link code: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: u.Email, Action: "response.identity_unlink", Target: channel, Detail: truncRunes(cleanLine(u.Email+" unlinked "+addr), 400)})
	})
	if err != nil {
		return err
	}
	if !gone {
		return fail(http.StatusNotFound, "not_linked", "Nothing is linked on this channel.")
	}
	return nil
}

func errChatNotLinked(channel string) *apierr.Error {
	return fail(http.StatusForbidden, "approver_not_linked", "Your "+chatNames[channel]+" account is not linked to Vedette yet. Sign in to Vedette and open My account.")
}

// chatNotLinked answers a press from a listed approver whose ID is not linked: nothing is decided, and the answer, which notify shows only to the
// person who pressed (notify POST-8), holds a new link code. The log line never holds the code.
func (s *Service) chatNotLinked(ctx context.Context, u User, channel, ext, target, actor string) error {
	name := chatNames[channel]
	if !slices.Contains(privateAnswer, channel) {
		_ = s.refuse(ctx, fail(http.StatusForbidden, "approver_not_linked", name+" "+ext+" is not linked to a Vedette account yet; no code is shown on this channel"), target, actor)
		return fail(http.StatusForbidden, "approver_not_linked", "Your "+name+" account is not linked to Vedette yet. Approve in Vedette for now.")
	}
	code, err := "", error(nil)
	made := s.noteLinkCode(u.ID, channel)
	if made {
		if code, err = newLinkCode(); err != nil {
			return err
		}
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.putCode(ctx, tx, u.ID, channel, ext, code) }); err != nil {
			return err
		}
	}
	logged := fail(http.StatusForbidden, "approver_not_linked", name+" "+ext+" is not linked to a Vedette account yet; "+
		map[bool]string{true: "a link code was shown to the person who pressed", false: "too many link codes this hour"}[made])
	_ = s.refuse(ctx, logged, target, actor)
	if !made {
		return fail(http.StatusForbidden, "approver_not_linked", "Your "+name+" account is not linked to Vedette yet, and too many link codes were made this hour. Approve in Vedette, or try again later.")
	}
	return fail(http.StatusForbidden, "approver_not_linked", "Your "+name+" account is not linked to Vedette yet. Sign in to Vedette, open My account and enter code "+code+" within 10 minutes, then press again.")
}
