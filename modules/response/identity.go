package response

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
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
	Name        string  `json:"name,omitempty"` // the shown name of the address (Zalo personal, D-447)
	Linked      bool    `json:"linked"`
	LinkedAt    *string `json:"linked_at"`
	Method      string  `json:"method"` // email_code, chat_code, or unavailable (no private answer on this channel yet)
	CodeWaiting bool    `json:"code_waiting"`
}

// CodeSent answers Send code: the address masked and when a new code may be asked for.
type CodeSent struct {
	SentTo      string `json:"sent_to"`
	ResendAfter int    `json:"resend_after"`
	// Code is set only for a channel where the person proves the ID by sending the code from it (sendLink): shown to the signed-in
	// person alone, it proves nothing until it arrives from the listed ID.
	Code string `json:"code,omitempty"`
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
// person link a stranger's mistyped ID (L7 again). A Slack listener is added here once notify guarantees the same (ephemeral).
var privateAnswer = []string{"telegram"}

// sendLink lists the chat channels linked by a confirm link (D-447, option A; it replaced D-243's code sent from the ID): when an
// administrator lists the person with an ID, the box's account sends that ID a single-use link (ChatLinkToken), and only the person,
// signed in to Vedette as themself, confirms it (ConfirmLink, POST). Opening the link proves the message reached that account; signing in
// proves who the person is; a reply from the account proves nothing and links nothing. No administrator path links on someone's behalf.
var sendLink = []string{"zalo-personal"}

// linkTokenRE is a confirm link's token: the hint of the person it is for (linkHint), "-", 128 random bits in base64url.
var linkTokenRE = regexp.MustCompile(`^[0-9a-f]{8}-[A-Za-z0-9_-]{22}$`)

// linkHint tells, before anything is read, whether a token can be the signed-in person's: another person gets a clear refusal and the
// token is not touched (the hint is not secret; the 128 random bits are).
func linkHint(userID string) string {
	sum := sha256.Sum256([]byte("vedette-link-hint-v1\n" + userID))
	return hex.EncodeToString(sum[:4])
}

func newLinkToken(userID string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("response: link token: %w", err)
	}
	return linkHint(userID) + "-" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

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
			row := Identity{Channel: t, Label: chans[i].Label, Address: a.Address, Name: a.Name, Linked: linked, Method: "unavailable"}
			switch {
			case t == "email":
				row.Method = "email_code"
			case slices.Contains(privateAnswer, t):
				row.Method = "chat_code"
			case slices.Contains(sendLink, t):
				row.Method = "send_code"
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
	i := slices.IndexFunc(rows, func(r Identity) bool { return r.Channel == channel && !r.Linked }) // listed twice: the ID still to link
	if i < 0 {
		i = slices.IndexFunc(rows, func(r Identity) bool { return r.Channel == channel })
	}
	switch {
	case i < 0:
		return CodeSent{}, fail(http.StatusNotFound, "not_listed", "You are not on the approver list of this channel.")
	case rows[i].Method == "unavailable":
		return CodeSent{}, fail(http.StatusBadRequest, "chat_channel", "This channel cannot be linked yet. Approve in Vedette.")
	case rows[i].Method == "send_code":
		return CodeSent{}, fail(http.StatusBadRequest, "chat_channel", "An administrator sends a link to your "+chatNames[channel]+" account when they list you; open it and confirm while signed in to Vedette.")
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
// still the person's on the channel's list. On a sendLink channel the code is the token of the confirm link the box sent to the ID (D-447):
// a token for another person is refused before anything is read, so it stays valid for its person.
func (s *Service) ConfirmLink(ctx context.Context, who Actor, channel, code string) (Identity, error) {
	u, err := s.person(ctx, who)
	if err != nil {
		return Identity{}, err
	}
	if !slices.Contains(sendLink, channel) {
		return s.confirmCode(ctx, u, channel, code)
	}
	c := strings.TrimSpace(code)
	switch {
	case !linkTokenRE.MatchString(c):
		return Identity{}, fail(http.StatusBadRequest, "invalid_link", "This link is not complete. Open it again from the "+chatNames[channel]+" message.")
	case subtle.ConstantTimeCompare([]byte(c[:8]), []byte(linkHint(u.ID))) != 1:
		return Identity{}, fail(http.StatusForbidden, "other_account", "This link is for another Vedette account. Sign out, then sign in as the person the "+chatNames[channel]+" message names.")
	}
	id, err := s.confirmCode(ctx, u, channel, c)
	if ae, ok := apierr.As(err); ok { // the words of a link, not of a typed code
		switch ae.Code {
		case "code_expired":
			return Identity{}, fail(http.StatusBadRequest, "code_expired", "This link has expired. Ask your administrator to press Send again.")
		case "no_code":
			return Identity{}, fail(http.StatusBadRequest, "no_code", "This link was already used or was replaced by a newer one.")
		case "wrong_code", "too_many_tries":
			return Identity{}, fail(http.StatusBadRequest, ae.Code, "This link is not valid. Ask your administrator to press Send again.")
		}
	}
	return id, err
}

// confirmCode checks the person's waiting code (on a sendLink channel, the token of the confirm link) for the channel and links the address
// it was made for.
func (s *Service) confirmCode(ctx context.Context, u User, channel, code string) (Identity, error) {
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
		if slices.Contains(sendLink, channel) != linkTokenRE.MatchString(c) || (!linkTokenRE.MatchString(c) && (len(c) != 6 || strings.Trim(c, "0123456789") != "")) {
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

// issueLinkToken makes the token of a confirm link for a sendLink channel (the same limits as a mailed code: one a minute, five an hour);
// it replaces any token waiting.
func (s *Service) issueLinkToken(ctx context.Context, u User, channel, addr string) (string, error) {
	var sent string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT sent_at FROM resp_link_codes WHERE user_id = ? AND channel = ?`, u.ID, channel).Scan(&sent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("response: read link code: %w", err)
	}
	if at, perr := time.Parse(time.RFC3339Nano, sent); err == nil && perr == nil {
		if wait := linkCodeResend - s.now().Sub(at); wait > 0 {
			secs := int((wait + time.Second - 1) / time.Second)
			return "", fail(http.StatusTooManyRequests, "resend_too_soon", fmt.Sprintf("Wait %d seconds before sending a new link.", secs)).With("retry_after", secs)
		}
	}
	if !s.noteLinkCode(u.ID, channel) {
		return "", fail(http.StatusTooManyRequests, "too_many_codes", "Too many links were made for this person in the last hour. Try again later.")
	}
	token, err := newLinkToken(u.ID)
	if err != nil {
		return "", err
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.putCode(ctx, tx, u.ID, channel, addr, token) }); err != nil {
		return "", err
	}
	return token, nil
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
	if slices.Contains(sendLink, channel) {
		_ = s.refuse(ctx, fail(http.StatusForbidden, "approver_not_linked", name+" "+ext+" is not linked to a Vedette account yet"), target, actor)
		return fail(http.StatusForbidden, "approver_not_linked", "Your "+name+" account is not linked to Vedette yet. Open the link Vedette sent to this account and confirm it while signed in to Vedette, or ask your administrator to send it again.")
	}
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

// ChatLinkToken makes the token of a confirm link for a sendLink channel when an administrator lists the person with that ID (notify sends
// https://<box>/link/zalo?c=<token> to the ID: Config.LinkCodes, D-447). The token is 128 random bits after the person's hint, single use,
// valid 10 minutes, kept hashed with (person, channel, address), and only ConfirmLink by that person, signed in, uses it: making it links
// nothing. The person must be an active operator or admin listed with exactly that address and not linked yet; one a minute and five an
// hour; a new one replaces the one waiting. name is how the message names the person (their name, else their email).
func (s *Service) ChatLinkToken(ctx context.Context, userID, channel, address string) (token, name string, err error) {
	if !s.on() {
		return "", "", fail(http.StatusServiceUnavailable, "link_unavailable", "Approvers cannot be linked now: the Response module is off.")
	}
	if !slices.Contains(sendLink, channel) {
		return "", "", fail(http.StatusBadRequest, "chat_channel", "This channel is not linked by a confirm link.")
	}
	if s.cfg.Users == nil {
		return "", "", fail(http.StatusNotFound, "not_listed", "This person is not an approver on this channel.")
	}
	u, ok, err := s.cfg.Users.Lookup(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if !ok || u.Disabled || (u.Role != "operator" && u.Role != "admin") {
		return "", "", fail(http.StatusNotFound, "not_listed", "This person is not an approver on this channel.")
	}
	rows, err := s.mine(ctx, u)
	if err != nil {
		return "", "", err
	}
	i := slices.IndexFunc(rows, func(r Identity) bool { return r.Channel == channel && sameAddress(channel, r.Address, address) })
	switch {
	case i < 0:
		return "", "", fail(http.StatusNotFound, "not_listed", "This person is not listed with this address on the channel. Save the channel first.")
	case rows[i].Linked:
		return "", "", fail(http.StatusConflict, "already_linked", "This address is already linked.")
	}
	if token, err = s.issueLinkToken(ctx, u, channel, address); err != nil {
		return "", "", err
	}
	if name = strings.TrimSpace(u.Name); name == "" {
		name = u.Email
	}
	return token, name, nil
}

// DropChatLink ends the person's proof of exactly this address on the channel, and any code waiting for it, when an administrator removes
// them as an approver or gives them another address (notify Config.LinkCodes, D-447): a proof held to an old address must not count again
// if the list later names that address once more. Nothing linked is no error. The audit row is response.identity_unlink by the actor.
func (s *Service) DropChatLink(ctx context.Context, actor, userID, channel, address string) error {
	s.mu.Lock() // as Unlink: a decision that passed its re-check under the lock runs before the proof goes, never after
	defer s.mu.Unlock()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var got string
		err := tx.QueryRowContext(ctx, `SELECT address FROM resp_identity WHERE user_id = ? AND channel = ?`, userID, channel).Scan(&got)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !sameAddress(channel, got, address)) {
			_, err = tx.ExecContext(ctx, `DELETE FROM resp_link_codes WHERE user_id = ? AND channel = ? AND address = ?`, userID, channel, address)
			return err
		}
		if err != nil {
			return fmt.Errorf("response: read identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_identity WHERE user_id = ? AND channel = ?`, userID, channel); err != nil {
			return fmt.Errorf("response: delete identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_link_codes WHERE user_id = ? AND channel = ?`, userID, channel); err != nil {
			return fmt.Errorf("response: delete link code: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "response.identity_unlink", Target: channel,
			Detail: truncRunes(cleanLine(userID+" no longer linked "+address+": an administrator changed the approver list"), 400)})
	})
}
