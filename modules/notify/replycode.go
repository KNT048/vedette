package notify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// Zalo personal reply codes (docs/specs/approval-tokens.md 7, 7.1; D-96, D-242). notify makes the codes and records their hashes through
// TokenRecorder.RecordReplyCode before the message goes out; response keeps the records and checks a reply against them.

// replyAlphabet has 32 characters (no 0 1 I O): a CSPRNG byte & 31 picks one with no bias.
const replyAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// newReplyCodes makes the two codes of one approver for one request: "A-" (approve) and "R-" (reject), each 6 characters from its own
// random bytes (30 bits).
func newReplyCodes() (approve, reject string, err error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("notify: make reply codes: %w", err)
	}
	code := func(prefix string, r []byte) string {
		out := []byte(prefix)
		for _, x := range r {
			out = append(out, replyAlphabet[x&31])
		}
		return string(out)
	}
	return code("A-", b[:6]), code("R-", b[6:]), nil
}

// replyCodeHash is code_hash of spec 7.1: lowercase hex SHA-256 of the label, the request, the person, the decision and the code, joined
// by LF, with no LF at the end. The request id and user id never hold LF (idRE, core user ids), so the input is not ambiguous.
func replyCodeHash(requestID, userID string, approve bool, code string) string {
	decision := "reject"
	if approve {
		decision = "approve"
	}
	sum := sha256.Sum256([]byte("vedette-reply-code-v1\n" + requestID + "\n" + userID + "\n" + decision + "\n" + code))
	return hex.EncodeToString(sum[:])
}

// replyCodesAllowed: a request gets reply codes only when a recorder is wired, it is low or medium risk (D-96 (3): the weakest channel;
// an unknown risk counts as high), not in-app only, and response allows chat decisions for it (NoChatButtons, D-175: an approver must be
// able to read the whole change in the message).
//
// The job "zalo-listen" (zalolisten.go) reads the replies under the same conditions (Decisions and the recorder wired, the channel
// takes approvals), so a code is only sent when something can read the answer.
func (s *Service) replyCodesAllowed(req ApprovalRequest) bool {
	return s.cfg.Decisions != nil && s.cfg.Tokens != nil && !req.InAppOnly && !req.NoChatButtons && (req.Risk == RiskLow || req.Risk == RiskMedium)
}

// recordReplyCodes makes the codes of one approver and records both hashes; the plain codes only go into the message. A failure means
// no message may carry them.
func (s *Service) recordReplyCodes(ctx context.Context, req ApprovalRequest, a Approver, expires time.Time) (*channel.ReplyCodes, error) {
	approve, reject, err := newReplyCodes()
	if err != nil {
		return nil, err
	}
	for _, c := range []struct {
		approve bool
		code    string
	}{{true, approve}, {false, reject}} {
		rc := ReplyCode{RequestID: req.ID, UserID: a.UserID, Address: a.Address, Approve: c.approve, CodeHash: replyCodeHash(req.ID, a.UserID, c.approve, c.code), ExpiresAt: expires}
		if err := s.cfg.Tokens.RecordReplyCode(ctx, rc); err != nil {
			return nil, fmt.Errorf("notify: record reply code: %w", err)
		}
	}
	return &channel.ReplyCodes{Approve: approve, Reject: reject, Until: expires.In(s.loc(ctx)).Format("15:04")}, nil
}
