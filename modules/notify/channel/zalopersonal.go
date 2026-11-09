package channel

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// ZaloPersonalConfig is the stored configuration of the unofficial Zalo personal
// channel (D-46): the recipient (a user or group ID) and the session captured by
// scanning the QR code, which is the secret.
type ZaloPersonalConfig struct {
	UserID  string
	Session Secret
}

var zaloPersonalUserRE = regexp.MustCompile(`^\d{6,25}$`)

type zaloPersonalSender struct {
	noPrint
	user string
}

// NewZaloPersonal validates the stored configuration. Sending is not
// implemented: it would mean porting the reverse-engineered personal-account
// protocol (QR login, request signing), which is a legal and effort decision for
// the maintainers. Send returns ErrUnsupported.
func NewZaloPersonal(cfg ZaloPersonalConfig) (Sender, error) {
	user := strings.TrimSpace(cfg.UserID)
	if !zaloPersonalUserRE.MatchString(user) {
		return nil, cfgErr("bad_user_id", "The recipient is the numeric Zalo ID of a user or a group (6 to 25 digits).")
	}
	if cfg.Session.IsZero() {
		return nil, cfgErr("secret_required", "Scan the QR code with the Zalo app first. This channel has no saved session yet.")
	}
	return &zaloPersonalSender{user: user}, nil
}

func (*zaloPersonalSender) Type() Type { return ZaloPersonal }

func (z *zaloPersonalSender) Send(context.Context, Message) (Receipt, error) {
	return Receipt{}, fmt.Errorf("notify: zalo-personal: %w: the unofficial Zalo personal protocol is not implemented (D-46); use Zalo OA, Telegram or email", ErrUnsupported)
}

func (z *zaloPersonalSender) Dest() string { return "Zalo " + z.user }
