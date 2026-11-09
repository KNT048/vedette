package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ZaloConfig configures an official Zalo OA channel (customer-service message to a follower).
type ZaloConfig struct {
	OAID    string       // Official Account ID, 6 to 20 digits
	UserID  string       // recipient: the Zalo user_id of a person who followed or messaged the OA
	Token   Secret       // OA access token from Zalo Developers
	BaseURL string       // empty = https://openapi.zalo.me ; set only by tests to point at a fake
	Client  *http.Client // nil = NewHTTPClient()
}

var (
	zaloOARE   = regexp.MustCompile(`^\d{6,20}$`)
	zaloUserRE = regexp.MustCompile(`^\d{6,25}$`)
)

const (
	zaloAPI      = "https://openapi.zalo.me"
	zaloSendPath = "/v3.0/oa/message/cs"
	zaloTextMax  = 2000
	zaloMinToken = 20
)

type zaloSender struct {
	oa, user string
	token    Secret
	endpoint string
	client   *http.Client
}

// NewZalo validates cfg and returns the adapter.
func NewZalo(cfg ZaloConfig) (Sender, error) {
	oa, user := strings.TrimSpace(cfg.OAID), strings.TrimSpace(cfg.UserID)
	if !zaloOARE.MatchString(oa) {
		return nil, cfgErr("bad_oa_id", "OA ID is a string of digits, shown in the Official Account management page.")
	}
	if !zaloUserRE.MatchString(user) {
		return nil, cfgErr("bad_user_id", "The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA.")
	}
	tok := strings.TrimSpace(cfg.Token.Reveal())
	if tok == "" {
		return nil, cfgErr("secret_required", "Enter the access token. This channel has no saved key yet.")
	}
	if len(tok) < zaloMinToken {
		return nil, cfgErr("bad_token", "The Zalo access token is too short. Copy the whole string from Zalo Developers.")
	}
	for _, r := range tok {
		if r <= ' ' || r > '~' {
			return nil, cfgErr("bad_token", "The Zalo access token has a character that is not allowed. Copy it again without spaces.")
		}
	}
	base := zaloAPI
	if cfg.BaseURL != "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return nil, cfgErr("bad_base_url", "The Zalo API address is not valid.")
		}
		base = strings.TrimRight(u.String(), "/")
	}
	return &zaloSender{oa: oa, user: user, token: NewSecret(tok), endpoint: base + zaloSendPath, client: clientOrDefault(cfg.Client)}, nil
}

func (*zaloSender) Type() Type { return Zalo }

func (z *zaloSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	body, err := json.Marshal(map[string]any{
		"recipient": map[string]string{"user_id": z.user},
		"message":   map[string]string{"text": fit(m.norm().lines(link), zaloTextMax)},
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: zalo: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, z.endpoint, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: zalo: build request: %s", transportReason(err, []Secret{z.token}))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("access_token", z.token.Reveal())
	code, ans, err := do(z.client, Zalo, req, z.token)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Zalo, code, ans, z.token)
	}
	// The Open API answers HTTP 200 for most failures and puts the verdict in "error" (0 = success).
	var out struct {
		Error   *int   `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(ans, &out) != nil || out.Error == nil {
		return Receipt{}, &StatusError{Channel: Zalo, Code: code, Reason: "the answer did not confirm delivery"}
	}
	if *out.Error != 0 {
		return Receipt{}, &StatusError{Channel: Zalo, Code: code, Reason: fmt.Sprintf("Zalo error %d: %s", *out.Error, reasonFrom([]byte(out.Message), z.token))}
	}
	return Receipt{To: "OA " + z.oa, Detail: fmt.Sprintf("Zalo OA %s sent the message to recipient %s.", z.oa, z.user)}, nil
}
