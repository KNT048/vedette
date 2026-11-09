package channel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

const zaloToken = "zalo-access-token-0123456789abcdef" //nolint:gosec // fake token for tests

func TestZaloConfig(t *testing.T) {
	t.Parallel()
	ok := ZaloConfig{OAID: "1234567890", UserID: "987654321", Token: NewSecret(zaloToken)}
	if _, err := NewZalo(ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mod  func(*ZaloConfig)
		code string
	}{
		"oa letters":   {func(c *ZaloConfig) { c.OAID = "abc123456" }, "bad_oa_id"},
		"oa short":     {func(c *ZaloConfig) { c.OAID = "12345" }, "bad_oa_id"},
		"user letters": {func(c *ZaloConfig) { c.UserID = "12345x" }, "bad_user_id"},
		"user long":    {func(c *ZaloConfig) { c.UserID = strings.Repeat("1", 26) }, "bad_user_id"},
		"no token":     {func(c *ZaloConfig) { c.Token = Secret{} }, "secret_required"},
		"short token":  {func(c *ZaloConfig) { c.Token = NewSecret("short") }, "bad_token"},
		"token space":  {func(c *ZaloConfig) { c.Token = NewSecret(zaloToken + " x") }, "bad_token"},
		"token lf":     {func(c *ZaloConfig) { c.Token = NewSecret(zaloToken + "\nX-A: b") }, "bad_token"},
	} {
		cfg := ok
		c.mod(&cfg)
		_, err := NewZalo(cfg)
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != c.code {
			t.Errorf("%s: err = %v, want %s", name, err, c.code)
		}
		mustNot(t, errString(err), "0123456789abcdef")
	}
}

func TestZaloSend(t *testing.T) {
	t.Parallel()
	var hdr http.Header
	var path string
	var body struct {
		Recipient struct {
			UserID string `json:"user_id"`
		} `json:"recipient"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr, path = r.Header.Clone(), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = io.WriteString(w, `{"error":0,"message":"Success","data":{"message_id":"m1"}}`)
	}))
	t.Cleanup(srv.Close)
	s, err := newZaloAt(srv.URL+"/", ZaloConfig{OAID: "1234567890", UserID: "987654321", Token: NewSecret(zaloToken), Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.Send(context.Background(), sample)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "OA 1234567890" || path != "/v3.0/oa/message/cs" || hdr.Get("access_token") != zaloToken || body.Recipient.UserID != "987654321" {
		t.Errorf("rec=%+v path=%q recipient=%q token header ok=%v", rec, path, body.Recipient.UserID, hdr.Get("access_token") == zaloToken)
	}
	if !strings.HasPrefix(body.Message.Text, "Critical: ") || !strings.HasSuffix(body.Message.Text, sample.Link) {
		t.Errorf("text %q", body.Message.Text)
	}
	mustNot(t, rec.Detail, zaloToken)
}

func TestContract_FORBID2_ZaloErrorsNeverContainToken(t *testing.T) {
	t.Parallel()
	var answer string
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	s, _ := newZaloAt(srv.URL, ZaloConfig{OAID: "1234567890", UserID: "987654321", Token: NewSecret(zaloToken), Client: srv.Client()})
	for name, c := range map[string]struct {
		status   int
		body     string
		provider bool // a ProviderError (HTTP 2xx, provider says no) rather than a StatusError
		code     int
		reason   string
	}{
		"provider error in 200": {200, `{"error":-216,"message":"Access token is invalid ` + zaloToken + `"}`, true, -216, "Access token is invalid [redacted]"},
		"http error":            {401, `unauthorized ` + zaloToken, false, 401, "unauthorized [redacted]"},
		"garbage":               {200, `<html>`, true, 0, "did not confirm"},
		"no error field":        {200, `{"message":"hi"}`, true, 0, "did not confirm"},
	} {
		status, answer = c.status, c.body
		_, err := s.Send(context.Background(), sample)
		var pe *ProviderError
		var se *StatusError
		switch {
		case c.provider && errors.As(err, &pe):
			if pe.Code != c.code || !strings.Contains(pe.Reason, c.reason) || errors.As(err, &se) || strings.Contains(err.Error(), "HTTP 200") {
				t.Errorf("%s: err = %v", name, err)
			}
		case !c.provider && errors.As(err, &se):
			if se.Code != c.code || !strings.Contains(se.Reason, c.reason) {
				t.Errorf("%s: err = %v", name, err)
			}
		default:
			t.Errorf("%s: wrong error type: %v", name, err)
		}
		mustNot(t, errString(err), zaloToken)
	}

}

func TestContract_D46_ZaloPersonalValidatesButDoesNotSend(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]ZaloPersonalConfig{
		"no user":    {UserID: "", Session: NewSecret("sess")},
		"letters":    {UserID: "abc", Session: NewSecret("sess")},
		"no session": {UserID: "123456789"},
	} {
		if _, err := NewZaloPersonal(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	s, err := NewZaloPersonal(ZaloPersonalConfig{UserID: "123456789", Session: NewSecret("zl-session-secret-value")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(context.Background(), sample)
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), "zl-session-secret-value")
}

func FuzzZaloText(f *testing.F) {
	f.Add("t", "w", "a")
	f.Add(strings.Repeat("é", 4000), "\xe2\x80\xae\x00", strings.Repeat("x", 9000))
	f.Fuzz(func(t *testing.T, title, what, action string) {
		out := fit(Message{Severity: "low", Title: title, What: what, Action: action, Items: []string{what}, Link: "https://h/x"}.norm().lines("https://h/x"), zaloTextMax)
		if !utf8.ValidString(out) || utf8.RuneCountInString(out) > zaloTextMax || !strings.HasSuffix(out, "Details: https://h/x") {
			t.Fatalf("bad zalo text (%d runes)", utf8.RuneCountInString(out))
		}
	})
}
