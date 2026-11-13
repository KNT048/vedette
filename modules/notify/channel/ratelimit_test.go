package channel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// D-483: every HTTP adapter turns a 429 into a RateLimitError with the wait the provider named (Telegram in the body, others in
// Retry-After), bounded, and the StatusError stays underneath.
func TestTooManyRequestsIsARateLimitWithItsWait(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		header, body string
		want         time.Duration
	}{
		"telegram body":    {"", `{"ok":false,"error_code":429,"parameters":{"retry_after":17}}`, 17 * time.Second},
		"retry-after":      {"42", `{}`, 42 * time.Second},
		"nothing said":     {"", `rate limited`, 0},
		"absurd capped":    {"999999999", ``, time.Hour},
		"negative junk":    {"-5", ``, 0},
		"date in the past": {"Wed, 21 Oct 2015 07:28:00 GMT", ``, 0},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(c.body))
		}))
		s, err := newTelegramAt(srv.URL, TelegramConfig{Token: secrets.NewValue(tgToken), ChatID: "-1002145678901", Client: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Send(context.Background(), sample)
		srv.Close()
		var rl *RateLimitError
		var se *StatusError
		if !errors.As(err, &rl) || rl.Wait != c.want || !errors.As(err, &se) || se.Code != 429 {
			t.Errorf("%s: err = %v, wait %v, want %v", name, err, func() time.Duration {
				if rl == nil {
					return -1
				}
				return rl.Wait
			}(), c.want)
		}
	}
}

// D-483: a refused refresh token says what to do (get a new one), never what Zalo wrote, and nothing is sent with no token.
func TestZaloRefusedRefreshTokenSaysGetANewOne(t *testing.T) {
	t.Parallel()
	var sends int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == zaloSendPath {
			sends++
		}
		_, _ = w.Write([]byte(`{"error":-14014,"error_name":"Invalid refresh token","error_description":"internal detail"}`))
	}))
	t.Cleanup(srv.Close)
	g, err := ZaloOASecret("", "app-secret-key-123", "refresh-token-first-0123456789", "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newZaloAt(srv.URL, ZaloConfig{OAID: "1234567890", UserID: "987654321", AppID: "4318650137000000000", Token: secrets.NewValue(g), Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	s.(*zaloSender).tokenURL = srv.URL + "/v4/oa/access_token"
	_, err = s.Send(context.Background(), sample)
	var si *SignInError
	if !errors.As(err, &si) || si.Msg != zaloRefreshText || sends != 0 {
		t.Fatalf("err = %v, sends %d", err, sends)
	}
	mustNot(t, err.Error(), "internal detail")
}
