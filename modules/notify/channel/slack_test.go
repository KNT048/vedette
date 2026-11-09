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
	"time"

	"github.com/knt048/vedette/core/secrets"
)

const slackHook = "https://hooks.slack.com/services/T0EXAMPLE1/B0EXAMPLE2/XyzSecretPathToken123"

func TestContract_INV8_SlackWebhookShape(t *testing.T) {
	t.Parallel()
	for in, code := range map[string]string{
		slackHook: "",
		"":        "secret_required",
		"http://hooks.slack.com/services/T1/B2/X3":              "bad_webhook",
		"https://hooks.slack.com.evil.com/services/T1/B2/X3":    "bad_webhook",
		"https://evil.com/hooks.slack.com/services/T1/B2/X3":    "bad_webhook",
		"https://hooks.slack.com/services/T1/B2":                "bad_webhook",
		"https://hooks.slack.com/services/T1/B2/X3?x=1":         "bad_webhook",
		"https://hooks.slack.com/services/T1/B2/X3#f":           "bad_webhook",
		"https://user@hooks.slack.com/services/T1/B2/X3":        "bad_webhook",
		"https://hooks.slack.com:8443/services/T1/B2/X3":        "bad_webhook",
		"https://hooks.slack.com/other/T1/B2/X3":                "bad_webhook",
		"https://hooks.slack.com/services/T1/B2/X3/extra":       "bad_webhook",
		"https://hooks.slack.com/services/../services/T1/B2/X3": "bad_webhook",
		"not a url": "bad_webhook",
	} {
		_, err := NewSlack(SlackConfig{Webhook: secrets.NewValue(in)})
		if code == "" {
			if err != nil {
				t.Errorf("NewSlack(%q): %v", in, err)
			}
			continue
		}
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != code || !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewSlack(%q) = %v, want code %s", in, err, code)
		}
		mustNot(t, errString(err), "Token123", "T1/B2")
	}
	if _, err := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook), Label: strings.Repeat("x", 81)}); err == nil {
		t.Error("81-char label accepted")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestSlackSendEscapesAndPosts(t *testing.T) {
	t.Parallel()
	var got struct {
		path, ctype string
		body        map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.ctype = r.URL.Path, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got.body)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	s, err := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook), Label: "#it-alerts", Client: clientTo(t, srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Title = "<!channel> & <@U123> <https://evil.example|click>"
	m.What = "a < b & c > d"
	m.Items = []string{"<!here>"}
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "#it-alerts" || got.path != "/services/T0EXAMPLE1/B0EXAMPLE2/XyzSecretPathToken123" || !strings.HasPrefix(got.ctype, "application/json") {
		t.Errorf("receipt %+v path %q ctype %q", rec, got.path, got.ctype)
	}
	text, _ := got.body["text"].(string)
	mustNot(t, text, "<!channel>", "<@U123>", "<https://evil", "<!here>")
	for _, want := range []string{"&lt;!channel&gt; &amp; &lt;@U123&gt;", "a &lt; b &amp; c &gt; d", "<https://192.168.10.2/incidents/al-4|Open in Vedette>", "What to do first:", "Device: PC-HR-01"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if !strings.HasPrefix(text, "*Critical: ") {
		t.Errorf("head not bold: %q", text)
	}
}

func TestContract_FORBID2_SlackErrorsNeverContainSecret(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		// A hostile or buggy server echoing the request path, plus a huge body.
		_, _ = io.WriteString(w, "no_service "+r.URL.Path+" "+strings.Repeat("A", 1<<20)) //nolint:gosec // test server echoing the request on purpose
	}))
	t.Cleanup(srv.Close)
	s, _ := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook), Client: clientTo(t, srv.URL)})
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 || se.Channel != Slack {
		t.Fatalf("err = %v", err)
	}
	if len(se.Reason) > 130 {
		t.Errorf("reason not capped: %d bytes", len(se.Reason))
	}
	mustNot(t, err.Error(), "XyzSecretPathToken123", "T0EXAMPLE1")
}

func TestContract_FORBID2_SlackTransportErrorHasNoURL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL
	srv.Close() // connection refused
	s, _ := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook), Client: clientTo(t, dead)})
	_, err := s.Send(context.Background(), sample)
	if err == nil {
		t.Fatal("expected error")
	}
	mustNot(t, err.Error(), "XyzSecretPathToken123", "hooks.slack.com", "/services/")
}

func TestSlackContextDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); srv.Close() })
	s, _ := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook), Client: clientTo(t, srv.URL)})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := s.Send(ctx, sample)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func TestSendRejectsBadMessage(t *testing.T) {
	t.Parallel()
	s, _ := NewSlack(SlackConfig{Webhook: secrets.NewValue(slackHook)})
	for name, mod := range map[string]func(*Message){
		"severity": func(m *Message) { m.Severity = "urgent" },
		"title":    func(m *Message) { m.Title = " \u200b\n" },
		"link":     func(m *Message) { m.Link = "javascript:alert(1)" },
	} {
		m := sample
		mod(&m)
		if _, err := s.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func FuzzSlackText(f *testing.F) {
	f.Add("<!channel> & <@U1>", "a>b", "<http://x|y>")
	f.Add("\u202e", "\x00", "&amp;&lt;")
	f.Fuzz(func(t *testing.T, title, what, item string) {
		n := Message{Severity: "low", Title: title, What: what, Items: []string{item}, Link: "https://h/a?b=1&c=2"}.norm()
		out := slackText(n, "https://h/a?b=1&c=2")
		// The only raw "<" allowed is the one that opens our own link.
		body := strings.TrimSuffix(out, "<https://h/a?b=1&amp;c=2|Open in Vedette>")
		if len(body) == len(out) {
			t.Fatalf("link suffix missing: %q", out)
		}
		if strings.ContainsAny(body, "<>") {
			t.Fatalf("unescaped angle bracket: %q", out)
		}
		for i := 0; i+1 < len(body); i++ {
			if body[i] == '&' && !strings.HasPrefix(body[i:], "&amp;") && !strings.HasPrefix(body[i:], "&lt;") && !strings.HasPrefix(body[i:], "&gt;") {
				t.Fatalf("unescaped ampersand at %d: %q", i, body)
			}
		}
	})
}
