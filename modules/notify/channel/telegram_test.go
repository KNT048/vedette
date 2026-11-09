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

const tgToken = "123456789:AAHexampleExampleExampleExample_0123456789"

func TestTelegramConfig(t *testing.T) {
	t.Parallel()
	ok := TelegramConfig{Token: NewSecret(tgToken), ChatID: "-1002145678901"}
	if _, err := NewTelegram(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*TelegramConfig){
		"empty token":   func(c *TelegramConfig) { c.Token = Secret{} },
		"short token":   func(c *TelegramConfig) { c.Token = NewSecret("123:abc") },
		"token slash":   func(c *TelegramConfig) { c.Token = NewSecret(tgToken + "/../x") },
		"token newline": func(c *TelegramConfig) { c.Token = NewSecret(tgToken + "\nX") },
		"chat letters":  func(c *TelegramConfig) { c.ChatID = "abc" },
		"chat short":    func(c *TelegramConfig) { c.ChatID = "@ab" },
		"base ftp":      func(c *TelegramConfig) { c.BaseURL = "ftp://x" },
		"base userinfo": func(c *TelegramConfig) { c.BaseURL = "http://u:p@x" },
	} {
		c := ok
		mod(&c)
		_, err := NewTelegram(c)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
		mustNot(t, errString(err), "AAHexample")
	}
	if _, err := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "@vedette_alerts"}); err != nil {
		t.Errorf("public channel name rejected: %v", err)
	}
}

func TestTelegramSend(t *testing.T) {
	t.Parallel()
	var path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
	t.Cleanup(srv.Close)
	s, err := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "-1002145678901", BaseURL: srv.URL + "/", Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Title = "<b>bold</b> & [x](http://evil) *y*"
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "chat -1002145678901" || path != "/bot"+tgToken+"/sendMessage" {
		t.Errorf("receipt %+v path %q", rec, path)
	}
	if _, has := body["parse_mode"]; has {
		t.Error("parse_mode must not be sent (plain text is the safe choice)")
	}
	text, _ := body["text"].(string)
	if !strings.Contains(text, "<b>bold</b> & [x](http://evil) *y*") || !strings.HasSuffix(text, "Details: https://192.168.10.2/incidents/al-4") {
		t.Errorf("text = %q", text)
	}
	if body["chat_id"] != "-1002145678901" {
		t.Errorf("chat_id = %v", body["chat_id"])
	}
}

func TestTelegramLongTextKeepsLink(t *testing.T) {
	t.Parallel()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	s, _ := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "12345", BaseURL: srv.URL, Client: srv.Client()})
	m := sample
	m.What, m.Action = strings.Repeat("w", 5000), strings.Repeat("a", 5000)
	for range 30 {
		m.Items = append(m.Items, strings.Repeat("i", 500))
	}
	if _, err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	text := body["text"].(string)
	if utf8.RuneCountInString(text) > telegramTextMax || !strings.HasSuffix(text, m.Link) {
		t.Errorf("%d runes, suffix ok=%v", utf8.RuneCountInString(text), strings.HasSuffix(text, m.Link))
	}
}

func TestContract_FORBID2_TelegramErrorsNeverContainToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized (`+r.URL.Path+`)"}`)
	}))
	t.Cleanup(srv.Close)
	s, _ := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "12345", BaseURL: srv.URL, Client: srv.Client()})
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), "AAHexample", tgToken)

	// Transport failure: *url.Error carries the full URL with /bot<token>/ in it.
	dead := httptest.NewServer(http.NotFoundHandler())
	base := dead.URL
	dead.Close()
	s2, _ := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "12345", BaseURL: base})
	_, err = s2.Send(context.Background(), sample)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	mustNot(t, err.Error(), "AAHexample", tgToken, "/bot", "sendMessage")
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		t.Errorf("transport error keeps a wrapped *url.Error: %v", err)
	}
}

func TestTelegramRejectsUnconfirmedOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"ok":false}`) }))
	t.Cleanup(srv.Close)
	s, _ := NewTelegram(TelegramConfig{Token: NewSecret(tgToken), ChatID: "12345", BaseURL: srv.URL, Client: srv.Client()})
	if _, err := s.Send(context.Background(), sample); err == nil {
		t.Fatal("ok:false accepted")
	}
}

func FuzzTelegramText(f *testing.F) {
	f.Add("t", "w", "a", "i")
	f.Add(strings.Repeat("é", 3000), strings.Repeat("‮", 10), "\x00", strings.Repeat("x", 9000))
	f.Fuzz(func(t *testing.T, title, what, action, item string) {
		n := Message{Severity: "medium", Title: title, What: what, Action: action, Items: []string{item}, Link: "https://h/x"}.norm()
		out := telegramText(n, "https://h/x")
		if !utf8.ValidString(out) || utf8.RuneCountInString(out) > telegramTextMax || !strings.HasSuffix(out, "Details: https://h/x") {
			t.Fatalf("bad telegram text (%d runes)", utf8.RuneCountInString(out))
		}
		if body, err := json.Marshal(map[string]any{"text": out}); err != nil || !json.Valid(body) {
			t.Fatalf("not encodable: %v", err)
		}
	})
}
