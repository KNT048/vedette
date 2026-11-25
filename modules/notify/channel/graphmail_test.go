package channel

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

const graphSecret = "Gr8Q~graph.client_secret-456" //nolint:gosec // G101: a test value, not a credential

// fakeGraph is both the Microsoft token endpoint and Microsoft Graph: clientTo sends every host to it, and it tells them apart by
// path. send answers each sendMail request.
type fakeGraph struct {
	srv        *httptest.Server
	tokenCalls atomic.Int32
	sendCalls  atomic.Int32
	mu         sync.Mutex
	lastPath   string
	lastAuth   string
	lastType   string
	lastMIME   string
	tokenBody  func(form url.Values) (int, string)
	send       func() (int, string)
	nextTokens []string
}

func startFakeGraph(t *testing.T, send func() (int, string)) *fakeGraph {
	t.Helper()
	g := &fakeGraph{send: send, nextTokens: []string{"graph-token-1", "graph-token-2", "graph-token-3"}}
	g.tokenBody = func(form url.Values) (int, string) {
		if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != testClient || form.Get("client_secret") != graphSecret ||
			form.Get("scope") != "https://graph.microsoft.com/.default" {
			return 400, `{"error":"invalid_scope","error_description":"AADSTS70011 wrong scope"}`
		}
		g.mu.Lock()
		tok := g.nextTokens[0]
		if len(g.nextTokens) > 1 {
			g.nextTokens = g.nextTokens[1:]
		}
		g.mu.Unlock()
		return 200, `{"token_type":"Bearer","expires_in":3599,"access_token":"` + tok + `"}`
	}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/"+testTenant+"/oauth2/v2.0/token" {
			g.tokenCalls.Add(1)
			_ = r.ParseForm()
			code, body := g.tokenBody(r.PostForm)
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
			return
		}
		g.sendCalls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.lastPath, g.lastAuth, g.lastType, g.lastMIME = r.URL.EscapedPath(), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(raw)
		g.mu.Unlock()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		code, body := g.send()
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func graphCfg(t *testing.T, g *fakeGraph) EmailConfig {
	return EmailConfig{Host: "graph.microsoft.com", Port: 443, Security: SecuritySSL, Provider: "microsoft-graph", Username: "alerts@acme.example",
		TenantID: testTenant, ClientID: testClient, Password: secrets.NewValue(graphSecret), From: "alerts@acme.example",
		To: []string{"it@acme.example", "director@acme.example"}, HTTPClient: clientTo(t, g.srv.URL),
		Now: func() time.Time { return time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC) }}
}

func TestEmailAuthKnowsMicrosoftGraph(t *testing.T) {
	t.Parallel()
	if a, ok := EmailAuth("microsoft-graph"); !ok || a != AuthMicrosoftGraph {
		t.Fatalf("EmailAuth(microsoft-graph) = %q, %v", a, ok)
	}
}

// The Graph preset gets an app-only token with the client secret (scope graph.microsoft.com/.default) and posts the MIME message to
// /v1.0/users/<mailbox>/sendMail: no SMTP session at all. The token is cached like the SMTP presets' tokens.
func TestGraphSendMailWithClientSecret(t *testing.T) {
	t.Parallel()
	g := startFakeGraph(t, func() (int, string) { return http.StatusAccepted, "" })
	s, err := NewEmail(graphCfg(t, g))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := s.Send(context.Background(), sample)
	if err != nil {
		t.Fatal(err)
	}
	if rc.To != "it@acme.example, director@acme.example" {
		t.Errorf("receipt to %q", rc.To)
	}
	g.mu.Lock()
	path, auth, typ, body := g.lastPath, g.lastAuth, g.lastType, g.lastMIME
	g.mu.Unlock()
	if path != "/v1.0/users/alerts@acme.example/sendMail" {
		t.Errorf("path %q", path)
	}
	if auth != "Bearer graph-token-1" || typ != "text/plain" {
		t.Errorf("auth %q, content type %q", auth, typ)
	}
	mime, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("the body is not base64 MIME: %v", err)
	}
	for _, want := range []string{"From: Vedette <alerts@acme.example>", "To: it@acme.example,\r\n director@acme.example", "Subject: [Vedette]", "PC-HR-01"} {
		if !strings.Contains(string(mime), want) {
			t.Errorf("MIME lacks %q:\n%s", want, mime)
		}
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if n := g.tokenCalls.Load(); n != 1 {
		t.Errorf("token requests = %d, want 1 (cached)", n)
	}
	if n := g.sendCalls.Load(); n != 2 {
		t.Errorf("sendMail requests = %d, want 2", n)
	}
}

// Every refusal is a fixed sentence that says what to fix: Graph's own message text, the token and the secret never show.
func TestGraphSendMailRefusals(t *testing.T) {
	t.Parallel()
	echo := `","message":"Access is denied graph-token-1 ` + graphSecret + `"}}`
	for name, c := range map[string]struct {
		code       int
		body, want string
	}{
		"no app permission":  {403, `{"error":{"code":"ErrorAccessDenied` + echo, "application permission Mail.Send"},
		"no consent":         {401, `{"error":{"code":"NoPermissionsInAccessToken` + echo, "admin consent"},
		"policy denies":      {403, `{"error":{"code":"Authorization_RequestDenied` + echo, "Mail.Send"},
		"mailbox not found":  {404, `{"error":{"code":"ErrorInvalidUser` + echo, "cannot find the mailbox alerts@acme.example"},
		"no exchange":        {404, `{"error":{"code":"MailboxNotEnabledForRESTAPI` + echo, "cannot find the mailbox"},
		"resource not found": {404, `{"error":{"code":"ResourceNotFound` + echo, "cannot find the mailbox"},
		"send as":            {403, `{"error":{"code":"ErrorSendAsDenied` + echo, "Send As"},
		"server error":       {503, `<html>busy graph-token-1</html>`, "HTTP 503"},
		"odd code":           {400, `{"error":{"code":"Bad\r\nCode` + echo, "(HTTP 400)"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := startFakeGraph(t, func() (int, string) { return c.code, c.body })
			s, err := NewEmail(graphCfg(t, g))
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Send(context.Background(), sample)
			var si *SignInError
			if !errors.As(err, &si) || !strings.Contains(si.Msg, c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			mustNot(t, err.Error(), "graph-token", graphSecret, "Access is denied", "busy", "\r", "\n")
		})
	}
}

// A token Graph refuses (401 InvalidAuthenticationToken) is dropped: the next send asks for a new one.
func TestGraphRefusedTokenIsDropped(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	g := startFakeGraph(t, func() (int, string) {
		if n.Add(1) == 1 {
			return 401, `{"error":{"code":"InvalidAuthenticationToken","message":"Lifetime validation failed"}}`
		}
		return 202, ""
	})
	s, err := NewEmail(graphCfg(t, g))
	if err != nil {
		t.Fatal(err)
	}
	var si *SignInError
	if _, err := s.Send(context.Background(), sample); !errors.As(err, &si) || !strings.Contains(si.Msg, "client secret") {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	auth := g.lastAuth
	g.mu.Unlock()
	if g.tokenCalls.Load() != 2 || auth != "Bearer graph-token-2" {
		t.Errorf("token calls %d, last auth %q: the refused token was used again", g.tokenCalls.Load(), auth)
	}
}

// The token service refusing the client secret says so, and Graph is never called without a token.
func TestGraphTokenRefusalNeverCallsGraph(t *testing.T) {
	t.Parallel()
	g := startFakeGraph(t, func() (int, string) { return 202, "" })
	g.tokenBody = func(url.Values) (int, string) {
		return 401, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. ` + graphSecret + `"}`
	}
	s, err := NewEmail(graphCfg(t, g))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(context.Background(), sample)
	var si *SignInError
	if !errors.As(err, &si) || !strings.Contains(si.Msg, "client secret") {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), "AADSTS", graphSecret)
	if g.sendCalls.Load() != 0 {
		t.Error("Graph was called without a token")
	}
}

// Graph asking to slow down is a RateLimitError (the delivery job waits), not a failure.
func TestGraphTooManyRequestsWaits(t *testing.T) {
	t.Parallel()
	g := startFakeGraph(t, func() (int, string) { return 429, `{"error":{"code":"ApplicationThrottled","message":"slow down"}}` })
	s, err := NewEmail(graphCfg(t, g))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(context.Background(), sample)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want a RateLimitError", err)
	}
}

func TestGraphConfigRefusals(t *testing.T) {
	t.Parallel()
	base := EmailConfig{Host: "graph.microsoft.com", Port: 443, Security: SecuritySSL, Provider: "microsoft-graph", Username: "alerts@acme.example",
		TenantID: testTenant, ClientID: testClient, Password: secrets.NewValue(graphSecret), From: "alerts@acme.example", To: []string{"it@acme.example"}}
	if _, err := NewEmail(base); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mod  func(*EmailConfig)
		code string
	}{
		"another host":       {func(c *EmailConfig) { c.Host = "graph.acme.example" }, "bad_host"},
		"smtp host":          {func(c *EmailConfig) { c.Host = "smtp.office365.com" }, "bad_host"},
		"another port":       {func(c *EmailConfig) { c.Port = 8443 }, "bad_port"},
		"starttls":           {func(c *EmailConfig) { c.Security, c.Port = SecurityStartTLS, 587 }, "bad_port"},
		"no encryption":      {func(c *EmailConfig) { c.Security = SecurityNone }, "bad_security"},
		"tenant with a path": {func(c *EmailConfig) { c.TenantID = "acme.onmicrosoft.com/../x" }, "bad_tenant_id"},
		"client not a guid":  {func(c *EmailConfig) { c.ClientID = "my-app" }, "bad_client_id"},
		"mailbox not email":  {func(c *EmailConfig) { c.Username = "alerts/../../me" }, "bad_username"},
		"no client secret":   {func(c *EmailConfig) { c.Password = secrets.Value{} }, "secret_required"},
		"secret with a CRLF": {func(c *EmailConfig) { c.Password = secrets.NewValue("abc\r\ndef") }, "bad_secret"},
	} {
		cfg := base
		c.mod(&cfg)
		_, err := NewEmail(cfg)
		if !isCode(err, c.code) {
			t.Errorf("%s: err = %v, want %s", name, err, c.code)
		}
		mustNot(t, errString(err), graphSecret)
	}
}
