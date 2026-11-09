package channel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// streamServer accepts connections and, after an optional greeting, sends
// "250-AAAA…" forever. It reports how it was used through its address only: the
// client must give up on its own.
func streamServer(t *testing.T, implicit, greetFirst bool) (port int, roots *x509.CertPool) {
	t.Helper()
	cert, pool := newTLSMaterial(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				c := net.Conn(raw)
				if implicit {
					c = tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				}
				chunk := []byte("250-" + strings.Repeat("A", 4000) + "\r\n")
				if greetFirst {
					_, _ = c.Write([]byte("220 ready\r\n"))
					_, _ = bufio.NewReader(c).ReadString('\n') // EHLO
				} else {
					chunk = []byte("220-" + strings.Repeat("A", 4000) + "\r\n")
				}
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pool
}

// A hostile SMTP server that never stops talking must not make the box read
// without limit: net/smtp reads greetings and replies with no bound of its own.
func TestContract_SYS6_SMTPServerResponsesAreBounded(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		security          string
		implicit, greeted bool
	}{
		"endless greeting, plain":      {SecurityNone, false, false},
		"endless greeting, implicit":   {SecuritySSL, true, false},
		"endless EHLO reply, starttls": {SecurityStartTLS, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			port, roots := streamServer(t, c.implicit, c.greeted)
			s, err := NewEmail(EmailConfig{Host: "127.0.0.1", Port: port, Security: c.security, Username: "u", Password: NewSecret("p"),
				From: "alerts@acme.example", To: []string{"it@acme.example"}, RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			_, err = s.Send(ctx, sample)
			if err == nil || !strings.Contains(err.Error(), "more data than one session allows") {
				t.Fatalf("err = %v (took %v), want the byte budget to stop the session", err, time.Since(start))
			}
		})
	}
}

func TestBudgetConnStopsAtLimit(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	go func() { _, _ = b.Write(make([]byte, 100)); _ = b.Close() }()
	c := &budgetConn{Conn: a, left: 64}
	buf := make([]byte, 1000)
	total := 0
	var err error
	for err == nil {
		var n int
		n, err = c.Read(buf)
		total += n
	}
	if total != 64 || !errors.Is(err, errServerTooMuch) {
		t.Errorf("read %d bytes, err = %v", total, err)
	}
}

// Every sender prints as a fixed string, so no verb can reach its secrets
// (fmt cannot call Secret's Format on an unexported field and would print it).
func TestContract_FORBID2_SendersNeverPrintSecrets(t *testing.T) {
	t.Parallel()
	const (
		hook = "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/PrintLeakSlackTok"
		tgt  = "123456789:AAHprintLeakTelegramTokenXXXXXXXXXXXXXXXX"
		zt   = "zalo-PrintLeakAccessToken-0123456789"
		pw   = "PrintLeakSmtpPassword" //nolint:gosec // fake test value
		wk   = "PrintLeakSigningKey-0123456789"
		wu   = "https://hooks.example.com/PrintLeakWebhookPath?k=PrintLeakQueryKey"
		sess = "PrintLeakZaloSession"
	)
	mk := map[string]func() (Sender, error){
		"slack":    func() (Sender, error) { return NewSlack(SlackConfig{Webhook: NewSecret(hook)}) },
		"telegram": func() (Sender, error) { return NewTelegram(TelegramConfig{Token: NewSecret(tgt), ChatID: "12345"}) },
		"zalo": func() (Sender, error) {
			return NewZalo(ZaloConfig{OAID: "1234567890", UserID: "987654321", Token: NewSecret(zt)})
		},
		"email": func() (Sender, error) {
			return NewEmail(EmailConfig{Host: "smtp.acme.example", Port: 587, Security: SecurityStartTLS, Username: "u", Password: NewSecret(pw), From: "a@acme.example", To: []string{"b@acme.example"}})
		},
		"webhook": func() (Sender, error) {
			return NewWebhook(WebhookConfig{URL: NewSecret(wu), SigningKey: NewSecret(wk)})
		},
		"zalo-personal": func() (Sender, error) {
			return NewZaloPersonal(ZaloPersonalConfig{UserID: "123456789", Session: NewSecret(sess)})
		},
	}
	for name, f := range mk {
		s, err := f()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := fmt.Sprintf("%v|%+v|%#v|%s|%q|%v|%+v", s, s, s, s, s, []Sender{s}, map[string]Sender{"k": s})
		mustNot(t, out, "PrintLeak")
	}
}

func TestClientOrDefaultNeverFollowsRedirects(t *testing.T) {
	t.Parallel()
	own := &http.Client{}
	got := clientOrDefault(own)
	if got.CheckRedirect == nil || own.CheckRedirect != nil || got == own {
		t.Error("caller client must be copied with CheckRedirect set, and left untouched")
	}
	if clientOrDefault(nil).CheckRedirect == nil {
		t.Error("default client follows redirects")
	}
}

func TestDefang(t *testing.T) {
	t.Parallel()
	in := "see http://evil.com/x now @admin /start (/cmd) and/or a@b.co"
	out := defang(in)
	if strings.Contains(out, "://") || strings.Contains(out, " @a") || strings.Contains(out, " /s") || strings.Contains(out, "(/c") {
		t.Errorf("not neutralised: %q", out)
	}
	for _, keep := range []string{"and/or", "a@b.co", "evil.com"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was changed in %q", keep, out)
		}
	}
	if strings.ReplaceAll(out, zwj, "") != in {
		t.Error("defang changed more than it inserted")
	}
}

func TestTelegramAndZaloNeutraliseFeedLinksOnly(t *testing.T) {
	t.Parallel()
	m := sample
	m.Title = "@everyone http://evil.example/x /start"
	m.Device = "PC (/cmd)"
	m.Items = []string{"https://evil.example/y"}
	for name, text := range map[string]string{
		"telegram": telegramText(m.norm(), m.Link),
		"zalo":     fit(m.norm().mapText(defang).lines(m.Link), zaloTextMax),
	} {
		body, details, _ := strings.Cut(text, "\nDetails: ")
		if strings.Contains(body, "://") || strings.Contains(body, " @e") || strings.Contains(body, "@e") && !strings.Contains(body, "@"+zwj+"e") {
			t.Errorf("%s: feed text still links: %q", name, body)
		}
		if details != m.Link {
			t.Errorf("%s: the box's own link was altered: %q", name, details)
		}
	}
}

func TestSlackFormatNeutralisesMrkdwn(t *testing.T) {
	t.Parallel()
	out := slackFormat("*bold* _it_ ~gone~ `code` snake_case _lead trail_")
	if strings.ContainsAny(out, "*~`") || strings.Contains(out, " _") || strings.Contains(out, "_ ") {
		t.Errorf("formatting survives: %q", out)
	}
	if !strings.Contains(out, "snake_case") {
		t.Errorf("intra-word underscore was changed: %q", out)
	}
	m := sample
	m.Title = "*boom* `x`"
	text := slackText(m.norm(), m.Link)
	if strings.Count(text, "*") != 2 { // only the two that bold the head
		t.Errorf("feed asterisks reached Slack: %q", text)
	}
}

func FuzzDefang(f *testing.F) {
	f.Add("http://x @y /z (/w) a/b a@b")
	f.Add("//@@//")
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) { // both functions only ever see normalised (valid UTF-8) text
			return
		}
		if strings.Contains(s, zwj) {
			return
		}
		out := defang(s)
		if strings.ReplaceAll(out, zwj, "") != s || strings.Contains(out, "://") && strings.Contains(s, "://") {
			t.Fatalf("defang(%q) = %q", s, out)
		}
		r := []rune(out)
		for i, c := range r {
			if (c == '@' || c == '/') && (i == 0 || (!unicode.IsLetter(r[i-1]) && !unicode.IsDigit(r[i-1]))) && (i+1 >= len(r) || string(r[i+1]) != zwj) {
				t.Fatalf("unneutralised %q at %d in %q", c, i, out)
			}
		}
	})
}

func FuzzSlackFormat(f *testing.F) {
	f.Add("*a* _b_ ~c~ `d` e_f")
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			return
		}
		out := slackFormat(s)
		if strings.ContainsAny(out, "*~`") || utf8.RuneCountInString(out) != utf8.RuneCountInString(strings.ToValidUTF8(s, "�")) {
			t.Fatalf("slackFormat(%q) = %q", s, out)
		}
	})
}

func TestValidEmailRejectsPercent(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"a%b@acme.example", "user%other.com@acme.example", "%@acme.example"} {
		if validEmail(in) {
			t.Errorf("validEmail(%q) accepted", in)
		}
	}
}

func headerLines(t *testing.T, raw []byte, name string) []string {
	t.Helper()
	var out []string
	in := false
	for _, l := range strings.Split(string(raw), "\r\n") {
		switch {
		case l == "":
			return out
		case strings.HasPrefix(l, name+": "):
			in = true
			out = append(out, l)
		case in && (l[0] == ' ' || l[0] == '\t'):
			out = append(out, l)
		default:
			in = false
		}
	}
	return out
}

func TestSubjectFoldsTo78Characters(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("server is being exploited ", 6)
	for name, title := range map[string]string{
		"long ascii":        long,
		"long unicode":      strings.Repeat("máy chủ bị khai thác ", 8),
		"unfoldable ascii":  strings.Repeat("x", 120),
		"looks like a word": "=?utf-8?q?hidden?= and more text",
		"short":             "short title",
	} {
		m := sample
		m.Title = title
		n := m.norm()
		raw, err := buildMIME("alerts@acme.example", []string{"it@acme.example"}, n, m.Link, time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range headerLines(t, raw, "Subject") {
			if len(l) > 78 {
				t.Errorf("%s: subject line of %d characters: %q", name, len(l), l)
			}
		}
		msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
		want := strings.Join(strings.Fields(emailSubject(n)), " ")
		if err != nil || strings.Join(strings.Fields(got), " ") != want {
			t.Errorf("%s: decoded subject %q, want %q (%v)", name, got, want, err)
		}
	}
}
