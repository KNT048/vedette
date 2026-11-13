package channel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

func emailCfg(f *fakeSMTP, security string) EmailConfig {
	return EmailConfig{
		Host: "127.0.0.1", Port: f.port(), Security: security, Username: f.user, Password: secrets.NewValue(f.pass),
		From: "alerts@acme.example", To: []string{"it@acme.example", "director@acme.example"}, RootCAs: f.roots,
		Now: func() time.Time { return time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC) }, AllowLoopback: true,
	}
}

func TestContract_INV8_SMTPConfig(t *testing.T) {
	t.Parallel()
	box := []netip.Addr{netip.MustParseAddr("192.168.1.9")}
	ok := EmailConfig{Host: "smtp.acme.example", Port: 587, Security: SecurityStartTLS, Username: "alerts@acme.example", Password: secrets.NewValue("pw-1234"), From: "alerts@acme.example", To: []string{"it@acme.example"},
		BoxAddrsFunc: func() ([]netip.Addr, bool) { return box, true }}
	if _, err := NewEmail(ok); err != nil {
		t.Fatal(err)
	}
	box = append(box, netip.MustParseAddr("10.0.0.7")) // an address the box gets after the first check counts too
	for name, c := range map[string]struct {
		mod  func(*EmailConfig)
		code string
	}{
		"host path":      {func(c *EmailConfig) { c.Host = "smtp.acme.example/x" }, "bad_host"},
		"host port":      {func(c *EmailConfig) { c.Host = "smtp.acme.example:587" }, "bad_host"},
		"host crlf":      {func(c *EmailConfig) { c.Host = "smtp.acme.example\r\nX: y" }, "bad_host"},
		"host ipv6":      {func(c *EmailConfig) { c.Host = "::1" }, "bad_host"},
		"host empty":     {func(c *EmailConfig) { c.Host = "" }, "bad_host"},
		"port 0":         {func(c *EmailConfig) { c.Port = 0 }, "bad_port"},
		"port 70000":     {func(c *EmailConfig) { c.Port = 70000 }, "bad_port"},
		"security":       {func(c *EmailConfig) { c.Security = "tls" }, "bad_security"},
		"587 with ssl":   {func(c *EmailConfig) { c.Security = SecuritySSL }, "port_mismatch"},
		"465 starttls":   {func(c *EmailConfig) { c.Port = 465 }, "port_mismatch"},
		"none external":  {func(c *EmailConfig) { c.Security, c.Port = SecurityNone, 25 }, "insecure_smtp"},
		"no username":    {func(c *EmailConfig) { c.Username = "" }, "bad_username"},
		"username lf":    {func(c *EmailConfig) { c.Username = "a\nb" }, "bad_username"},
		"no password":    {func(c *EmailConfig) { c.Password = secrets.Value{} }, "secret_required"},
		"bad from":       {func(c *EmailConfig) { c.From = "Name <a@acme.example>" }, "bad_from"},
		"from injection": {func(c *EmailConfig) { c.From = "a@acme.example\r\nBcc: x@y.zz" }, "bad_from"},
		"no recipients":  {func(c *EmailConfig) { c.To = nil }, "bad_to"},
		"bad recipient":  {func(c *EmailConfig) { c.To = []string{"it@acme.example", "nope"} }, "bad_to"},
		"rcpt injection": {func(c *EmailConfig) { c.To = []string{"a@acme.example\r\nBcc: x@y.zz"} }, "bad_to"},
		// the webhook's rule (walk 3): in a container 127.0.0.1 is core itself; link-local holds the metadata service
		"loopback":         {func(c *EmailConfig) { c.Host = "127.0.0.1" }, "bad_host"},
		"loopback /8":      {func(c *EmailConfig) { c.Host = "127.0.0.53" }, "bad_host"},
		"localhost name":   {func(c *EmailConfig) { c.Host = "mail.localhost" }, "bad_host"},
		"metadata":         {func(c *EmailConfig) { c.Host = "169.254.169.254" }, "bad_host"},
		"metadata alibaba": {func(c *EmailConfig) { c.Host = "100.100.100.200" }, "bad_host"},
		"metadata oracle":  {func(c *EmailConfig) { c.Host = "192.0.0.192" }, "bad_host"},
		"metadata name":    {func(c *EmailConfig) { c.Host = "metadata.google.internal" }, "bad_host"},
		"unspecified":      {func(c *EmailConfig) { c.Host = "0.0.0.0" }, "bad_host"},
		"multicast":        {func(c *EmailConfig) { c.Host = "224.0.0.1" }, "bad_host"},
		"box address":      {func(c *EmailConfig) { c.Host, c.Port, c.Security = "192.168.1.9", 8443, SecuritySSL }, "bad_host"}, // D-446: Vedette's own port
		"box address late": {func(c *EmailConfig) { c.Host, c.Port, c.Security = "10.0.0.7", 514, SecuritySSL }, "bad_host"},
	} {
		cfg := ok
		c.mod(&cfg)
		_, err := NewEmail(cfg)
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != c.code {
			t.Errorf("%s: err = %v, want %s", name, err, c.code)
		}
		mustNot(t, errString(err), "pw-1234")
	}
	for _, c := range []EmailConfig{
		{Host: "smtp.acme.example", Port: 465, Security: SecuritySSL, Username: "u", Password: secrets.NewValue("p"), From: "a@acme.example", To: []string{"b@acme.example"}},
		{Host: "mail.lan", Port: 25, Security: SecurityNone, From: "a@acme.example", To: []string{"b@acme.example"}}, // internal relay, no auth
		{Host: "192.168.1.5", Port: 2525, Security: SecurityStartTLS, Username: "u", Password: secrets.NewValue("p"), From: "a@acme.example", To: []string{"b@acme.example"}},
	} {
		if _, err := NewEmail(c); err != nil {
			t.Errorf("%s:%d %s rejected: %v", c.Host, c.Port, c.Security, err)
		}
	}
}

func TestParseRecipients(t *testing.T) {
	t.Parallel()
	got, err := ParseRecipients("it@acme.example, director@acme.example;ops@acme.example ,")
	if err != nil || len(got) != 3 || got[2] != "ops@acme.example" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "a@acme.example, nope", "a@b.co\r\nBcc: x@y.zz"} {
		if _, err := ParseRecipients(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseRecipients(%q) = %v", bad, err)
		}
	}
	// the bad one is named (walk 3): one line, cut to 60 characters
	for in, want := range map[string]string{
		"boss@walk3.example, not-an-email":                   "not-an-email is not a valid email address. Separate several recipients with commas.",
		"a@acme.example, x\u202e@" + strings.Repeat("y", 80): "x@" + strings.Repeat("y", 57) + "… is not a valid email address. Separate several recipients with commas.",
		"a@acme.example, \u200b":                             "A recipient email is not valid. Separate several recipients with commas.",
	} {
		var ce *ConfigError
		if _, err := ParseRecipients(in); !errors.As(err, &ce) || ce.Code != "bad_to" || ce.Msg != want {
			t.Errorf("ParseRecipients(%q) = %v, want %q", in, err, want)
		}
	}
}

// A name that resolves to a forbidden address passes the save check; the connection is refused (the webhook's dialControl).
func TestSMTPRefusesALoopbackConnection(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{})
	s, err := NewEmail(emailCfg(f, SecurityNone))
	if err != nil {
		t.Fatal(err)
	}
	s.(*emailSender).cfg.AllowLoopback = false // as if smtp.acme.example had resolved to 127.0.0.1
	if _, err := s.Send(context.Background(), sample); err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("err = %v, want the connection refused", err)
	}
	if _, _, from, _, _ := f.snapshot(); from != "" {
		t.Errorf("the server got MAIL FROM %q", from)
	}
}

func parseSent(t *testing.T, data string) (*mail.Message, string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("sent data is not a valid message: %v\n%s", err, data)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	return msg, string(b)
}

func TestSMTPStartTLSSend(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: true})
	s, err := NewEmail(emailCfg(f, SecurityStartTLS))
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Title = "Café <b>server</b> được khai thác"
	m.What = "line one\n.line starting with a dot\nlast"
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "it@acme.example, director@acme.example" {
		t.Errorf("receipt %+v", rec)
	}
	authPlain, authTLS, from, rcpts, data := f.snapshot()
	if authPlain || !authTLS {
		t.Errorf("AUTH before TLS = %v, after TLS = %v", authPlain, authTLS)
	}
	if from != "alerts@acme.example" || len(rcpts) != 2 || rcpts[1] != "director@acme.example" {
		t.Errorf("envelope from=%q rcpts=%v", from, rcpts)
	}
	msg, body := parseSent(t, data)
	subj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subj != "[Vedette] Critical: Café <b>server</b> được khai thác" {
		t.Errorf("subject %q (%v)", subj, err)
	}
	if got := msg.Header.Get("From"); got != "Vedette <alerts@acme.example>" {
		t.Errorf("From %q", got)
	}
	if to, _ := msg.Header.AddressList("To"); len(to) != 2 {
		t.Errorf("To = %v", to)
	}
	for _, want := range []string{"Hello,", "Device: PC-HR-01", "\n.line starting with a dot\n", "What to do first:", "Details: https://192.168.10.2/incidents/al-4", "sent automatically by Vedette"} {
		if !strings.Contains(strings.ReplaceAll(body, "\r\n", "\n"), want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" || !strings.HasSuffix(strings.Trim(msg.Header.Get("Message-ID"), "<>"), "@acme.example") {
		t.Errorf("headers %v", msg.Header)
	}
}

func TestSMTPImplicitTLSSend(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{implicit: true})
	s, err := NewEmail(emailCfg(f, SecuritySSL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	authPlain, authTLS, _, _, data := f.snapshot()
	if authPlain || !authTLS || data == "" {
		t.Errorf("authPlain=%v authTLS=%v data=%d bytes", authPlain, authTLS, len(data))
	}
}

func TestSMTPNeverAuthenticatesInTheClear(t *testing.T) {
	t.Parallel()
	t.Run("server without STARTTLS", func(t *testing.T) {
		t.Parallel()
		f := startFakeSMTP(t, &fakeSMTP{starttls: false})
		s, _ := NewEmail(emailCfg(f, SecurityStartTLS))
		_, err := s.Send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
			t.Fatalf("err = %v", err)
		}
		authPlain, authTLS, from, _, _ := f.snapshot()
		if authPlain || authTLS || from != "" {
			t.Errorf("session went on: authPlain=%v authTLS=%v from=%q", authPlain, authTLS, from)
		}
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		t.Parallel()
		f := startFakeSMTP(t, &fakeSMTP{starttls: true})
		cfg := emailCfg(f, SecurityStartTLS)
		cfg.RootCAs = nil // system roots do not know the test CA
		s, _ := NewEmail(cfg)
		_, err := s.Send(context.Background(), sample)
		if err == nil {
			t.Fatal("untrusted certificate accepted")
		}
		// It must fail for the right reason: the certificate, not some other fault.
		var se *StatusError
		if errors.As(err, &se) || !strings.Contains(err.Error(), "starttls") || !strings.Contains(err.Error(), "x509: certificate") {
			t.Errorf("expected a certificate verification error during starttls, got: %v", err)
		}
		authPlain, authTLS, _, _, _ := f.snapshot()
		if authPlain || authTLS {
			t.Errorf("credentials sent to an unverified server: %v %v", authPlain, authTLS)
		}
	})
	t.Run("none sends no AUTH even when offered", func(t *testing.T) {
		t.Parallel()
		f := startFakeSMTP(t, &fakeSMTP{})
		cfg := emailCfg(f, SecurityNone)
		s, err := NewEmail(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Send(context.Background(), sample); err != nil {
			t.Fatal(err)
		}
		authPlain, authTLS, _, rcpts, _ := f.snapshot()
		if authPlain || authTLS || len(rcpts) != 2 {
			t.Errorf("authPlain=%v authTLS=%v rcpts=%v", authPlain, authTLS, rcpts)
		}
	})
}

func TestContract_FORBID2_SMTPBadLoginErrorHasNoPassword(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{implicit: true})
	cfg := emailCfg(f, SecuritySSL)
	cfg.Password = secrets.NewValue("wrong-Password-1")
	s, _ := NewEmail(cfg)
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 535 || se.Channel != Email {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), "wrong-Password-1")
	// The fake echoes the base64 payload decoded; the password must have been scrubbed from the reason.
	mustNot(t, se.Reason, "Password-1")
}

func TestSMTPConnectFailureAndDeadline(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{})
	cfg := emailCfg(f, SecurityNone)
	_ = f.ln.Close()
	s, _ := NewEmail(cfg)
	if _, err := s.Send(context.Background(), sample); err == nil {
		t.Fatal("expected connect error")
	}
	// A pre-cancelled context fails fast without a session.
	g := startFakeSMTP(t, &fakeSMTP{})
	s2, _ := NewEmail(emailCfg(g, SecurityNone))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s2.Send(ctx, sample); err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func TestContract_FORBID_HeaderInjectionImpossible(t *testing.T) {
	t.Parallel()
	f := startFakeSMTP(t, &fakeSMTP{starttls: true})
	s, _ := NewEmail(emailCfg(f, SecurityStartTLS))
	m := sample
	m.Title = "hello\r\nBcc: attacker@evil.example\r\nX-Evil: 1"
	m.Device = "dev\r\n\r\nInjected body"
	m.ID = "x\r\nBcc: attacker@evil.example"
	if _, err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	_, _, _, rcpts, data := f.snapshot()
	if len(rcpts) != 2 {
		t.Errorf("recipients = %v", rcpts)
	}
	msg, _ := parseSent(t, data)
	for k := range msg.Header {
		switch k {
		case "Date", "From", "To", "Subject", "Message-Id", "Mime-Version", "Content-Type", "Content-Transfer-Encoding", "Auto-Submitted", "X-Auto-Response-Suppress":
		default:
			t.Errorf("unexpected header %q", k)
		}
	}
	// The text is still there, but only inside the one Subject value (newlines became spaces).
	if subj := msg.Header.Get("Subject"); !strings.Contains(subj, "hello Bcc: attacker") || strings.ContainsAny(subj, "\r\n") {
		t.Errorf("subject %q", subj)
	}
}

func FuzzBuildMIME(f *testing.F) {
	f.Add("hello", "dev", "what", "act")
	f.Add("a\r\nBcc: x@y.zz", "\r\n\r\nbody", "\n.\r\n", "=?utf-8?q?x?=")
	f.Add(strings.Repeat("é", 300), "\u202e", "\x00", ".")
	allowed := map[string]bool{"Date": true, "From": true, "To": true, "Subject": true, "Message-Id": true, "Mime-Version": true, "Content-Type": true, "Content-Transfer-Encoding": true, "Auto-Submitted": true, "X-Auto-Response-Suppress": true}
	f.Fuzz(func(t *testing.T, title, device, what, action string) {
		m := Message{ID: title, Kind: what, Severity: "high", Title: title, Device: device, What: what, Action: action, Items: []string{what}, Link: "https://h/x"}
		if m.check() != nil {
			return
		}
		raw, err := buildMIME("alerts@acme.example", []string{"a@acme.example", "b@acme.example"}, m.norm(), "https://h/x", time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("not a valid message: %v", err)
		}
		for k, v := range msg.Header {
			if !allowed[k] || len(v) != 1 {
				t.Fatalf("unexpected header %q (%d values)", k, len(v))
			}
		}
		if to, err := msg.Header.AddressList("To"); err != nil || len(to) != 2 {
			t.Fatalf("To changed: %v %v", to, err)
		}
		for _, l := range headerLines(t, raw, "Subject") {
			if len(l) > 78 {
				t.Fatalf("subject line of %d characters", len(l))
			}
		}
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			if len(sc.Text()) > 998 {
				t.Fatalf("line of %d bytes", len(sc.Text()))
			}
		}
		if strings.Contains(strings.ReplaceAll(string(raw), "\r\n", ""), "\n") || strings.Contains(strings.ReplaceAll(string(raw), "\r\n", ""), "\r") {
			t.Fatal("bare CR or LF in message")
		}
	})
}

// D-446 (walk 4): a mail server on the machine that runs Vedette, at the machine's LAN address and the mail port, is accepted; loopback
// and Vedette's own ports there get the one sentence for Vedette itself, which no longer points at the address it refused.
func TestD446_SMTPOnTheMachine(t *testing.T) {
	t.Parallel()
	machine := func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("10.123.45.67")}, true }
	base := EmailConfig{Host: "10.123.45.67", Port: 587, Security: SecurityStartTLS, Username: "alerts@acme.example", Password: secrets.NewValue("pw-1234"),
		From: "alerts@acme.example", To: []string{"it@acme.example"}, BoxAddrsFunc: machine}
	if _, err := NewEmail(base); err != nil {
		t.Fatalf("the machine's LAN address on 587: %v", err)
	}
	for _, c := range []struct {
		host string
		port int
	}{{"10.123.45.67", 6514}, {"127.0.0.1", 587}, {"mail.localhost", 25}} {
		cfg := base
		cfg.Host, cfg.Port, cfg.Security = c.host, c.port, SecuritySSL
		_, err := NewEmail(cfg)
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != "bad_host" || ce.Msg != OwnText {
			t.Errorf("%s:%d: %v", c.host, c.port, err)
		}
	}
}
