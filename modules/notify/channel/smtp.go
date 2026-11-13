package channel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/secrets"
)

// SMTP security modes, spelled as in contract.ts.
const (
	SecurityStartTLS = "starttls"
	SecuritySSL      = "ssl"
	SecurityNone     = "none"
)

// EmailConfig configures the email channel (also used for two-step sign-in
// codes, D-35). The server is the customer's own SMTP relay (PRIVACY flow 5).
type EmailConfig struct {
	Host     string // domain name or IPv4 address
	Port     int    // 587 goes with starttls, 465 with ssl
	Security string // starttls | ssl | none
	Provider string // the preset of the email dialog (D-449, EmailAuth); "" = custom
	Username string // required unless Security is none; with OAuth2 the mailbox to send as; unused for Postmark
	// Password is the secret: the password, app password or API key; the Microsoft 365 client secret; the Google service account
	// key file (JSON). Required unless Security is none.
	Password secrets.Value
	TenantID string // Microsoft 365: Directory (tenant) ID, a GUID or a domain such as company.onmicrosoft.com
	ClientID string // Microsoft 365: Application (client) ID, a GUID
	// HTTPClient makes the OAuth2 token requests (login.microsoftonline.com, oauth2.googleapis.com); redirects are never followed.
	// nil = a plain client with a timeout.
	HTTPClient *http.Client
	// Tokens is the OAuth2 token cache shared by the senders of one service; nil = this sender's own.
	Tokens  *TokenCache
	From    string         // sender address
	To      []string       // recipients, at least one; see ParseRecipients
	RootCAs *x509.CertPool // nil = system roots; tests add their own CA
	Now     func() time.Time
	// BoxAddrsFunc lists the machine's addresses, asked at save and at every connection: the server is never on Vedette's own ports
	// there (D-446), as for a webhook. known=false refuses Vedette's own ports on every address and nothing more (loopback, link-local,
	// multicast and unspecified are refused all the same): the email channel also carries the two-step sign-in codes, which must not
	// stop while the host has not answered (#157).
	BoxAddrsFunc func() (addrs []netip.Addr, known bool)
	// SelfAddrsFunc lists more addresses that are Vedette itself (the honeypot's decoys): refused on every port (D-446). nil: none.
	SelfAddrsFunc func() []netip.Addr
	// AllowLoopback is for tests only (the fake SMTP servers of the notify and cmd/vedette tests listen on 127.0.0.1); production
	// code never sets it: core never runs on the host network, so loopback is core itself.
	AllowLoopback bool
	// dialAddr, when set, is where the session connects instead of Host:Port (tests: the OAuth2 presets accept only the provider's
	// own host name, and the fake server listens on 127.0.0.1). TLS still verifies Host.
	dialAddr string
}

const (
	emailTimeout  = 30 * time.Second
	maxRecipients = 20
	maxSubject    = 150
)

type emailSender struct {
	noPrint
	cfg    EmailConfig
	addr   string
	tls    *tls.Config
	box    func() ([]netip.Addr, bool) // EmailConfig.BoxAddrsFunc; unknown refuses only Vedette's ports (ownAddr), never the whole channel
	auth   string                      // EmailAuth of the provider
	gkey   googleKey                   // the parsed Google key (AuthGoogle)
	client *http.Client                // token requests
	tokens *TokenCache
}

// ParseRecipients splits a "a@x.com, b@y.com" field (commas or semicolons) and validates each address.
func ParseRecipients(s string) ([]string, error) {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 || len(out) > maxRecipients {
		return nil, cfgErr("bad_to", "Enter between 1 and 20 recipient emails, separated by commas.")
	}
	for _, a := range out {
		if !validEmail(a) {
			return nil, badRecipient(a)
		}
	}
	return out, nil
}

// badRecipient names the recipient that is not an email address. It is what the person typed: one line, control
// characters removed, cut to 60 characters; the GUI shows it as text.
func badRecipient(a string) error {
	if a = Line(a, 60); a == "" { // nothing printable is left to name
		return cfgErr("bad_to", "A recipient email is not valid. Separate several recipients with commas.")
	}
	return cfgErr("bad_to", a+" is not a valid email address. Separate several recipients with commas.")
}

// NewEmail validates cfg at the boundary (INV-8) and returns the adapter.
//
// Credentials are only ever sent after the connection is encrypted: with
// starttls the adapter requires the STARTTLS extension and a completed
// handshake before AUTH, with ssl the whole session is TLS. Security "none" is
// accepted only for an internal host and then never authenticates. Sign-in
// (D-449): AUTH PLAIN, else LOGIN, with a password; XOAUTH2, else OAUTHBEARER,
// with an OAuth2 token for Microsoft 365 and Google Workspace (smtpauth.go).
func NewEmail(cfg EmailConfig) (Sender, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	if !validHost(cfg.Host) {
		return nil, cfgErr("bad_host", "The SMTP server must be a domain name or an IP address, for example smtp.company.com.")
	}
	box := cfg.BoxAddrsFunc
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, cfgErr("bad_port", "The SMTP port is a number from 1 to 65535 (usually 587 or 465).")
	}
	// The webhook's rule: Vedette itself (ownAddr, D-446: loopback, core's own container, Vedette's ports on the machine) and
	// link-local, which holds the cloud metadata service (forbiddenAddr). A name that resolves to such an address is refused when
	// connecting (dialControl).
	host := strings.TrimSuffix(strings.ToLower(cfg.Host), ".")
	a, aerr := netip.ParseAddr(host)
	if (aerr == nil && ownAddr(a, uint16(cfg.Port), cfg.AllowLoopback, ownOf(box, cfg.SelfAddrsFunc))) || (!cfg.AllowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost"))) {
		return nil, cfgErr("bad_host", OwnText)
	}
	if (aerr == nil && forbiddenAddr(a, cfg.AllowLoopback)) || metadataName(host) {
		return nil, cfgErr("bad_host", "The SMTP server cannot be a link-local or multicast address, a cloud metadata service, or an unspecified address.")
	}
	switch cfg.Security {
	case SecurityStartTLS, SecuritySSL, SecurityNone:
	default:
		return nil, cfgErr("bad_security", "Choose an encryption type: STARTTLS, SSL/TLS or none.")
	}
	if cfg.Security == SecuritySSL && cfg.Port == 587 {
		return nil, cfgErr("port_mismatch", "Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS.")
	}
	if cfg.Security == SecurityStartTLS && cfg.Port == 465 {
		return nil, cfgErr("port_mismatch", "Port 465 uses SSL/TLS, not STARTTLS. Choose SSL/TLS, or change the port to 587 for STARTTLS.")
	}
	auth, ok := EmailAuth(cfg.Provider)
	if !ok {
		return nil, cfgErr("bad_provider", "Choose an email provider from the list, or Custom SMTP.")
	}
	var gkey googleKey
	switch {
	case cfg.Security == SecurityNone && auth != AuthPassword:
		return nil, cfgErr("bad_security", "This provider signs in, so the connection must be encrypted. Choose STARTTLS or SSL/TLS.")
	case cfg.Security == SecurityNone:
		if !internalHost(cfg.Host) {
			return nil, cfgErr("insecure_smtp", "Unencrypted SMTP is only allowed for a server on your internal network. Choose STARTTLS or SSL/TLS.")
		}
	case auth == AuthMicrosoft || auth == AuthGoogle:
		// The token goes only to the provider's own server: .default carries every permission of the app, so a token sent to a server
		// the admin typed by mistake (or on purpose) is a live credential there (D-449 review).
		if want := oauthHost[auth]; host != want {
			return nil, cfgErr("bad_host", "This sign-in sends its token only to "+want+". Enter "+want+" as the SMTP server.")
		}
		if !validEmail(cfg.Username) {
			return nil, cfgErr("bad_username", "Enter the mailbox Vedette sends as, for example alerts@company.com.")
		}
		if auth == AuthMicrosoft {
			if !guidRE.MatchString(cfg.TenantID) && !validDomain(strings.ToLower(cfg.TenantID)) {
				return nil, cfgErr("bad_tenant_id", "The tenant ID is the Directory (tenant) ID of the app registration, for example "+
					"72f988bf-86f1-41af-91ab-2d7cd011db47, or your domain such as company.onmicrosoft.com.")
			}
			if !guidRE.MatchString(cfg.ClientID) {
				return nil, cfgErr("bad_client_id", "The client ID is the Application (client) ID of the app registration, for example 0a1b2c3d-4e5f-6789-abcd-ef0123456789.")
			}
		}
		if !isSet(cfg.Password) {
			return nil, cfgErr("secret_required", map[string]string{AuthMicrosoft: "Enter the client secret of the app registration.",
				AuthGoogle: "Choose the JSON key file of the service account."}[auth])
		}
		if auth == AuthGoogle {
			k, err := parseGoogleKey(cfg.Password.Reveal())
			if err != nil {
				return nil, err
			}
			gkey = k
		} else if p := cfg.Password.Reveal(); len(p) > 256 || !validHeaderText(p) {
			return nil, cfgErr("bad_secret", "The client secret is the Value of a secret under Certificates & secrets of the app registration (not its Secret ID). Copy it again.")
		}
	default:
		if auth == AuthTokenAsUser {
			cfg.Username = "" // the server token is the username too; it is never stored as a field
		} else if !validHeaderText(cfg.Username) {
			return nil, cfgErr("bad_username", "Enter the SMTP username (usually the email address).")
		}
		if !isSet(cfg.Password) {
			return nil, cfgErr("secret_required", "Enter the SMTP password. This channel has no saved key yet.")
		}
		if p := cfg.Password.Reveal(); len(p) > 1024 || strings.ContainsFunc(p, unicode.IsControl) {
			if auth == AuthTokenAsUser {
				return nil, cfgErr("bad_secret", "The server API token is one line of letters, digits and dashes. Copy it again from the server's API Tokens tab in Postmark.")
			}
			return nil, cfgErr("bad_secret", "The password has a control character (such as a line break) or is too long. Copy it again.")
		}
	}
	if !validEmail(cfg.From) {
		return nil, cfgErr("bad_from", "The sender email is not valid, for example alerts@company.com.")
	}
	if len(cfg.To) == 0 || len(cfg.To) > maxRecipients {
		return nil, cfgErr("bad_to", "Enter between 1 and 20 recipient emails, separated by commas.")
	}
	for _, a := range cfg.To {
		if !validEmail(a) {
			return nil, badRecipient(a)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.To = append([]string(nil), cfg.To...)
	tokens := cfg.Tokens
	if tokens == nil {
		tokens = NewTokenCache()
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	if cfg.dialAddr != "" {
		addr = cfg.dialAddr
	}
	return &emailSender{
		cfg:    cfg,
		addr:   addr,
		tls:    &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		box:    box,
		auth:   auth,
		gkey:   gkey,
		client: tokenClient(cfg.HTTPClient),
		tokens: tokens,
	}, nil
}

// oauthHost is the only SMTP server each OAuth2 sign-in sends its token to.
var oauthHost = map[string]string{AuthMicrosoft: "smtp.office365.com", AuthGoogle: "smtp.gmail.com"}

// validHeaderText reports whether s is non-empty printable text with no control characters (SMTP username).
func validHeaderText(s string) bool {
	return s != "" && len(s) <= 256 && clean(s, false) == s && strings.TrimSpace(s) == s
}

func (*emailSender) Type() Type { return Email }

func (e *emailSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	raw, err := buildMIME(e.cfg.From, e.cfg.To, m.norm(), link, e.cfg.Now())
	if err != nil {
		return Receipt{}, err
	}
	if err := e.deliver(ctx, raw); err != nil {
		return Receipt{}, err
	}
	to := strings.Join(e.cfg.To, ", ")
	return Receipt{To: to, Detail: "Email sent to " + to + "."}, nil
}

// emailSubject and emailBody are the human-readable parts; m must be normalised.
func emailSubject(m Message) string { return "[Vedette] " + truncRunes(m.head(), maxSubject) }

func emailBody(m Message, link string) string {
	l := m.lines(link)
	return strings.Join(append([]string{"Hello,", ""}, append(l[1:], "", "This email was sent automatically by Vedette on your company box.")...), "\n")
}

// foldSubject returns the Subject value folded so that every header line,
// "Subject: " included, is at most 78 characters. Printable ASCII is folded at
// spaces (words are separated by single spaces); anything else, a word too long
// to fold, or text containing "=?" (which a reader would decode as an encoded
// word) becomes a series of RFC 2047 Q encoded words. mime.QEncoding does not
// fold and leaves ASCII chunks unencoded, so the words are built here: 4 runes
// of up to 4 bytes each encode to at most 48 characters plus the 12 of
// "=?utf-8?q?" and "?=", so a word line is at most 61 characters. Every byte outside [A-Za-z0-9] is
// written as =XX (a space as =20), so no CR, LF or "?" can survive in a word.
func foldSubject(s string) string {
	ascii := true
	for _, r := range s {
		if r < ' ' || r > '~' {
			ascii = false
			break
		}
	}
	if ascii && !strings.Contains(s, "=?") {
		if f, ok := foldWords(s); ok {
			return f
		}
	}
	var words []string
	for r := []rune(s); len(r) > 0; {
		n := min(4, len(r))
		var w strings.Builder
		w.WriteString("=?utf-8?q?")
		for _, c := range []byte(string(r[:n])) {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
				w.WriteByte(c)
			} else {
				fmt.Fprintf(&w, "=%02X", c)
			}
		}
		w.WriteString("?=")
		words = append(words, w.String())
		r = r[n:]
	}
	return strings.Join(words, "\r\n ")
}

// buildMIME renders the RFC 5322 message. Header values come only from
// validated addresses and from a subject that is one clean line (printable ASCII or
// RFC 2047 encoded words, see foldSubject); CR and LF can never be emitted raw.
func buildMIME(from string, to []string, m Message, link string, now time.Time) ([]byte, error) {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("notify: email: message id: %w", err)
	}
	domain := from[strings.LastIndexByte(from, '@')+1:]
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("Date", now.Format(time.RFC1123Z))
	h("From", "Vedette <"+from+">")
	h("To", strings.Join(to, ",\r\n "))
	h("Subject", foldSubject(emailSubject(m)))
	h("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(emailBody(m, link))); err != nil {
		return nil, fmt.Errorf("notify: email: encode body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("notify: email: encode body: %w", err)
	}
	return b.Bytes(), nil
}

// deliver runs one SMTP session.
func (e *emailSender) deliver(ctx context.Context, raw []byte) error {
	ctx, cancel := context.WithTimeout(ctx, emailTimeout)
	defer cancel()
	sec := []secrets.Value{e.cfg.Password}
	var tok *oauthToken
	if e.oauth() { // the token first: no SMTP session waits on the token service, and none is opened when it refuses
		v, k, err := e.token(ctx)
		if err != nil {
			return err
		}
		tok = &oauthToken{v, k}
		sec = append(sec, v)
	}
	fail := func(stage string, err error) error {
		var te *textproto.Error
		if errors.As(err, &te) {
			return &StatusError{Channel: Email, Code: te.Code, Reason: reasonFrom([]byte(te.Msg), sec...)}
		}
		return fmt.Errorf("notify: email: %s: %s", stage, transportReason(err, sec))
	}

	d := net.Dialer{Control: dialControl(e.cfg.AllowLoopback, e.box, e.cfg.SelfAddrsFunc, false)} // after name resolution: a name that resolves to a forbidden address is refused too
	raw0, err := d.DialContext(ctx, "tcp", e.addr)
	if err != nil {
		return fail("connect", err)
	}
	// Every byte the server sends passes through the budget, below TLS so that
	// implicit TLS and STARTTLS are both covered and net/smtp still sees a *tls.Conn.
	budget := &budgetConn{Conn: raw0, left: maxSessionBytes}
	var conn net.Conn = budget
	if e.cfg.Security == SecuritySSL {
		tc := tls.Client(conn, e.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return fail("connect", err)
		}
		conn = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fail("greeting", err)
	}
	defer func() { _ = c.Close() }()

	if e.cfg.Security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			// net/smtp swallows read errors in Extension: tell a spent budget from a plain no.
			if budget.left <= 0 {
				return fail("starttls", errServerTooMuch)
			}
			return &SignInError{Msg: "The mail server does not offer STARTTLS, so nothing was sent: credentials are never sent unencrypted. Check the port, or choose SSL/TLS on 465."}
		}
		if err := c.StartTLS(e.tls); err != nil {
			return fail("starttls", err)
		}
	}
	if e.cfg.Security != SecurityNone {
		if _, encrypted := c.TLSConnectionState(); !encrypted {
			return fmt.Errorf("notify: email: %w", errUnencryptedAuth)
		}
		if err := e.signIn(c, tok); err != nil {
			return err
		}
	}
	if err := c.Mail(e.cfg.From); err != nil {
		return fail("sender", err)
	}
	for _, r := range e.cfg.To {
		if err := c.Rcpt(r); err != nil {
			return fail("recipient", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fail("data", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fail("data", err)
	}
	if err := w.Close(); err != nil {
		return fail("data", err)
	}
	_ = c.Quit()
	return nil
}

func (e *emailSender) Dest() string { return strings.Join(e.cfg.To, ", ") }

// maxSessionBytes bounds everything one SMTP session may read from the server;
// net/smtp itself reads greeting and reply lines without a limit.
const maxSessionBytes = 1 << 20

var errServerTooMuch = errors.New("the server sent more data than one session allows")

// budgetConn fails Read once the byte budget is spent.
type budgetConn struct {
	net.Conn
	left int64
}

func (c *budgetConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errServerTooMuch
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= int64(n)
	return n, err
}

const subjectLineMax = 78

// foldWords folds printable ASCII at spaces to lines of at most subjectLineMax
// characters; ok is false when a word is too long for that.
func foldWords(s string) (string, bool) {
	words := strings.Fields(s)
	if len(words) == 0 {
		return "", true
	}
	lines := []string{words[0]}
	room := subjectLineMax - len("Subject: ")
	if len(words[0]) > room {
		return "", false
	}
	for _, w := range words[1:] {
		last := len(lines) - 1
		limit := subjectLineMax
		if last == 0 {
			limit = room
		}
		switch {
		case len(lines[last])+1+len(w) <= limit:
			lines[last] += " " + w
		case 1+len(w) <= subjectLineMax:
			lines = append(lines, " "+w) // the fold keeps the separating space at the start of the line
		default:
			return "", false
		}
	}
	return strings.Join(lines, "\r\n"), true
}
