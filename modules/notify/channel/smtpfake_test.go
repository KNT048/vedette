package channel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal in-process SMTP server for tests. It records what it
// saw, in particular whether AUTH ever arrived on an unencrypted connection.
type fakeSMTP struct {
	ln       net.Listener
	cert     tls.Certificate
	roots    *x509.CertPool
	implicit bool // TLS from the first byte (port 465 style)
	starttls bool // advertise STARTTLS
	user     string
	pass     string
	mechs    []string // AUTH mechanisms offered; nil = PLAIN
	token    string   // the bearer token XOAUTH2 and OAUTHBEARER accept
	endless  bool     // after a refused token, challenge again and again instead of answering 535

	mu        sync.Mutex
	authPlain bool // AUTH arrived before TLS
	authTLS   bool // AUTH arrived after TLS
	sessions  int
	mech      string // the last AUTH mechanism used
	mailFrom  string
	rcpts     []string
	data      string
}

func newTLSMaterial(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vedette test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost", "smtp.office365.com", "smtp.gmail.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func startFakeSMTP(t *testing.T, f *fakeSMTP) *fakeSMTP {
	t.Helper()
	f.cert, f.roots = newTLSMaterial(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	if f.user == "" {
		f.user, f.pass = "alerts@acme.example", "S3cret-Pass-word"
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); f.serve(c) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) tlsConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12}
}

func (f *fakeSMTP) serve(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	f.mu.Lock()
	f.sessions++
	f.mu.Unlock()
	conn := net.Conn(raw)
	encrypted := false
	if f.implicit {
		conn, encrypted = tls.Server(raw, f.tlsConfig()), true
	}
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = fmt.Fprintf(conn, "%s\r\n", s) }
	say("220 fake.smtp ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250-fake.smtp")
			if f.starttls && !encrypted {
				say("250-STARTTLS")
			}
			mechs := f.mechs
			if mechs == nil {
				mechs = []string{"PLAIN"}
			}
			say("250 AUTH " + strings.Join(mechs, " ")) // advertised even without TLS: the client must not use it
		case up == "STARTTLS":
			say("220 go ahead")
			conn = tls.Server(raw, f.tlsConfig())
			r = bufio.NewReader(conn)
			encrypted = true
		case strings.HasPrefix(up, "AUTH "):
			f.mu.Lock()
			if encrypted {
				f.authTLS = true
			} else {
				f.authPlain = true
			}
			f.mu.Unlock()
			if !f.auth(line, r, say) {
				return
			}
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.mailFrom = strings.Trim(line[len("MAIL FROM:"):], "<> ")
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, strings.Trim(line[len("RCPT TO:"):], "<> "))
			f.mu.Unlock()
			say("250 ok")
		case up == "DATA":
			say("354 end with <CRLF>.<CRLF>")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(strings.TrimPrefix(l, ".")) // dot-unstuffing (a leading dot is always doubled)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}

// auth runs one AUTH exchange; false = the connection broke. A refusal echoes what the client sent, decoded, on purpose: the
// client must scrub it.
func (f *fakeSMTP) auth(line string, r *bufio.Reader, say func(string)) bool {
	fields := strings.Fields(line)
	mech := strings.ToUpper(fields[1])
	f.mu.Lock()
	f.mech = mech
	f.mu.Unlock()
	initial := func() string {
		if len(fields) < 3 {
			return ""
		}
		b, _ := base64.StdEncoding.DecodeString(fields[2])
		return string(b)
	}
	read := func() (string, bool) {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", false
		}
		b, _ := base64.StdEncoding.DecodeString(strings.TrimRight(l, "\r\n"))
		return string(b), true
	}
	oauthRefuse := func(want string) bool { // the server's JSON challenge, the client's answer, then 535 (Google's XOAUTH2 page)
		say("334 " + base64.StdEncoding.EncodeToString([]byte(`{"status":"401","schemes":"bearer"}`)))
		got, ok := read()
		if !ok {
			return false
		}
		if got != want {
			say("501 5.5.2 bad answer to the challenge")
			return true
		}
		for f.endless {
			say("334 " + base64.StdEncoding.EncodeToString([]byte(`{"status":"401"}`)))
			l, err := r.ReadString('\n')
			if err != nil || strings.HasPrefix(l, "*") {
				say("501 5.7.0 cancelled")
				return err == nil
			}
		}
		say("535 5.7.8 token not accepted " + initial())
		return true
	}
	switch mech {
	case "PLAIN":
		parts := strings.Split(initial(), "\x00")
		if len(parts) == 3 && parts[1] == f.user && parts[2] == f.pass {
			say("235 2.7.0 authenticated")
		} else {
			say("535 5.7.8 bad credentials for " + initial())
		}
	case "LOGIN":
		say("334 VXNlcm5hbWU6")
		u, ok := read()
		if !ok {
			return false
		}
		say("334 UGFzc3dvcmQ6")
		p, ok := read()
		if !ok {
			return false
		}
		if u == f.user && p == f.pass {
			say("235 2.7.0 authenticated")
		} else {
			say("535 5.7.8 bad credentials for " + u + " " + p)
		}
	case "XOAUTH2":
		if initial() == "user="+f.user+"\x01auth=Bearer "+f.token+"\x01\x01" && f.token != "" {
			say("235 2.7.0 accepted")
			return true
		}
		return oauthRefuse("")
	case "OAUTHBEARER":
		in := initial()
		if strings.HasPrefix(in, "n,a="+f.user+",\x01host=") && strings.HasSuffix(in, "\x01auth=Bearer "+f.token+"\x01\x01") && f.token != "" {
			say("235 2.7.0 accepted")
			return true
		}
		return oauthRefuse("\x01")
	default:
		say("504 5.5.4 unrecognized authentication type")
	}
	return true
}

func (f *fakeSMTP) usedMech() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mech
}

func (f *fakeSMTP) snapshot() (authPlain, authTLS bool, from string, rcpts []string, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authPlain, f.authTLS, f.mailFrom, append([]string(nil), f.rcpts...), f.data
}
