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

	mu        sync.Mutex
	authPlain bool // AUTH arrived before TLS
	authTLS   bool // AUTH arrived after TLS
	sessions  int
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
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
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
			say("250 AUTH PLAIN") // advertised even without TLS: the client must not use it
		case up == "STARTTLS":
			say("220 go ahead")
			conn = tls.Server(raw, f.tlsConfig())
			r = bufio.NewReader(conn)
			encrypted = true
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			if encrypted {
				f.authTLS = true
			} else {
				f.authPlain = true
			}
			f.mu.Unlock()
			b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			parts := strings.Split(string(b), "\x00")
			if len(parts) == 3 && parts[1] == f.user && parts[2] == f.pass {
				say("235 2.7.0 authenticated")
			} else {
				say("535 5.7.8 bad credentials for " + string(b)) // echoes the secret on purpose
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

func (f *fakeSMTP) snapshot() (authPlain, authTLS bool, from string, rcpts []string, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authPlain, f.authTLS, f.mailFrom, append([]string(nil), f.rcpts...), f.data
}
