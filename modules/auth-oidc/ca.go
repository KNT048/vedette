package authoidc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// Limits of the identity provider's CA (D-378, INV-12).
const (
	maxCAPEM  = 64 << 10
	maxCACert = 5
)

// CACert is one saved CA certificate as GET /core/oidc shows it.
type CACert struct {
	Subject  string
	NotAfter time.Time
}

func invalidCA(why string) *apierr.Error {
	return apierr.New(400, "invalid_ca", "The CA certificate "+why+". Paste the PEM of the CA that signed the identity provider's certificate (-----BEGIN CERTIFICATE-----).")
}

// parseCA checks the pasted CA text at the edge (INV-12): only CERTIFICATE blocks without headers, 1..5 of them, at most 64 KiB, each
// a CA that has not expired at now. It returns the text normalised (the blocks re-encoded, nothing else); "" is no CA.
func parseCA(raw string, now time.Time) (string, *apierr.Error) {
	if len(raw) > maxCAPEM {
		return "", invalidCA("text is larger than 64 KB")
	}
	rest := []byte(strings.TrimSpace(raw))
	n := 0
	var out bytes.Buffer
	for len(bytes.TrimSpace(rest)) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		switch {
		case b == nil:
			return "", invalidCA("text is not PEM, or has text outside the PEM blocks")
		case b.Type != "CERTIFICATE" || len(b.Headers) > 0:
			return "", invalidCA("text holds a " + pemType(b.Type) + " block; only certificates are accepted (never a private key)")
		case n == maxCACert:
			return "", invalidCA("text holds more than 5 certificates")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return "", invalidCA("cannot be read")
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return "", invalidCA(`"` + subject(c) + `" is not a CA certificate (the server's own certificate?)`)
		}
		if now.After(c.NotAfter) {
			return "", invalidCA(`"` + subject(c) + `" expired on ` + c.NotAfter.UTC().Format("2006-01-02"))
		}
		n++
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes}) // a bytes.Buffer does not fail
	}
	return out.String(), nil
}

// pemType names a block type in a refusal without echoing more than a short, printable word.
func pemType(t string) string {
	if len(t) > 40 || strings.ContainsFunc(t, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return "non-certificate"
	}
	return t
}

func subject(c *x509.Certificate) string {
	s := c.Subject.CommonName
	if s == "" {
		s = c.Subject.String()
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// certsOf reads saved CA text (checked when saved, so a block that does not parse is skipped).
func certsOf(pemText string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(pemText)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return out
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// CACerts lists the saved certificates for the API (subject and expiry, D-378).
func (c Config) CACerts() []CACert {
	var out []CACert
	for _, x := range certsOf(c.CAPEM) {
		out = append(out, CACert{Subject: subject(x), NotAfter: x.NotAfter.UTC()})
	}
	return out
}

// clientFor is the HTTP client for an identity provider with these saved CA certificates: the module's client when there are none;
// otherwise the same limits (newClient) with RootCAs = the system roots + these certificates, for this client only (D-378). Never
// InsecureSkipVerify. From the save on, expiry is the TLS handshake's business.
func (s *Service) clientFor(caPEM string) *http.Client {
	if caPEM == "" {
		return s.client
	}
	t, ok := s.base.(*http.Transport)
	if !ok {
		return s.client // a unit test's round tripper: no TLS to add roots to
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, c := range certsOf(caPEM) {
		pool.AddCert(c)
	}
	t = t.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.RootCAs = pool
	return newClient(t)
}
