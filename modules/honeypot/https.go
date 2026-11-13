package honeypot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The certificate of the HTTPS trap (D-467). Core makes it: a self-signed RSA 2048 certificate, as a NAS or a printer makes for
// itself on first boot, naming the Trap IP that decides the service (its host name; the vendor as organization). It is NOT signed
// by the box CA nor by the sensor CA: a certificate browsers or agents trust must never sit in a container an attacker talks to,
// and an issuer naming Vedette would give the decoy away. The private key and the certificate are one core_secret row (purpose
// certPurpose, AES-256-GCM, never exported: core INV-13, D-154); hp_config key "https" holds only its id. Core writes both to
// config/ for the container, which needs the key to serve TLS; it is the decoy's own key and nothing trusts it. The key is
// never logged. The same key and certificate are kept across restarts, as a real device keeps its own; a new certificate is
// made only when the name it should carry changes or it is about to expire.
const (
	certPurpose = "hp_https.key"
	certLife    = 5 * 365 * 24 * time.Hour
	certRenew   = 30 * 24 * time.Hour // a certificate this close to its end is made again
)

// httpsCert is the certificate in use: what writeFiles writes, cached in memory (guarded by applyMu).
type httpsCert struct {
	certPEM, keyPEM []byte
	cn, org         string
	notAfter        time.Time
}

// certSubject is the name the certificate of look carries: the Trap IP's host name in lower case, its vendor as organization.
func certSubject(look Look) (cn, org string) {
	cn = strings.ToLower(look.Name)
	if cn == "" {
		cn = "localhost"
	}
	for _, v := range vendors {
		if v.id == look.Vendor {
			org = v.name
		}
	}
	return cn, org
}

// httpsFiles returns the PEM certificate and key of the HTTPS trap for look, making and storing a new pair when there is none, the
// stored one names another Trap IP, or it expires within certRenew. Called by writeFiles under applyMu.
func (s *Service) httpsFiles(ctx context.Context, look Look) (certPEM, keyPEM []byte, err error) {
	cn, org := certSubject(look)
	now := s.now()
	if s.https == nil {
		if s.https, err = s.loadHTTPSCert(ctx); err != nil {
			s.cfg.Log.WarnContext(ctx, "honeypot: the stored certificate of the HTTPS trap cannot be used; a new one is made", "error", err)
			s.https = nil
		}
	}
	if c := s.https; c != nil && c.cn == cn && c.org == org && now.Add(certRenew).Before(c.notAfter) {
		return c.certPEM, c.keyPEM, nil
	}
	c, err := newHTTPSCert(cn, org, now)
	if err != nil {
		return nil, nil, err
	}
	bundle := append(append([]byte{}, c.keyPEM...), c.certPEM...)
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var ref struct {
			SecretID string `json:"secret_id"`
		}
		if err := loadJSON(ctx, tx, "https", &ref); err != nil {
			return err
		}
		if ref.SecretID != "" {
			if err := s.cfg.Secrets.Delete(ctx, tx, ref.SecretID); err != nil {
				return fmt.Errorf("honeypot: drop the old HTTPS certificate: %w", err)
			}
		}
		id, _, err := s.cfg.Secrets.Seal(ctx, tx, certPurpose, bundle, false)
		if err != nil {
			return fmt.Errorf("honeypot: store the HTTPS certificate: %w", err)
		}
		ref.SecretID = id
		return s.saveJSON(ctx, tx, "https", ref)
	})
	if err != nil {
		return nil, nil, err
	}
	s.https = c
	s.cfg.Log.InfoContext(ctx, "honeypot: made the certificate of the HTTPS trap", "name", cn, "organization", org, "not_after", c.notAfter)
	return c.certPEM, c.keyPEM, nil
}

// loadHTTPSCert reads the stored pair; nil without error when there is none.
func (s *Service) loadHTTPSCert(ctx context.Context) (*httpsCert, error) {
	var ref struct {
		SecretID string `json:"secret_id"`
	}
	if err := loadJSON(ctx, s.db.Reader(), "https", &ref); err != nil || ref.SecretID == "" {
		return nil, err
	}
	raw, err := s.cfg.Secrets.Open(ctx, s.db.Reader(), ref.SecretID, certPurpose)
	if err != nil {
		return nil, fmt.Errorf("honeypot: open the HTTPS certificate: %w", err)
	}
	return parseHTTPSBundle(raw)
}

// parseHTTPSBundle splits a stored bundle (key PEM, then certificate PEM) and reads the certificate's name and end.
func parseHTTPSBundle(raw []byte) (*httpsCert, error) {
	keyBlock, rest := pem.Decode(raw)
	certBlock, _ := pem.Decode(rest)
	if keyBlock == nil || certBlock == nil || keyBlock.Type != "PRIVATE KEY" || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("honeypot: the stored HTTPS certificate is not a key and a certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("honeypot: the stored HTTPS certificate: %w", err)
	}
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}
	return &httpsCert{certPEM: pem.EncodeToMemory(certBlock), keyPEM: pem.EncodeToMemory(keyBlock), cn: cert.Subject.CommonName, org: org, notAfter: cert.NotAfter}, nil
}

// newHTTPSCert makes a self-signed server certificate for cn (also its one DNS name) and a new RSA 2048 key.
func newHTTPSCert(cn, org string, now time.Time) (*httpsCert, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("honeypot: HTTPS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("honeypot: HTTPS serial: %w", err)
	}
	name := pkix.Name{CommonName: cn}
	if org != "" {
		name.Organization = []string{org}
	}
	start := now.Add(-time.Hour).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: name, Issuer: name, DNSNames: []string{cn},
		NotBefore: start, NotAfter: start.Add(certLife),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("honeypot: HTTPS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("honeypot: HTTPS key: %w", err)
	}
	return &httpsCert{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		cn:      cn, org: org, notAfter: tmpl.NotAfter,
	}, nil
}
