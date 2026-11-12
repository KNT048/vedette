package authoidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	authoidc "github.com/knt048/vedette/modules/auth-oidc"
)

// certPEM is a self-signed certificate, a CA or not, valid until notAfter.
func certPEM(t *testing.T, cn string, isCA bool, notAfter time.Time) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func ptr(s string) *string { return &s }

// INV-12 (D-378): an identity provider whose certificate the system roots do not trust works once its CA is saved, for discovery,
// keys and the token exchange; removing the CA stops it again; a CA saved before is kept when a save leaves the field out.
func TestContract_INV12_PrivateCA(t *testing.T) {
	w := newWorldBase(t, http.DefaultTransport.(*http.Transport).Clone()) // system roots only: the fake IdP's CA is unknown
	_, err := w.svc.Test(t.Context(), "admin@acme.example")
	wantCode(t, err, 502, "discovery_failed")
	if e, _ := apierr.As(err); !strings.Contains(e.Message, "does not trust") || !strings.Contains(e.Message, "Identity provider CA certificate") {
		t.Fatalf("message = %q", e.Message)
	}

	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.idp.srv.Certificate().Raw})) // httptest's certificate is a CA
	w.configure(authoidc.Save{CAPEM: ptr("\n  " + ca + "\n"), DefaultRole: routes.Viewer})
	if _, err := w.svc.Test(t.Context(), "admin@acme.example"); err != nil {
		t.Fatalf("Test with the CA: %v", err)
	}
	if _, err := w.signIn(); err != nil {
		t.Fatalf("sign-in with the CA (token endpoint and keys through the same client): %v", err)
	}
	c, _, err := w.svc.View(t.Context(), origin)
	if err != nil || c.CAPEM != ca || len(c.CACerts()) != 1 || c.CACerts()[0].NotAfter.IsZero() {
		t.Fatalf("View = %q %+v, %v", c.CAPEM, c.CACerts(), err)
	}

	w.configure(authoidc.Save{}) // CAPEM nil: keep
	if _, err := w.svc.Test(t.Context(), "admin@acme.example"); err != nil {
		t.Fatalf("Test after a save without the field: %v", err)
	}
	w.configure(authoidc.Save{CAPEM: ptr("")}) // remove
	_, err = w.svc.Test(t.Context(), "admin@acme.example")
	wantCode(t, err, 502, "discovery_failed")
}

// INV-12: the pasted text is checked at the edge; a refusal saves nothing.
func TestContract_INV12_CARefused(t *testing.T) {
	w := newWorld(t)
	now := w.env.Clock.Now()
	good := certPEM(t, "Acme Root", true, now.Add(365*24*time.Hour))
	w.configure(authoidc.Save{CAPEM: ptr(good)})
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
	for name, in := range map[string]string{
		"not PEM":       "hello",
		"text after":    good + "trailing words",
		"private key":   good + key,
		"broken DER":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})),
		"not a CA":      certPEM(t, "idp.acme.example", false, now.Add(time.Hour)),
		"expired":       certPEM(t, "Old Root", true, now.Add(-time.Hour)),
		"six":           strings.Repeat(good, 6),
		"over 64 KB":    good + strings.Repeat(" ", 64<<10),
		"with a header": "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		_, err := w.svc.Store(t.Context(), "admin@acme.example", origin, authoidc.Save{Issuer: w.idp.issuer(), ClientID: "vedette", Scopes: "openid", GroupsClaim: "groups", CAPEM: ptr(in)})
		if e, ok := apierr.As(err); !ok || e.Status != 400 || e.Code != "invalid_ca" {
			t.Errorf("%s: err = %v, want 400 invalid_ca", name, err)
		}
	}
	if c, _, _ := w.svc.View(t.Context(), origin); c.CAPEM != good {
		t.Fatalf("a refused save changed the CA: %q", c.CAPEM)
	}
	if _, err := w.svc.Store(t.Context(), "admin@acme.example", origin, authoidc.Save{Issuer: w.idp.issuer(), ClientID: "vedette", Scopes: "openid", GroupsClaim: "groups", CAPEM: ptr(strings.Repeat(good, 5))}); err != nil {
		t.Fatalf("five CAs: %v", err)
	}
}
