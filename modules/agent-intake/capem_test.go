package agentintake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// anchorFile is what the trust anchor of the test world gives: like an owner's -tls-cert file that holds its key too, with junk
// and a PEM header around the certificate (cmd/vedette gives the box CA's certificate alone; that is TestIntakeTrustAnchor).
var anchorCert, anchorFile = func() (string, string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Vedette box CA"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		panic(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	file := "junk\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Note": "x"}, Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return cert, file
}()

func (w *world) get(path string) *httptest.ResponseRecorder {
	w.t.Helper()
	r := httptest.NewRequestWithContext(w.t.Context(), http.MethodGet, server.Prefix+path, nil)
	r.RemoteAddr = peerA + ":40000"
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

// INV-11: GET /intake/ca.pem is public and serves the certificate blocks of the trust anchor as a PEM file, never another block.
func TestContract_INV11_CaPemServesTheCertificateOnly(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	rec := w.get("/intake/ca.pem")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("GET /intake/ca.pem = %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if body := rec.Body.String(); body != anchorCert || strings.Contains(body, "PRIVATE") || strings.Contains(body, "Note") {
		t.Fatalf("body:\n%s", body)
	}
	// The module off: 404 like every route of it (SYS-5).
	w.gate.Set("agent-intake", false)
	if rec := w.get("/intake/ca.pem"); rec.Code != 404 {
		t.Fatalf("module off = %d", rec.Code)
	}
}

// Without TLS (a box on loopback) there is nothing to pin: 404.
func TestCaPemWithoutTLSIsNotFound(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	svc, err := agentintake.New(agentintake.Config{DB: w.db, Audit: w.aud, Sink: w.inv, Software: w.inv})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agentintake.NewIntakeHandlers(svc).InventoryGetIntakeCaPem(context.Background())
	if e, ok := apierr.As(err); !ok || e.Status != 404 {
		t.Fatalf("no trust anchor: %v", err)
	}
}
