package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

func firstCert(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatalf("no PEM block in %q", raw)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// What agent-intake pins (INV-11): none on loopback, the box CA (never the leaf, so a renewal keeps every agent connected) for the box's own
// pair, and exactly the chain the owner supplied for -tls-cert.
func TestTrustAnchorChoice(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db := filepath.Join(dir, "vedette.db")

	if _, err := trustAnchor(options{db: db, listen: "127.0.0.1:8080"})(); !errors.Is(err, agentintake.ErrNoTrustAnchor) {
		t.Fatalf("loopback without a certificate: %v", err)
	}

	leaf, key := filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
	if err := ensureCert(leaf, key, []string{"box.acme.example"}); err != nil {
		t.Fatal(err)
	}
	got, err := trustAnchor(options{db: db, listen: "0.0.0.0:8443"})()
	caCrt, _ := boxCAPaths(leaf)
	if err != nil || !bytes.Equal(got, mustRead(t, caCrt)) || !firstCert(t, got).IsCA || bytes.Contains(got, mustRead(t, leaf)) {
		t.Fatalf("self-signed pair: %v, want the box CA (IsCA) and not the leaf", err)
	}

	ownerDir := t.TempDir()
	oLeaf, oKey := filepath.Join(ownerDir, "o.crt"), filepath.Join(ownerDir, "o.key")
	if err := ensureCert(oLeaf, oKey, []string{"owner.example"}); err != nil {
		t.Fatal(err)
	}
	got, err = trustAnchor(options{db: db, listen: "0.0.0.0:8443", tlsCert: oLeaf, tlsKey: oKey})()
	if err != nil || !bytes.Equal(got, mustRead(t, oLeaf)) || firstCert(t, got).IsCA {
		t.Fatalf("owner certificate: %v, want the owner's file as supplied", err)
	}
	if bytes.Contains(got, []byte("PRIVATE KEY")) {
		t.Fatal("a key in the trust anchor")
	}
}

// The default of -osquery-dir is where the core image puts the packages.
func TestDefaultOsqueryDirIsTheImagePath(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../deploy/containers/core/Containerfile")
	if err != nil {
		t.Fatal(err)
	}
	if want := "COPY --from=osquery /out/ " + defaultOsqueryDir + "/\n"; !strings.Contains(string(raw), want) {
		t.Fatalf("core/Containerfile does not hold %q", want)
	}
}
