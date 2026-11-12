package main

import (
	"bytes"
	"context"
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

// What agent-intake pins (INV-11): none on loopback, the sealed box CA (never the leaf, so a renewal keeps every agent connected) for
// the box's own pair, and the file the owner supplied for -tls-cert as read (agent-intake keeps its CERTIFICATE blocks only).
func TestTrustAnchorChoice(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db := filepath.Join(dir, "vedette.db")
	caCert := caPEM(t, testCA(t, dir))
	sealed := func(context.Context) ([]byte, error) { return caCert, nil }

	for _, s := range []func(context.Context) ([]byte, error){nil, sealed} {
		if _, err := trustAnchor(options{db: db, listen: "127.0.0.1:8080"}, s)(); !errors.Is(err, agentintake.ErrNoTrustAnchor) {
			t.Fatalf("loopback without a certificate: %v", err)
		}
	}
	if _, err := trustAnchor(options{db: db, listen: "0.0.0.0:8443"}, nil)(); !errors.Is(err, agentintake.ErrNoTrustAnchor) {
		t.Fatalf("no TLS: %v", err)
	}

	got, err := trustAnchor(options{db: db, listen: "0.0.0.0:8443"}, sealed)()
	if err != nil || !bytes.Equal(got, caCert) || !firstCert(t, got).IsCA {
		t.Fatalf("self-signed pair: %v, want the sealed box CA (IsCA)", err)
	}
	busy := errors.New("busy")
	if _, err := trustAnchor(options{db: db, listen: "0.0.0.0:8443"}, func(context.Context) ([]byte, error) { return nil, busy })(); !errors.Is(err, busy) {
		t.Fatalf("a refused CA read: %v, want it passed through (503 server_busy)", err)
	}

	ownerDir := t.TempDir()
	oLeaf, oKey := filepath.Join(ownerDir, "o.crt"), filepath.Join(ownerDir, "o.key")
	if err := ensureCert(t, oLeaf, oKey, []string{"owner.example"}); err != nil {
		t.Fatal(err)
	}
	got, err = trustAnchor(options{db: db, listen: "0.0.0.0:8443", tlsCert: oLeaf, tlsKey: oKey}, sealed)()
	if err != nil || !bytes.Equal(got, mustRead(t, oLeaf)) || firstCert(t, got).IsCA {
		t.Fatalf("owner certificate: %v, want the owner's file as supplied", err)
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
