package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec" //nolint:depguard // the test runs openssl verify with fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// WP-26 slice 1 (D-262): the box CA signs the self-made 8443 leaf.

func caPool(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	crt, _ := boxCAPaths(filepath.Join(dir, "x.crt"))
	if !p.AppendCertsFromPEM(mustRead(t, crt)) {
		t.Fatal("the CA file holds no certificate")
	}
	return p
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path the test made
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifyUnderOnlyTheCA is what an agent that pins the CA does: the roots are the CA and nothing else.
func verifyUnderOnlyTheCA(t *testing.T, dir string, leaf *x509.Certificate, name string, at time.Time) {
	t.Helper()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool(t, dir), DNSName: name, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("the leaf does not verify against the box CA alone: %v", err)
	}
}

func TestBoxCAFreshBoxLeafChainsToIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	caCrt, caKey := boxCAPaths(crt)
	for _, p := range []string{crt, key, caCrt, caKey} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	ca, leaf := readCert(t, caCrt), readCert(t, crt)
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Errorf("the CA is not CA:TRUE, pathlen 0: %+v", ca)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("CA key usage %v", ca.KeyUsage)
	}
	if got := ca.NotAfter.Sub(ca.NotBefore); got < 19*365*24*time.Hour {
		t.Errorf("the CA lives %v, want about 20 years", got)
	}
	if !slices.Contains(ca.Subject.Organization, selfSignedOrg) || ca.Subject.CommonName == leaf.Subject.CommonName {
		t.Errorf("CA subject %v", ca.Subject)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("the 8443 leaf is a CA (Firefox refuses that)")
	}
	if leaf.Issuer.String() != ca.Subject.String() || leaf.Issuer.String() == leaf.Subject.String() {
		t.Errorf("issuer %v, subject %v", leaf.Issuer, leaf.Subject)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ext key usage %v", leaf.ExtKeyUsage)
	}
	verifyUnderOnlyTheCA(t, dir, leaf, "box.acme.example", time.Now())
	if _, _, err := loadTLS(crt, key); err != nil {
		t.Fatal(err)
	}
	// Idempotent: a second start leaves both pairs alone.
	before, beforeCA := mustRead(t, crt), mustRead(t, caCrt)
	if err := ensureCert(crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) || !bytes.Equal(beforeCA, mustRead(t, caCrt)) {
		t.Fatal("a second start replaced a file")
	}
}

func TestBoxCASurvivesRenewalAndAddressChange(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, crt := newTestRenewer(t, m)
	dir := filepath.Dir(crt)
	caCrt, caKey := boxCAPaths(crt)
	caBefore, caKeyBefore := mustRead(t, caCrt), mustRead(t, caKey)
	first := servedLeaf(t, r)
	// An address change: a new leaf, the same key, the same CA.
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	second := servedLeaf(t, r)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 || !hasIP(second, "203.0.113.7") {
		t.Fatal("not re-issued")
	}
	verifyUnderOnlyTheCA(t, dir, second, "box.acme.example", time.Now())
	if !bytes.Equal(second.AuthorityKeyId, first.AuthorityKeyId) || len(second.AuthorityKeyId) == 0 {
		t.Error("the authority key id changed or is empty")
	}
	// An expiry renewal 800 days on: the clock moves, the CA does not.
	later := time.Now().Add(800 * 24 * time.Hour)
	r.now = func() time.Time { return later }
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	third := servedLeaf(t, r)
	if third.SerialNumber.Cmp(second.SerialNumber) == 0 || !third.NotAfter.After(second.NotAfter) {
		t.Fatal("not renewed")
	}
	verifyUnderOnlyTheCA(t, dir, third, "box.acme.example", later)
	if !third.PublicKey.(*ecdsa.PublicKey).Equal(first.PublicKey) {
		t.Error("the leaf key changed")
	}
	if !bytes.Equal(caBefore, mustRead(t, caCrt)) || !bytes.Equal(caKeyBefore, mustRead(t, caKey)) {
		t.Fatal("a renewal touched the CA")
	}
	// The renewal at start (ensureCertAt) does the same.
	if err := ensureCertAt(crt, filepath.Join(dir, "c.key"), []string{"box.acme.example"}, func() time.Time { return later.Add(790 * 24 * time.Hour) }, nil); err != nil {
		t.Fatal(err)
	}
	verifyUnderOnlyTheCA(t, dir, readCert(t, crt), "box.acme.example", later.Add(790*24*time.Hour))
	if !bytes.Equal(caBefore, mustRead(t, caCrt)) {
		t.Fatal("the start-up renewal touched the CA")
	}
}

// writeOldSelfSigned writes what a box before this slice had: a self-signed leaf (CA:FALSE) for its key.
func writeOldSelfSigned(t *testing.T, crt, key string, dns []string, ips ...string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Vedette", Organization: []string{selfSignedOrg}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(400 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
		DNSNames: dns,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	if err := writeAtomic(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBoxCAUpgradeOfAnOldSelfSignedLeaf(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	k := writeOldSelfSigned(t, crt, key, []string{"old.acme.example"}, "198.51.100.4")
	old := readCert(t, crt)
	// Flags that differ from the old SANs: the upgrade keeps the old names and adds the flag's.
	if err := ensureCert(crt, key, []string{"new.acme.example"}); err != nil {
		t.Fatal(err)
	}
	leaf := readCert(t, crt)
	if leaf.SerialNumber.Cmp(old.SerialNumber) == 0 || leaf.IsCA {
		t.Fatal("the old leaf was not re-issued as a plain leaf")
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Error("the leaf key changed at the upgrade")
	}
	for _, want := range []string{"old.acme.example", "new.acme.example", "198.51.100.4", "localhost"} {
		if leaf.VerifyHostname(want) != nil {
			t.Errorf("SANs lack %q: %v %v", want, leaf.DNSNames, leaf.IPAddresses)
		}
	}
	verifyUnderOnlyTheCA(t, dir, leaf, "old.acme.example", time.Now())
	if _, _, err := loadTLS(crt, key); err != nil {
		t.Fatal(err)
	}
	// Once only: the next start leaves the pair alone.
	again := mustRead(t, crt)
	if err := ensureCert(crt, key, []string{"new.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, mustRead(t, crt)) {
		t.Fatal("the upgrade ran twice")
	}
}

// A running box whose CA was replaced under it (files deleted by hand) gets its leaf signed by the new one
// at the next check, not at the next start.
func TestBoxCAReplacedCAReissuesTheLeafAtTheNextCheck(t *testing.T) {
	t.Parallel()
	r, crt := newTestRenewer(t, nil)
	caCrt, caKey := boxCAPaths(crt)
	for _, p := range []string{caCrt, caKey} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verifyUnderOnlyTheCA(t, filepath.Dir(crt), servedLeaf(t, r), "box.acme.example", time.Now())
}

func TestBoxCAFilesAreChecked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(crt, key, nil); err != nil {
		t.Fatal(err)
	}
	caCrt, caKey := boxCAPaths(crt)
	// Every unusable state is quarantined and replaced, with one ERROR on log, never an error (H-1).
	states := map[string]func(){
		"key readable by others": func() { _ = os.Chmod(caKey, 0o644) }, //nolint:gosec // the state under test
		"key missing":            func() { _ = os.Remove(caKey) },
		"key does not match": func() {
			other := t.TempDir()
			if err := ensureCert(filepath.Join(other, "c.crt"), filepath.Join(other, "c.key"), nil); err != nil {
				t.Error(err)
			}
			_, ok := boxCAPaths(filepath.Join(other, "c.crt"))
			_ = os.WriteFile(caKey, mustRead(t, ok), 0o600)
		},
		"unparsable": func() { _ = os.WriteFile(caCrt, []byte("junk"), 0o600) },
		"not a CA":   func() { _ = os.WriteFile(caCrt, mustRead(t, crt), 0o600) },
	}
	at := time.Now()
	for name, damage := range states {
		old := mustRead(t, caCrt)
		damage()
		var logBuf bytes.Buffer
		at = at.Add(time.Second) // a distinct quarantine name each time
		ca, err := ensureBoxCA(crt, at, slog.New(slog.NewTextHandler(&logBuf, nil)))
		if err != nil || !ca.cert.IsCA {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(logBuf.String(), "level=ERROR") || !strings.Contains(logBuf.String(), "enrol") || strings.Contains(logBuf.String(), "PRIVATE") {
			t.Errorf("%s: log %q", name, logBuf.String())
		}
		if bytes.Equal(old, mustRead(t, caCrt)) {
			t.Errorf("%s: the CA was not replaced", name)
		}
		for _, p := range []string{caCrt, caKey} {
			if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("%s: %s: %v %v", name, p, info, err)
			}
		}
		if q, _ := filepath.Glob(caCrt + ".quarantine-*"); len(q) == 0 {
			t.Errorf("%s: the old CA certificate was not moved aside", name)
		}
	}
	// A key alone is an interrupted first start: replaced without an ERROR.
	if err := os.Remove(caCrt); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureBoxCA(crt, time.Now(), nil); err != nil || !readCert(t, caCrt).IsCA {
		t.Fatalf("a key alone: %v", err)
	}
}

// H-1: transport() comes up for every broken-CA state: the CA is quarantined and replaced and the leaf follows.
func TestBoxCABrokenCADoesNotStopTransport(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"mode", "key missing", "mismatch", "unparsable"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			o := options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}
			if _, _, _, _, err := transport(o); err != nil {
				t.Fatal(err)
			}
			crt := filepath.Join(dir, "vedette-selfsigned.crt")
			caCrt, caKey := boxCAPaths(crt)
			served := mustRead(t, crt)
			switch name {
			case "mode":
				_ = os.Chmod(caKey, 0o644) //nolint:gosec // the state under test
			case "key missing":
				_ = os.Remove(caKey)
			case "mismatch":
				other := t.TempDir()
				_ = ensureCert(filepath.Join(other, "c.crt"), filepath.Join(other, "c.key"), nil)
				_, ok := boxCAPaths(filepath.Join(other, "c.crt"))
				_ = os.WriteFile(caKey, mustRead(t, ok), 0o600)
			case "unparsable":
				_ = os.WriteFile(caCrt, []byte("junk"), 0o600)
			}
			cfg, _, _, renew, err := transport(o)
			if err != nil || renew == nil || cfg.GetCertificate == nil {
				t.Fatalf("transport with a %s CA: %v", name, err)
			}
			// At start the unusable CA is quarantined and replaced, and the leaf follows under the new CA, same key.
			if bytes.Equal(served, mustRead(t, crt)) {
				t.Error("the leaf was not re-issued under the new CA")
			}
			if err := renew.Check(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
				t.Fatal(err)
			}
			verifyUnderOnlyTheCA(t, dir, servedLeaf(t, renew), "box.acme.example", time.Now())
			if q, _ := filepath.Glob(filepath.Join(dir, "vedette-selfsigned-ca.crt.quarantine-*")); len(q) == 0 {
				t.Error("the old CA certificate was not quarantined")
			}
		})
	}
}

// H-1 / L-1: replacing a CA near its expiry moves the old files aside first. A crash between the two writes
// of the new CA (the new key written, no certificate yet) starts and heals; swapping the writes (certificate
// first) would leave an old key with a new certificate, which loadBoxCA rejects.
func TestBoxCAReplacementCrashStates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt := filepath.Join(dir, "c.crt")
	caCrt, caKey := boxCAPaths(crt)
	old, err := ensureBoxCA(crt, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(boxCALifetime - selfSignedLifetime/2)
	// The crash: the first write of the new CA lands, the second does not. makeBoxCA with a writer that fails
	// on its second call; the old pair is moved aside by ensureBoxCA before this, so what remains is the
	// new key alone. (Writing the certificate first would leave a certificate and no key: the check below
	// that the key exists and the certificate does not fails.)
	for _, p := range []string{caCrt, caKey} {
		if err := os.Rename(p, p+".quarantine-1"); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	_, err = makeBoxCA(caCrt, caKey, later, func(path string, data []byte) error {
		calls++
		if calls == 2 {
			return errors.New("crash")
		}
		return writeAtomic(path, data)
	})
	if err == nil || calls != 2 {
		t.Fatalf("makeBoxCA: %v after %d writes", err, calls)
	}
	if !fileExists(caKey) || fileExists(caCrt) {
		t.Fatalf("after the crash: key %v, certificate %v; want the key alone", fileExists(caKey), fileExists(caCrt))
	}
	// And it heals at the next start, without an ERROR (nothing enrolled yet to lose).
	var logBuf bytes.Buffer
	ca, err := ensureBoxCA(crt, later, slog.New(slog.NewTextHandler(&logBuf, nil)))
	if err != nil || ca.cert.Equal(old.cert) || logBuf.Len() != 0 {
		t.Fatalf("key alone after a crash: %v %q", err, logBuf.String())
	}
	if _, err := loadBoxCA(caCrt, caKey); err != nil {
		t.Fatalf("the healed pair does not load: %v", err)
	}
	// The real replacement near expiry: the old files are moved aside, the new pair loads.
	later2 := later.Add(boxCALifetime - selfSignedLifetime/2)
	if _, err := ensureBoxCA(crt, later2, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if q, _ := filepath.Glob(caCrt + ".quarantine-*"); len(q) < 2 {
		t.Errorf("old CA certificates moved aside: %v", q)
	}
	if _, err := loadBoxCA(caCrt, caKey); err != nil {
		t.Fatal(err)
	}
}

// H-1: an upgrade on a data directory that cannot be written must not stop core: the old leaf is kept.
func TestBoxCAUpgradeInAReadOnlyDirectoryKeepsTheOldLeaf(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
	writeOldSelfSigned(t, crt, key, []string{"old.acme.example"})
	before := mustRead(t, crt)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a read-only directory is the state under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory the test made, made writable again
	cfg, _, _, renew, err := transport(options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "old.acme.example"})
	if err != nil || cfg == nil || renew == nil {
		t.Fatalf("transport: %v", err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) {
		t.Fatal("the leaf changed")
	}
	if err := renew.Check(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) {
		t.Fatal("the leaf changed in Check")
	}
	// Writable again: the next Check upgrades it.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory the test made, made writable again
		t.Fatal(err)
	}
	if err := renew.Check(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	verifyUnderOnlyTheCA(t, dir, servedLeaf(t, renew), "old.acme.example", time.Now())
}

// H-1: a CA that cannot be made at all (the directory is read-only) never stops a Check while the leaf in use
// needs nothing; an expiring leaf still reports the error.
func TestBoxCACheckKeepsServingWithoutACA(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	r, crt := newTestRenewer(t, nil)
	dir := filepath.Dir(crt)
	_, caKey := boxCAPaths(crt)
	if err := os.Chmod(caKey, 0o644); err != nil { //nolint:gosec // the state under test; unusable: quarantine needs to move files in dir
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a read-only directory is the state under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory the test made, made writable again
	var logBuf bytes.Buffer
	if err := r.Check(t.Context(), slog.New(slog.NewTextHandler(&logBuf, nil))); err != nil {
		t.Fatalf("a valid leaf and a broken CA stopped Check: %v", err)
	}
	if !strings.Contains(logBuf.String(), "box CA is not available") {
		t.Errorf("no reason logged: %q", logBuf.String())
	}
	later := time.Now().Add(800 * 24 * time.Hour)
	r.now = func() time.Time { return later }
	if err := r.Check(t.Context(), nil); err == nil {
		t.Fatal("an expiring leaf with no CA reported no error")
	}
}

func TestBoxCAExpiringIsReplaced(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt := filepath.Join(dir, "c.crt")
	a, err := ensureBoxCA(crt, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ensureBoxCA(crt, time.Now(), nil)
	if err != nil || !a.cert.Equal(b.cert) {
		t.Fatalf("a young CA was replaced: %v", err)
	}
	c, err := ensureBoxCA(crt, time.Now().Add(boxCALifetime-selfSignedLifetime/2), slog.New(slog.DiscardHandler)) // cannot cover a new leaf
	if err != nil || a.cert.Equal(c.cert) {
		t.Fatalf("an old CA was kept: %v", err)
	}
}

func TestBoxCAKeyNeverInLogs(t *testing.T) {
	t.Parallel()
	r, crt := newTestRenewer(t, &fakeMgmt{addrs: []string{"203.0.113.9"}})
	var buf bytes.Buffer
	if err := r.Check(t.Context(), slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
		t.Fatal(err)
	}
	_, caKey := boxCAPaths(crt)
	blk, _ := pem.Decode(mustRead(t, caKey))
	if buf.Len() == 0 || strings.Contains(buf.String(), "PRIVATE") || strings.Contains(buf.String(), caKey) {
		t.Errorf("log: %q", buf.String())
	}
	if blk == nil {
		t.Fatal("CA key is not PEM")
	}
}

func TestTrustAnchorPEM(t *testing.T) {
	t.Parallel()
	// Box's own pair: the CA, not the leaf, and no key.
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(crt, key, nil); err != nil {
		t.Fatal(err)
	}
	caCrt, _ := boxCAPaths(crt)
	got, err := trustAnchorPEM(crt, false)
	if err != nil || !bytes.Equal(got, mustRead(t, caCrt)) {
		t.Fatalf("self-made: %v\n%s", err, got)
	}
	// Owner-supplied: the chain as supplied (leaf-only gives that leaf); a key in the same file is never copied.
	ownerDir := t.TempDir()
	oc, ok, _ := writeTestPair(t, ownerDir, &x509.Certificate{Subject: pkix.Name{CommonName: "owner"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"owner.example"}})
	leafOnly, err := trustAnchorPEM(oc, true)
	if err != nil || !bytes.Equal(leafOnly, mustRead(t, oc)) {
		t.Fatalf("owner leaf: %v", err)
	}
	both := append(append([]byte("junk\n"), mustRead(t, oc)...), mustRead(t, ok)...)
	if err := os.WriteFile(oc, both, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = trustAnchorPEM(oc, true)
	if err != nil || bytes.Contains(got, []byte("PRIVATE")) || !bytes.Equal(got, leafOnly) {
		t.Fatalf("owner file with a key: %v\n%s", err, got)
	}
	if _, err := trustAnchorPEM(filepath.Join(ownerDir, "none.crt"), true); err == nil {
		t.Fatal("a missing file gave an anchor")
	}
}

// The owner's -tls-cert is never touched and never gets a CA made beside it.
func TestOwnerCertIsNotGivenACA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key, _ := writeTestPair(t, dir, &x509.Certificate{Subject: pkix.Name{CommonName: "owner", Organization: []string{"Acme"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour), DNSNames: []string{"owner.example"}})
	before, beforeKey := mustRead(t, crt), mustRead(t, key)
	cfg, _, _, renew, err := transport(options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", tlsCert: crt, tlsKey: key})
	if err != nil || renew != nil || cfg == nil {
		t.Fatalf("transport: %v %v", renew, err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) || !bytes.Equal(beforeKey, mustRead(t, key)) {
		t.Fatal("the owner's pair changed")
	}
	if caCrt, caKey := boxCAPaths(crt); fileExists(caCrt) || fileExists(caKey) {
		t.Fatal("a CA was made next to the owner's certificate")
	}
	// Even an owner pair placed at the self-made names (own organization, about to expire) is left alone.
	own := filepath.Join(dir, "vedette-selfsigned.crt")
	if err := os.WriteFile(own, before, 0o600); err != nil {
		t.Fatal(err)
	}
	ownKey := filepath.Join(dir, "vedette-selfsigned.key")
	if err := os.WriteFile(ownKey, beforeKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(own, ownKey, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustRead(t, own)) {
		t.Fatal("a foreign certificate at the self-made name was re-issued")
	}
}

// openssl verify -CAfile ca.pem leaf.pem, when openssl is installed: a second implementation agrees.
func TestBoxCAOpenSSLVerify(t *testing.T) {
	t.Parallel()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not on PATH")
	}
	m := &fakeMgmt{}
	r, crt := newTestRenewer(t, m)
	caCrt, _ := boxCAPaths(crt)
	run := func(label string) {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), bin, "verify", "-CAfile", caCrt, "-purpose", "sslserver", crt).CombinedOutput() //nolint:gosec // a path the test made
		if err != nil || !strings.Contains(string(out), ": OK") {
			t.Fatalf("%s: openssl verify: %v\n%s", label, err, out)
		}
	}
	run("fresh")
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	run("after a reissue")
	// Upgrade from an old self-signed leaf.
	dir := t.TempDir()
	oc, ok := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	writeOldSelfSigned(t, oc, ok, []string{"old.example"})
	if err := ensureCert(oc, ok, nil); err != nil {
		t.Fatal(err)
	}
	caCrt2, _ := boxCAPaths(oc)
	out, err := exec.CommandContext(t.Context(), bin, "verify", "-CAfile", caCrt2, "-purpose", "sslserver", oc).CombinedOutput() //nolint:gosec // a path the test made
	if err != nil || !strings.Contains(string(out), ": OK") {
		t.Fatalf("after the upgrade: %v\n%s", err, out)
	}
}
