package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
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
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// WP-26 slice 1 (D-262): the box CA signs the self-made 8443 leaf; D-351: it is sealed in core_secret.

// testCAs holds one box CA store per data directory of a test, so a second call for the same directory is the same box restarting.
var testCAs sync.Map

// testCA is the box CA store of a test's data directory: a migrated database (in a directory of its own, so a test that makes the
// data directory read-only does not stop the database) and a master key of its own.
func testCA(t *testing.T, dir string) *boxCAStore {
	t.Helper()
	if v, ok := testCAs.Load(dir); ok {
		return v.(*boxCAStore) //nolint:forcetypeassert // only this function stores
	}
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	s := newTestCAStore(t, filepath.Join(t.TempDir(), "vedette.db"), key, dir)
	testCAs.Store(dir, s)
	return s
}

// newTestCAStore opens (or makes, migrated) the database at dbPath and returns a box CA store with that master key.
func newTestCAStore(t *testing.T, dbPath string, key []byte, dataDir string) *boxCAStore {
	t.Helper()
	var db *store.DB
	var err error
	if fileExists(dbPath) {
		db, err = store.Open(context.Background(), dbPath, slog.New(slog.DiscardHandler))
	} else {
		db, err = openMigrated(context.Background(), dbPath, slog.New(slog.DiscardHandler))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sec, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newBoxCAStore(db, sec, audit.New(nil), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ensureCert is ensureCertAt now, with the test CA of the certificate's directory.
func ensureCert(t *testing.T, certPath, keyPath string, hosts []string) error {
	t.Helper()
	return ensureCertAt(t.Context(), testCA(t, filepath.Dir(certPath)), certPath, keyPath, hosts, time.Now, nil)
}

// testTransport is transport with the test CA of the database's directory.
func testTransport(t *testing.T, o options) (*tls.Config, []string, bool, *selfSignedRenewer, error) {
	t.Helper()
	return transport(t.Context(), o, testCA(t, filepath.Dir(o.db)))
}

// caPEM is the certificate of the store's current CA, PEM.
func caPEM(t *testing.T, s *boxCAStore) []byte {
	t.Helper()
	ca, err := s.current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// sealedCert is the certificate of the CA sealed for dir (made when there is none).
func sealedCert(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	ca, err := testCA(t, dir).ensure(t.Context(), time.Now(), slog.New(slog.DiscardHandler), false)
	if err != nil {
		t.Fatal(err)
	}
	return ca.cert
}

func caPool(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	p.AddCert(sealedCert(t, dir))
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

// auditRows are the "action detail" of the box-ca audit rows.
func auditRows(t *testing.T, s *boxCAStore) []string {
	t.Helper()
	rows, err := s.db.Reader().QueryContext(t.Context(), `SELECT action || ' ' || coalesce(detail, '') FROM core_audit WHERE action LIKE 'box-ca.%' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func sealedRows(t *testing.T, s *boxCAStore) int {
	t.Helper()
	var n int
	if err := s.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_secret WHERE purpose = ?`, boxCAPurpose).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func legacyFiles(dir string) (crt, key string) {
	return filepath.Join(dir, boxCAName+".crt"), filepath.Join(dir, boxCAName+".key")
}

// writeLegacyCA writes what a box between D-262 and D-351 had: the CA as two files in the data directory.
func writeLegacyCA(t *testing.T, dir string, now time.Time) *boxCA {
	t.Helper()
	ca, plain, err := newBoxCA(now)
	if err != nil {
		t.Fatal(err)
	}
	crt, key := legacyFiles(dir)
	keyBlk, rest := pem.Decode(plain)
	if err := writeAtomic(key, pem.EncodeToMemory(keyBlk)); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(crt, rest); err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestBoxCAFreshBoxLeafChainsToIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureCert(t, crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{crt, key} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	if c, k := legacyFiles(dir); fileExists(c) || fileExists(k) {
		t.Fatal("the CA was written to disk (D-351: it is sealed in core_secret)")
	}
	s := testCA(t, dir)
	if sealedRows(t, s) != 1 || len(auditRows(t, s)) != 1 || !strings.HasPrefix(auditRows(t, s)[0], "box-ca.create ecdsa-p256 serial=") {
		t.Fatalf("sealed rows %d, audit %q", sealedRows(t, s), auditRows(t, s))
	}
	ca, leaf := sealedCert(t, dir), readCert(t, crt)
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
	// L-2: two boxes' CAs have different subjects.
	other := sealedCert(t, t.TempDir())
	if len(ca.Subject.OrganizationalUnit) != 1 || !strings.HasPrefix(ca.Subject.OrganizationalUnit[0], "box ") || ca.Subject.String() == other.Subject.String() {
		t.Errorf("CA subjects %v and %v", ca.Subject, other.Subject)
	}
	// L-3: 825 days from NotBefore to NotAfter, not a minute more.
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != selfSignedLifetime {
		t.Errorf("the leaf lives %v, want %v", got, selfSignedLifetime)
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
	// Idempotent: a second start leaves the pair and the CA alone.
	before := mustRead(t, crt)
	if err := ensureCert(t, crt, key, []string{"box.acme.example", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) || !sealedCert(t, dir).Equal(ca) || len(auditRows(t, s)) != 1 {
		t.Fatal("a second start replaced something")
	}
}

func TestBoxCASurvivesRenewalAndAddressChange(t *testing.T) {
	t.Parallel()
	m := &fakeMgmt{}
	r, crt := newTestRenewer(t, m)
	dir := filepath.Dir(crt)
	caBefore := sealedCert(t, dir)
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
	if !caBefore.Equal(sealedCert(t, dir)) {
		t.Fatal("a renewal touched the CA")
	}
	// The renewal at start (ensureCertAt) does the same.
	at := later.Add(790 * 24 * time.Hour)
	if err := ensureCertAt(t.Context(), r.ca, crt, filepath.Join(dir, "c.key"), []string{"box.acme.example"}, func() time.Time { return at }, nil); err != nil {
		t.Fatal(err)
	}
	verifyUnderOnlyTheCA(t, dir, readCert(t, crt), "box.acme.example", at)
	if !caBefore.Equal(sealedCert(t, dir)) || len(auditRows(t, r.ca)) != 1 {
		t.Fatal("the start-up renewal touched the CA")
	}
}

// writeOldSelfSigned writes what a box before D-262 had: a self-signed leaf (CA:FALSE) for its key.
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
	if err := ensureCert(t, crt, key, []string{"new.acme.example"}); err != nil {
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
	if err := ensureCert(t, crt, key, []string{"new.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, mustRead(t, crt)) {
		t.Fatal("the upgrade ran twice")
	}
}

// A box that had the CA as two files (D-262) has it sealed once at its next start, the same CA (enrolled agents keep working), and
// the files are removed: no plaintext CA key stays on disk. The leaf, already signed by it, is not touched.
func TestBoxCALegacyFilesAreMigratedOnce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	legacy := writeLegacyCA(t, dir, time.Now())
	crt, key := filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := selfSignedPEM(legacy, k, []string{"box.acme.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	if err := writeAtomic(crt, leafPEM); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	o := options{db: filepath.Join(dir, "vedette.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example", log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	if _, _, _, _, err := testTransport(t, o); err != nil {
		t.Fatal(err)
	}
	s := testCA(t, dir)
	if !sealedCert(t, dir).Equal(legacy.cert) {
		t.Fatal("the sealed CA is not the one of the files")
	}
	if c, kf := legacyFiles(dir); fileExists(c) || fileExists(kf) {
		t.Fatal("the legacy files were not removed")
	}
	if !bytes.Equal(leafPEM, mustRead(t, crt)) {
		t.Fatal("the leaf, signed by the same CA, was re-issued")
	}
	if rows := auditRows(t, s); len(rows) != 1 || !strings.HasPrefix(rows[0], "box-ca.migrate ") || strings.Contains(logBuf.String(), "level=ERROR") {
		t.Fatalf("audit %q, log %q", rows, logBuf.String())
	}
	// Once: files that show up again (a copy put back, a crash between the commit and the removal) are never read again; the
	// first start that finds them removes them.
	writeLegacyCA(t, dir, time.Now())
	s2 := &boxCAStore{db: s.db, sec: s.sec, op: s.op, aud: s.aud, legacyCrt: s.legacyCrt, legacyKey: s.legacyKey} // a restart
	ca, err := s2.ensure(t.Context(), time.Now(), nil, true)
	if err != nil || !ca.cert.Equal(legacy.cert) || len(auditRows(t, s)) != 1 {
		t.Fatalf("second start: %v, audit %q", err, auditRows(t, s))
	}
	if c, kf := legacyFiles(dir); fileExists(c) || fileExists(kf) {
		t.Fatal("leftover legacy files were not removed")
	}
}

// The point of D-351: vedette.db and vedette.key restored into a fresh data directory (no leaf, no CA file) give the same CA, and
// the new leaf the box makes there verifies under the CA the agents pinned before.
func TestBoxCARestoreKeepsTheCA(t *testing.T) {
	t.Parallel()
	key := make([]byte, secrets.KeySize)
	_, _ = rand.Read(key)
	oldDir, oldDB := t.TempDir(), filepath.Join(t.TempDir(), "vedette.db")
	old := newTestCAStore(t, oldDB, key, oldDir)
	if _, _, _, _, err := transport(t.Context(), options{db: filepath.Join(oldDir, "vedette.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}, old); err != nil {
		t.Fatal(err)
	}
	pinned := caPEM(t, old)
	// The backup: the database as a snapshot takes it (store.SnapshotTo, modules/core/snapshot.go) and the master key.
	backup := filepath.Join(t.TempDir(), "vedette.db")
	if err := old.db.SnapshotTo(t.Context(), backup); err != nil {
		t.Fatal(err)
	}
	newDir := t.TempDir()
	restored := newTestCAStore(t, backup, key, newDir)
	_, _, _, renew, err := transport(t.Context(), options{db: filepath.Join(newDir, "vedette.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}, restored)
	if err != nil {
		t.Fatal(err)
	}
	if got := caPEM(t, restored); !bytes.Equal(got, pinned) {
		t.Fatal("the restored box has another CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pinned) {
		t.Fatal("the pinned PEM holds no certificate")
	}
	if _, err := servedLeaf(t, renew).Verify(x509.VerifyOptions{Roots: roots, DNSName: "box.acme.example"}); err != nil {
		t.Fatalf("the restored box's new leaf does not verify under the pinned CA: %v", err)
	}
	// Without the right master key the sealed CA cannot be opened: a new CA is sealed in a row of its own (the agents must enrol
	// again), never an error, and the old row is left as it was (M1).
	other := make([]byte, secrets.KeySize)
	_, _ = rand.Read(other)
	backup2 := filepath.Join(t.TempDir(), "vedette.db")
	if err := old.db.SnapshotTo(t.Context(), backup2); err != nil {
		t.Fatal(err)
	}
	keyless := newTestCAStore(t, backup2, other, t.TempDir())
	var logBuf bytes.Buffer
	ca, err := keyless.ensure(t.Context(), time.Now(), slog.New(slog.NewTextHandler(&logBuf, nil)), true)
	if err != nil || bytes.Equal(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), pinned) || sealedRows(t, keyless) != 2 {
		t.Fatalf("another master key: %v, %d rows", err, sealedRows(t, keyless))
	}
	var oldCipher, keptCipher []byte
	if err := old.db.Reader().QueryRowContext(t.Context(), `SELECT ciphertext FROM core_secret WHERE purpose = ? ORDER BY created_at LIMIT 1`, boxCAPurpose).Scan(&oldCipher); err != nil {
		t.Fatal(err)
	}
	if err := keyless.db.Reader().QueryRowContext(t.Context(), `SELECT ciphertext FROM core_secret WHERE purpose = ? ORDER BY created_at LIMIT 1`, boxCAPurpose).Scan(&keptCipher); err != nil || !bytes.Equal(oldCipher, keptCipher) {
		t.Fatalf("the old CA row was touched: %v", err)
	}
	// A restart with the same wrong key keeps the new CA (the newest row it can open).
	sec2, _ := secrets.New(other)
	again, err := newBoxCAStore(keyless.db, sec2, audit.New(nil), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c2, err := again.ensure(t.Context(), time.Now(), nil, true); err != nil || !c2.cert.Equal(ca.cert) || sealedRows(t, keyless) != 2 {
		t.Fatalf("restart with the same key: %v", err)
	}
	// The right key put back: the old CA again (the newer row does not decrypt under it), nothing replaced.
	secRight, _ := secrets.New(key)
	right, err := newBoxCAStore(keyless.db, secRight, audit.New(nil), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := caPEM(t, right); !bytes.Equal(got, pinned) || sealedRows(t, keyless) != 2 {
		t.Fatal("the right master key did not bring the old CA back")
	}
	if rows := auditRows(t, keyless); !strings.HasPrefix(rows[len(rows)-1], "box-ca.replace ") || !strings.HasSuffix(rows[len(rows)-1], "reason=cannot_decrypt") ||
		!strings.Contains(logBuf.String(), "level=ERROR") || !strings.Contains(logBuf.String(), "enrol") {
		t.Fatalf("audit %q, log %q", rows, logBuf.String())
	}
}

// A running box whose sealed CA was replaced under it gets its leaf signed by the new one at the next check, not at the next start.
func TestBoxCAReplacedCAReissuesTheLeafAtTheNextCheck(t *testing.T) {
	t.Parallel()
	r, crt := newTestRenewer(t, nil)
	if err := r.ca.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM core_secret WHERE purpose = ?`, boxCAPurpose)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verifyUnderOnlyTheCA(t, filepath.Dir(crt), servedLeaf(t, r), "box.acme.example", time.Now())
}

// Legacy files that cannot be used are moved aside and a new CA is sealed, with one ERROR on log, never an error (H-1).
func TestBoxCAUnusableLegacyFilesAreQuarantined(t *testing.T) {
	t.Parallel()
	states := map[string]func(t *testing.T, crt, key string){
		"key readable by others": func(_ *testing.T, _, key string) { _ = os.Chmod(key, 0o644) }, //nolint:gosec // the state under test
		"key missing":            func(_ *testing.T, _, key string) { _ = os.Remove(key) },
		"key does not match": func(t *testing.T, _, key string) {
			o := t.TempDir()
			writeLegacyCA(t, o, time.Now())
			_, ok := legacyFiles(o)
			_ = os.WriteFile(key, mustRead(t, ok), 0o600)
		},
		"unparsable":      func(_ *testing.T, crt, _ string) { _ = os.WriteFile(crt, []byte("junk"), 0o600) },
		"about to expire": func(*testing.T, string, string) {},
	}
	for name, damage := range states {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			at := time.Now()
			if name == "about to expire" {
				at = at.Add(-boxCALifetime + selfSignedLifetime/2)
			}
			old := writeLegacyCA(t, dir, at)
			crt, key := legacyFiles(dir)
			damage(t, crt, key)
			var logBuf bytes.Buffer
			ca, err := testCA(t, dir).ensure(t.Context(), time.Now(), slog.New(slog.NewTextHandler(&logBuf, nil)), true)
			if err != nil || !ca.cert.IsCA || ca.cert.Equal(old.cert) {
				t.Fatalf("%v", err)
			}
			if !strings.Contains(logBuf.String(), "level=ERROR") || !strings.Contains(logBuf.String(), "enrol") || strings.Contains(logBuf.String(), "PRIVATE") {
				t.Errorf("log %q", logBuf.String())
			}
			if q, _ := filepath.Glob(crt + ".quarantine-*"); len(q) != 1 {
				t.Error("the old CA certificate was not moved aside")
			}
			qk, _ := filepath.Glob(key + ".quarantine-*") // L-a: a key moved aside because others could read it is not left readable
			for _, p := range qk {
				if info, err := os.Stat(p); err != nil || info.Mode().Perm()&0o077 != 0 {
					t.Errorf("quarantined key %s: %v %v", p, info, err)
				}
			}
			if fileExists(crt) || fileExists(key) {
				t.Error("a legacy file stayed under its name")
			}
			if rows := auditRows(t, testCA(t, dir)); len(rows) != 1 || !strings.HasPrefix(rows[0], "box-ca.create ") || !strings.Contains(rows[0], "reason=") {
				t.Errorf("audit %q", rows)
			}
		})
	}
	// A key alone is an interrupted first start: removed and replaced without an ERROR.
	dir := t.TempDir()
	writeLegacyCA(t, dir, time.Now())
	crt, key := legacyFiles(dir)
	_ = os.Remove(crt)
	var logBuf bytes.Buffer
	if _, err := testCA(t, dir).ensure(t.Context(), time.Now(), slog.New(slog.NewTextHandler(&logBuf, nil)), true); err != nil || logBuf.Len() != 0 || fileExists(key) {
		t.Fatalf("a key alone: %v %q, key still there %v", err, logBuf.String(), fileExists(key))
	}
}

// H-1: transport() comes up for every unusable sealed CA: it is replaced and the leaf follows.
func TestBoxCABrokenCADoesNotStopTransport(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"damaged", "expiring"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			o := options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}
			if _, _, _, _, err := testTransport(t, o); err != nil {
				t.Fatal(err)
			}
			s := testCA(t, dir)
			crt := filepath.Join(dir, "vedette-selfsigned.crt")
			served := mustRead(t, crt)
			plain := []byte("junk")
			if name == "expiring" {
				_, p, err := newBoxCA(time.Now().Add(-boxCALifetime + selfSignedLifetime/2))
				if err != nil {
					t.Fatal(err)
				}
				plain = p
			}
			if err := s.db.Write(t.Context(), func(tx *sql.Tx) error {
				var id string
				if err := tx.QueryRowContext(t.Context(), `SELECT id FROM core_secret WHERE purpose = ?`, boxCAPurpose).Scan(&id); err != nil {
					return err
				}
				_, err := s.sec.Replace(t.Context(), tx, id, boxCAPurpose, plain, false)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			cfg, _, _, renew, err := testTransport(t, o)
			if err != nil || renew == nil || cfg.GetCertificate == nil {
				t.Fatalf("transport with a %s CA: %v", name, err)
			}
			if bytes.Equal(served, mustRead(t, crt)) {
				t.Error("the leaf was not re-issued under the new CA")
			}
			if err := renew.Check(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
				t.Fatal(err)
			}
			verifyUnderOnlyTheCA(t, dir, servedLeaf(t, renew), "box.acme.example", time.Now())
			if rows := auditRows(t, s); !strings.HasSuffix(rows[len(rows)-1], "reason="+name) || sealedRows(t, s) != 1 {
				t.Errorf("audit %q", rows)
			}
		})
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
	testCA(t, dir) // made now: its database lives elsewhere and stays writable

	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a read-only directory is the state under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory the test made, made writable again
	cfg, _, _, renew, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", hosts: "old.acme.example"})
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

// H-1: a CA that cannot be read at all (the database fails) never stops a Check while the leaf in use needs nothing; an expiring
// leaf still reports the error.
func TestBoxCACheckKeepsServingWithoutACA(t *testing.T) {
	t.Parallel()
	r, _ := newTestRenewer(t, nil)
	key := make([]byte, secrets.KeySize)
	broken := newTestCAStore(t, filepath.Join(t.TempDir(), "vedette.db"), key, t.TempDir())
	if err := broken.db.Close(); err != nil {
		t.Fatal(err)
	}
	r.ca = broken
	var logBuf bytes.Buffer
	if err := r.Check(t.Context(), slog.New(slog.NewTextHandler(&logBuf, nil))); err != nil {
		t.Fatalf("a valid leaf and no CA stopped Check: %v", err)
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
	s := testCA(t, t.TempDir())
	a, err := s.ensure(t.Context(), time.Now(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ensure(t.Context(), time.Now(), nil, true)
	if err != nil || !a.cert.Equal(b.cert) {
		t.Fatalf("a young CA was replaced: %v", err)
	}
	c, err := s.ensure(t.Context(), time.Now().Add(boxCALifetime-selfSignedLifetime/2), slog.New(slog.DiscardHandler), true) // cannot cover a new leaf
	if err != nil || a.cert.Equal(c.cert) || sealedRows(t, s) != 1 {
		t.Fatalf("an old CA was kept: %v", err)
	}
}

// The key is sealed: never in a log line, an audit row, or the plaintext of the database file.
func TestBoxCAKeyNeverInLogsOrInTheClear(t *testing.T) {
	t.Parallel()
	r, crt := newTestRenewer(t, &fakeMgmt{addrs: []string{"203.0.113.9"}})
	var buf bytes.Buffer
	if err := r.Check(t.Context(), slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
		t.Fatal(err)
	}
	ca, err := r.ca.ensure(t.Context(), time.Now(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 || strings.Contains(buf.String(), "PRIVATE") {
		t.Errorf("log: %q", buf.String())
	}
	for _, row := range auditRows(t, r.ca) {
		if strings.Contains(row, "PRIVATE") || strings.Contains(row, "BEGIN") {
			t.Errorf("audit row %q", row)
		}
	}
	var n int
	if err := r.ca.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_secret WHERE instr(ciphertext, ?) > 0 OR instr(ciphertext, ?) > 0`, keyDER, []byte("PRIVATE KEY")).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the CA key is in the clear in core_secret: %d %v", n, err)
	}
	if c, k := legacyFiles(filepath.Dir(crt)); fileExists(c) || fileExists(k) {
		t.Fatal("a CA file is on disk")
	}
}

// GET /intake/ca.pem gets the box CA's certificate for the box's own pair, the owner's file for -tls-cert (agent-intake keeps its
// CERTIFICATE blocks), nothing on plain HTTP.
func TestIntakeTrustAnchor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg, _, _, renew, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443"})
	if err != nil {
		t.Fatal(err)
	}
	anchor := intakeTrustAnchor(cfg, "", testCA(t, dir), renew)
	got, err := anchor(t.Context())
	if err != nil || bytes.Contains(got, []byte("PRIVATE")) {
		t.Fatalf("self-made: %v\n%s", err, got)
	}
	blk, rest := pem.Decode(got)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(blk.Bytes, sealedCert(t, dir).Raw) {
		t.Fatalf("self-made anchor is not the CA certificate alone:\n%s", got)
	}
	// L3: a CA that does not sign the leaf in use (replaced, the new leaf not written yet) is not handed out; the next check
	// re-issues the leaf and the new CA is served.
	if err := testCA(t, dir).db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM core_secret WHERE purpose = ?`, boxCAPurpose)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := testCA(t, dir).ensure(t.Context(), time.Now(), slog.New(slog.DiscardHandler), true); err != nil {
		t.Fatal(err)
	}
	if got, err := anchor(t.Context()); err == nil {
		t.Fatalf("a CA that does not sign the leaf in use was served:\n%s", got)
	}
	if err := renew.Check(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if got, err := anchor(t.Context()); err != nil || !bytes.Equal(got, caPEM(t, testCA(t, dir))) {
		t.Fatalf("after the re-issue: %v", err)
	}
	ownerDir := t.TempDir()
	oc, ok, _ := writeTestPair(t, ownerDir, &x509.Certificate{Subject: pkix.Name{CommonName: "owner"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"owner.example"}})
	ocfg, _, _, _, err := testTransport(t, options{db: filepath.Join(ownerDir, "v.db"), listen: "0.0.0.0:8443", tlsCert: oc, tlsKey: ok})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := intakeTrustAnchor(ocfg, oc, testCA(t, ownerDir), nil)(t.Context()); err != nil || !bytes.Equal(got, mustRead(t, oc)) {
		t.Fatalf("owner: %v", err)
	}
	if intakeTrustAnchor(nil, "", testCA(t, ownerDir), nil) != nil {
		t.Fatal("plain HTTP has a trust anchor")
	}
}

// The owner's -tls-cert is never touched and never gets a CA made for it.
func TestOwnerCertIsNotGivenACA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	crt, key, _ := writeTestPair(t, dir, &x509.Certificate{Subject: pkix.Name{CommonName: "owner", Organization: []string{"Acme"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour), DNSNames: []string{"owner.example"}})
	before, beforeKey := mustRead(t, crt), mustRead(t, key)
	cfg, _, _, renew, err := testTransport(t, options{db: filepath.Join(dir, "v.db"), listen: "0.0.0.0:8443", tlsCert: crt, tlsKey: key})
	if err != nil || renew != nil || cfg == nil {
		t.Fatalf("transport: %v %v", renew, err)
	}
	if !bytes.Equal(before, mustRead(t, crt)) || !bytes.Equal(beforeKey, mustRead(t, key)) {
		t.Fatal("the owner's pair changed")
	}
	if sealedRows(t, testCA(t, dir)) != 0 {
		t.Fatal("a CA was made for the owner's certificate")
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
	if err := ensureCert(t, own, ownKey, nil); err != nil {
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
	verify := func(label, dir, leaf string) {
		t.Helper()
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(caFile, caPEM(t, testCA(t, dir)), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.CommandContext(t.Context(), bin, "verify", "-CAfile", caFile, "-purpose", "sslserver", leaf).CombinedOutput() //nolint:gosec // a path the test made
		if err != nil || !strings.Contains(string(out), ": OK") {
			t.Fatalf("%s: openssl verify: %v\n%s", label, err, out)
		}
	}
	m := &fakeMgmt{}
	r, crt := newTestRenewer(t, m)
	verify("fresh", filepath.Dir(crt), crt)
	m.set(nil, "203.0.113.7")
	if err := r.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verify("after a reissue", filepath.Dir(crt), crt)
	// Upgrade from an old self-signed leaf.
	dir := t.TempDir()
	oc, ok := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	writeOldSelfSigned(t, oc, ok, []string{"old.example"})
	if err := ensureCert(t, oc, ok, nil); err != nil {
		t.Fatal(err)
	}
	verify("after the upgrade", dir, oc)
}

// M-1: a read error on the legacy files that says nothing about them (here EACCES on the key) never moves them aside nor seals
// anything while the leaf in use needs nothing; once readable they are migrated, the same CA; an error that never goes away is
// replaced when a new leaf is required.
func TestBoxCAUnreadableLegacyIsNotReplacedUnlessALeafIsRequired(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := t.TempDir()
	legacy := writeLegacyCA(t, dir, time.Now())
	crt, key := legacyFiles(dir)
	quarantined := func() int {
		a, _ := filepath.Glob(crt + ".quarantine-*")
		b, _ := filepath.Glob(key + ".quarantine-*")
		return len(a) + len(b)
	}
	if err := os.Chmod(key, 0); err != nil {
		t.Fatal(err)
	}
	s := testCA(t, dir)
	if _, err := s.ensure(t.Context(), time.Now(), nil, false); !errors.Is(err, errCAUnreadable) {
		t.Fatalf("ensure = %v, want errCAUnreadable", err)
	}
	if quarantined() != 0 || sealedRows(t, s) != 0 || !fileExists(crt) {
		t.Fatal("a read error moved the CA aside or sealed one")
	}
	// Readable again: the same CA is migrated.
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if ca, err := s.ensure(t.Context(), time.Now(), nil, false); err != nil || !ca.cert.Equal(legacy.cert) || quarantined() != 0 {
		t.Fatalf("after the error went away: %v", err)
	}
	// An error that never goes away: when a new leaf is required the legacy pair is replaced.
	dir2 := t.TempDir()
	legacy2 := writeLegacyCA(t, dir2, time.Now())
	_, key2 := legacyFiles(dir2)
	if err := os.Chmod(key2, 0); err != nil {
		t.Fatal(err)
	}
	ca, err := testCA(t, dir2).ensure(t.Context(), time.Now(), slog.New(slog.DiscardHandler), true)
	if err != nil || ca.cert.Equal(legacy2.cert) {
		t.Fatalf("not replaced when required: %v", err)
	}
	if q, _ := filepath.Glob(filepath.Join(dir2, "*.quarantine-*")); len(q) != 2 {
		t.Fatalf("files aside: %v", q)
	}
}

// L-b: the CA is there and only the leaf cannot be written (read-only directory): the old leaf is kept.
func TestBoxCAUpgradeKeepsTheOldLeafWhenOnlyTheLeafWriteFails(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	writeOldSelfSigned(t, crt, key, []string{"old.example"})
	s := testCA(t, dir)
	if _, err := s.ensure(t.Context(), time.Now(), nil, true); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, crt)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a read-only directory is the state under test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory the test made, made writable again
	replaced, err := renewSelfSigned(t.Context(), s, crt, key, nil, time.Now, slog.New(slog.DiscardHandler))
	if err != nil || replaced || !bytes.Equal(before, mustRead(t, crt)) {
		t.Fatalf("renewSelfSigned = %v, %v", replaced, err)
	}
}

// L1: the legacy files are sealed and removed whatever the TLS mode: a box on -tls-cert or on loopback HTTP keeps no plaintext CA
// key on disk; a box without files gets no CA.
func TestBoxCALegacyFilesAreSealedWithoutSelfSignedTLS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	legacy := writeLegacyCA(t, dir, time.Now())
	s := testCA(t, dir)
	if err := s.migrateLegacy(t.Context(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if c, k := legacyFiles(dir); fileExists(c) || fileExists(k) || !sealedCert(t, dir).Equal(legacy.cert) {
		t.Fatal("the legacy CA was not sealed and removed")
	}
	// A key alone is removed; nothing at all makes nothing.
	alone := t.TempDir()
	writeLegacyCA(t, alone, time.Now())
	crt, key := legacyFiles(alone)
	_ = os.Remove(crt)
	if err := testCA(t, alone).migrateLegacy(t.Context(), nil); err != nil || fileExists(key) || sealedRows(t, testCA(t, alone)) != 0 {
		t.Fatalf("a key alone: %v", err)
	}
	empty := t.TempDir()
	if err := testCA(t, empty).migrateLegacy(t.Context(), nil); err != nil || sealedRows(t, testCA(t, empty)) != 0 {
		t.Fatalf("no files: %v", err)
	}
}
