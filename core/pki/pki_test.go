package pki_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/pki"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

var t0 = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: t0} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var masterKey = bytes.Repeat([]byte{9}, secrets.KeySize)

type env struct {
	db  *store.DB
	clk *clock
	dir string // creds dir
	log *syncBuffer
}

// syncBuffer collects what pki logs, so a test can look for key material in it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (e *env) logger() *slog.Logger { return slog.New(slog.NewTextHandler(e.log, nil)) }

// auditRows returns "action target detail" of every audit row of actor system, oldest first.
func (e *env) auditRows(t *testing.T) []string {
	t.Helper()
	rs, err := e.db.Reader().QueryContext(t.Context(), `SELECT action, target, coalesce(detail, '') FROM core_audit WHERE user = 'system' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []string
	for rs.Next() {
		var a, tg, d string
		if err := rs.Scan(&a, &tg, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+" "+tg+" "+d)
	}
	return out
}

func countPrefix(rows []string, prefix string) int {
	n := 0
	for _, r := range rows {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{db: storetest.NewMigrated(t, "core", "../../modules/core/migrations/sqlite"), clk: newClock(), dir: filepath.Join(t.TempDir(), "creds"), log: &syncBuffer{}}
}

// open is a core start: a new secrets.Store (the purpose can be restricted once per store) over the same database.
func (e *env) open(t *testing.T) *pki.Authority {
	t.Helper()
	a, err := e.tryOpen(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) tryOpen(key []byte) (*pki.Authority, error) {
	s, err := secrets.New(key)
	if err != nil {
		return nil, err
	}
	return pki.Open(context.Background(), pki.Options{DB: e.db, Secrets: s, Audit: audit.New(e.clk.Now), Now: e.clk.Now, Log: e.logger()})
}

func (e *env) bundle(t *testing.T, role sensorlink.Role) *sensorlink.Bundle {
	t.Helper()
	b, err := readFile(filepath.Join(e.dir, string(role), pki.BundleName))
	if err != nil {
		t.Fatal(err)
	}
	bu, err := sensorlink.ParseBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return bu
}

type certRow struct {
	role, serial, notAfter string
	retired                *string
}

func (e *env) rows(t *testing.T, role sensorlink.Role) []certRow {
	t.Helper()
	rs, err := e.db.Reader().QueryContext(t.Context(), `SELECT role, serial, not_after, retired_at FROM core_sensor_cert WHERE role = ? ORDER BY rowid`, string(role))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []certRow
	for rs.Next() {
		var c certRow
		var ret sql.NullString
		if err := rs.Scan(&c.role, &c.serial, &c.notAfter, &ret); err != nil {
			t.Fatal(err)
		}
		if ret.Valid {
			c.retired = &ret.String
		}
		out = append(out, c)
	}
	return out
}

// D-110 (1): one CA, made the first time, sealed in core_secret under a purpose only this package may read.
func TestCAIsMadeOnceAndSealed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	ca, err := x509.ParseCertificate(pemDecode(a.CACertPEM()))
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !ca.IsCA || !ca.MaxPathLenZero || ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("CA certificate: %+v", ca)
	}
	if d := ca.NotAfter.Sub(t0); d < 3649*24*time.Hour || d > 3651*24*time.Hour {
		t.Errorf("CA validity ends %v after now, want 10 years", d)
	}
	// a restart on the same database finds the same CA
	b := e.open(t)
	if !bytes.Equal(a.CACertPEM(), b.CACertPEM()) {
		t.Error("a second start made another CA")
	}
	// the key is in core_secret, encrypted, and nobody else can read it
	var id, purpose string
	var ct []byte
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id, purpose, ciphertext FROM core_secret WHERE purpose = 'core_sensor_ca'`).Scan(&id, &purpose, &ct); err != nil {
		t.Fatalf("no CA secret row: %v", err)
	}
	if bytes.Contains(ct, []byte("PRIVATE KEY")) || bytes.Contains(ct, ca.Raw) {
		t.Error("the CA secret is not encrypted")
	}
	var n int
	_ = e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_secret WHERE purpose = 'core_sensor_ca'`).Scan(&n)
	if n != 1 {
		t.Errorf("%d CA rows", n)
	}
	s, _ := secrets.New(masterKey)
	if _, err := pki.Open(t.Context(), pki.Options{DB: e.db, Secrets: s, Audit: audit.New(e.clk.Now), Now: e.clk.Now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(t.Context(), e.db.Reader(), id, "core_sensor_ca"); !errors.Is(err, secrets.ErrRestricted) {
		t.Errorf("secrets.Store.Open of the CA key = %v, want ErrRestricted", err)
	}
	// L4: the purpose is closed from the start of the process (pki reserves it in an init function), so a store that never ran
	// pki.Open refuses it as well
	fresh, _ := secrets.New(masterKey)
	if _, err := fresh.Open(t.Context(), e.db.Reader(), id, "core_sensor_ca"); !errors.Is(err, secrets.ErrRestricted) {
		t.Errorf("Open of the CA key on a store that never ran pki.Open = %v, want ErrRestricted", err)
	}
	// the purpose can be restricted once per store: a second Open on it is an error, not a second reader
	if _, err := pki.Open(t.Context(), pki.Options{DB: e.db, Secrets: s, Audit: audit.New(e.clk.Now), Now: e.clk.Now}); err == nil {
		t.Error("a second pki.Open on the same secrets.Store succeeded")
	}
}

// Two starts at the same moment with no CA yet end with one CA.
func TestCAFirstUseRace(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var wg sync.WaitGroup
	pems := make([][]byte, 4)
	for i := range pems {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a, err := e.tryOpen(masterKey); err == nil {
				pems[i] = a.CACertPEM()
			}
		}()
	}
	wg.Wait()
	for i, p := range pems {
		if p == nil || !bytes.Equal(p, pems[0]) {
			t.Fatalf("start %d got a different CA or failed", i)
		}
	}
}

// D-110 (1), spec section 4, core INV-24 (M2 of the SP-1 review): a restore without master.key (or a master.key made again)
// leaves a CA row sealed under a key the box does not have. pki.Open replaces it with a new CA and retires the live leaves of the
// old one; Start writes new bundles; the old CA's certificates no longer get in.
func TestLostMasterKeyGivesANewCA(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old := e.open(t)
	if err := old.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	oldCA := old.CACertPEM()
	oldBundle := e.bundle(t, sensorlink.Passive)

	a, err := e.tryOpen(bytes.Repeat([]byte{1}, secrets.KeySize)) // the box's key is not the one that sealed the CA
	if err != nil {
		t.Fatalf("pki.Open with another master key = %v; want a new CA (and new leaves at Start)", err)
	}
	if bytes.Equal(a.CACertPEM(), oldCA) {
		t.Fatal("the old CA came back under another master key")
	}
	if a.SerialValid(sensorlink.Passive, oldBundle.Leaf.SerialNumber) {
		t.Error("a leaf of the old CA is still a live serial")
	}
	for _, r := range e.rows(t, sensorlink.Passive) {
		if r.retired == nil {
			t.Errorf("serial %s of the old CA was not retired", r.serial)
		}
	}
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	b := e.bundle(t, sensorlink.Passive)
	if !bytes.Equal(b.CA.Raw, pemDecode(a.CACertPEM())) {
		t.Error("the new bundle does not carry the new CA")
	}
	if err := b.Leaf.CheckSignatureFrom(b.CA); err != nil {
		t.Errorf("the new leaf is not signed by the new CA: %v", err)
	}
	if _, err := oldBundle.Leaf.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("a leaf of the old CA chains to the new CA's pool")
	}
	var n int
	_ = e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_secret WHERE purpose = 'core_sensor_ca'`).Scan(&n)
	if n != 1 {
		t.Errorf("%d CA rows after a replacement, want the one row replaced", n)
	}
	rows := e.auditRows(t)
	if countPrefix(rows, "sensor-ca.create ") != 1 || countPrefix(rows, "sensor-ca.replace sensor-ca reason=cannot_decrypt") != 1 {
		t.Errorf("audit rows = %q", rows)
	}
	if !strings.Contains(e.log.String(), "sensor_ca_replaced") || !strings.Contains(e.log.String(), "cannot_decrypt") {
		t.Errorf("no warning in the log: %s", e.log.String())
	}
}

// M2: a CA that is expired, not yet valid or damaged is replaced too, and each says why in the audit row. A failure of the
// database is not one of these (the CA is never thrown away for it).
func TestACAThatCannotBeUsedIsReplaced(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, reason string
		spoil        func(t *testing.T, e *env)
	}{
		{"expired", "expired", func(_ *testing.T, e *env) { e.clk.Advance(11 * 365 * 24 * time.Hour) }},
		{"not yet valid", "not_yet_valid", func(_ *testing.T, e *env) { e.clk.Advance(-time.Hour) }}, // the clock went back: NotBefore is an hour ahead
		{"damaged", "damaged", func(t *testing.T, e *env) {
			s, _ := secrets.New(masterKey)
			var id string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM core_secret WHERE purpose = 'core_sensor_ca'`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
				_, err := s.Replace(t.Context(), tx, id, "core_sensor_ca", []byte("not a pem"), false)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			a := e.open(t)
			if err := a.Start(t.Context(), e.dir); err != nil {
				t.Fatal(err)
			}
			old := a.CACertPEM()
			c.spoil(t, e)
			b, err := e.tryOpen(masterKey)
			if err != nil {
				t.Fatalf("Open = %v, want a replacement", err)
			}
			if bytes.Equal(b.CACertPEM(), old) {
				t.Error("the CA was not replaced")
			}
			if rows := e.auditRows(t); countPrefix(rows, "sensor-ca.replace sensor-ca reason="+c.reason) != 1 {
				t.Errorf("audit rows = %q", rows)
			}
			if err := b.Start(t.Context(), e.dir); err != nil {
				t.Fatal(err)
			}
			if _, err := e.bundle(t, sensorlink.Active).Leaf.Verify(x509.VerifyOptions{Roots: b.ClientCAs(), CurrentTime: e.clk.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Errorf("the new bundle does not chain to the new CA: %v", err)
			}
			// and a CA that works is left alone
			if c2, err := e.tryOpen(masterKey); err != nil || !bytes.Equal(c2.CACertPEM(), b.CACertPEM()) {
				t.Errorf("a usable CA was replaced again: %v", err)
			}
		})
	}
}

// M3 of the SP-1 review, SYS-3 and spec section 11: every change the CA makes is a core_audit row, actor system, in the
// transaction of the change; no row or log line holds key material.
func TestEveryPKIChangeIsAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	for range 3 { // three issues per role: the third retires the first serial of each
		if err := a.Start(t.Context(), e.dir); err != nil {
			t.Fatal(err)
		}
	}
	rows := e.auditRows(t)
	if countPrefix(rows, "sensor-ca.create sensor-ca ") != 1 {
		t.Errorf("CA create rows: %q", rows)
	}
	if n := countPrefix(rows, "sensor-cert.issue "); n != 6 {
		t.Errorf("%d issue rows, want 6 (3 per role): %q", n, rows)
	}
	if n := countPrefix(rows, "sensor-cert.retire "); n != 2 {
		t.Errorf("%d retire rows, want 2 (the first serial of each role): %q", n, rows)
	}
	for _, role := range sensorlink.Roles {
		r := e.rows(t, role)
		want := "sensor-cert.issue " + string(role) + " serial=" + r[2].serial + " not_after=" + r[2].notAfter
		if !slices.Contains(rows, want) {
			t.Errorf("no issue row %q in %q", want, rows)
		}
		if want := "sensor-cert.retire " + string(role) + " serial=" + r[0].serial; !slices.Contains(rows, want) {
			t.Errorf("no retire row %q in %q", want, rows)
		}
	}
	// the audit chain still verifies, and nothing in it or in the log is key material
	if res, err := audit.Verify(t.Context(), e.db.Reader()); err != nil || res.BrokenAt != 0 {
		t.Errorf("audit chain: %v %+v", err, res)
	}
	var all strings.Builder
	all.WriteString(e.log.String())
	for _, r := range rows {
		all.WriteString(r)
	}
	for _, bad := range []string{"PRIVATE KEY", "BEGIN", "MIG", "master"} {
		if strings.Contains(all.String(), bad) {
			t.Errorf("audit or log text contains %q", bad)
		}
	}
}

// D-110 (2): the shape of every certificate.
func TestLeafCertificates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	for _, role := range sensorlink.Roles {
		bu := e.bundle(t, role)
		leaf := bu.Leaf
		got, err := sensorlink.ClientRole(leaf)
		if err != nil || got != role {
			t.Errorf("%s: role %q %v", role, got, err)
		}
		if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "vedette:sensor:"+string(role) ||
			len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || leaf.IsCA {
			t.Errorf("%s: leaf = EKU %v URIs %v DNS %v IP %v CA %v", role, leaf.ExtKeyUsage, leaf.URIs, leaf.DNSNames, leaf.IPAddresses, leaf.IsCA)
		}
		if d := leaf.NotAfter.Sub(t0); d != pki.LeafLifetime {
			t.Errorf("%s: ends %v from now, want 7 days", role, d)
		}
		if leaf.NotBefore.After(t0) || t0.Sub(leaf.NotBefore) > 5*time.Minute {
			t.Errorf("%s: NotBefore %v", role, leaf.NotBefore)
		}
		if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
			t.Errorf("%s: key is not P-256", role)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("%s: does not chain to the CA: %v", role, err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Errorf("%s: a sensor leaf can be a server", role)
		}
		if !bu.CA.Equal(mustCA(t, a)) {
			t.Errorf("%s: the CA in the bundle is not the CA", role)
		}
	}
	// the server leaf
	sc, err := a.ServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := sc.Leaf
	if len(srv.ExtKeyUsage) != 1 || srv.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(srv.URIs) != 0 || len(srv.DNSNames) != 1 || srv.DNSNames[0] != "core" ||
		len(srv.IPAddresses) != 1 || !srv.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("server leaf = EKU %v URIs %v DNS %v IP %v", srv.ExtKeyUsage, srv.URIs, srv.DNSNames, srv.IPAddresses)
	}
	for _, name := range []string{"core", "127.0.0.1"} {
		if _, err := srv.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), CurrentTime: t0, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("server leaf for %s: %v", name, err)
		}
	}
	if _, err := srv.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("the server leaf can be a client")
	}
	// the files: 0640, and no CA key anywhere in them
	for _, role := range sensorlink.Roles {
		p := filepath.Join(e.dir, string(role), pki.BundleName)
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
		b, _ := readFile(p)
		if strings.Count(string(b), "PRIVATE KEY") != 2 { // BEGIN and END of the one leaf key
			t.Errorf("%s holds %d PRIVATE KEY markers, want one key", p, strings.Count(string(b), "PRIVATE KEY")/2)
		}
	}
}

func mustCA(t *testing.T, a *pki.Authority) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(pemDecode(a.CACertPEM()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// D-110 (2)(5): every serial is recorded; the current and the previous one are live, older ones are retired with a time, and
// that survives a restart.
func TestSerialTable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	var serials []string
	for i := range 3 {
		if err := a.Start(t.Context(), e.dir); err != nil {
			t.Fatal(err)
		}
		serials = append(serials, e.bundle(t, sensorlink.Passive).Leaf.SerialNumber.Text(16))
		if i < 2 {
			e.clk.Advance(time.Hour)
		}
	}
	rows := e.rows(t, sensorlink.Passive)
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	for i, r := range rows {
		if r.serial != serials[i] || r.role != "passive" {
			t.Errorf("row %d = %+v, want serial %s", i, r, serials[i])
		}
	}
	if rows[0].retired == nil || *rows[0].retired != store.FormatTS(t0.Add(2*time.Hour)) || rows[1].retired != nil || rows[2].retired != nil {
		t.Errorf("retired_at = %v %v %v; only the oldest is retired, at the time of the third issue", ptr(rows[0].retired), ptr(rows[1].retired), ptr(rows[2].retired))
	}
	if rows[2].notAfter != store.FormatTS(t0.Add(2*time.Hour+pki.LeafLifetime)) {
		t.Errorf("not_after = %s", rows[2].notAfter)
	}
	check := func(a *pki.Authority) {
		t.Helper()
		for i, want := range []bool{false, true, true} {
			if got := a.SerialValid(sensorlink.Passive, bigFromHex(t, serials[i])); got != want {
				t.Errorf("SerialValid(serial %d) = %v, want %v", i, got, want)
			}
		}
		if a.SerialValid(sensorlink.Active, bigFromHex(t, serials[2])) {
			t.Error("a passive serial is valid for the active role")
		}
		if a.SerialValid(sensorlink.Passive, bigFromHex(t, "1")) || a.SerialValid(sensorlink.Passive, nil) || a.SerialValid(sensorlink.Passive, bigFromHex(t, "0")) {
			t.Error("a serial that was never issued is valid")
		}
		if a.SerialValid("server", bigFromHex(t, serials[2])) {
			t.Error("an unknown role has valid serials")
		}
	}
	check(a)
	check(e.open(t)) // after a restart the table is what says which serials are live
	if len(e.rows(t, sensorlink.Active)) != 3 {
		t.Error("the active role was not issued alongside")
	}
}

func ptr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// D-110 (3): at start and daily, a leaf is replaced when a third of its life or less is left; otherwise nothing is touched.
func TestRenewal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	first := e.bundle(t, sensorlink.Passive).Leaf.SerialNumber
	firstActive := e.bundle(t, sensorlink.Active).Leaf.SerialNumber
	srv1, _ := a.ServerCertificate(nil)
	path := filepath.Join(e.dir, "passive", pki.BundleName)
	before, _ := os.Stat(path)

	e.clk.Advance(4 * 24 * time.Hour) // 3 days of 7 left: more than a third
	if err := a.Renew(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || len(e.rows(t, sensorlink.Passive)) != 1 {
		t.Error("Renew replaced a leaf that was not due")
	}
	if srv2, _ := a.ServerCertificate(nil); srv2 != srv1 {
		t.Error("Renew replaced a server leaf that was not due")
	}

	e.clk.Advance(24 * time.Hour) // 2 days left: a third is 2 days 8 hours
	if err := a.Renew(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	now := e.bundle(t, sensorlink.Passive).Leaf
	if now.SerialNumber.Cmp(first) == 0 || len(e.rows(t, sensorlink.Passive)) != 2 || e.bundle(t, sensorlink.Active).Leaf.SerialNumber.Cmp(firstActive) == 0 {
		t.Errorf("the leaves were not replaced when due")
	}
	if srv2, _ := a.ServerCertificate(nil); srv2 == srv1 || srv2.Leaf.NotAfter.Before(srv1.Leaf.NotAfter.Add(24*time.Hour)) {
		t.Error("the server leaf was not replaced when due")
	}
	if !a.SerialValid(sensorlink.Passive, first) || !a.SerialValid(sensorlink.Passive, now.SerialNumber) {
		t.Error("on rotation the previous serial must stay valid")
	}
	if now.NotAfter.Sub(e.clk.Now()) != pki.LeafLifetime {
		t.Errorf("the new leaf lives %v", now.NotAfter.Sub(e.clk.Now()))
	}
	// and right after, nothing is due again
	if err := a.Renew(t.Context(), e.dir); err != nil || len(e.rows(t, sensorlink.Passive)) != 2 {
		t.Errorf("a second Renew: %v, %d rows", err, len(e.rows(t, sensorlink.Passive)))
	}
	// a third rotation retires the first serial
	e.clk.Advance(5 * 24 * time.Hour)
	if err := a.Renew(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	if a.SerialValid(sensorlink.Passive, first) || len(e.rows(t, sensorlink.Passive)) != 3 || e.rows(t, sensorlink.Passive)[0].retired == nil {
		t.Error("the serial before the previous one is not retired")
	}
}

// A bundle that could not be written is kept in memory (it is the only copy of its key) and written by the next Renew, without
// issuing again.
func TestPendingBundleIsWrittenLater(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	elsewhere := t.TempDir()
	if err := os.MkdirAll(e.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(e.dir, "passive")); err != nil { // a planted link where the role dir goes
		t.Fatal(err)
	}
	err := a.Start(t.Context(), e.dir)
	if !errors.Is(err, pki.ErrCredsPath) {
		t.Fatalf("Start = %v, want ErrCredsPath", err)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Errorf("the writer wrote through the link: %v", ents)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "active", pki.BundleName)); err != nil {
		t.Errorf("the other role was not written: %v", err)
	}
	if err := os.Remove(filepath.Join(e.dir, "passive")); err != nil {
		t.Fatal(err)
	}
	if err := a.Renew(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	rows := e.rows(t, sensorlink.Passive)
	if len(rows) != 1 || e.bundle(t, sensorlink.Passive).Leaf.SerialNumber.Text(16) != rows[0].serial {
		t.Errorf("the pending bundle was not the one written: %d rows", len(rows))
	}
}

// stubBackend answers only heartbeats.
type stubBackend struct{ sensorlink.Backend }

const inst = "0123456789abcdef0123456789abcdef"

func (stubBackend) PassiveHeartbeat(context.Context, *sensorlink.PassiveHeartbeat) (string, error) {
	return inst, nil
}

// D-110 (4)(5), D-109 (2) with the real CA: certificates rotate without a restart of core or the sensor; the previous serial
// works until a second rotation; the serial before it is refused on a live connection and on a new one.
func TestRotationEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.open(t)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	srv, err := sensorlink.NewServer(sensorlink.Options{Identity: a, Backend: stubBackend{}, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.PeerCertificates[0].SerialNumber.Text(16))
		mu.Unlock()
		srv.Handler().ServeHTTP(w, r)
	}))
	cfg := srv.TLSConfig()
	first, _ := a.ServerCertificate(nil)
	cfg.Certificates = []tls.Certificate{*first} // httptest would add its own; production serves through GetCertificate
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)

	passivePath := filepath.Join(e.dir, "passive", pki.BundleName)
	c, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: ts.URL, CredsPath: passivePath, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	hb := func(cl *sensorlink.Client) error {
		_, err := cl.PassiveHeartbeat(t.Context(), &sensorlink.PassiveHeartbeat{Version: "1.0.0"})
		return err
	}
	if err := hb(c); err != nil {
		t.Fatal(err)
	}
	oldBundle, _ := readFile(passivePath)
	oldPath := filepath.Join(t.TempDir(), "old", "sensor.pem")
	if err := os.MkdirAll(filepath.Dir(oldPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(oldPath, oldBundle); err != nil {
		t.Fatal(err)
	}
	oldClient, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: ts.URL, CredsPath: oldPath, Now: e.clk.Now}) // never reloads: its file never changes
	if err != nil {
		t.Fatal(err)
	}
	if err := hb(oldClient); err != nil {
		t.Fatal(err)
	}

	// rotation 1: the daily job, no restart of anything
	e.clk.Advance(5 * 24 * time.Hour)
	if err := a.Renew(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	if err := hb(c); err != nil {
		t.Fatalf("the client after rotation: %v", err)
	}
	if err := hb(oldClient); err != nil {
		t.Fatalf("the previous serial must work until it is retired: %v", err)
	}
	// rotation 2 (a core restart): the serial of rotation 0 is retired
	e.clk.Advance(time.Hour)
	if err := a.Start(t.Context(), e.dir); err != nil {
		t.Fatal(err)
	}
	if err := hb(c); err != nil {
		t.Fatalf("the client after the second rotation: %v", err)
	}
	// the old client still holds a live connection: the serial check of the request refuses it (403 cert_retired) ...
	err = hb(oldClient)
	var we *sensorlink.Error
	if !errors.As(err, &we) || we.Code != sensorlink.CodeCertRetired {
		t.Fatalf("a retired serial on a live connection: %v, want 403 cert_retired (its certificate has two days left, so only the serial check stops it)", err)
	}
	// ... and a new connection with it does not get past the handshake
	fresh, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: ts.URL, CredsPath: oldPath, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := hb(fresh); err == nil {
		t.Fatal("a retired serial got through a new handshake")
	}
	mu.Lock()
	defer mu.Unlock()
	// old, old | new1 | old (previous serial) | new2 | old (refused per request); the refused handshake never reaches a handler
	if len(seen) != 6 || seen[0] != seen[1] || seen[0] != seen[3] || seen[0] != seen[5] || seen[2] == seen[0] || seen[4] == seen[2] || seen[4] == seen[0] {
		t.Errorf("serials seen by the server = %v", seen)
	}
}

func TestMigrationConstraints(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	good := `INSERT INTO core_sensor_cert (serial, role, not_after) VALUES (?, ?, '2026-11-17T08:00:00.000Z')`
	w := func(args ...any) error {
		return e.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), good, args...); return err })
	}
	if err := w("abc123", "passive"); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]any{"duplicate serial": {"abc123", "active"}, "unknown role": {"abc124", "server"}, "serial not hex": {"xyz", "active"}, "empty serial": {"", "active"}, "upper-case hex": {"ABC", "active"}} {
		if err := w(args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO core_sensor_cert (serial, role, not_after) VALUES ('d', 'active', 'tomorrow')`)
		return err
	})
	if err == nil {
		t.Error("a not_after that is not a timestamp was accepted")
	}
}

// the tests read and write files of their own temp directories
func readFile(p string) ([]byte, error) { return os.ReadFile(p) } //nolint:gosec // a path the test made

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }
