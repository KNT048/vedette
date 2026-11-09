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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{db: storetest.NewMigrated(t, "core", "../../modules/core/migrations/sqlite"), clk: newClock(), dir: filepath.Join(t.TempDir(), "creds")}
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
	return pki.Open(context.Background(), pki.Options{DB: e.db, Secrets: s, Now: e.clk.Now})
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
	if _, err := pki.Open(t.Context(), pki.Options{DB: e.db, Secrets: s, Now: e.clk.Now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(t.Context(), e.db.Reader(), id, "core_sensor_ca"); !errors.Is(err, secrets.ErrRestricted) {
		t.Errorf("secrets.Store.Open of the CA key = %v, want ErrRestricted", err)
	}
	// the purpose can be restricted once per store: a second Open on it is an error, not a second reader
	if _, err := pki.Open(t.Context(), pki.Options{DB: e.db, Secrets: s, Now: e.clk.Now}); err == nil {
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

// D-110 (1): without the master key the CA cannot be opened (the remedy is a restore that makes a new one), and a CA past its
// ten years is refused rather than used.
func TestCANotUsable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.open(t)
	if _, err := e.tryOpen(bytes.Repeat([]byte{1}, secrets.KeySize)); err == nil {
		t.Error("the CA opened with another master key")
	}
	e.clk.Advance(11 * 365 * 24 * time.Hour)
	if _, err := e.tryOpen(masterKey); !errors.Is(err, pki.ErrCA) {
		t.Errorf("an expired CA: %v, want ErrCA", err)
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
