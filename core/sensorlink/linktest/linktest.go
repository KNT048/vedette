// Package linktest runs the sensor link the way production does, for tests of the modules on either end: a real core/pki
// authority with an ephemeral CA, a sensorlink.Server over TLS 1.3 with mutual authentication (httptest), and credentials
// bundles written to disk for each role so a real sensorlink.Client connects. Nothing here is linked into a binary.
package linktest

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/pki"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store/storetest"
)

// Link is a running server and the credentials of the sensors that may talk to it.
type Link struct {
	URL       string // https://127.0.0.1:port
	Dir       string // the creds directory: <Dir>/<role>/sensor.pem
	Authority *pki.Authority
	Server    *httptest.Server
}

// New starts a server for backend. mut adjusts the server options (ModuleOn, Now, BodyTimeout). It closes with the test.
func New(t testing.TB, backend sensorlink.Backend, mut ...func(*sensorlink.Options)) *Link {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	migrations := filepath.Join(filepath.Dir(file), "../../../modules/core/migrations/sqlite")
	db := storetest.NewMigrated(t, "core", migrations)
	key := make([]byte, secrets.KeySize)
	for i := range key {
		key[i] = 7
	}
	sec, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := pki.Open(t.Context(), pki.Options{DB: db, Secrets: sec, Audit: audit.New(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "creds")
	if err := auth.Start(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	o := sensorlink.Options{Identity: auth, Backend: backend}
	for _, m := range mut {
		m(&o)
	}
	srv, err := sensorlink.NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	cfg := srv.TLSConfig()
	first, err := auth.ServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{*first} // httptest would add its own; production serves through GetCertificate
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &Link{URL: ts.URL, Dir: dir, Authority: auth, Server: ts}
}

// CredsPath is the bundle of a role.
func (l *Link) CredsPath(r sensorlink.Role) string {
	return filepath.Join(l.Dir, string(r), pki.BundleName)
}

// Client is a sensor of the role, connected with its own bundle.
func (l *Link) Client(t testing.TB, r sensorlink.Role) *sensorlink.Client {
	t.Helper()
	c, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: l.URL, CredsPath: l.CredsPath(r)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
