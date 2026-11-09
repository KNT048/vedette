// Package authtest builds a ready auth.Service for tests: a migrated SQLite database, a fake clock, a fake
// code mailer and cheap argon2 parameters.
package authtest

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// Password is the password of every user made by Env.User.
const Password = "correct horse battery staple"

// Cheap is what Config.Argon2 uses in tests: a real argon2id, just fast.
var Cheap = auth.Params{Memory: 64, Time: 1, Threads: 1}

// Clock is a manual clock. The zero time is 2026-11-09T08:00:00Z.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *Clock { return &Clock{t: time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)} }

// Now implements the Config.Clock function.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Mailer is a fake auth.CodeMailer that records what it was asked to send.
type Mailer struct {
	mu        sync.Mutex
	available bool
	failSend  bool
	sent      []Mail
}

// Mail is one message the fake mailer was given.
type Mail struct{ To, Code string }

// SetAvailable sets what Available reports.
func (m *Mailer) SetAvailable(v bool) { m.mu.Lock(); m.available = v; m.mu.Unlock() }

// FailSend makes SendCode fail.
func (m *Mailer) FailSend(v bool) { m.mu.Lock(); m.failSend = v; m.mu.Unlock() }

// Available implements auth.CodeMailer.
func (m *Mailer) Available(context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.available
}

// SendCode implements auth.CodeMailer.
func (m *Mailer) SendCode(_ context.Context, to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSend {
		return errors.New("smtp: connection refused")
	}
	m.sent = append(m.sent, Mail{To: to, Code: code})
	return nil
}

// Sent returns every message so far.
func (m *Mailer) Sent() []Mail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Mail(nil), m.sent...)
}

// LastCode returns the code of the newest message ("" when none).
func (m *Mailer) LastCode() string {
	s := m.Sent()
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1].Code
}

// Env is one test world.
type Env struct {
	Svc     *auth.Service
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Clock   *Clock
	Mailer  *Mailer
	Logs    *bytes.Buffer
}

// New builds an Env with the email channel available. modify, when given, may change the Config before
// the Service is built (for example MaxHashing).
func New(t testing.TB, modify ...func(*auth.Config)) *Env {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", os.DirFS(migrationsDir(t))); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(bytes.Repeat([]byte{9}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	clock := newClock()
	logs := &bytes.Buffer{}
	mailer := &Mailer{available: true}
	al := audit.New(clock.Now)
	// MaxHashing is fixed so a test does not depend on the CPUs of the machine running it: the default is half
	// the CPUs, which is one slot on a 2-3 CPU laptop, where a test that hashes while another hash is running
	// would wait HashWait and get 503 (issue #70). Tests of the gate itself set their own value.
	cfg := auth.Config{DB: db, Secrets: sec, Audit: al, Mailer: mailer, Clock: clock.Now, Log: slog.New(slog.NewTextHandler(logs, nil)), Argon2: Cheap, MaxHashing: 4}
	for _, m := range modify {
		m(&cfg)
	}
	svc, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{Svc: svc, DB: db, Secrets: sec, Audit: al, Clock: clock, Mailer: mailer, Logs: logs}
}

// User creates an account with Password and returns it.
func (e *Env) User(t testing.TB, email string, role routes.Role) auth.User {
	t.Helper()
	hash, err := e.Svc.HashPassword(t.Context(), Password, email)
	if err != nil {
		t.Fatal(err)
	}
	var u auth.User
	err = e.DB.Write(t.Context(), func(tx *sql.Tx) (err error) {
		u, err = e.Svc.CreateUser(t.Context(), tx, "system", auth.NewUser{Name: "Test " + email, Email: email, Role: role, PasswordHash: hash})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Login signs in with Password from 192.0.2.1 and returns the result.
func (e *Env) Login(t testing.TB, email, code string) (auth.LoginResult, error) {
	t.Helper()
	return e.Svc.Login(t.Context(), auth.LoginRequest{Email: email, Password: Password, Code: code, IP: netip.MustParseAddr("192.0.2.1"), UserAgent: "authtest"})
}

// Count runs a SELECT count(*) query.
func (e *Env) Count(t testing.TB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.DB.Reader().QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// migrationsDir finds modules/core/migrations/sqlite from this file's location: core must not import
// modules/core (dependency direction is module -> core), so the SQL files are read from disk.
func migrationsDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("authtest: cannot locate the source tree")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "modules", "core", "migrations", "sqlite")
}
