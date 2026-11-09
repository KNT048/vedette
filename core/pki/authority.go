package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

const (
	// LeafLifetime is the life of every leaf (D-110 (3)): short, so that a stolen certificate ends by itself.
	LeafLifetime = 7 * 24 * time.Hour
	// RenewBefore is how little lifetime may be left before a leaf is replaced: a third.
	RenewBefore = LeafLifetime / 3
	// live is how many serials of a role are accepted at once: the current one and the one before it.
	live = 2
)

// Options configures an Authority.
type Options struct {
	DB      *store.DB
	Secrets *secrets.Store
	// Now is the clock for the validity of certificates and for the renewal test. nil means time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// Authority is the CA, the server leaf and the table of live serials of the sensor link.
type Authority struct {
	db  *store.DB
	sec *secrets.Store
	now func() time.Time
	log *slog.Logger
	ca  *ca

	mu       sync.RWMutex
	srv      *tls.Certificate
	liveSN   map[sensorlink.Role][]string // newest first, at most live
	notAfter map[sensorlink.Role]time.Time
	pending  map[sensorlink.Role][]byte // a bundle issued but not yet written (the key exists only here)
}

var _ sensorlink.Identity = (*Authority)(nil)

// Open restricts the CA purpose in the secrets store, loads the CA (making it the first time) and reads the live serials.
// It can be called once per secrets.Store: that is what makes this package the only reader of the CA key.
func Open(ctx context.Context, o Options) (*Authority, error) {
	if o.DB == nil || o.Secrets == nil {
		return nil, errors.New("pki: Open needs a database and a secrets store")
	}
	a := &Authority{
		db: o.DB, sec: o.Secrets, now: o.Now, log: o.Log,
		liveSN: map[sensorlink.Role][]string{}, notAfter: map[sensorlink.Role]time.Time{}, pending: map[sensorlink.Role][]byte{},
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	op, err := o.Secrets.Restrict(caPurpose)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	if a.ca, err = a.loadOrCreateCA(ctx, op); err != nil {
		return nil, err
	}
	for _, r := range sensorlink.Roles {
		rows, err := coredb.New(a.db.Reader()).ListLiveSensorCerts(ctx, string(r))
		if err != nil {
			return nil, fmt.Errorf("pki: read live serials: %w", err)
		}
		for _, row := range rows[:min(len(rows), live)] {
			a.liveSN[r] = append(a.liveSN[r], row.Serial)
		}
	}
	return a, nil
}

// CACertPEM is the CA certificate, for tests and for the bundles.
func (a *Authority) CACertPEM() []byte { return certPEM(a.ca.cert.Raw) }

// ClientCAs is the pool a sensor certificate must chain to: the sensor CA and nothing else.
func (a *Authority) ClientCAs() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.ca.cert)
	return p
}

// ServerCertificate returns the current server leaf (tls.Config.GetCertificate). Start must have run.
func (a *Authority) ServerCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.srv == nil {
		return nil, errors.New("pki: no server certificate yet")
	}
	return a.srv, nil
}

// SerialValid reports whether serial is the current or the previous serial of role. It is a memory read: the server asks it
// on every request.
func (a *Authority) SerialValid(role sensorlink.Role, serial *big.Int) bool {
	if serial == nil || serial.Sign() <= 0 {
		return false
	}
	hex := serial.Text(16)
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, s := range a.liveSN[role] {
		if s == hex {
			return true
		}
	}
	return false
}

// issueClient makes a new leaf for role, records its serial, retires every serial of the role older than the previous one,
// and returns the bundle (key, leaf, CA).
func (a *Authority) issueClient(ctx context.Context, role sensorlink.Role) ([]byte, error) {
	if !role.Valid() {
		return nil, fmt.Errorf("pki: unknown role %q", role)
	}
	key, cert, err := a.signLeaf(clientTemplate(role))
	if err != nil {
		return nil, err
	}
	hex := cert.SerialNumber.Text(16)
	var liveNow []string
	err = a.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		if err := q.InsertSensorCert(ctx, coredb.InsertSensorCertParams{Serial: hex, Role: string(role), NotAfter: store.FormatTS(cert.NotAfter)}); err != nil {
			return fmt.Errorf("pki: record the serial: %w", err)
		}
		rows, err := q.ListLiveSensorCerts(ctx, string(role))
		if err != nil {
			return fmt.Errorf("pki: list live serials: %w", err)
		}
		now := store.FormatTS(a.now())
		liveNow = liveNow[:0]
		for i, row := range rows {
			if i < live {
				liveNow = append(liveNow, row.Serial)
				continue
			}
			if err := q.RetireSensorCert(ctx, coredb.RetireSensorCertParams{RetiredAt: &now, Serial: row.Serial}); err != nil {
				return fmt.Errorf("pki: retire a serial: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.liveSN[role] = liveNow
	a.notAfter[role] = cert.NotAfter
	a.mu.Unlock()
	return a.bundle(key, cert.Raw)
}

// issueServer makes the server leaf of the sensor listener (EKU serverAuth only; SAN 127.0.0.1 and core).
func (a *Authority) issueServer() error {
	key, cert, err := a.signLeaf(serverTemplate())
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.srv = &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	a.notAfter[serverKey] = cert.NotAfter
	a.mu.Unlock()
	return nil
}

// serverKey keys the server leaf in notAfter next to the two roles.
const serverKey sensorlink.Role = "server"

// Start makes the server leaf and a fresh leaf for each role and writes the two bundles into dir (<dir>/<role>/sensor.pem),
// before the listener opens (D-110 (4)). A start always issues: core never reads a bundle back, so it cannot know the key of
// the leaf it issued last time. The serial before stays valid, so a sensor that has not read the new file yet keeps working.
func (a *Authority) Start(ctx context.Context, dir string) error {
	if err := a.issueServer(); err != nil {
		return err
	}
	var errs []error
	for _, r := range sensorlink.Roles {
		errs = append(errs, a.renewRole(ctx, dir, r))
	}
	return errors.Join(errs...)
}

// Renew is the daily job (and the start-up check): it replaces the server leaf and the leaf of a role when a third of the
// lifetime or less is left, and writes again a bundle that could not be written before. Nothing happens when nothing is due.
// ponytail: called from a job once core wires the listener (SP-5); until then nothing calls it.
func (a *Authority) Renew(ctx context.Context, dir string) error {
	var errs []error
	if a.due(serverKey) {
		errs = append(errs, a.issueServer())
	}
	for _, r := range sensorlink.Roles {
		if a.due(r) || a.hasPending(r) {
			errs = append(errs, a.renewRole(ctx, dir, r))
		}
	}
	return errors.Join(errs...)
}

func (a *Authority) due(r sensorlink.Role) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	na, ok := a.notAfter[r]
	return !ok || na.Sub(a.now()) <= RenewBefore
}

func (a *Authority) hasPending(r sensorlink.Role) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pending[r] != nil
}

// renewRole writes the pending bundle of a role when there is one (the last issue could not be written), and issues a new one
// otherwise or when the leaf is due.
func (a *Authority) renewRole(ctx context.Context, dir string, r sensorlink.Role) error {
	a.mu.RLock()
	b := a.pending[r]
	a.mu.RUnlock()
	if b == nil || a.due(r) {
		var err error
		if b, err = a.issueClient(ctx, r); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.pending[r] = b
	a.mu.Unlock()
	if err := WriteBundle(dir, r, b); err != nil {
		a.log.ErrorContext(ctx, "sensor_creds_not_written", "role", string(r), "error", err)
		return err
	}
	a.mu.Lock()
	delete(a.pending, r)
	a.mu.Unlock()
	return nil
}
