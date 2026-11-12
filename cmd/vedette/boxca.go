package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// The box CA (WP-26 slice 1, D-262): a CA of its own, never the 8443 leaf (Firefox refuses a CA certificate as the server's
// end-entity certificate), signs the self-made leaf, so an agent that pins the CA (GET /intake/ca.pem) keeps trusting the box
// through every leaf re-issue (D-139). Made once, never rotated by a renewal; only an expired CA, or one that cannot cover a new
// leaf, is replaced.
//
// Its key and certificate are one core_secret row of purpose core_box_ca (D-351): vedette.db and vedette.key carry it, so a backup
// restored with its master key keeps every enrolment, and the JSON export never holds it (core_secret is skipAll). Reading the
// purpose is restricted to boxCAStore. A box from before D-351 had the pair as two files next to the leaf: they are sealed once
// and removed, so no plaintext CA key stays on disk.
const (
	boxCALifetime = 20 * 365 * 24 * time.Hour
	boxCAName     = "vedette-selfsigned-ca"
	// boxCAPurpose is the core_secret purpose of the box CA. Only this file names it.
	boxCAPurpose = "core_box_ca"
)

func init() { secrets.Reserve(boxCAPurpose) } // closed to Store.Open from the start of the process; boxCAStore holds the Opener

// boxCA is the box CA: its certificate and key.
type boxCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// boxCAStore keeps the box CA in core_secret. One per process (it restricts the purpose on its secrets.Store).
type boxCAStore struct {
	db  *store.DB
	sec *secrets.Store
	op  *secrets.Opener
	aud *audit.Log
	// legacyCrt and legacyKey are the files of a box before D-351, next to the leaf: read only while nothing is sealed.
	legacyCrt, legacyKey string

	mu    sync.Mutex
	cur   *boxCA // the CA the last ensure returned (GET /intake/ca.pem)
	swept bool   // leftover legacy files were removed (or that failed and was logged) once in this process
}

// newBoxCAStore restricts the purpose on sec and returns the store; dataDir is the directory of the database and of the leaf.
func newBoxCAStore(db *store.DB, sec *secrets.Store, aud *audit.Log, dataDir string) (*boxCAStore, error) {
	op, err := sec.Restrict(boxCAPurpose)
	if err != nil {
		return nil, fmt.Errorf("tls: box CA: %w", err)
	}
	return &boxCAStore{db: db, sec: sec, op: op, aud: aud,
		legacyCrt: filepath.Join(dataDir, boxCAName+".crt"), legacyKey: filepath.Join(dataDir, boxCAName+".key")}, nil
}

// notSignedBy reports whether leaf does not chain to ca (an old self-signed leaf, or a CA that was replaced).
func notSignedBy(leaf *x509.Certificate, ca *boxCA) bool {
	return leaf.CheckSignatureFrom(ca.cert) != nil
}

// sealedCA is what core_secret holds for the purpose.
type sealedCA struct {
	id     string // the row read ("" when no row decrypts under this master key)
	ca     *boxCA // set when the row can be used
	reason string // why there is no usable CA: cannot_decrypt (rows exist, none decrypts), damaged, expiring
}

// read looks at the sealed CA rows, newest first, and takes the first that decrypts under this master key. A row that does not
// decrypt (a wrong or regenerated master key) is never overwritten (M1): a new CA is sealed in a row of its own, and putting the
// right key back finds the old CA again, since the newer row does not decrypt under it. A row that decrypts but does not parse or
// cannot cover a new leaf is replaced in place. Only a database failure is an error.
func (s *boxCAStore) read(ctx context.Context, q coredb.DBTX, now time.Time) (sealedCA, error) {
	// ponytail: a hand-written query (sqlc's GetSecretIDByPurpose takes the oldest row); move it to core/store/queries if a second caller needs it.
	rows, err := q.QueryContext(ctx, `SELECT id FROM core_secret WHERE purpose = ? ORDER BY created_at DESC, id DESC`, boxCAPurpose)
	if err != nil {
		return sealedCA{}, fmt.Errorf("tls: box CA: find: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return sealedCA{}, fmt.Errorf("tls: box CA: find: %w", err)
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return sealedCA{}, fmt.Errorf("tls: box CA: find: %w", err)
	}
	for _, id := range ids {
		plain, err := s.op.Open(ctx, q, id)
		switch {
		case errors.Is(err, secrets.ErrDecrypt):
			continue
		case err != nil:
			return sealedCA{}, fmt.Errorf("tls: box CA: %w", err)
		}
		ca, err := parseBoxCA(plain, plain)
		switch {
		case err != nil:
			return sealedCA{id: id, reason: "damaged"}, nil
		case ca.cert.NotAfter.Sub(now) <= selfSignedLifetime:
			return sealedCA{id: id, reason: "expiring"}, nil
		}
		return sealedCA{id: id, ca: ca}, nil
	}
	if len(ids) > 0 {
		return sealedCA{reason: "cannot_decrypt"}, nil
	}
	return sealedCA{}, nil
}

// ensure returns the box CA: the sealed one; else the legacy files, sealed once (migrate); else a new one, sealed. When no sealed
// CA can be used (none decrypts under this master key; or the newest that does is damaged or expires within selfSignedLifetime) a
// new CA is made, with one ERROR on log and an audit row box-ca.replace that the audit list shows to administrators: the leaf
// follows at its next check, and enrolled agents must enrol again. A damaged or expiring row is overwritten; rows that do not
// decrypt are kept (read). Legacy files that cannot be used are moved aside as *.quarantine-<unix> (the purge sweeps those). A
// read error on the legacy files that is not "does not exist" (EMFILE, EIO, EACCES) says nothing about them: with mustHave false
// it is returned and nothing changes (callers keep serving a valid leaf); with mustHave true the files are replaced. Every change
// is an audit row (box-ca.create, box-ca.migrate, box-ca.replace; actor system); no key or PEM is ever logged.
func (s *boxCAStore) ensure(ctx context.Context, now time.Time, log *slog.Logger, mustHave bool) (*boxCA, error) {
	if log == nil {
		log = slog.Default()
	}
	st, err := s.read(ctx, s.db.Reader(), now)
	if err != nil {
		return nil, err
	}
	if st.ca != nil {
		s.keep(ctx, st.ca, log)
		return st.ca, nil
	}
	var (
		out    *boxCA
		event  string // the audit action: box-ca.create, box-ca.migrate, box-ca.replace
		why    string // the reason a CA was replaced (sealed or legacy)
		legacy legacyCA
	)
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		out, event, why, legacy = nil, "", "", legacyCA{}
		st, err := s.read(ctx, tx, now)
		if err != nil {
			return err
		}
		if st.ca != nil { // another caller sealed it between our read and this transaction
			out = st.ca
			return nil
		}
		var plain []byte
		why = st.reason
		if st.id == "" { // no row this key can use: the legacy files, if any
			if legacy, err = s.readLegacy(mustHave); err != nil {
				return err
			}
			if legacy.ca != nil && legacy.ca.cert.NotAfter.Sub(now) > selfSignedLifetime {
				out, plain, event = legacy.ca, legacy.pem, "box-ca.migrate"
			} else if legacy.ca != nil {
				legacy.reason = "it is about to expire"
			}
			if legacy.reason != "" {
				why = legacy.reason
			}
		}
		if out == nil {
			if out, plain, err = newBoxCA(now); err != nil {
				return err
			}
			event = "box-ca.create"
			if st.reason != "" {
				event = "box-ca.replace"
			}
		}
		if st.id != "" {
			_, err = s.sec.Replace(ctx, tx, st.id, boxCAPurpose, plain, false)
		} else {
			_, _, err = s.sec.Seal(ctx, tx, boxCAPurpose, plain, false)
		}
		if err != nil {
			return fmt.Errorf("tls: seal the box CA: %w", err)
		}
		detail := "ecdsa-p256 serial=" + out.cert.SerialNumber.Text(16)
		if why != "" {
			detail += " reason=" + why
		}
		if err := s.aud.Append(ctx, tx, audit.Entry{User: "system", Action: event, Target: "box-ca", Detail: detail}); err != nil {
			return fmt.Errorf("tls: box CA: audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if event == "box-ca.migrate" {
		log.InfoContext(ctx, "the box CA was moved into the database (core_secret, D-351); its files are removed")
	}
	switch {
	case why != "" && event == "box-ca.migrate": // the sealed CA does not decrypt, but the old files hold a CA that does
		log.ErrorContext(ctx, "the box CA in the database does not decrypt with this master key; the CA of the old files is used instead: agents enrolled after it was moved into the database must run the install command again, or put the right vedette.key back",
			"reason", why)
	case why != "": // a sealed or legacy CA that could not be kept
		if legacy.found {
			s.quarantineLegacy(ctx, now, log)
		}
		log.ErrorContext(ctx, "the box CA could not be kept and was replaced; enrolled agents must run the install command again", "reason", why)
	}
	s.keep(ctx, out, log)
	return out, nil
}

// keep remembers ca for current and, once per process, removes the legacy files a sealed CA makes useless: the copy that was just
// migrated, a key left alone by an interrupted first start before D-351, or a crash between the migration's commit and its removal.
func (s *boxCAStore) keep(ctx context.Context, ca *boxCA, log *slog.Logger) {
	s.mu.Lock()
	s.cur = ca
	sweep := !s.swept
	s.swept = true
	s.mu.Unlock()
	if !sweep {
		return
	}
	for _, p := range []string{s.legacyKey, s.legacyCrt} { // the key first: no plaintext key is left even if the second remove fails
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.WarnContext(ctx, "an old box CA file could not be removed; the CA in the database is the one in use", "file", filepath.Base(p), "error", err)
		}
	}
}

// current is the CA the last ensure returned (ensure when there is none yet).
func (s *boxCAStore) current(ctx context.Context) (*boxCA, error) {
	s.mu.Lock()
	ca := s.cur
	s.mu.Unlock()
	if ca != nil {
		return ca, nil
	}
	return s.ensure(ctx, time.Now(), nil, false)
}

// migrateLegacy seals the legacy files of a box before D-351 and removes them, whatever the TLS mode (L1): a box on -tls-cert or on
// loopback HTTP, which never asks for the CA, must not keep a plaintext CA key on disk either. A key alone (an interrupted first
// start before D-351) is removed. Nothing is made when there are no files.
func (s *boxCAStore) migrateLegacy(ctx context.Context, log *slog.Logger) error {
	if _, err := os.Lstat(s.legacyCrt); err == nil {
		_, err := s.ensure(ctx, time.Now(), log, false)
		return err
	}
	if err := os.Remove(s.legacyKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tls: box CA: %w", err)
	}
	return nil
}

// legacyCA is what the files of a box before D-351 hold.
type legacyCA struct {
	found  bool   // the certificate file exists
	ca     *boxCA // the pair, when it loads
	pem    []byte // key then certificate, as sealed
	reason string // why the pair cannot be used
}

// errCAUnreadable marks a read or stat error on the legacy files other than "does not exist" (EMFILE, EIO, EACCES): the files
// may be fine, so nothing is moved aside because of it (M-1).
var errCAUnreadable = errors.New("the box CA files could not be read")

// readLegacy reads the legacy pair. A key without its certificate (an interrupted first start) counts as no pair: keep removes it.
// The error is errCAUnreadable with mustHave false, or a stat error on the certificate file.
func (s *boxCAStore) readLegacy(mustHave bool) (legacyCA, error) {
	if _, err := os.Lstat(s.legacyCrt); errors.Is(err, fs.ErrNotExist) {
		return legacyCA{}, nil
	} else if err != nil {
		return legacyCA{}, fmt.Errorf("tls: box CA: %w", err)
	}
	ca, plain, err := loadLegacyBoxCA(s.legacyCrt, s.legacyKey)
	switch {
	case err == nil:
		return legacyCA{found: true, ca: ca, pem: plain}, nil
	case errors.Is(err, errCAUnreadable) && !mustHave:
		return legacyCA{}, err // maybe passing (EMFILE, EIO): move nothing; callers keep serving a valid leaf
	}
	return legacyCA{found: true, reason: err.Error()}, nil
}

// loadLegacyBoxCA reads the legacy pair and says why it cannot be used: key missing or with a mode wider than 0600, files that
// hold no PEM, do not parse or match, a certificate that is not a CA. A read or stat error that is not "does not exist" wraps
// errCAUnreadable instead: that says nothing about the files.
func loadLegacyBoxCA(crtPath, keyPath string) (*boxCA, []byte, error) {
	if _, err := os.Stat(keyPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: %w", errCAUnreadable, err)
	}
	if err := checkKeyFile(keyPath); err != nil {
		return nil, nil, err
	}
	var files [2][]byte
	for i, p := range []string{crtPath, keyPath} {
		b, err := os.ReadFile(p) //nolint:gosec // the legacy CA files in the data directory
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("%w: %w", errCAUnreadable, err)
		}
		files[i] = b
	}
	ca, err := parseBoxCA(files[0], files[1])
	if err != nil {
		return nil, nil, err
	}
	return ca, append(append([]byte(nil), files[1]...), files[0]...), nil
}

// quarantineLegacy moves the legacy files aside (the certificate first: a crash between the two renames leaves a key alone, which
// keep removes) and makes the key 0600: it may have been moved because others could read it. A failure is logged: the new CA is
// sealed already, and keep removes what is left.
func (s *boxCAStore) quarantineLegacy(ctx context.Context, now time.Time, log *slog.Logger) {
	stamp := ".quarantine-" + strconv.FormatInt(now.Unix(), 10)
	for _, p := range []string{s.legacyCrt, s.legacyKey} {
		if err := os.Rename(p, p+stamp); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.WarnContext(ctx, "an old box CA file could not be moved aside", "file", filepath.Base(p), "error", err)
		}
	}
	_ = os.Chmod(s.legacyKey+stamp, 0o600)
}

// parseBoxCA reads a CA pair from PEM (the first certificate of certPEM, the first private key of keyPEM; the sealed row holds
// both in one text, passed twice).
func parseBoxCA(certPEM, keyPEM []byte) (*boxCA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err //nolint:wrapcheck // the reason is logged and audited as is
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if err != nil || !ok || !cert.IsCA {
		return nil, errors.New("not a CA certificate with its key")
	}
	return &boxCA{cert: cert, key: signer}, nil
}

// newBoxCA makes a CA and returns it with its key and certificate as one PEM text (what is sealed). The subject's organization marks
// it as this program's; the organizational unit is the start of the SHA-256 of its public key, so two boxes' CAs are told apart in
// a trust store (L-2).
func newBoxCA(now time.Time) (*boxCA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("tls: serial: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("tls: encode CA public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Vedette box CA", Organization: []string{selfSignedOrg}, OrganizationalUnit: []string{"box " + hex.EncodeToString(sum[:8])}},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(boxCALifetime),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: parse CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: encode CA key: %w", err)
	}
	plain := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return &boxCA{cert: cert, key: key}, plain, nil
}

// trustAnchorRetry is the Retry-After (seconds) of a /intake/ca.pem refused while the leaf is re-issued under a new CA.
const trustAnchorRetry = 30

// intakeTrustAnchor is the box CA that GET /intake/ca.pem and the install scripts pin for the box's own pair (agent-intake INV-11): its
// certificate, only while the leaf in use is signed by it (L3: a CA replaced while the new leaf could not be written is not handed out:
// 503 server_busy with Retry-After, never logged per request, and the renewer is asked to check now); nil when the box serves no TLS
// (loopback). An owner's -tls-cert never comes here (cmd/vedette trustAnchor reads it).
func intakeTrustAnchor(cfg *tls.Config, ca *boxCAStore, renew *selfSignedRenewer) func(context.Context) ([]byte, error) {
	if cfg == nil {
		return nil
	}
	return func(ctx context.Context) ([]byte, error) {
		c, err := ca.current(ctx)
		if err != nil {
			return nil, err
		}
		if leaf, err := renew.leaf(); err != nil || notSignedBy(leaf, c) {
			renew.Kick() // the check re-issues the leaf soon (at most once per addrSyncGap); it logs its own failure
			return nil, apierr.New(http.StatusServiceUnavailable, "server_busy", "The box certificate is being renewed. Try again in a minute.").
				With("retry_after", trustAnchorRetry)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}), nil
	}
}
