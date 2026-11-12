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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

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
	id     string // "" when there is no row
	ca     *boxCA // set when the row can be used
	reason string // why the row cannot be used: cannot_decrypt, damaged, expiring
}

// read looks at the sealed CA. Only a database failure is an error: a row that does not decrypt (another master key), does not
// parse or cannot cover a new leaf is a reason to replace it, like core/pki does for the sensor CA.
func (s *boxCAStore) read(ctx context.Context, q coredb.DBTX, now time.Time) (sealedCA, error) {
	id, err := coredb.New(q).GetSecretIDByPurpose(ctx, boxCAPurpose)
	if errors.Is(err, sql.ErrNoRows) {
		return sealedCA{}, nil
	}
	if err != nil {
		return sealedCA{}, fmt.Errorf("tls: box CA: find: %w", err)
	}
	plain, err := s.op.Open(ctx, q, id)
	switch {
	case errors.Is(err, secrets.ErrDecrypt):
		return sealedCA{id: id, reason: "cannot_decrypt"}, nil
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

// ensure returns the box CA: the sealed one; else the legacy files, sealed once (migrate); else a new one, sealed. A sealed CA that
// cannot be used (it does not decrypt under this master key, it is damaged, it expires within selfSignedLifetime) is replaced in
// the transaction that finds it, with one ERROR on log: the leaf follows at its next check, and enrolled agents must enrol again.
// Legacy files that cannot be used are moved aside as *.quarantine-<unix> (the purge sweeps those) and a new CA is made, with the
// same ERROR. A read error on the legacy files that is not "does not exist" (EMFILE, EIO, EACCES) says nothing about them: with
// mustHave false it is returned and nothing changes (callers keep serving a valid leaf); with mustHave true the files are replaced.
// Every change is an audit row (box-ca.create, box-ca.migrate, box-ca.replace; actor system); no key or PEM is ever logged.
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
		if st.id == "" {
			if legacy, err = s.readLegacy(mustHave); err != nil {
				return err
			}
			if legacy.ca != nil && legacy.ca.cert.NotAfter.Sub(now) > selfSignedLifetime {
				out, plain, event = legacy.ca, legacy.pem, "box-ca.migrate"
			} else if legacy.ca != nil {
				legacy.reason = "it is about to expire"
			}
			why = legacy.reason
		} else {
			why = st.reason
		}
		if out == nil {
			if out, plain, err = newBoxCA(now); err != nil {
				return err
			}
			event = "box-ca.create"
			if st.id != "" {
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
	switch {
	case event == "box-ca.migrate":
		log.InfoContext(ctx, "the box CA was moved into the database (core_secret, D-351); its files are removed")
	case why != "": // a sealed or legacy CA that could not be kept
		if legacy.found {
			s.quarantineLegacy(ctx, now, log)
		}
		log.ErrorContext(ctx, "the box CA could not be kept and was replaced; enrolled agents must run the install command again", "reason", why)
	}
	s.keep(ctx, out, log)
	return out, nil
}

// keep remembers ca for certPEM and, once per process, removes the legacy files a sealed CA makes useless: the copy that was just
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

// certPEM is the box CA's certificate, PEM (what GET /intake/ca.pem serves for the box's own pair). Never the key.
func (s *boxCAStore) certPEM(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	ca := s.cur
	s.mu.Unlock()
	if ca == nil {
		var err error
		if ca, err = s.ensure(ctx, time.Now(), nil, false); err != nil {
			return nil, err
		}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), nil
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

// intakeTrustAnchor is what GET /intake/ca.pem serves (agent-intake INV-11): the box CA's certificate for the box's own pair; for a
// certificate the owner supplied (-tls-cert), the file as supplied, read at each request (agent-intake keeps only its CERTIFICATE
// blocks: the chain, or the leaf alone; a key in the same file never leaves); nil when the box serves no TLS (loopback).
func intakeTrustAnchor(cfg *tls.Config, ownerCert string, ca *boxCAStore) func(context.Context) ([]byte, error) {
	switch {
	case cfg == nil:
		return nil
	case ownerCert != "":
		return func(context.Context) ([]byte, error) {
			b, err := os.ReadFile(ownerCert) //nolint:gosec // the -tls-cert path the owner configured
			if err != nil {
				return nil, fmt.Errorf("tls: trust anchor: %w", err)
			}
			return b, nil
		}
	}
	return ca.certPEM
}
