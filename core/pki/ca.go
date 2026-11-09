// Package pki is the small certificate authority core runs for its own sensors (D-110): an ECDSA P-256 CA, the server leaf of
// the sensor listener, the 7-day client leaves of the two sensor roles, the table of live serials, renewal at a third of the
// lifetime left, and the writer that hands a role its bundle through a volume.
//
// The CA signs nothing else. It is not the certificate of the web UI on 8443 and it is not an osquery CA: a CA that browsers or
// LAN agents trust must not be able to mint a sensor identity. Its key is a core_secret row of purpose core_sensor_ca whose
// reading is restricted to this package (Open restricts the purpose; TestOnlyPKINamesTheCAPurpose scans the tree).
//
// Authority implements sensorlink.Identity. Leaf private keys exist in memory only long enough to be written to the bundle
// file; core never reads a bundle back (the D-89 pattern).
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

const (
	// caPurpose is the core_secret purpose of the CA key. Only this file names it.
	caPurpose  = "core_sensor_ca"
	caLifetime = 10 * 365 * 24 * time.Hour
	// skew is how far a certificate's NotBefore is set back, so a sensor whose clock is a little behind still accepts it.
	skew = time.Minute
)

func init() { secrets.Reserve(caPurpose) } // closed to Store.Open from the start of the process, before pki.Open has run

// ErrCA means the stored CA could not be used (damaged, expired or not yet valid). pki.Open does not fail on it: it makes a new
// CA in its place (D-110 (1)); the error is what openCA reports and what a caller sees when the replacement itself fails.
var ErrCA = errors.New("pki: the stored CA is not usable")

// caError says why a stored CA is unusable; it is ErrCA.
type caError struct{ reason string }

func (e *caError) Error() string        { return "pki: the stored CA is not usable: " + e.reason }
func (e *caError) Is(target error) bool { return target == ErrCA }

// unusable reports whether err means the CA row cannot be used and should be replaced (and why), as opposed to a failure of the
// database, which must not be answered by throwing a CA away.
func unusable(err error) (string, bool) {
	var ce *caError
	switch {
	case errors.As(err, &ce):
		return ce.reason, true
	case errors.Is(err, secrets.ErrDecrypt):
		return "cannot_decrypt", true // a master.key that is not the one that sealed it (lost, or a keyless restore)
	}
	return "", false
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// loadOrCreateCA returns the CA of this box. The first time it makes one (audit sensor-ca.create). A stored CA that cannot be
// used (it does not decrypt under this master.key, it is damaged, it is expired or not yet valid) is replaced in the same
// write transaction that found it, together with the retirement of every live leaf of the old CA (audit sensor-ca.replace): a
// restore without master.key, or a master.key made again, gives a new CA and new leaves, as D-110 (1) says, and Start writes the
// new bundles. Callers racing on first use all get the same CA: the check and the write run in one write transaction.
func (a *Authority) loadOrCreateCA(ctx context.Context, op *secrets.Opener) (*ca, error) {
	if id, err := coredb.New(a.db.Reader()).GetSecretIDByPurpose(ctx, caPurpose); err == nil {
		c, err := a.openCA(ctx, op, a.db.Reader(), id)
		if err == nil {
			return c, nil
		}
		if _, bad := unusable(err); !bad {
			return nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("pki: find the CA: %w", err)
	}
	var out *ca
	replaced := ""
	err := a.db.Write(ctx, func(tx *sql.Tx) error {
		replaced = ""
		id, err := coredb.New(tx).GetSecretIDByPurpose(ctx, caPurpose)
		switch {
		case err == nil: // another caller may have made or replaced it between our read and this transaction
			c, oerr := a.openCA(ctx, op, tx, id)
			if oerr == nil {
				out = c
				return nil
			}
			reason, bad := unusable(oerr)
			if !bad {
				return oerr
			}
			replaced = reason
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("pki: find the CA: %w", err)
		}
		c, plain, err := a.newCA()
		if err != nil {
			return err
		}
		if replaced == "" {
			if _, _, err := a.sec.Seal(ctx, tx, caPurpose, plain, false); err != nil {
				return fmt.Errorf("pki: seal the CA: %w", err)
			}
			err = a.record(ctx, tx, "sensor-ca.create", "sensor-ca", "ecdsa-p256 "+c.cert.SerialNumber.Text(16))
		} else {
			if _, err := a.sec.Replace(ctx, tx, id, caPurpose, plain, false); err != nil {
				return fmt.Errorf("pki: replace the CA: %w", err)
			}
			err = a.record(ctx, tx, "sensor-ca.replace", "sensor-ca", "reason="+replaced+" new_serial="+c.cert.SerialNumber.Text(16))
			if err == nil {
				err = a.retireAll(ctx, tx)
			}
		}
		out = c
		return err
	})
	if err == nil && replaced != "" {
		a.log.WarnContext(ctx, "sensor_ca_replaced", "reason", replaced)
	}
	return out, err
}

// retireAll retires every live leaf: they were signed by a CA that is gone.
func (a *Authority) retireAll(ctx context.Context, tx *sql.Tx) error {
	q := coredb.New(tx)
	now := store.FormatTS(a.now())
	for _, r := range sensorlink.Roles {
		rows, err := q.ListLiveSensorCerts(ctx, string(r))
		if err != nil {
			return fmt.Errorf("pki: list live serials: %w", err)
		}
		for _, row := range rows {
			if err := q.RetireSensorCert(ctx, coredb.RetireSensorCertParams{RetiredAt: &now, Serial: row.Serial}); err != nil {
				return fmt.Errorf("pki: retire a serial: %w", err)
			}
			if err := a.record(ctx, tx, "sensor-cert.retire", string(r), "serial="+row.Serial+" ca_replaced"); err != nil {
				return err
			}
		}
	}
	return nil
}

// record writes one audit row, actor system, in the transaction of the change it describes (SYS-3). Details never hold key
// material: serials, roles, times and reasons only.
func (a *Authority) record(ctx context.Context, tx *sql.Tx, action, target, detail string) error {
	if err := a.audit.Append(ctx, tx, audit.Entry{User: "system", Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("pki: audit %s: %w", action, err)
	}
	return nil
}

func (a *Authority) openCA(ctx context.Context, op *secrets.Opener, q coredb.DBTX, id string) (*ca, error) {
	plain, err := op.Open(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("pki: open the CA: %w", err)
	}
	var cert *x509.Certificate
	var key *ecdsa.PrivateKey
	for rest := plain; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			ek, ok := k.(*ecdsa.PrivateKey)
			if err != nil || !ok || ek.Curve != elliptic.P256() {
				return nil, &caError{"damaged"}
			}
			key = ek
		case "CERTIFICATE":
			if cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
				return nil, &caError{"damaged"}
			}
		}
	}
	if cert == nil || key == nil || !cert.IsCA {
		return nil, &caError{"damaged"}
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, &caError{"damaged"}
	}
	now := a.now()
	switch {
	case now.After(cert.NotAfter):
		return nil, &caError{"expired"}
	case now.Before(cert.NotBefore):
		return nil, &caError{"not_yet_valid"}
	}
	return &ca{cert: cert, key: key}, nil
}

// newCA makes a CA and returns it with the PEM that is sealed: the key and the certificate.
func (a *Authority) newCA() (*ca, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Vedette sensor CA", Organization: []string{"Vedette"}},
		NotBefore:             now.Add(-skew),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: CA key: %w", err)
	}
	plain := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return &ca{cert: cert, key: key}, plain, nil
}

// newSerial returns a random 127-bit positive serial (RFC 5280 asks for at most 20 octets and a positive number).
func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}
