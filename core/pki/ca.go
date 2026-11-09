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

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store/coredb"
)

const (
	// caPurpose is the core_secret purpose of the CA key. Only this file names it.
	caPurpose  = "core_sensor_ca"
	caLifetime = 10 * 365 * 24 * time.Hour
	// skew is how far a certificate's NotBefore is set back, so a sensor whose clock is a little behind still accepts it.
	skew = time.Minute
)

// ErrCA means the stored CA could not be used (damaged, or expired). The remedy is the D-110 one: restore without the
// master key and core makes a new CA and new leaves.
var ErrCA = errors.New("pki: the stored CA is not usable")

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// loadOrCreateCA returns the CA of this box, making it the first time. Callers racing on first use all get the same CA: the
// check and the insert run in one write transaction.
func (a *Authority) loadOrCreateCA(ctx context.Context, op *secrets.Opener) (*ca, error) {
	if id, err := coredb.New(a.db.Reader()).GetSecretIDByPurpose(ctx, caPurpose); err == nil {
		return a.openCA(ctx, op, a.db.Reader(), id)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("pki: find the CA: %w", err)
	}
	var out *ca
	err := a.db.Write(ctx, func(tx *sql.Tx) error {
		id, err := coredb.New(tx).GetSecretIDByPurpose(ctx, caPurpose)
		if err == nil { // another caller made it between our read and this transaction
			out, err = a.openCA(ctx, op, tx, id)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("pki: find the CA: %w", err)
		}
		c, plain, err := a.newCA()
		if err != nil {
			return err
		}
		if _, _, err := a.sec.Seal(ctx, tx, caPurpose, plain, false); err != nil {
			return fmt.Errorf("pki: seal the CA: %w", err)
		}
		out = c
		return nil
	})
	return out, err
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
				return nil, ErrCA
			}
			key = ek
		case "CERTIFICATE":
			if cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
				return nil, ErrCA
			}
		}
	}
	if cert == nil || key == nil || !cert.IsCA {
		return nil, ErrCA
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, ErrCA
	}
	if a.now().After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: expired", ErrCA)
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
