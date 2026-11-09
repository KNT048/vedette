package sensorlink

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// MaxBundle is the largest credentials file the client reads. A bundle is a key, a leaf and the CA: about 1.5 KiB.
const MaxBundle = 64 << 10

// Bundle is what core writes to <creds>/<role>/sensor.pem (D-110 (4)): the private key, the leaf certificate and the CA
// certificate, in one file so a reader never sees a key that belongs to another certificate.
type Bundle struct {
	Cert tls.Certificate
	Leaf *x509.Certificate
	CA   *x509.Certificate
	Pool *x509.CertPool // only CA
}

// ParseBundle reads a bundle from PEM: exactly one private key and exactly two certificates, the leaf first and then the CA.
// The key must belong to the leaf, and the leaf must be a sensor client certificate that chains to the CA.
func ParseBundle(data []byte) (*Bundle, error) {
	var certs [][]byte
	var keys int
	for rest := data; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certs = append(certs, blk.Bytes)
		case "PRIVATE KEY":
			keys++
		default:
			return nil, fmt.Errorf("sensorlink: bundle has a %q block", blk.Type)
		}
	}
	if keys != 1 || len(certs) != 2 {
		return nil, errors.New("sensorlink: bundle must hold one key and two certificates")
	}
	cert, err := tls.X509KeyPair(data, data) // checks that the key belongs to the first certificate
	if err != nil {
		return nil, fmt.Errorf("sensorlink: bundle key and certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("sensorlink: bundle leaf: %w", err)
	}
	ca, err := x509.ParseCertificate(certs[1])
	if err != nil {
		return nil, fmt.Errorf("sensorlink: bundle CA: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("sensorlink: bundle CA is not a CA")
	}
	if _, err := ClientRole(leaf); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert.Leaf = leaf
	return &Bundle{Cert: cert, Leaf: leaf, CA: ca, Pool: pool}, nil
}

// readBundleFile reads the bundle at path without following a symlink, never blocking on a FIFO, refusing anything that is
// not a regular file or is larger than MaxBundle. It returns the file's info, so the caller can tell when the file changed.
func readBundleFile(path string) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the path is the sensor's own configuration
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxBundle {
		return nil, nil, errors.New("sensorlink: credentials file is not a regular file of a sane size")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBundle+1))
	if err != nil {
		return nil, nil, err
	}
	return b, fi, nil
}
