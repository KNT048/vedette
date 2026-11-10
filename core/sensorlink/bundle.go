package sensorlink

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// The leaf must chain to this CA, with this CA as the only root, for client auth. The clock is not the question here (a
	// bundle is read long after it was made, and expiry is the TLS handshake's business), so the check is made at the middle of
	// the leaf's own life.
	mid := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: mid, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("sensorlink: bundle leaf does not chain to the bundle CA: %w", err)
	}
	cert.Leaf = leaf
	return &Bundle{Cert: cert, Leaf: leaf, CA: ca, Pool: pool}, nil
}

// readBundleFile reads the bundle at path and refuses what the writer would never have made (D-110 (4)):
//   - a symlink as the file, or as the directory that holds it (the volume is shared with a container that is being attacked;
//     the file is opened through os.OpenRoot on its directory, so no component below that directory can lead out of it);
//   - anything that is not a regular file, or is larger than MaxBundle (a FIFO is never opened blocking);
//   - a file with a mode core does not write: core writes 0640 (owner and group read), so any bit outside 0640 (group write,
//     any access for other, execute) is refused; 0600 and 0400 are inside it.
//
// It returns the file's info, so the caller can tell when the file changed.
func readBundleFile(path string) ([]byte, os.FileInfo, error) {
	dir, name := filepath.Dir(path), filepath.Base(path) // Dir has no trailing slash: Lstat of "link/" would follow the link
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return nil, nil, errors.New("sensorlink: credentials path names no file")
	}
	if di, err := os.Lstat(dir); err != nil {
		return nil, nil, err
	} else if di.Mode()&os.ModeSymlink != 0 || !di.IsDir() {
		return nil, nil, errors.New("sensorlink: the credentials directory is a symlink or not a directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	if li, err := root.Lstat(name); err != nil {
		return nil, nil, err
	} else if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("sensorlink: the credentials file is a symlink")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	if fi.Mode().Perm()&^0o640 != 0 {
		return nil, nil, fmt.Errorf("sensorlink: credentials file has mode %04o: it holds a private key, and core writes it 0640", fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBundle+1))
	if err != nil {
		return nil, nil, err
	}
	return b, fi, nil
}
