package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/knt048/vedette/core/sensorlink"
)

// clientTemplate is a sensor leaf: EKU clientAuth only and exactly one URI SAN, the role. The CN says nothing the server uses.
func clientTemplate(role sensorlink.Role) *x509.Certificate {
	u, _ := url.Parse(role.URI()) // the URI is a constant of the form vedette:sensor:<role>
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "vedette-sensor-" + string(role)},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{u},
		BasicConstraintsValid: true,
	}
}

// serverTemplate is the leaf of the sensor listener: EKU serverAuth only; SAN 127.0.0.1 (the published port) and core (the
// compose profile). A sensor certificate cannot be a server: it has the wrong EKU and no name.
func serverTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "vedette-core-sensor-link"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"core"},
		BasicConstraintsValid: true,
	}
}

// signLeaf generates a P-256 key and has the CA sign tmpl for LeafLifetime.
func (a *Authority) signLeaf(tmpl *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: leaf key: %w", err)
	}
	if tmpl.SerialNumber, err = newSerial(); err != nil {
		return nil, nil, err
	}
	now := a.now()
	tmpl.NotBefore, tmpl.NotAfter = now.Add(-skew), now.Add(LeafLifetime)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.ca.cert, &key.PublicKey, a.ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: sign leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse leaf: %w", err)
	}
	return key, cert, nil
}

// bundle is the file a role reads: the private key, the leaf and the CA, in this order.
func (a *Authority) bundle(key *ecdsa.PrivateKey, leafDER []byte) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: leaf key: %w", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	b = append(b, certPEM(leafDER)...)
	return append(b, certPEM(a.ca.cert.Raw)...), nil
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
