package sensorlink

import (
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
)

// Role is what a sensor certificate says its holder may do (D-111). The role is the URI SAN of the certificate, never the CN.
type Role string

// The two sensor roles. passive is the capture process (container sensor), active the nmap worker (container scan).
const (
	Passive Role = "passive"
	Active  Role = "active"
)

// Roles lists every role in a fixed order.
var Roles = []Role{Passive, Active}

const uriPrefix = "vedette:sensor:"

// URI is the URI SAN the certificate of this role carries.
func (r Role) URI() string { return uriPrefix + string(r) }

// Valid reports whether r is one of the two roles.
func (r Role) Valid() bool { return r == Passive || r == Active }

// ErrIdentity is wrapped by every refusal of a sensor certificate.
var ErrIdentity = errors.New("sensorlink: not a sensor certificate")

// ClientRole checks that leaf is a sensor client certificate and returns its role: not a CA, ExtKeyUsage exactly clientAuth
// (a server certificate used as a client fails here), and exactly one URI SAN naming a known role (D-110 (2)).
func ClientRole(leaf *x509.Certificate) (Role, error) {
	if leaf == nil || leaf.IsCA {
		return "", ErrIdentity
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(leaf.UnknownExtKeyUsage) != 0 {
		return "", ErrIdentity
	}
	if len(leaf.URIs) != 1 {
		return "", ErrIdentity
	}
	return roleOfURI(leaf.URIs[0])
}

func roleOfURI(u *url.URL) (Role, error) {
	for _, r := range Roles {
		if u.String() == r.URI() {
			return r, nil
		}
	}
	return "", ErrIdentity
}
