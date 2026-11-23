// Package proofat is the one bound of where a domain's ownership record may sit: on the domain itself or on a parent
// name of it down to its registered domain, the name one label below the longest public suffix of the Public Suffix List with both
// its sections (ICANN's com and co.uk, and the private ddns.net, github.io, s3.amazonaws.com). Core (exposure), the scan worker and
// vedette-host all ask it, so none of them trusts another to have checked: a record never counts on or above a public suffix, where
// names of many owners meet.
//
// It is a leaf: the standard library and golang.org/x/net/publicsuffix only, because the sensor binary links it
// (TestBinaryDependencies there).
package proofat

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Registered is the registered domain of name ("example.org" for git.example.org, "example.ddns.net" for
// x.example.ddns.net); ok is false when name is a public suffix or under none.
func Registered(name string) (string, bool) {
	r, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || r == "" {
		return "", false
	}
	return r, true
}

// IsPublicSuffix says whether name is itself a public suffix of the list (co.uk, ddns.net, github.io).
func IsPublicSuffix(name string) bool {
	s, _ := publicsuffix.PublicSuffix(name)
	return s == name
}

// under says whether name is parent or a name under it.
func under(name, parent string) bool { return name == parent || strings.HasSuffix(name, "."+parent) }

// Within says whether a record on at may prove domain: at is domain or a parent name of it, and at is domain's registered domain
// or under it (never a public suffix or a name above one).
func Within(domain, at string) bool {
	r, ok := Registered(domain)
	return ok && at != "" && under(domain, at) && under(at, r)
}
