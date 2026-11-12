package ai

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
)

// SetNewsNetwork makes the CVE news fetcher resolve names with resolve and connect with connect instead of the network. Every check
// of the fetcher still runs (allowed host, port 443, a public resolved address, redirects, sizes); only the final connect (and its
// Control hook, tested on its own) is replaced, and TLS trusts roots. Tests only: no configuration or request can reach it, and the product never calls it. The in-package tests and the end-to-end box (cmd/vedette/e2enews_test.go, a _test file the release binary does not contain) are its only callers.
func (s *Service) SetNewsNetwork(resolve func(ctx context.Context, host string) ([]netip.Addr, error), connect func(ctx context.Context, network, addr string) (net.Conn, error), roots *x509.CertPool) {
	t := newsTransport(resolve, connect)
	t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	s.news.client.Transport = t
}
