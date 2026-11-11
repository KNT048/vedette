package ai

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"time"
)

// HoldHookTest takes the one place for a hook test and returns the function that gives it back, so a test can make the next one wait.
func (s *Service) HoldHookTest() (release func()) {
	s.testSlot <- struct{}{}
	return func() { <-s.testSlot }
}

// MemoryLinesForCall returns the memory lines a call of the job would send (after the hooks) and the ids left out.
func (s *Service) MemoryLinesForCall(ctx context.Context, job Job) (sent string, left []string, err error) {
	mc, err := s.memoryForCall(ctx, s.Hooks(), job)
	return mc.block.Text, mc.left, err
}

// SetNewsNetwork makes the CVE news fetcher resolve names with resolve and connect with connect instead of the network. Every check
// of the fetcher still runs (allowed host, port 443, a public resolved address, redirects, sizes); only the final connect (and its
// Control hook, tested on its own) is replaced, and TLS trusts roots. Tests only: no configuration can reach it.
func (s *Service) SetNewsNetwork(resolve func(ctx context.Context, host string) ([]netip.Addr, error), connect func(ctx context.Context, network, addr string) (net.Conn, error), roots *x509.CertPool) {
	t := newsTransport(resolve, connect)
	t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	s.news.client.Transport = t
}

// NewsControl is the socket Control hook of the fetcher.
func NewsControl(address string) error { return newsControl("tcp", address, nil) }

// SetNewsTimeouts shortens the fetch deadlines of CVE news.
func (s *Service) SetNewsTimeouts(one, total time.Duration) {
	s.news.timeout, s.news.total = one, total
}
