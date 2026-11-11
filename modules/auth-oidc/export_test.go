package authoidc

import (
	"errors"
	"log/slog"
	"net/http"
)

// Forget drops the discovery cache (tests change the fake provider's document).
func (s *Service) Forget() { s.forget() }

// SetLogger swaps the logger (tests read what is logged).
func (s *Service) SetLogger(l *slog.Logger) { s.log = l }

// CheckTransportRefusesHTTP proves the capped transport refuses a plain http request before it is sent.
func CheckTransportRefusesHTTP() error {
	sent := false
	c := newClient(roundTripFunc(func(*http.Request) (*http.Response, error) { sent = true; return nil, errors.New("sent") }))
	resp, err := c.Get("http://idp.example/.well-known/openid-configuration") //nolint:noctx // a unit check of the transport
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || sent {
		return errors.New("an http request went out")
	}
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
