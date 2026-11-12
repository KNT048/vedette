package agentintake

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/netip"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// IntakeHandlers implement the public osquery operations of the module (CONTRACT "Endpoints owned"). The server answers 404 for all
// of them while the module is off (SYS-5) and cuts the body at the caps of BodyLimits before these methods run. enroll, config
// and log never return an error for a bad credential: that is HTTP 200 + node_invalid (INV-13); status answers 403 (D-265 (1)); the other
// 4xx are the server's (413, 400) and the 429 here.
type IntakeHandlers struct{ s *Service }

// NewIntakeHandlers wraps the service; nil gives 501 for every operation (server.Fallback), like a module that is not wired.
func NewIntakeHandlers(s *Service) *IntakeHandlers { return &IntakeHandlers{s: s} }

func exchange(ctx context.Context) (server.Exchange, error) {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return server.Exchange{}, errors.New("agentintake: no HTTP exchange in the request context")
	}
	return x, nil
}

// peer is the TCP address of the connection: forwarded headers are never read (INV-12).
func peer(ctx context.Context) (netip.Addr, server.Exchange, error) {
	x, err := exchange(ctx)
	if err != nil {
		return netip.Addr{}, x, err
	}
	return x.ClientAddr(), x, nil
}

// reject counts a request that cannot hold a credential of ours (a malformed secret or key) like a wrong one, and answers errNodeInvalid.
func (s *Service) reject(ctx context.Context, op string, src netip.Addr) error {
	key := srcKey(src)
	if w := s.fail.blocked(key); w > 0 {
		return rateLimited(w)
	}
	s.fail.fail(key)
	s.logReject(ctx, op, src, "shape")
	return errNodeInvalid
}

// InventoryPostIntakeOsqueryEnroll implements POST /intake/osquery/enroll.
func (h *IntakeHandlers) InventoryPostIntakeOsqueryEnroll(ctx context.Context, req *oas.InventoryPostIntakeOsqueryEnrollReq) (*oas.InventoryPostIntakeOsqueryEnrollOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	src, _, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	in, ok := parseEnroll(req)
	var key string
	if ok {
		key, err = h.s.Enroll(ctx, src, in)
	} else {
		err = h.s.reject(ctx, "enroll", src)
	}
	switch {
	case errors.Is(err, errNodeInvalid):
		return &oas.InventoryPostIntakeOsqueryEnrollOK{NodeInvalid: true}, nil
	case err != nil:
		return nil, err
	}
	return &oas.InventoryPostIntakeOsqueryEnrollOK{NodeKey: oas.NewOptString(key)}, nil
}

// InventoryPostIntakeOsqueryConfig implements POST /intake/osquery/config.
func (h *IntakeHandlers) InventoryPostIntakeOsqueryConfig(ctx context.Context, req *oas.InventoryPostIntakeOsqueryConfigReq) (*oas.InventoryPostIntakeOsqueryConfigOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	src, _, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	key, ok := parseConfig(req)
	if ok {
		err = h.s.Config(ctx, src, key)
	} else {
		err = h.s.reject(ctx, "config", src)
	}
	switch {
	case errors.Is(err, errNodeInvalid):
		return &oas.InventoryPostIntakeOsqueryConfigOK{NodeInvalid: oas.NewOptBool(true)}, nil
	case err != nil:
		return nil, err
	}
	return configResponse(), nil
}

// InventoryPostIntakeOsqueryLog implements POST /intake/osquery/log.
func (h *IntakeHandlers) InventoryPostIntakeOsqueryLog(ctx context.Context, req *oas.InventoryPostIntakeOsqueryLogReq) (*oas.InventoryPostIntakeOsqueryLogOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	src, _, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	in, ok := parseLog(req)
	if ok {
		err = h.s.Log(ctx, src, in)
	} else {
		err = h.s.reject(ctx, "log", src)
	}
	switch {
	case errors.Is(err, errNodeInvalid):
		return &oas.InventoryPostIntakeOsqueryLogOK{NodeInvalid: true}, nil
	case err != nil:
		return nil, err
	}
	return &oas.InventoryPostIntakeOsqueryLogOK{}, nil
}

// InventoryPostIntakeOsqueryStatus implements POST /intake/osquery/status: the token comes in the Authorization header, never the URL.
func (h *IntakeHandlers) InventoryPostIntakeOsqueryStatus(ctx context.Context) (*oas.InventoryPostIntakeOsqueryStatusOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	src, x, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	secret, _ := parseStatus(x.R.Header.Get("Authorization")) // "" when it is not a token: counted and refused like a wrong one
	enrolled, hosts, err := h.s.Status(ctx, src, secret)
	if err != nil {
		return nil, err
	}
	return &oas.InventoryPostIntakeOsqueryStatusOK{Enrolled: enrolled, Hosts: hosts}, nil
}

// InventoryGetIntakeCaPem implements GET /intake/ca.pem (INV-11, public): the certificate osquery pins with --tls_server_certs. Only the
// CERTIFICATE blocks of the trust anchor are copied, so nothing else a PEM file may hold (a private key next to an owner's
// certificate) can leave; 404 when the box serves no TLS.
func (h *IntakeHandlers) InventoryGetIntakeCaPem(ctx context.Context) (oas.InventoryGetIntakeCaPemOK, error) {
	if h.s == nil {
		return oas.InventoryGetIntakeCaPemOK{}, apierr.NotImplemented()
	}
	if h.s.cfg.TrustAnchor == nil {
		return oas.InventoryGetIntakeCaPemOK{}, apierr.NotFound()
	}
	x, err := exchange(ctx)
	if err != nil {
		return oas.InventoryGetIntakeCaPemOK{}, err
	}
	raw, err := h.s.cfg.TrustAnchor(ctx)
	if err != nil {
		return oas.InventoryGetIntakeCaPemOK{}, err
	}
	var out []byte
	for {
		var blk *pem.Block
		if blk, raw = pem.Decode(raw); blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: blk.Bytes})...) // headers dropped too
		}
	}
	if len(out) == 0 {
		return oas.InventoryGetIntakeCaPemOK{}, errors.New("agentintake: the trust anchor holds no certificate")
	}
	x.SetContentType("application/x-pem-file")
	return oas.InventoryGetIntakeCaPemOK{Data: bytes.NewReader(out)}, nil
}
