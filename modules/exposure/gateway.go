package exposure

import (
	"context"
	"strings"
	"unicode"
)

const maxGatewayName = 80

// GatewayNote answers "which device probably answers these ports" for GET /exposure/targets (INV-16). It is nil when no
// IP target (the box's own public IP) has an open port in its newest scan, or when no Gateway is wired: a domain's subdomains often
// sit at a hosting provider, so only the box's own IPs say anything about the gateway. A lookup that fails is logged and answered
// as "cannot tell" (all nil): the page never claims what it did not read.
func (s *Service) GatewayNote(ctx context.Context, items []TargetView) *GatewayView {
	open := false
	for _, t := range items {
		if t.Kind == KindIP && t.Origin != "person" && len(t.OpenPorts) > 0 {
			open = true
			break
		}
	}
	return s.gatewayNote(ctx, open)
}

// gatewayNote is the gateway note when one of the box's own IPs has an open service (open); nil otherwise.
func (s *Service) gatewayNote(ctx context.Context, open bool) *GatewayView {
	if s.cfg.Gateway == nil || !open {
		return nil
	}
	g, err := s.cfg.Gateway.Gateway(ctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the gateway", "err", err)
		return &GatewayView{}
	}
	v := &GatewayView{}
	if !g.IP.IsValid() {
		return v
	}
	ip := g.IP.String()
	v.IP = &ip
	if g.DeviceID == "" {
		return v
	}
	id, name := g.DeviceID, cleanName(g.Name)
	v.DeviceID, v.Name, v.OpenExploited = &id, &name, max(g.OpenExploited, 0)
	return v
}

// cleanName makes a device label safe to show: no control characters, at most maxGatewayName characters. The label comes from the
// network (a host name a device announced), so it is untrusted.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	r := []rune(strings.TrimSpace(s))
	return string(r[:min(len(r), maxGatewayName)])
}
