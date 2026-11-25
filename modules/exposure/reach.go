package exposure

import (
	"context"
	"errors"
	"time"
)

// reachTimeout bounds the one round of the public IP services that tells a box that could not reach anything from a target that
// answered nothing.
const reachTimeout = 30 * time.Second

// answered says something of the target answered this scan: an open port, a page, a certificate, an admin page, a service that
// identification named, a page ZAP read, or a finding or finished check of an engine.
func answered(c Content) bool {
	return len(c.Ports) > 0 || len(c.Certs) > 0 || len(c.AdminPanels) > 0 || len(c.Services) > 0 || len(c.WebPages) > 0 ||
		len(c.WebFindings) > 0 || len(c.Greenbone) > 0 || len(c.TemplatesRan) > 0 || len(c.ScriptsRan) > 0
}

// reached is the check a scan's results pass before they are written. A scan to which nothing answered is a result only when the box
// itself could reach the Internet, so one round of the three public IP services (INV-2) runs then: when none of them answers either,
// the box had no network (a cable, an address conflict, a route or DNS fault) and the scan is incomplete. It ends with an error that
// says so and nothing is written, so the target keeps the rows of its last complete scan. nil when something answered, or when the
// services answered (a target that answers nothing is a result).
func (s *Service) reached(ctx context.Context, t Target, c Content) error {
	if answered(c) || ctx.Err() != nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	_, err := s.cfg.Prober.Round(rctx)
	if err == nil || errors.Is(err, ErrNoAgreement) || ctx.Err() != nil {
		return nil
	}
	s.cfg.Log.WarnContext(ctx, "exposure: a scan got no answer and the box could not reach the public IP services either", "target", t.Value, "error", err)
	return errUnreachable(t.Value)
}

// errUnreachable is the end of a scan that reached nothing while the box was offline.
func errUnreachable(target string) *APIError {
	return apiErr(502, "unreachable", "The box could not reach %s, nor the public services it uses to check its own Internet connection, so this scan is "+
		"incomplete: nothing was saved and the results of the last complete scan stay. Check the box's network (cable, address, DNS), then scan again.", target)
}
