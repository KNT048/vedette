package exposure

import (
	"context"
	"net/netip"
	"time"
)

// The host's own witness of a person's press (CONTRACT INV-24a): the host does not take core's word that a person started the scan
// whose active web pass asks for the disruptive rules. When a person presses Scan now (or Run once now) on the box's own IP with
// testing terms that include the disruptive checks, exposure asks the host for a grant (zap.authorize, with the person's actor
// label); the host keeps it in its memory, and each page of that scan's active pass that asks for the disruptive rules hands it back.
// The host runs them only while it holds (that person, that address, one active pass, 6 hours from the press), and only when its own
// read of the box's gateway is not carrier-grade NAT; otherwise the page runs without them and the scan says why (WebScan
// .DisruptiveRefused). A scan the box runs by itself never asks.

// DisruptiveGranter is the host's zap.authorize: the grant of the disruptive rules on ip for user's press.
type DisruptiveGranter interface {
	GrantDisruptive(ctx context.Context, user string, ip netip.Addr) (string, error)
}

// grantWait bounds the wait for the host's answer to the press: it is asked at the press, so it is long there by the active pass.
const grantWait = 30 * time.Second

// pressGrant is the grant asked for at the press of one scan; done is closed once the host answered (grant "" when it did not give
// one).
type pressGrant struct {
	done  chan struct{}
	grant string
	at    time.Time
}

// askGrant asks the host for the grant of run runID's press when the scan may run the disruptive rules: a person's scan of the box's
// own IP (not a typed one) whose testing terms include them. It does not wait: the host answers while the scan waits in the queue or
// runs its first steps, and the active pass waits for the answer (grantOf). A failure is logged; the pass then runs without the
// disruptive rules, and says why.
func (s *Service) askGrant(runID, user string, t Target) {
	g, ok := s.cfg.Web.(DisruptiveGranter)
	if !ok || user == SystemUser || t.Kind != KindIP || t.Typed || !t.mode().Disruptive {
		return
	}
	ip, err := netip.ParseAddr(t.Value)
	if err != nil {
		return
	}
	now := s.clock()
	p := &pressGrant{done: make(chan struct{}), at: now}
	s.runMu.Lock()
	if s.grants == nil {
		s.grants = map[string]*pressGrant{}
	}
	for id, old := range s.grants { // a run that never started (taken back in the queue): its grant is past the host's lifetime
		if now.Sub(old.at) > 12*time.Hour {
			delete(s.grants, id)
		}
	}
	s.grants[runID] = p
	s.runMu.Unlock()
	go func() {
		defer close(p.done)
		ctx, cancel := context.WithTimeout(context.Background(), grantWait)
		defer cancel()
		grant, err := g.GrantDisruptive(ctx, user, ip.Unmap())
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "exposure: the host gave no grant of the disruptive rules for this press; the active web scan runs without them", "target", t.Value, "error", err)
			return
		}
		p.grant = grant
	}()
}

// grantOf is the grant of run runID's press, waiting for the host's answer when it is still on its way; "" when none.
func (s *Service) grantOf(ctx context.Context, runID string) string {
	s.runMu.Lock()
	p := s.grants[runID]
	s.runMu.Unlock()
	if p == nil {
		return ""
	}
	select {
	case <-p.done:
		return p.grant
	case <-ctx.Done():
		return ""
	}
}
