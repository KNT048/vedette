package exposure

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// D-591 (FULL-5 slice 2): a new domain gets the box-bound token from the DomainFence (a random one without it); an OpenVAS task on a
// domain's address that is not the box's asks the host's fence again every 3 minutes while it runs and is stopped by a no; its probe
// row names the domain, the name and the CNAME chain.

func TestAddDomainTakesTheBoxBoundToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.DomainFence = &fakeFence{}
	v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example")
	if err != nil || v.Token != deepToken {
		t.Fatalf("token %q, %v", v.Token, err)
	}
	e2 := newEnv(t)
	e2.svc.cfg.DomainFence = failingFence{}
	v, err = e2.svc.AddDomain(e2.ctx(), "admin@acme.example", "acme.example")
	if err != nil || len(v.Token) != 16 || v.Token == deepToken {
		t.Fatalf("a host that does not answer: token %q, %v", v.Token, err)
	}
}

type failingFence struct{}

func (failingFence) Token(context.Context, string) (string, error) { return "", errors.New("no host") }

// fencedGB is fakeGB whose host checks the domain fence and says no (the TXT record went while the task ran).
type fencedGB struct {
	*fakeGB
	mu    sync.Mutex
	calls int
}

func (f *fencedGB) CheckDomainIP(context.Context, DomainScope, netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return errors.New("host: target_not_owned")
}

func TestOpenVASStopsWhenTheHostsFenceSaysNoMidRun(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	fg := &fencedGB{fakeGB: h}
	e.svc.cfg.Greenbone = fg
	h.gvm.with(func(g *fakeGVM) { g.states = []string{"Running"} })
	e.svc.gb().poll = time.Millisecond
	st := ScanTarget{ID: "t", Kind: KindDomain, Value: "acme.example", User: "admin@acme.example", Mode: ScanMode{Full: true},
		Domain: &DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: deepToken, Chain: "www.acme.example -> web.acme.example"}}
	type res struct {
		err error
	}
	done := make(chan res, 1)
	go func() {
		_, _, _, err := e.svc.runGreenbone(e.ctx(), st, netip.MustParseAddr(ipB), h.gvm.log, time.Millisecond)
		done <- res{err}
	}()
	tick := time.NewTicker(time.Millisecond) // the task's start is a state of the fake gvmd: look until it is there
	defer tick.Stop()
	for end := time.Now().Add(30 * time.Second); !h.gvm.seen("start_task"); <-tick.C {
		if time.Now().After(end) {
			t.Fatal("the task never started")
		}
	}
	e.advance(gbFenceRecheck)
	var r res
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the task was not stopped")
	}
	var un *Unavailable
	if !errors.As(r.err, &un) || un.Reason != notGBFencedMid || fg.calls != 1 || !h.gvm.seen("stop_task") {
		t.Fatalf("err %v, cmds %q", r.err, h.gvm.cmds)
	}
	if rows := h.gvm.log.rows; len(rows) != 1 || !strings.Contains(rows[0].Note, "CNAME chain www.acme.example -> web.acme.example") {
		t.Fatalf("probe rows %+v", rows)
	}
}
