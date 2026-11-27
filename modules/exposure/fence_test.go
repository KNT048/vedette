package exposure

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A new domain gets the box-bound token from the DomainFence; a random one without a host, or when the host
// cannot give one for a reason that does not pass (review r2 M-B); none, and no domain, when the host is only busy or does not answer.
// A doomed add asks the host nothing, a failed add and a deleted domain give the slot back (review r2 M-A). An OpenVAS task on a
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
	// review r2 M-B: a host that is busy or does not answer: "try again", no domain
	e2 := newEnv(t)
	e2.svc.cfg.DomainFence = failingFence{err: ErrFenceDown}
	if _, err := e2.svc.AddDomain(e2.ctx(), "admin@acme.example", "acme.example"); !errors.Is(err, ErrFenceDown) {
		t.Fatalf("a host that does not answer: %v", err)
	}
	if l, err := e2.svc.Targets(e2.ctx()); err != nil || len(l) != 0 {
		t.Fatalf("targets %+v %v", l, err)
	}
	// review r2 M-B: a host that cannot give one (older, unusable key): the random token, the domain is added
	e4 := newEnv(t)
	e4.svc.cfg.DomainFence = failingFence{err: errors.New("host: unknown_command")}
	if v, err := e4.svc.AddDomain(e4.ctx(), "admin@acme.example", "acme.example"); err != nil || len(v.Token) != 16 || v.Token == deepToken {
		t.Fatalf("an older host: token %q, %v", v.Token, err)
	}
	// a container-only install (no host, no fence) keeps the random token
	e3 := newEnv(t)
	e3.svc.cfg.DomainFence = nil
	if v, err := e3.svc.AddDomain(e3.ctx(), "admin@acme.example", "acme.example"); err != nil || len(v.Token) != 16 || v.Token == deepToken {
		t.Fatalf("no fence: token %q, %v", v.Token, err)
	}
}

type failingFence struct{ err error }

func (f failingFence) Token(context.Context, string) (string, error) { return "", f.err }

// slotFence counts the tokens asked and the slots given back; during runs once inside Token (the moment between the host's answer
// and core's write).
type slotFence struct {
	asked, forgot []string
	during        func()
}

func (f *slotFence) Token(_ context.Context, domain string) (string, error) {
	f.asked = append(f.asked, domain)
	if f.during != nil {
		f.during()
		f.during = nil
	}
	return deepToken, nil
}

func (f *slotFence) Forget(_ context.Context, domain string) error {
	f.forgot = append(f.forgot, domain)
	return nil
}

// Review r2 M-A: a duplicate or a full list asks the host for nothing; an add that fails after the host's answer gives the slot back
// (unless the domain was added meanwhile: that target keeps it); deleting a domain target gives its slot back, an IP's does not.
func TestDomainFenceSlots(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := &slotFence{}
	e.svc.cfg.DomainFence = f
	if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example"); err == nil || len(f.asked) != 1 {
		t.Fatalf("a duplicate: %v, asked %q", err, f.asked)
	}
	fill := func(n int) {
		err := e.svc.write(e.ctx(), func(tx *sql.Tx, _ func(string, any)) error {
			for i := range n {
				if err := insertTarget(e.ctx(), tx, Target{ID: "xt-fill" + strconv.Itoa(i), Kind: KindDomain, Value: "fill" + strconv.Itoa(i) + ".example", Token: "0123456789abcdef", CreatedAt: e.clock.Now()}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.during = func() { fill(MaxTargets - 1) } // the list fills up between the host's answer and the write
	if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "late.example"); !errors.Is(err, ErrTooMany) || !slices.Equal(f.forgot, []string{"late.example"}) {
		t.Fatalf("a failed add: %v, forgot %q", err, f.forgot)
	}
	if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "more.example"); !errors.Is(err, ErrTooMany) || slices.Contains(f.asked, "more.example") {
		t.Fatalf("a full list: %v, asked %q", err, f.asked)
	}
	ts, _ := e.svc.Targets(e.ctx())
	var id string
	for _, v := range ts {
		if v.Value == "acme.example" {
			id = v.ID
		}
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", id); err != nil || f.forgot[len(f.forgot)-1] != "acme.example" {
		t.Fatalf("delete: %v, forgot %q", err, f.forgot)
	}
}

// fencedGB is fakeGB whose host checks the domain fence and says no (the TXT record went while the task ran).
type fencedGB struct {
	*fakeGB
	mu    sync.Mutex
	calls int
	last  FenceCheck
}

func (f *fencedGB) CheckDomainIP(_ context.Context, _ DomainScope, _ netip.Addr, c FenceCheck) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = c
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
	st := ScanTarget{ID: "t", Kind: KindDomain, Value: "acme.example", User: "admin@acme.example", Mode: modeAll,
		Domain: &DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: deepToken, Chain: "www.acme.example -> web.acme.example"}}
	type res struct {
		r   gbResult
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := e.svc.runGreenbone(e.ctx(), GreenboneTimeout, st, netip.MustParseAddr(ipB), []int{443}, h.gvm.log, time.Millisecond)
		done <- res{r, err}
	}()
	tick := time.NewTicker(time.Millisecond) // the task's start is a state of the fake gvmd: look until it is there
	defer tick.Stop()
	for end := time.Now().Add(30 * time.Second); !h.gvm.seen("start_task"); <-tick.C {
		if time.Now().After(end) {
			t.Fatal("the task never started")
		}
	}
	// #958: gbWait takes its baseline (checked := s.clock()) only after start_task, so one advance may land before it and never
	// reach a recheck. Advance by a recheck period until the run ends, a bounded number of times (20 × 3 min stays under
	// GreenboneTimeout, so only the fence can end the run) and within a real-time cap.
	var r res
	step := time.NewTicker(20 * time.Millisecond)
	defer step.Stop()
	deadline := time.After(30 * time.Second)
	for advances := 0; ; {
		select {
		case r = <-done:
		case <-step.C:
			if advances < 20 {
				e.advance(gbFenceRecheck)
				advances++
			}
			continue
		case <-deadline:
			t.Fatal("the task was not stopped")
		}
		break
	}
	// The fence ended a scan that ran: its own end (state "ended"), its rows discarded, the task stopped
	if r.err != nil || r.r.end != gbEndFenced || len(r.r.rows) != 0 || fg.calls != 1 || fg.last != (FenceCheck{Disruptive: true, Recheck: true}) || !h.gvm.seen("stop_task") {
		t.Fatalf("result %+v, err %v, cmds %q", r.r, r.err, h.gvm.cmds)
	}
	if rows := h.gvm.log.rows; len(rows) != 1 || !strings.Contains(rows[0].Fence, "CNAME chain www.acme.example -> web.acme.example") {
		t.Fatalf("probe rows %+v", rows)
	}
}
