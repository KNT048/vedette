package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/inventory"
)

// fakeInfo is GET /v1/info of a fake vedette-host: the next answer and how often it was asked.
type fakeInfo struct {
	name  string
	err   error
	calls int
}

func (f *fakeInfo) Info(context.Context) (api.Info, error) {
	f.calls++
	return api.Info{Hostname: f.name}, f.err
}

// #471: the box's name is the OS host name vedette-host reports, checked again in core; "vedette" without a valid one; the last good
// name survives a host that stops answering; the host is asked again only after the TTL (a good answer) or the retry gap (no answer).
// ok is false only until the host has answered once.
func TestBoxHostNameComesFromTheHost(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	f := &fakeInfo{err: errors.New("host down")}
	b := newBoxHostNameFrom(f.Info, func() time.Time { return now })
	ctx := t.Context()
	check := func(step, wantName string, wantOK bool, wantCalls int) {
		t.Helper()
		if got, ok := b.Get(ctx); got != wantName || ok != wantOK || f.calls != wantCalls {
			t.Fatalf("%s: %q %v after %d calls, want %q %v after %d", step, got, ok, f.calls, wantName, wantOK, wantCalls)
		}
	}

	check("host down at start", fallbackBoxName, false, 1)
	f.err, f.name = nil, "box-01"
	check("inside the retry gap", fallbackBoxName, false, 1)
	now = now.Add(boxNameRetry)
	check("after the retry gap", "box-01", true, 2)
	f.err = errors.New("host down")
	now = now.Add(boxNameTTL)
	check("host down after a good answer", "box-01", true, 3)
	f.err, f.name = nil, "box-02.corp.example"
	check("inside the retry gap after a failure", "box-01", true, 3)
	now = now.Add(boxNameRetry)
	check("renamed machine", "box-02.corp.example", true, 4)

	// A name the host should never send is not passed on; an older host without the field gives "vedette" too. Both are answers (ok).
	for _, bad := range []string{"bad name", "box\n", "box_01", "-box", "hộp", strings.Repeat("a", 65), "box\x00", ""} {
		f.name = bad
		now = now.Add(boxNameTTL)
		if got, ok := b.Get(ctx); got != fallbackBoxName || !ok {
			t.Errorf("host name %q: got %q %v", bad, got, ok)
		}
	}
}

// A caller whose own context ended is not a host failure: the next caller asks at once.
func TestBoxHostNameCallerCancelIsNoHostFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	f := &fakeInfo{name: "box-01"}
	b := newBoxHostNameFrom(func(ctx context.Context) (api.Info, error) {
		if err := ctx.Err(); err != nil {
			f.calls++
			return api.Info{}, err
		}
		return f.Info(ctx)
	}, func() time.Time { return now })
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	if got, ok := b.Get(gone); got != fallbackBoxName || ok {
		t.Fatalf("cancelled caller: %q %v", got, ok)
	}
	if got, ok := b.Get(t.Context()); got != "box-01" || !ok || f.calls != 2 {
		t.Fatalf("next caller: %q %v after %d calls (a retry gap was set)", got, ok, f.calls)
	}
}

func TestBoxHostNameWithoutAHost(t *testing.T) {
	t.Parallel()
	var none *boxHostName
	if got, ok := none.Get(t.Context()); got != fallbackBoxName || !ok {
		t.Fatalf("nil: %q %v", got, ok)
	}
	want := fallbackBoxName
	if h, err := os.Hostname(); err == nil && api.ValidHostname(h) {
		want = h // container-only: the compose file's hostname; development: the machine's
	}
	if got, ok := newBoxHostName("").Get(t.Context()); got != want || !ok {
		t.Fatalf("no host: %q %v, want %q", got, ok, want)
	}
}

func runBoxJob(t *testing.T, d deps) {
	t.Helper()
	for _, j := range inventoryJobs(d) {
		if j.Name == "box" {
			if err := j.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("no box job")
}

// The box's device row and the Logs sources page carry the name the host reports (#471), not the container's. After a restart of core
// while the host does not answer yet (a host upgrade), the row keeps that name instead of turning into "vedette" until the next run.
func TestBoxRowAndLogsPageUseTheHostName(t *testing.T) {
	f := &fakeInfo{name: "office-box"}
	s := newStackWith(t, func(d *deps) { d.BoxName = newBoxHostNameFrom(f.Info, time.Now) })
	ctx := t.Context()
	runBoxJob(t, *s.d)
	name, _, ok, err := s.d.Inventory.BoxName(ctx)
	if err != nil || !ok || name != "office-box" {
		t.Fatalf("box row: %q %v %v", name, ok, err)
	}
	info, err := (logsBox{*s.d}).Info(ctx)
	if err != nil || info.Hostname != "office-box" {
		t.Fatalf("logs page: %+v %v", info, err)
	}

	down := &fakeInfo{err: errors.New("host restarting")}
	restarted := *s.d
	restarted.BoxName = newBoxHostNameFrom(down.Info, time.Now) // a fresh core: empty memory
	runBoxJob(t, restarted)
	if name, _, _, err := s.d.Inventory.BoxName(ctx); err != nil || name != "office-box" || down.calls != 1 {
		t.Fatalf("box row after a restart with the host down: %q %v (%d calls)", name, err, down.calls)
	}
	// r2 LOW 2: the Logs page and SIEM records agree with the row meanwhile (buildServices wires useRow).
	restarted.BoxName.useRow(boxRowName(s.d.Inventory))
	if info, err := (logsBox{restarted}).Info(ctx); err != nil || info.Hostname != "office-box" {
		t.Fatalf("logs page after a restart with the host down: %+v %v", info, err)
	}
	if got := restarted.BoxName.Name(ctx); got != "office-box" {
		t.Fatalf("SIEM HOSTNAME after a restart with the host down: %q", got)
	}
}

// buildServices gives the box's name the row to fall back on.
func TestBuildServicesWiresTheRowName(t *testing.T) {
	down := &fakeInfo{err: errors.New("host restarting")}
	s := newStackWith(t, func(d *deps) { d.BoxName = newBoxHostNameFrom(down.Info, time.Now) })
	if _, err := s.d.Inventory.EnsureBox(t.Context(), inventory.BoxInfo{Hostname: "office-box"}); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.d.BoxName.Get(t.Context()); got != "office-box" || ok {
		t.Fatalf("%q %v", got, ok)
	}
}

// The honeypot's box before the inventory has a box row is named like the row will be (#471), not after the container.
func TestHoneypotBoxNameBeforeTheRow(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if _, _, found, err := s.d.Inventory.BoxName(t.Context()); err != nil || found {
		t.Fatalf("a box row already: %v %v", found, err)
	}
	for box, want := range map[*boxHostName]string{nil: fallbackBoxName, newBoxHostNameFrom((&fakeInfo{name: "office-box"}).Info, time.Now): "office-box"} {
		if b, err := (honeypotInventory{inv: s.d.Inventory, box: box}).Box(t.Context()); err != nil || b.Name != want {
			t.Errorf("box %q: %+v %v", want, b, err)
		}
	}
}

// With no box row yet and no answer from the host, the row is still made, named "vedette" (EnsureBox needs a name).
func TestBoxRowIsMadeWhileTheHostIsDown(t *testing.T) {
	down := &fakeInfo{err: errors.New("host restarting")}
	s := newStackWith(t, func(d *deps) { d.BoxName = newBoxHostNameFrom(down.Info, time.Now) })
	runBoxJob(t, *s.d)
	if name, _, ok, err := s.d.Inventory.BoxName(t.Context()); err != nil || !ok || name != fallbackBoxName {
		t.Fatalf("box row: %q %v %v", name, ok, err)
	}
}
