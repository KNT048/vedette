package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
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
func TestBoxHostNameComesFromTheHost(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	f := &fakeInfo{err: errors.New("host down")}
	b := newBoxHostNameFrom(f.Info, func() time.Time { return now })
	ctx := t.Context()

	if got := b.Get(ctx); got != fallbackBoxName {
		t.Fatalf("host down at start: %q", got)
	}
	f.err, f.name = nil, "box-01"
	if got := b.Get(ctx); got != fallbackBoxName || f.calls != 1 {
		t.Fatalf("inside the retry gap: %q after %d calls", got, f.calls)
	}
	now = now.Add(boxNameRetry)
	if got := b.Get(ctx); got != "box-01" || f.calls != 2 {
		t.Fatalf("after the retry gap: %q after %d calls", got, f.calls)
	}
	f.err = errors.New("host down")
	now = now.Add(boxNameTTL)
	if got := b.Get(ctx); got != "box-01" || f.calls != 3 {
		t.Fatalf("host down after a good answer: %q after %d calls", got, f.calls)
	}
	f.err, f.name = nil, "box-02.corp.example"
	if got := b.Get(ctx); got != "box-01" || f.calls != 3 {
		t.Fatalf("inside the retry gap after a failure: %q after %d calls", got, f.calls)
	}
	now = now.Add(boxNameRetry)
	if got := b.Get(ctx); got != "box-02.corp.example" {
		t.Fatalf("renamed machine: %q", got)
	}

	// A name the host should never send is not passed on; an older host without the field gives "vedette" too.
	for _, bad := range []string{"bad name", "box\n", "box_01", "-box", "hộp", strings.Repeat("a", 65), "box\x00", ""} {
		f.name = bad
		now = now.Add(boxNameTTL)
		if got := b.Get(ctx); got != fallbackBoxName {
			t.Errorf("host name %q: got %q", bad, got)
		}
	}
}

func TestBoxHostNameWithoutAHost(t *testing.T) {
	t.Parallel()
	var none *boxHostName
	if got := none.Get(t.Context()); got != fallbackBoxName {
		t.Fatalf("nil: %q", got)
	}
	want := fallbackBoxName
	if h, err := os.Hostname(); err == nil && api.ValidHostname(h) {
		want = h // container-only: the compose file's hostname; development: the machine's
	}
	if got := newBoxHostName("").Get(t.Context()); got != want {
		t.Fatalf("no host: %q, want %q", got, want)
	}
}

// The box's device row and the Logs sources page carry the name the host reports (#471), not the container's.
func TestBoxRowAndLogsPageUseTheHostName(t *testing.T) {
	f := &fakeInfo{name: "office-box"}
	s := newStackWith(t, func(d *deps) { d.BoxName = newBoxHostNameFrom(f.Info, time.Now) })
	ctx := t.Context()
	var ran bool
	for _, j := range inventoryJobs(*s.d) {
		if j.Name == "box" {
			if err := j.Run(ctx); err != nil {
				t.Fatal(err)
			}
			ran = true
		}
	}
	if !ran {
		t.Fatal("no box job")
	}
	name, _, ok, err := s.d.Inventory.BoxName(ctx)
	if err != nil || !ok || name != "office-box" {
		t.Fatalf("box row: %q %v %v", name, ok, err)
	}
	info, err := (logsBox{*s.d}).Info(ctx)
	if err != nil || info.Hostname != "office-box" {
		t.Fatalf("logs page: %+v %v", info, err)
	}
}
