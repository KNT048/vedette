package sensoractive

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A rate-limited check (22 open before, no answer now) keeps what was known about 22 and says the check is incomplete; the next
// check that again gets no answer from 22 takes it off the list (two misses in a row, as the public scan's rule). A port that
// refused the connection is closed at once.
func TestNoAnswerKeptOnceThenDropped(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ratelimited_listed.xml", "ratelimited_grouped.xml"} {
		hosts, err := parseNmapXML(fixture(t, name))
		if err != nil || len(hosts) != 1 {
			t.Fatalf("%s: %v, %d hosts", name, err, len(hosts))
		}
		h := hosts[0]
		if got := h.answer(22); got != noAnswer {
			t.Fatalf("%s: port 22 answer %d, want noAnswer", name, got)
		}
		if got := h.answer(53); got != answeredOpen {
			t.Fatalf("%s: port 53 answer %d, want open", name, got)
		}
		if got := h.answer(5000); got == answeredOpen {
			t.Fatalf("%s: port 5000 reads open", name)
		}
		prev := DeviceFound{Reach: "top1000", Open: 3, Ports: []FoundPort{{Port: 22, Proto: "tcp"}, {Port: 53, Proto: "tcp"}, {Port: 443, Proto: "tcp"}}}
		first := foundOf(h, nmapargv.Normal, false, []DeviceFound{prev})
		if len(first.Gone) != 0 || !slices.Equal(first.NoAnswer, []int{22}) || len(first.Dropped) != 0 || len(first.New) != 0 {
			t.Fatalf("%s: first check after the rate limit: %+v (want 22 kept as no answer)", name, first)
		}
		second := foundOf(h, nmapargv.Normal, false, []DeviceFound{first, prev})
		if len(second.Gone) != 0 || len(second.NoAnswer) != 0 || !slices.Equal(second.Dropped, []int{22}) {
			t.Fatalf("%s: second check with no answer: %+v (want 22 dropped)", name, second)
		}
		// 22 answers again after the first miss: not "newly open"
		back := h
		back.ports = append(slices.Clone(h.ports), portInfo{number: 22, proto: "tcp", name: "ssh"})
		again := foundOf(back, nmapargv.Normal, false, []DeviceFound{first, prev})
		if len(again.New) != 0 || len(again.Gone) != 0 || len(again.Dropped) != 0 {
			t.Fatalf("%s: 22 back after one miss: %+v", name, again)
		}
	}
	// the listed fixture's port 80 refused the connection: closed at once
	hosts, _ := parseNmapXML(fixture(t, "ratelimited_listed.xml"))
	prev := DeviceFound{Reach: "top1000", Open: 2, Ports: []FoundPort{{Port: 53, Proto: "tcp"}, {Port: 80, Proto: "tcp"}}}
	if f := foundOf(hosts[0], nmapargv.Normal, false, []DeviceFound{prev}); !slices.Equal(f.Gone, []int{80}) || len(f.NoAnswer) != 0 {
		t.Fatalf("a port that refused the connection: %+v (want 80 gone)", f)
	}
	// the words and the items round-trip
	f := foundOf(hosts[0], nmapargv.Normal, false, []DeviceFound{{Reach: "top1000", Open: 1, Ports: []FoundPort{{Port: 22, Proto: "tcp"}}}})
	var back DeviceFound
	for _, it := range foundItems("a1", hosts[0].addr, f) {
		if it.SubjectKind == itemPort && it.Outcome == "no_answer" {
			p, _ := parsePortLabel(it.Label)
			back.NoAnswer = append(back.NoAnswer, p.Port)
		}
	}
	if !slices.Equal(back.NoAnswer, []int{22}) {
		t.Fatalf("items of a check with no answer from 22: %+v", foundItems("a1", hosts[0].addr, f))
	}
}

// The device's record after a rate-limited check: the services of the ports that gave no answer and were open before stay (outside
// the replace scope), and the software read from them is not replaced by a list that misses them.
func TestNoAnswerKeepsServicesAndSoftware(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "ratelimited_grouped.xml"))
	if err != nil {
		t.Fatal(err)
	}
	h := hosts[0]
	rec := &recordingSinks{}
	s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now, obs: rec, sw: rec, svc: rec}
	prev := DeviceFound{Reach: "top1000", Open: 3, Ports: []FoundPort{{Port: 22, Proto: "tcp"}, {Port: 53, Proto: "tcp"}, {Port: 443, Proto: "tcp"}}}
	f := foundOf(h, nmapargv.Normal, false, []DeviceFound{prev})
	if err := s.recordHost(context.Background(), "a1", h.addr, h, nmapargv.Normal, f.NoAnswer); err != nil {
		t.Fatal(err)
	}
	if len(rec.scopes) != 1 || inRanges(rec.scopes[0].Ports, 22) || !inRanges(rec.scopes[0].Ports, 21) || !inRanges(rec.scopes[0].Ports, 53) {
		t.Fatalf("replace scopes %+v: want every scanned port but 22", rec.scopes)
	}
	if rec.swCalls != 0 {
		t.Fatalf("software replaced %d times by a check that got no answer from a port open before", rec.swCalls)
	}
	// a complete check (22 refused the connection): software and every scanned port are replaced
	rec2 := &recordingSinks{}
	s.obs, s.sw, s.svc = rec2, rec2, rec2
	if err := s.recordHost(context.Background(), "a1", h.addr, h, nmapargv.Normal, nil); err != nil {
		t.Fatal(err)
	}
	if rec2.swCalls != 1 || len(rec2.scopes) != 1 || !inRanges(rec2.scopes[0].Ports, 22) {
		t.Fatalf("a complete check: %d software replaces, scopes %+v", rec2.swCalls, rec2.scopes)
	}
}

type recordingSinks struct {
	scopes  []observe.ServiceScope
	swCalls int
}

func (r *recordingSinks) Record(context.Context, []observe.Observation) error { return nil }
func (r *recordingSinks) ReplaceSoftware(context.Context, observe.AssetHint, observe.Source, []string, []observe.Software) error {
	r.swCalls++
	return nil
}
func (r *recordingSinks) ReplaceServices(_ context.Context, _ observe.AssetHint, _ observe.Source, sc observe.ServiceScope, _ []observe.Service) error {
	r.scopes = append(r.scopes, sc)
	return nil
}
func (r *recordingSinks) AddServices(context.Context, observe.AssetHint, observe.Source, []observe.Service) error {
	return nil
}
func (r *recordingSinks) PortReadTimes(context.Context, string, observe.Source) (map[int]time.Time, error) {
	return nil, nil
}
