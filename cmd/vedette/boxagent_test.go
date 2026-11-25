package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

type fakeBoxAgentHost struct {
	calls  int
	gotCA  string
	errs   []error // the answer of each call, in turn (nil: accepted)
	result string
	status api.Status
}

func (f *fakeBoxAgentHost) BoxAgentCheck(_ context.Context, ca, _, _ string) (api.Run, error) {
	f.calls++
	f.gotCA = ca
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return api.Run{}, err
		}
	}
	return api.Run{RunID: "r1", Status: api.StatusRunning}, nil
}

func (f *fakeBoxAgentHost) GetRun(context.Context, string) (api.Run, error) {
	res, _ := json.Marshal(api.BoxAgentCheckResult{State: f.result})
	st := f.status
	if st == "" {
		st = api.StatusSucceeded
	}
	return api.Run{RunID: "r1", Status: st, Result: res}, nil
}

func TestCheckBoxAgentGivesTheAnchorAndSaysWhatToDoWhenItRemovedAStaleAgent(t *testing.T) {
	ca := []byte(testCAPEMForAnchor(t))
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	h := &fakeBoxAgentHost{result: api.BoxAgentRemoved}
	audited := 0
	checkBoxAgent(t.Context(), log, h, func() ([]byte, error) { return ca, nil }, func(context.Context) { audited++ }, func(context.Context) bool { return true })
	if h.calls != 1 || h.gotCA != string(ca) || audited != 1 {
		t.Fatalf("calls %d, CA given %v, audited %d", h.calls, h.gotCA == string(ca), audited)
	}
	if !strings.Contains(buf.String(), "run the install command from Devices › Setup › Agents on the box") {
		t.Fatalf("the log line must say what to do:\n%s", buf.String())
	}
	// nothing to do: no audit row, no warning
	buf.Reset()
	h = &fakeBoxAgentHost{result: api.BoxAgentCurrent}
	checkBoxAgent(t.Context(), log, h, func() ([]byte, error) { return ca, nil }, func(context.Context) { audited++ }, func(context.Context) bool { return true })
	if audited != 1 || strings.Contains(buf.String(), "WARN") {
		t.Fatalf("a current agent: audited %d, log %s", audited, buf.String())
	}
}

func TestCheckBoxAgentRetriesWhatCanGetBetterAndStopsOnAnOldHost(t *testing.T) {
	ca := []byte(testCAPEMForAnchor(t))
	log := slog.New(slog.DiscardHandler)
	waits := 0
	wait := func(context.Context) bool { waits++; return true }
	// the anchor is not ready at the very first start, then the host is busy once, then it answers
	ready := 0
	anchor := func() ([]byte, error) {
		if ready++; ready == 1 {
			return nil, errors.New("server_busy")
		}
		return ca, nil
	}
	h := &fakeBoxAgentHost{errs: []error{&hostclient.Error{Status: 429, Code: api.CodeRateLimited}}, result: api.BoxAgentNone}
	checkBoxAgent(t.Context(), log, h, anchor, func(context.Context) { t.Fatal("audited") }, wait)
	if waits != 2 || h.calls != 2 {
		t.Fatalf("waits %d calls %d, want 2 and 2", waits, h.calls)
	}
	// an older host does not know the command: one call, no retry
	waits = 0
	h = &fakeBoxAgentHost{errs: []error{&hostclient.Error{Status: 404, Code: api.CodeUnknownCommand}}}
	checkBoxAgent(t.Context(), log, h, func() ([]byte, error) { return ca, nil }, func(context.Context) { t.Fatal("audited") }, wait)
	if waits != 0 || h.calls != 1 {
		t.Fatalf("old host: waits %d calls %d", waits, h.calls)
	}
	// a host that keeps failing is tried boxAgentTries times, then the next start tries again
	waits = 0
	h = &fakeBoxAgentHost{errs: []error{errors.New("x"), errors.New("x"), errors.New("x"), errors.New("x"), errors.New("x"), errors.New("x")}}
	checkBoxAgent(t.Context(), log, h, func() ([]byte, error) { return ca, nil }, func(context.Context) { t.Fatal("audited") }, wait)
	if h.calls != boxAgentTries || waits != boxAgentTries-1 {
		t.Fatalf("failing host: calls %d waits %d", h.calls, waits)
	}
	// a run that failed is not retried
	h = &fakeBoxAgentHost{status: api.StatusFailed}
	waits = 0
	checkBoxAgent(t.Context(), log, h, func() ([]byte, error) { return ca, nil }, func(context.Context) { t.Fatal("audited") }, wait)
	if h.calls != 1 || waits != 0 {
		t.Fatalf("failed run: calls %d waits %d", h.calls, waits)
	}
}
