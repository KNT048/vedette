package core

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/host/api"
)

// The storage shape of the Privacy switch of update checks is shared with the code that writes Privacy
// (GET and PATCH /core/privacy): the key and the field name are what makes the switch work.
func TestPrivacySettingShapeIsPinned(t *testing.T) {
	t.Parallel()
	if keyPrivacy != "core_privacy" {
		t.Errorf("key = %q", keyPrivacy)
	}
	for in, want := range map[string]*bool{`{"update_check":false}`: ptr(false), `{"update_check":true}`: ptr(true), `{}`: nil, `{"update_check":false,"telemetry":true}`: ptr(false)} {
		var p privacySetting
		if err := json.Unmarshal([]byte(in), &p); err != nil {
			t.Fatal(err)
		}
		if (p.UpdateCheck == nil) != (want == nil) || (want != nil && *p.UpdateCheck != *want) {
			t.Errorf("%s decodes to %v, want %v", in, p.UpdateCheck, want)
		}
	}
	b, err := json.Marshal(privacySetting{UpdateCheck: ptr(false)})
	if err != nil || string(b) != `{"update_check":false}` {
		t.Errorf("encoded = %s %v", b, err)
	}
}

func ptr[T any](v T) *T { return &v }

// slowRunsHost never answers ListRuns until its context ends.
type slowRunsHost struct{ Host }

func (slowRunsHost) ListRuns(ctx context.Context, _ int) ([]api.Run, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// The shared read of the run has its own time limit: a host that never answers ends in 503 host_unreachable
// for the waiting request, not in a request that waits for ever.
func TestOSRunRebuildHasATimeLimit(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := &OSHandlers{host: slowRunsHost{}, log: slog.New(slog.DiscardHandler), now: time.Now, ctx: ctx, loadTimeout: 50 * time.Millisecond}
	reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer reqCancel()
	_, err := h.current(reqCtx)
	h.wg.Wait()
	ae, ok := apierr.As(err)
	if !ok || ae.Status != 503 || ae.Code != CodeHostUnreachable {
		t.Fatalf("current with a host that never answers = %v, want 503 host_unreachable", err)
	}
	if h.loading != nil || h.loaded {
		t.Errorf("a failed rebuild left loading=%v loaded=%v: the next request must try again", h.loading, h.loaded)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Error("the request's own deadline was not what ended it")
	}
}
