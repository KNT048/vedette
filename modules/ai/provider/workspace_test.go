package provider

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Issue #118: an Anthropic key that is not scoped to a workspace gets HTTP 400 for every request. The adapter answers with its own
// error so the connection test can say what to do, and the key never appears in it.
const noWorkspaceBody = `{"type":"error","error":{"type":"invalid_request_error","message":"This API key is not scoped to a workspace, so this request must include the anthropic-workspace-id header."},"request_id":"req_0123"}`

func TestAnthropicKeyWithoutWorkspaceIsATypedError(t *testing.T) {
	srv := serve(t, 400, noWorkspaceBody, nil)
	p := must(t, cfg(StyleAnthropic, srv.URL))
	_, err := p.Complete(t.Context(), simpleReq)
	if !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("err = %v, want ErrNoWorkspace", err)
	}
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 400 {
		t.Fatalf("err = %#v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("the error holds the key: %v", err)
	}
	// the same 400 about something else stays an ordinary refused request
	srv2 := serve(t, 400, `{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: too large"}}`, nil)
	_, err = must(t, cfg(StyleAnthropic, srv2.URL)).Complete(t.Context(), simpleReq)
	if !errors.Is(err, ErrRequest) || errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("other 400 = %v", err)
	}
	// a probe stops at the first request with this error
	if _, err := Probe(t.Context(), p, func() time.Time { return time.Unix(0, 0) }); !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("probe err = %v", err)
	}
}
