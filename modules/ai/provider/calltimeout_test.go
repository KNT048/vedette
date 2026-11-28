package provider

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// deadlineTrip records the deadline of the request it is given and answers nothing.
type deadlineTrip struct{ left time.Duration }

func (d *deadlineTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	if dl, ok := r.Context().Deadline(); ok {
		d.left = time.Until(dl)
	}
	return nil, errors.New("no network in this test")
}

// A request may carry its own, longer timeout (a research turn whose provider-side tools run for minutes): every API style sends it with
// that deadline instead of the client's short one, and a request without one keeps the client's.
func TestRequestTimeoutOutlivesTheClientTimeout(t *testing.T) {
	t.Parallel()
	for _, style := range []APIStyle{StyleAnthropic, StyleOpenAI, StyleGemini} {
		p, err := New(Config{Style: style, BaseURL: "https://models.example.com", Model: "m-1", APIKey: NewSecret("k"), Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		trip := &deadlineTrip{}
		switch c := p.(type) {
		case *anthropic:
			c.h.c.Transport = trip
		case *openAI:
			c.h.c.Transport = trip
		case *gemini:
			c.h.c.Transport = trip
		}
		req := Request{Messages: []Message{{Role: RoleUser, Text: "hi"}}, MaxTokens: 10}
		_, _ = p.Complete(context.Background(), req)
		if trip.left <= 0 || trip.left > time.Second {
			t.Errorf("%s: a plain request has %v left, want the client's second", style, trip.left)
		}
		req.Timeout = 5 * time.Minute
		_, _ = p.Complete(context.Background(), req)
		if trip.left < 4*time.Minute {
			t.Errorf("%s: a request with its own 5 min timeout has %v left", style, trip.left)
		}
	}
}
