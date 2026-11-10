package findings

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// The event bus gives every handler a deadline (core/events DefaultTimeout, 5 s). While a long write holds the one
// writer (a KEV pull of 1,800 records, the first sync), a handler that waits for the writer past that deadline used
// to fail with "store: begin: context deadline exceeded": the event was gone for good and the finding was never created
// (or the findings of a deleted device stayed behind). The two handlers now wait for the writer on their own deadline.

// holdWriter keeps the single writer busy until the returned function is called.
func (e *env) holdWriter() (release func()) {
	e.t.Helper()
	held, rel, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = e.db.Write(context.Background(), func(*sql.Tx) error {
			close(held)
			<-rel
			return nil
		})
	}()
	<-held
	return func() { close(rel); <-done }
}

// busDeadline is a context whose deadline has passed by the time the writer is released.
func busDeadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestMatchIsNotLostWhenTheWriterIsBusyPastTheBusDeadline(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	release := e.holdWriter()
	hctx := busDeadline(t)
	type result struct {
		res UpsertResult
		err error
	}
	out := make(chan result, 1)
	go func() {
		res, err := e.svc.OnMatchChanged(hctx, "a-1")
		out <- result{res, err}
	}()
	<-hctx.Done() // the handler's deadline has passed and the writer is still held
	release()
	r := <-out
	if r.err != nil || len(r.res.Created) != 1 {
		t.Fatalf("OnMatchChanged after the deadline: %+v, %v", r.res, r.err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding`) != 1 {
		t.Fatal("the finding was not created")
	}
}

func TestDeviceDeleteIsNotLostWhenTheWriterIsBusyPastTheBusDeadline(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	release := e.holdWriter()
	hctx := busDeadline(t)
	type result struct {
		n   int
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := e.svc.OnAssetDeleted(hctx, "a-1")
		out <- result{n, err}
	}()
	<-hctx.Done()
	release()
	r := <-out
	if r.err != nil || r.n != 1 {
		t.Fatalf("OnAssetDeleted after the deadline: %d, %v", r.n, r.err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-1'`) != 0 {
		t.Fatal("the findings of the deleted device are still there")
	}
}
