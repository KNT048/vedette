package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// A sensor link request gets the writer wait limit: while another transaction holds the writer, its write answers ErrBusy
// (which the sensor backends turn into 503 store_busy) instead of waiting for the request's whole deadline (D-246).
func TestLimitWritesGivesSensorRequestsTheWaitLimit(t *testing.T) {
	db := storetest.New(t)
	taken, free, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		held <- db.Write(context.Background(), func(*sql.Tx) error { close(taken); <-free; return nil })
	}()
	<-taken
	var got error
	h := limitWrites(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = db.Write(r.Context(), func(*sql.Tx) error { return nil })
	}), 100*time.Millisecond)
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/sensor/v1/observations", nil))
	took := time.Since(start)
	close(free)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(got, store.ErrBusy) || took > 2*time.Second {
		t.Fatalf("write = %v after %v, want ErrBusy after about 100ms", got, took)
	}
}
