package server_test

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// writingHandler is a module handler whose operation writes to the database.
type writingHandler struct {
	server.Fallback
	db *store.DB
}

func (h writingHandler) FeedsDeleteFeedsCustomID(ctx context.Context, _ oas.FeedsDeleteFeedsCustomIDParams) error {
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (1)")
		return err
	})
}

// While a long transaction holds the writer, a request that needs it is answered 503 server_busy with Retry-After within
// store.RequestWriteWait, never a 500 and never a hang (D-246, issue #251).
func TestRequestGets503WhenTheWriterStaysBusy(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "CREATE TABLE t (v INTEGER)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	logs := &strings.Builder{}
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, nil))
	h, err := server.New(server.Config{
		API:  writingHandler{Fallback: server.Fallback{Log: log}, db: db},
		Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: servertest.NewGate(), Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{h: h, logs: logs}

	taken, free, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { // a module's long transaction, as the feeds pull of issue #251
		held <- db.Write(context.Background(), func(*sql.Tx) error { close(taken); <-free; return nil })
	}()
	<-taken
	start := time.Now()
	rec := r.do(t, req{method: "DELETE", path: "/feeds/custom/x", user: "admin", csrf: true})
	took := time.Since(start)
	close(free)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	b := wantError(t, rec, 503, "server_busy")
	if took < store.RequestWriteWait || took > store.RequestWriteWait+2*time.Second {
		t.Errorf("answered after %v, want about %v", took, store.RequestWriteWait)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "5" {
		t.Errorf("Retry-After = %q, want 5", ra)
	}
	if b.Error["retry_after"] != float64(5) {
		t.Errorf("retry_after = %v, want 5", b.Error["retry_after"])
	}
	if strings.Contains(logs.String(), "request failed") {
		t.Errorf("a busy writer was logged as a server fault:\n%s", logs)
	}

	// With the writer free again the same request goes through.
	if rec := r.do(t, req{method: "DELETE", path: "/feeds/custom/x", user: "admin", csrf: true}); rec.Code != 204 {
		t.Fatalf("status = %d after the writer was freed; body %s", rec.Code, rec.Body)
	}
}
