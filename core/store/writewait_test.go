package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// syncBuf is a log sink that two goroutines may write to.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func openLogged(t *testing.T) (*store.DB, *syncBuf) {
	t.Helper()
	buf := &syncBuf{}
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "w.db"), slog.New(slog.NewTextHandler(buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "CREATE TABLE t (v TEXT)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return db, buf
}

// holdWriter starts a write that keeps the writer until release is called; it returns once the writer is taken.
func holdWriter(t *testing.T, db *store.DB) (release func()) {
	t.Helper()
	taken, free, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- db.Write(context.Background(), func(tx *sql.Tx) error {
			close(taken)
			<-free
			_, err := tx.ExecContext(context.Background(), "INSERT INTO t VALUES ('holder')")
			return err
		})
	}()
	<-taken
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(free)
			if err := <-done; err != nil {
				t.Errorf("holder: %v", err)
			}
		})
	}
	t.Cleanup(release)
	return release
}

func insert(ctx context.Context, db *store.DB, v string) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (?)", v)
		return err
	})
}

func count(t *testing.T, db *store.DB, v string) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(t.Context(), "SELECT count(*) FROM t WHERE v = ?", v).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A request whose writer stays taken past its limit is refused with ErrBusy within the limit, nothing is written, and the
// refusal is logged with the caller (D-246).
func TestWriteRequestIsRefusedWhenTheWriterStaysBusy(t *testing.T) {
	db, logs := openLogged(t)
	holdWriter(t, db)
	const limit = 150 * time.Millisecond
	ctx := store.LimitWriteWait(t.Context(), limit)
	start := time.Now()
	err := insert(ctx, db, "request")
	took := time.Since(start)
	if !errors.Is(err, store.ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if took < limit || took > limit+time.Second {
		t.Errorf("refused after %v, want about %v", took, limit)
	}
	if n := count(t, db, "request"); n != 0 {
		t.Errorf("%d rows written by a refused write", n)
	}
	out := logs.String()
	if !strings.Contains(out, "writer stayed busy") || !strings.Contains(out, "module=core/store_test") ||
		!strings.Contains(out, "caller=github.com/knt048/vedette/core/store_test.insert") {
		t.Errorf("refusal log line missing or without its caller:\n%s", out)
	}
}

// Within the limit, a request waits for the writer like before.
func TestWriteRequestWaitsWithinTheLimit(t *testing.T) {
	db, _ := openLogged(t)
	release := holdWriter(t, db)
	ctx := store.LimitWriteWait(t.Context(), 5*time.Second)
	time.AfterFunc(100*time.Millisecond, release)
	if err := insert(ctx, db, "request"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, "request"); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// Jobs and other background work carry no limit: they wait for the writer on their own context, however long the hold (D-246).
func TestWriteJobsWaitOnTheirOwnContext(t *testing.T) {
	db, _ := openLogged(t)
	release := holdWriter(t, db)
	time.AfterFunc(400*time.Millisecond, release)
	if err := insert(t.Context(), db, "job"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, "job"); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// Work detached from a request keeps the value but not the limit once the request has ended: it waits like a job.
func TestWriteLimitEndsWithTheRequest(t *testing.T) {
	db, _ := openLogged(t)
	release := holdWriter(t, db)
	reqCtx, endRequest := context.WithCancel(t.Context())
	detached := context.WithoutCancel(store.LimitWriteWait(reqCtx, 50*time.Millisecond))
	endRequest()
	time.AfterFunc(300*time.Millisecond, release)
	if err := insert(detached, db, "after"); err != nil {
		t.Fatalf("detached write after the request ended: %v", err)
	}
}

// The caller's own deadline, shorter than the limit, is still the caller's error, not ErrBusy.
func TestWriteCallerDeadlineIsNotBusy(t *testing.T) {
	db, _ := openLogged(t)
	holdWriter(t, db)
	ctx, cancel := context.WithTimeout(store.LimitWriteWait(t.Context(), 5*time.Second), 50*time.Millisecond)
	defer cancel()
	err := insert(ctx, db, "x")
	if errors.Is(err, store.ErrBusy) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller's deadline", err)
	}
}

func slowWrite(ctx context.Context, db *store.DB) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO t VALUES ('secret-value')"); err != nil {
			return err
		}
		time.Sleep(store.SlowWrite + 50*time.Millisecond)
		return nil
	})
}

// A transaction that held the writer past SlowWrite is logged with its module, caller and duration, never its SQL or values.
func TestWriteLogsALongTransaction(t *testing.T) {
	db, logs := openLogged(t)
	if err := slowWrite(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "held the database writer") || !strings.Contains(out, "module=core/store_test") ||
		!strings.Contains(out, "caller=github.com/knt048/vedette/core/store_test.slowWrite") || !strings.Contains(out, "held=1.") {
		t.Errorf("long transaction not logged with module, caller and duration:\n%s", out)
	}
	if strings.Contains(out, "secret-value") || strings.Contains(out, "INSERT") {
		t.Errorf("the log carries SQL or values:\n%s", out)
	}
	// A short transaction is not logged.
	before := len(out)
	if err := insert(t.Context(), db, "quick"); err != nil {
		t.Fatal(err)
	}
	if extra := logs.String()[before:]; strings.Contains(extra, "held the database writer") {
		t.Errorf("a quick write was logged: %s", extra)
	}
}
