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
	if took < limit || took > limit+3*time.Second {
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

// A write detached with WithoutCancel ("must happen even if the caller leaves") waits on its own while the request is still live.
func TestWriteDetachedWaitsWhileTheRequestIsLive(t *testing.T) {
	db, _ := openLogged(t)
	release := holdWriter(t, db)
	reqCtx, endRequest := context.WithCancel(t.Context())
	defer endRequest()
	detached := context.WithoutCancel(store.LimitWriteWait(reqCtx, 50*time.Millisecond))
	time.AfterFunc(300*time.Millisecond, release)
	if err := insert(detached, db, "record"); err != nil {
		t.Fatalf("detached write during the request: %v", err)
	}
}

// A request that ends while its write waits lifts the limit for that write: it goes on waiting like a job.
func TestWriteLimitLiftsWhenTheRequestEndsDuringTheWait(t *testing.T) {
	db, _ := openLogged(t)
	release := holdWriter(t, db)
	reqCtx, endRequest := context.WithCancel(t.Context())
	// a background write started by the request, still bound to its life by a value-only link (not WithoutCancel)
	bg := &valueOnly{Context: store.LimitWriteWait(reqCtx, 200*time.Millisecond), base: t.Context()}
	time.AfterFunc(50*time.Millisecond, endRequest)
	time.AfterFunc(500*time.Millisecond, release)
	if err := insert(bg, db, "bg"); err != nil {
		t.Fatalf("write whose request ended during the wait: %v", err)
	}
}

// valueOnly takes the values of Context and the cancellation of base: a goroutine started by a request with its own lifetime.
type valueOnly struct {
	context.Context
	base context.Context
}

func (v *valueOnly) Done() <-chan struct{}       { return v.base.Done() }
func (v *valueOnly) Err() error                  { return v.base.Err() }
func (v *valueOnly) Deadline() (time.Time, bool) { return v.base.Deadline() }

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
		<-time.After(store.SlowWrite + 50*time.Millisecond) // a real hold of the writer: SQLite I/O does not run under synctest
		return nil
	})
}

// A panic in fn still names the function that called Write, not a frame of the panic.
func TestWriteLogsTheCallerOfAPanickingTransaction(t *testing.T) {
	db, logs := openLogged(t)
	func() {
		defer func() { _ = recover() }()
		_ = panickingWrite(t.Context(), db)
	}()
	if out := logs.String(); !strings.Contains(out, "caller=github.com/knt048/vedette/core/store_test.panickingWrite") {
		t.Errorf("caller of the panicking write not logged:\n%s", out)
	}
}

func panickingWrite(ctx context.Context, db *store.DB) error {
	return db.Write(ctx, func(*sql.Tx) error {
		<-time.After(store.SlowWrite + 50*time.Millisecond) // a real hold of the writer: SQLite I/O does not run under synctest
		panic("boom")
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

// A rollback that finds the transaction already gone is not an error. SQLite rolls a transaction back by itself when a statement is
// interrupted (the driver interrupts it when ctx ends, so at every shutdown) and on some I/O errors; the ROLLBACK that Write sends then
// fails with "no transaction is active", which Write logged as ERROR, and the end-to-end harness fails on any ERROR line (CI, #374).
// Here fn ends the transaction under database/sql itself, which leaves SQLite in that state on every run.
func TestWriteWhoseTransactionSQLiteAlreadyEndedLogsNoError(t *testing.T) {
	db, logs := openLogged(t)
	boom := errors.New("boom")
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), "INSERT INTO t VALUES ('gone')"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), "ROLLBACK"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Write = %v, want fn's error", err)
	}
	if out := logs.String(); strings.Contains(out, "level=ERROR") {
		t.Errorf("a rollback with no transaction left was logged as an error:\n%s", out)
	}
	if err := insert(t.Context(), db, "after"); err != nil || count(t, db, "after") != 1 || count(t, db, "gone") != 0 {
		t.Errorf("the writer after it: %v, %d rows 'after', %d rows 'gone'", err, count(t, db, "after"), count(t, db, "gone"))
	}
}

// The case seen at shutdown: writes interrupted by the end of their context. Whether database/sql's own rollback or Write's reaches the
// driver first is a race (about one write in 200 sent its ROLLBACK after SQLite had rolled back, on a loaded Mac); in no order is it an
// ERROR line.
func TestWritesInterruptedByTheirContextLogNoError(t *testing.T) {
	db, logs := openLogged(t)
	for range 50 {
		ctx, cancel := context.WithCancel(t.Context())
		err := db.Write(ctx, func(tx *sql.Tx) error {
			go func() { <-time.After(time.Millisecond); cancel() }() // only a trigger: before the statement or inside it, both are fine
			_, err := tx.ExecContext(ctx, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) INSERT INTO t SELECT x FROM c`)
			return err
		})
		cancel()
		if err == nil {
			t.Fatal("an endless insert committed")
		}
	}
	if out := logs.String(); strings.Contains(out, "level=ERROR") {
		t.Errorf("an interrupted write was logged as an error:\n%s", out)
	}
	if err := insert(t.Context(), db, "after"); err != nil {
		t.Errorf("the writer after the interrupted writes: %v", err)
	}
}
