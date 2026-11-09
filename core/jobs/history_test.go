package jobs_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

func migratedDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", os.DirFS("../../modules/core/migrations/sqlite")); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestHistoryKeepsLast200PerJob(t *testing.T) {
	t.Parallel()
	db := migratedDB(t)
	h := jobs.NewHistory(db)
	base := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	record := func(module, job string, i int, st jobs.Status, msg string) {
		t.Helper()
		at := base.Add(time.Duration(i) * time.Second)
		if err := h.Record(t.Context(), jobs.Run{Module: module, Job: job, StartedAt: at, FinishedAt: at.Add(time.Millisecond), Status: st, Error: msg}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range jobs.KeepRuns + 25 {
		record("feeds", "pull", i, jobs.StatusOK, "")
	}
	record("feeds", "other", 0, jobs.StatusError, "boom")
	record("scan", "pull", 0, jobs.StatusCancelled, "")

	var n int
	count := func(q string, args ...any) int {
		t.Helper()
		if err := db.Reader().QueryRowContext(t.Context(), q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count("SELECT count(*) FROM core_job_run WHERE module='feeds' AND job='pull'"); got != jobs.KeepRuns {
		t.Fatalf("rows for feeds/pull = %d, want %d", got, jobs.KeepRuns)
	}
	if got := count("SELECT count(*) FROM core_job_run WHERE job='other' OR module='scan'"); got != 2 {
		t.Fatalf("another job's rows were pruned: %d", got)
	}
	runs, err := h.Recent(t.Context(), "feeds", "pull", 3)
	if err != nil || len(runs) != 3 {
		t.Fatalf("Recent = %d rows, %v", len(runs), err)
	}
	if want := base.Add(time.Duration(jobs.KeepRuns+24) * time.Second); !runs[0].StartedAt.Equal(want) {
		t.Fatalf("newest run started %v, want %v (newest first)", runs[0].StartedAt, want)
	}
	oldest := count("SELECT count(*) FROM core_job_run WHERE module='feeds' AND job='pull' AND started_at < ?", store.FormatTS(base.Add(25*time.Second)))
	if oldest != 0 {
		t.Fatalf("the 25 oldest runs survived: %d", oldest)
	}
	errRuns, err := h.Recent(t.Context(), "feeds", "other", 10)
	if err != nil || len(errRuns) != 1 || errRuns[0].Status != jobs.StatusError || errRuns[0].Error != "boom" {
		t.Fatalf("error run = %+v, %v", errRuns, err)
	}
}

func TestHistoryRefusesBadRows(t *testing.T) {
	t.Parallel()
	db := migratedDB(t)
	h := jobs.NewHistory(db)
	now := time.Now()
	err := h.Record(t.Context(), jobs.Run{Module: "feeds", Job: "pull", StartedAt: now, FinishedAt: now, Status: "exploded"})
	if err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("an unknown status was accepted: %v", err)
	}
	err = h.Record(t.Context(), jobs.Run{Module: "feeds", Job: "pull", StartedAt: now, FinishedAt: now, Status: jobs.StatusError, Error: strings.Repeat("x", 1001)})
	if err == nil {
		t.Fatal("an error text over 1000 characters was accepted")
	}
	var n int
	if err := db.Reader().QueryRowContext(context.Background(), "SELECT count(*) FROM core_job_run").Scan(&n); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a refused run left %d rows", n)
	}
}
