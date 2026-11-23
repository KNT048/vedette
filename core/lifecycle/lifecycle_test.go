package lifecycle_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store/storetest"
)

// Participants run in registration order inside the caller's transaction; the first error stops the others and rolls back what
// the earlier ones wrote.
func TestHooksRunInOrderAndAnErrorRollsBack(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE t_moved (name TEXT NOT NULL)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var ran []string
	write := func(name string, fail error) lifecycle.Participant {
		return lifecycle.Participant{Name: name, DeviceMerged: func(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
			ran = append(ran, name)
			if _, err := tx.ExecContext(ctx, `INSERT INTO t_moved (name) VALUES (?)`, name+":"+m.From+">"+m.Into); err != nil {
				return err
			}
			return fail
		}}
	}
	var h lifecycle.Hooks
	h.Register(write("first", nil))
	h.Register(lifecycle.Participant{Name: "deletes only", DeviceDeleted: func(context.Context, *sql.Tx, lifecycle.Delete) error { return nil }})
	h.Register(write("second", nil))
	if got := h.Names(); !slices.Equal(got, []string{"first", "deletes only", "second"}) {
		t.Fatalf("names %v", got)
	}
	m := lifecycle.Merge{From: "a", Into: "b"}
	if err := db.Write(ctx, func(tx *sql.Tx) error { return h.DeviceMerged(ctx, tx, m) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ran, []string{"first", "second"}) {
		t.Fatalf("ran %v", ran)
	}
	count := func() int {
		var n int
		if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM t_moved`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}

	boom := errors.New("boom")
	h.Register(write("third", boom))
	h.Register(write("fourth", nil))
	ran = nil
	err := db.Write(ctx, func(tx *sql.Tx) error { return h.DeviceMerged(ctx, tx, m) })
	if !errors.Is(err, boom) {
		t.Fatalf("error %v, want boom", err)
	}
	if !slices.Equal(ran, []string{"first", "second", "third"}) {
		t.Fatalf("ran %v: the fourth must not run after the third failed", ran)
	}
	if n := count(); n != 2 {
		t.Fatalf("%d rows after the failed merge, want the 2 of before", n)
	}
}

func TestNilHooksCallNothing(t *testing.T) {
	t.Parallel()
	var h *lifecycle.Hooks
	if err := h.DeviceMerged(t.Context(), nil, lifecycle.Merge{}); err != nil {
		t.Fatal(err)
	}
	if err := h.DeviceDeleted(t.Context(), nil, lifecycle.Delete{}); err != nil {
		t.Fatal(err)
	}
	if err := h.FindingFolded(t.Context(), nil, lifecycle.FindingFold{}); err != nil {
		t.Fatal(err)
	}
	if err := h.FindingMoved(t.Context(), nil, lifecycle.FindingMove{}); err != nil {
		t.Fatal(err)
	}
	h.MergeCommitted(t.Context(), lifecycle.Merge{})
	h.DeleteCommitted(t.Context(), lifecycle.Delete{})
}

func TestRegisterRefusesADuplicateOrNamelessParticipant(t *testing.T) {
	t.Parallel()
	for _, p := range []lifecycle.Participant{{}, {Name: "x"}} {
		var h lifecycle.Hooks
		h.Register(lifecycle.Participant{Name: "x"})
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", p.Name)
				}
			}()
			h.Register(p)
		}()
	}
}

func TestSoftwareIDFollowsAFold(t *testing.T) {
	t.Parallel()
	m := lifecycle.Merge{Software: map[string]string{"s1": "s9"}}
	if m.SoftwareID("s1") != "s9" || m.SoftwareID("s2") != "s2" {
		t.Fatal("SoftwareID")
	}
}
