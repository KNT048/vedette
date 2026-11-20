// Package selfcheck is the registry of data invariants and the runner behind `vedette selfcheck`.
//
// An invariant is a named read-only query that returns one number: how many rows break the rule. Zero means the rule holds.
// Every module registers its own invariants from an init function in its package, next to the code that owns the data, so a
// rule is added where its table lives. The runner opens the database read-only: it never migrates, creates or writes.
package selfcheck

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Invariant is one rule. Name is "<module>.<rule>" in lower case; Query is a single SELECT that returns one integer column
// with one row: the number of violating rows. A rule SQL cannot state (a value recomputed by a Go function, such as a schedule's
// next due time across time zones) gives Count instead of Query: it reads through the read-only handle and returns the number.
type Invariant struct {
	Name  string
	Query string
	Count func(ctx context.Context, db *sql.DB) (int64, error)
}

var nameRule = regexp.MustCompile(`^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_]*$`)

var (
	mu       sync.Mutex
	registry []Invariant
)

// Register adds an invariant. It panics on a malformed or duplicate name or a query that is not one SELECT, because the
// call is made from an init function and a mistake must stop the build's own tests, not a customer's box.
func Register(inv Invariant) {
	if !nameRule.MatchString(inv.Name) {
		panic(fmt.Sprintf("selfcheck: invalid invariant name %q (want module.rule)", inv.Name))
	}
	q := strings.TrimSpace(inv.Query)
	switch {
	case inv.Count != nil && q != "":
		panic(fmt.Sprintf("selfcheck: invariant %q has both a query and a count", inv.Name))
	case inv.Count == nil && (!strings.HasPrefix(strings.ToUpper(q), "SELECT") || strings.Contains(strings.TrimSuffix(q, ";"), ";")):
		panic(fmt.Sprintf("selfcheck: invariant %q must be a single SELECT", inv.Name))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range registry {
		if r.Name == inv.Name {
			panic(fmt.Sprintf("selfcheck: invariant %q registered twice", inv.Name))
		}
	}
	registry = append(registry, Invariant{Name: inv.Name, Query: q, Count: inv.Count})
}

// Registered returns every invariant, sorted by name.
func Registered() []Invariant {
	mu.Lock()
	out := slices.Clone(registry)
	mu.Unlock()
	slices.SortFunc(out, func(a, b Invariant) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Result is the outcome of one invariant. Err is set when the query itself could not run (a missing table, for example);
// that counts as a failure.
type Result struct {
	Name  string
	Count int64
	Err   error
}

// Failed reports whether the invariant does not hold.
func (r Result) Failed() bool { return r.Err != nil || r.Count != 0 }

// OpenReadOnly opens an existing database file read-only: the file is never created, and no write, pragma that writes or
// migration is possible through the handle. Data is never written, but on a WAL database SQLite may create empty -wal and
// -shm side files next to it.
func OpenReadOnly(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("selfcheck: resolve path: %w", err)
	}
	if st, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("selfcheck: %w", err)
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("selfcheck: %s is not a database file", abs)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "query_only(1)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, fmt.Errorf("selfcheck: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Run evaluates the invariants in order, one result each. A query error is recorded in its result and the run goes on.
func Run(ctx context.Context, db *sql.DB, invs []Invariant) []Result {
	out := make([]Result, 0, len(invs))
	for _, inv := range invs {
		res := Result{Name: inv.Name}
		if inv.Count != nil {
			res.Count, res.Err = inv.Count(ctx, db)
		} else if err := db.QueryRowContext(ctx, inv.Query).Scan(&res.Count); err != nil {
			res.Err = err
		}
		out = append(out, res)
	}
	return out
}

// ErrFailed is returned by Command when at least one invariant does not hold.
var ErrFailed = errors.New("selfcheck: an invariant does not hold")

// Command is `vedette selfcheck`: it opens the database read-only, runs every registered invariant, prints one line each
// ("ok" or "FAIL", the count, the name) and returns ErrFailed when any invariant fails.
func Command(ctx context.Context, dbPath string, invs []Invariant, stdout io.Writer) error {
	db, err := OpenReadOnly(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	failed := 0
	for _, r := range Run(ctx, db, invs) {
		status := "ok  "
		if r.Failed() {
			status = "FAIL"
			failed++
		}
		line := fmt.Sprintf("%s %6d  %s", status, r.Count, r.Name)
		if r.Err != nil {
			line = fmt.Sprintf("%s %6s  %s: %v", status, "-", r.Name, r.Err)
		}
		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}
	if failed > 0 {
		_, _ = fmt.Fprintf(stdout, "%d of %d invariants do not hold\n", failed, len(invs))
		return ErrFailed
	}
	_, err = fmt.Fprintf(stdout, "all %d invariants hold\n", len(invs))
	return err
}

func init() {
	Register(Invariant{
		Name:  "sqlite.foreign_key_violations",
		Query: `SELECT count(*) FROM pragma_foreign_key_check`,
	})
}
