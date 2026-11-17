package feeds

import (
	"database/sql"
	"fmt"
	"testing"
)

// PublishedOf answers every CVE asked for that NVD dated, across more than one chunk, and leaves the others out (#825: one query
// per chunk, not one per CVE).
func TestPublishedOfReadsEveryAskedCVEAcrossChunks(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	n := publishedChunk + 37
	write(t, db, func(tx *sql.Tx) error {
		for i := range n {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_published (cve, published) VALUES (?, ?)`, fmt.Sprintf("CVE-2024-%05d", i), fmt.Sprintf("2024-%02d-01", 1+i%12)); err != nil {
				return err
			}
		}
		return nil
	})
	ask := []string{"CVE-2099-0001"} // never dated
	for i := range n {
		ask = append(ask, fmt.Sprintf("CVE-2024-%05d", i))
	}
	got, err := s.PublishedOf(t.Context(), ask)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n || got["CVE-2024-00000"] != "2024-01-01" || got[fmt.Sprintf("CVE-2024-%05d", n-1)] != fmt.Sprintf("2024-%02d-01", 1+(n-1)%12) {
		t.Fatalf("got %d of %d, first %q", len(got), n, got["CVE-2024-00000"])
	}
	if _, ok := got["CVE-2099-0001"]; ok {
		t.Fatal("a CVE NVD never dated has a day")
	}
	if got, err := s.PublishedOf(t.Context(), nil); err != nil || len(got) != 0 {
		t.Fatalf("nothing asked: %v %v", got, err)
	}
}
