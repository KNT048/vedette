package feeds

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// The reads below are for the modules that use the CISA list through their own ports (inventory.KEV,
// findings.Feeds). They answer from cisa-kev rows only: a custom feed's CVE is not a KEV entry.

// ProductCount is a vendor and product pair of the CISA list with the number of its CVEs.
type ProductCount struct {
	Vendor, Product string
	Count           int
}

// KevProducts lists every vendor and product pair of the CISA list with its CVE count, and a version that
// changes whenever the set of rows does (row count and newest update).
func (s *Store) KevProducts(ctx context.Context) (version string, list []ProductCount, err error) {
	var n int
	var newest string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*), coalesce(max(updated_at), '') FROM feeds_vuln WHERE source_id = 'cisa-kev'`).Scan(&n, &newest); err != nil {
		return "", nil, fmt.Errorf("feeds: read KEV version: %w", err)
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT vendor, product, count(*) FROM feeds_vuln WHERE source_id = 'cisa-kev' GROUP BY vendor, product ORDER BY lower(vendor), lower(product)`)
	if err != nil {
		return "", nil, fmt.Errorf("feeds: read KEV products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p ProductCount
		if err := rows.Scan(&p.Vendor, &p.Product, &p.Count); err != nil {
			return "", nil, fmt.Errorf("feeds: read KEV products: %w", err)
		}
		list = append(list, p)
	}
	return fmt.Sprintf("%d@%s", n, newest), list, rows.Err()
}

// KevCVEsByKeys returns the CVEs of the CISA list for these product keys (ProductKey form, lower case). A
// "Multiple products" entry of a vendor matches every key of that vendor (INV-11).
func (s *Store) KevCVEsByKeys(ctx context.Context, keys []string) ([]string, error) {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
		if v, _, ok := strings.Cut(k, "|"); ok {
			want[v+"|multiple products"] = true
		}
	}
	if len(want) == 0 {
		return []string{}, nil
	}
	all := slices.Sorted(func(yield func(string) bool) {
		for k := range want {
			if !yield(k) {
				return
			}
		}
	})
	out := []string{}
	for chunk := range slices.Chunk(all, 400) {
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev' AND product_key IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`) ORDER BY cve`, args...)
		if err != nil {
			return nil, fmt.Errorf("feeds: read CVEs of products: %w", err)
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: read CVEs of products: %w", err)
			}
			out = append(out, c)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// KevVulns returns every row of the CISA list, for matching.
func (s *Store) KevVulns(ctx context.Context) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `WHERE source_id = 'cisa-kev' ORDER BY cve`)
}

// KevVulnsByCVE returns the rows of the CISA list for these CVEs (upper case); CVEs not on it are absent.
func (s *Store) KevVulnsByCVE(ctx context.Context, cves []string) ([]VulnRow, error) {
	out := []VulnRow{}
	for chunk := range slices.Chunk(cves, 400) {
		args := make([]any, len(chunk))
		for i, c := range chunk {
			args[i] = c
		}
		rows, err := queryVulns(ctx, s.db.Reader(), `WHERE source_id = 'cisa-kev' AND cve IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}
