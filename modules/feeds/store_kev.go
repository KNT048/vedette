package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The reads below are for the modules that use the exploited lists through their own ports (inventory.KEV, findings.Feeds). They
// answer from the CISA list and VulnCheck KEV only: a custom feed's CVE is not a KEV entry.

// ProductCount is a vendor and product pair of the CISA list with the number of its CVEs.
type ProductCount struct {
	Vendor, Product string
	Count           int
}

// KevProducts lists every vendor and product pair of the exploited lists with its CVE count, and a version that changes whenever
// the set of entries does (entry count and newest update).
func (s *Store) KevProducts(ctx context.Context) (version string, list []ProductCount, err error) {
	var n int
	var newest string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*), coalesce(max(updated_at), '') FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')`).Scan(&n, &newest); err != nil {
		return "", nil, fmt.Errorf("feeds: read KEV version: %w", err)
	}
	all, err := s.KevVulns(ctx)
	if err != nil {
		return "", nil, err
	}
	at := map[Product]int{}
	for _, v := range all {
		p := Product{Vendor: v.Vendor, Product: v.Product}
		i, ok := at[p]
		if !ok {
			i = len(list)
			at[p] = i
			list = append(list, ProductCount{Vendor: v.Vendor, Product: v.Product})
		}
		list[i].Count++
	}
	slices.SortFunc(list, func(a, b ProductCount) int {
		if c := strings.Compare(strings.ToLower(a.Vendor), strings.ToLower(b.Vendor)); c != 0 {
			return c
		}
		if c := strings.Compare(strings.ToLower(a.Product), strings.ToLower(b.Product)); c != 0 {
			return c
		}
		if c := strings.Compare(a.Vendor, b.Vendor); c != 0 {
			return c
		}
		return strings.Compare(a.Product, b.Product)
	})
	return fmt.Sprintf("%d@%s", n, newest), list, nil
}

// KevCVEsByKeys returns the CVEs of the exploited lists for these product keys (productid.Key form, lower case). A "Multiple
// products" entry of a vendor matches every key of that vendor (INV-11).
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
	all, err := s.KevVulns(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, v := range all {
		if want[v.Key()] {
			out = append(out, v.CVE)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// KevVulns returns the owner entry of every CVE of the exploited lists (CISA, VulnCheck), for matching.
func (s *Store) KevVulns(ctx context.Context) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `AND `+kevSources+` ORDER BY k.cve`)
}

// KevVulnsByCVE returns the owner entries of the exploited lists for these CVEs (upper case); CVEs not on them are absent.
func (s *Store) KevVulnsByCVE(ctx context.Context, cves []string) ([]VulnRow, error) {
	out := []VulnRow{}
	for chunk := range slices.Chunk(cves, 400) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: read vulnerabilities: %w", err)
		}
		rows, err := queryVulns(ctx, s.db.Reader(), `AND `+kevSources+` AND k.cve IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// KevPulledAt is when the CISA list was last pulled successfully (zero = never). The weekly report names it as the source time of
// its exploited-list figures.
func (s *Store) KevPulledAt(ctx context.Context) (time.Time, error) {
	r, err := s.source(ctx, "cisa-kev")
	if errors.Is(err, ErrNotFound) || (err == nil && r.LastSuccess == nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("feeds: read KEV pull time: %w", err)
	}
	return *r.LastSuccess, nil
}
