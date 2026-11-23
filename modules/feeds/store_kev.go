package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/productid"
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
	rows, err := s.db.Reader().QueryContext(ctx, kevOwnerKeysSQL) // the owner entries KevVulns reads, without the page columns
	if err != nil {
		return "", nil, fmt.Errorf("feeds: read KEV products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	at := map[Product]int{}
	for rows.Next() {
		var cve string
		var p Product
		if err := rows.Scan(&cve, &p.Vendor, &p.Product); err != nil {
			return "", nil, fmt.Errorf("feeds: read KEV products: %w", err)
		}
		i, ok := at[p]
		if !ok {
			i = len(list)
			at[p] = i
			list = append(list, ProductCount{Vendor: p.Vendor, Product: p.Product})
		}
		list[i].Count++
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("feeds: read KEV products: %w", err)
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
// products" entry of a vendor matches every key of that vendor (INV-11). It is one lookup in KevIndex.
func (s *Store) KevCVEsByKeys(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return []string{}, nil
	}
	idx, err := s.KevIndex(ctx)
	if err != nil {
		return nil, err
	}
	return idx.CVEs(keys), nil
}

// KevIndex holds the CVEs of the exploited lists (CISA, VulnCheck) by the product key of their owner entry (productid.Key). It is
// never changed once built, so callers share it and look up many keys in it without reading the database again.
type KevIndex struct{ byKey map[string][]string }

// CVEs returns the sorted CVEs listed for any of keys (productid.Key form, lower case). A "Multiple products" entry of a vendor
// matches every key of that vendor (INV-11). Never nil.
func (x *KevIndex) CVEs(keys []string) []string {
	out := []string{}
	if x == nil {
		return out
	}
	for _, k := range keys {
		out = append(out, x.byKey[k]...)
		if v, _, ok := strings.Cut(k, "|"); ok {
			out = append(out, x.byKey[v+"|"+multipleProducts]...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// multipleProducts is the product of an entry that names a vendor's whole range, as productid.Key writes it.
const multipleProducts = "multiple products"

// kevIndexCache keeps the last KevIndex with the stamp it was read under (kevStamp).
type kevIndexCache struct {
	mu    sync.Mutex
	stamp string
	idx   *KevIndex
}

// KevIndex returns the index of the exploited-list CVEs by product key. It is read again only when kevStamp moved: a device page or
// an agent report looks up all of its software in one index, and most calls cost one small stamp query instead of reading every
// entry of the lists.
func (s *Store) KevIndex(ctx context.Context) (*KevIndex, error) {
	stamp, err := s.kevStamp(ctx) // read before the entries: a write in between leaves an index newer than its stamp, never older
	if err != nil {
		return nil, err
	}
	s.kevIdx.mu.Lock() // held while reading, so concurrent callers under a moved stamp read the lists once
	defer s.kevIdx.mu.Unlock()
	if s.kevIdx.idx != nil && s.kevIdx.stamp == stamp {
		return s.kevIdx.idx, nil
	}
	rows, err := s.db.Reader().QueryContext(ctx, kevOwnerKeysSQL)
	if err != nil {
		return nil, fmt.Errorf("feeds: read KEV index: %w", err)
	}
	defer func() { _ = rows.Close() }()
	idx := &KevIndex{byKey: map[string][]string{}}
	for rows.Next() {
		var cve, vendor, product string
		if err := rows.Scan(&cve, &vendor, &product); err != nil {
			return nil, fmt.Errorf("feeds: read KEV index: %w", err)
		}
		k := productid.Key(vendor, product)
		idx.byKey[k] = append(idx.byKey[k], cve)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: read KEV index: %w", err)
	}
	for k, list := range idx.byKey {
		slices.Sort(list)
		idx.byKey[k] = slices.Compact(list)
	}
	s.kevIdx.stamp, s.kevIdx.idx = stamp, idx
	return idx, nil
}

// kevOwnerKeysSQL reads the CVE, vendor and product of the owner entry of every CVE of the exploited lists: the rows KevVulns
// returns, without the columns and joins only the pages need.
const kevOwnerKeysSQL = `SELECT k.cve, k.vendor, k.product FROM feeds_kev k
WHERE ` + kevSources + ` AND k.list = (SELECT k2.list FROM feeds_kev k2 WHERE k2.cve = k.cve ORDER BY ` + ownerOrder + ` LIMIT 1)`

// kevStamp changes whenever the owner entries of the exploited lists may have changed: the last pull time and rev of their two feeds
// (each pull writes its entries in the transaction that sets its last pull time), and the count and newest change of their entries
// (which also covers a purge or a cascade from the catalogue). A custom feed's entry never owns a CVE these lists have.
func (s *Store) kevStamp(ctx context.Context) (string, error) {
	var stamp sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT COALESCE((SELECT group_concat(id || '=' || COALESCE(last_fetch, '') || '/' || rev, ',') FROM
(SELECT id, last_fetch, rev FROM feeds_source WHERE id IN ('cisa-kev', 'vulncheck-kev') ORDER BY id)), '')
|| ';' || (SELECT count(*) || '/' || COALESCE(max(updated_at), '') FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev'))`).Scan(&stamp)
	if err != nil {
		return "", fmt.Errorf("feeds: KEV stamp: %w", err)
	}
	return stamp.String, nil
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
