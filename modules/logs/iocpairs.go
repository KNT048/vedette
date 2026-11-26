package logs

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// The connections to listed destinations as a list a person reads (GET /logs/bad-connections, INV-7): one row per (source address,
// destination) over a time range instead of one row per hit, the way threat-intel consoles summarise matches. The rows are grouped by
// SQL over logs_ioc_hits (at most MaxIocRows rows), the devices are named from the inventory when read, then the search, the order and
// the page are applied here: a device's name lives in the inventory, not in this table, so the search over it cannot be SQL.

// IocPairsPageMax is the most rows one page of GET /logs/bad-connections returns.
const IocPairsPageMax = 200

// IocPair is one source address and one destination over the range (contract.ts IocPair).
type IocPair struct {
	SrcIP     string    `json:"src_ip"`
	AssetID   *string   `json:"asset_id"`
	AssetName *string   `json:"asset_name"`
	Dest      string    `json:"dest"`
	DestKind  string    `json:"dest_kind"`
	ListedAs  *string   `json:"listed_as"`
	Hits      int       `json:"hits"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Feeds     []string  `json:"feeds"`
	// Confidence is the highest confidence of the hits.
	Confidence float64  `json:"confidence"`
	SeenVia    []string `json:"seen_via"`
	// Blocked is how many of the hits the device that logged them blocked.
	Blocked int `json:"blocked"`
	// OtherDevices is how many other source addresses have hits on the same destination in the range.
	OtherDevices int `json:"other_devices"`
}

// IocPairs is the answer of GET /logs/bad-connections.
type IocPairs struct {
	Items []IocPair `json:"items"`
	// Total is the number of rows that match the search (every page); Hits the hits in the range, whatever the search.
	Total int `json:"total"`
	Hits  int `json:"hits"`
	// IOCMatching is Digest.IOCMatching: false when no connection can be matched now.
	IOCMatching bool `json:"ioc_matching"`
}

// IocPairQuery is the query of GET /logs/bad-connections: the range (24h or 7d, the Events tab's), the search, the order ("last": the
// newest last hit first, "hits": the most hits first) and the page.
type IocPairQuery struct {
	Window, Q, Sort string
	Offset, Limit   int
}

// iocPairsSQL groups the hits of the range by source address and listed destination (the name a feed lists: hits on several
// sub-domains of one listed name are one row, as in the digest, INV-7). The row names the one name asked for, or the listed name when
// several were. other is a window function over the groups: the source addresses of the same listed destination, this one left out.
const iocPairsSQL = `SELECT src_ip, CASE WHEN count(DISTINCT dest) > 1 THEN ` + iocListedKey + ` ELSE max(dest) END, dest_kind,
	CASE WHEN count(DISTINCT dest) > 1 THEN '' ELSE max(listed_as) END, count(*), min(ts), max(ts), max(confidence), sum(blocked),
	json_group_array(DISTINCT feeds), json_group_array(DISTINCT seen_via), count(*) OVER (PARTITION BY dest_kind, ` + iocListedKey + `) - 1
	FROM logs_ioc_hits WHERE ts >= ? GROUP BY src_ip, dest_kind, ` + iocListedKey

// iocListedKey is the listed name of a hit: listed_as when the feed lists a parent of the name asked for, else the name itself.
const iocListedKey = `coalesce(nullif(listed_as, ''), dest)`

// IocPairs lists the connections to listed destinations of the range, one row per source address and destination (INV-7). With the
// feeds module off the list is empty, as in the digest (PRE-3).
func (s *Service) IocPairs(ctx context.Context, q IocPairQuery) (IocPairs, error) {
	span, ok := windows[q.Window]
	if !ok || q.Window == "1h" {
		return IocPairs{}, apierr.New(400, "bad_window", "The time range must be 24h or 7d.")
	}
	if q.Sort == "" {
		q.Sort = "last"
	}
	if q.Sort != "last" && q.Sort != "hits" {
		return IocPairs{}, apierr.Invalid("The order must be last or hits.")
	}
	if q.Limit <= 0 || q.Limit > IocPairsPageMax {
		q.Limit = IocPairsPageMax
	}
	out := IocPairs{Items: []IocPair{}}
	if s.cfg.Feeds != nil && !s.cfg.Feeds.On() {
		return out, nil
	}
	if s.cfg.Feeds != nil {
		listed, err := s.cfg.Feeds.Listed(ctx)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "logs: bad connections: cannot tell whether a feed lists indicators", "err", err)
			listed = true
		}
		out.IOCMatching = listed
	}
	all, err := s.iocPairs(ctx, s.now().Add(-span))
	if err != nil {
		return IocPairs{}, err
	}
	for _, p := range all {
		out.Hits += p.Hits
	}
	needle := strings.ToLower(strings.TrimSpace(q.Q))
	if len([]rune(needle)) > 200 {
		needle = string([]rune(needle)[:200])
	}
	shown := all[:0:0]
	for _, p := range all {
		if needle == "" || p.matches(needle) {
			shown = append(shown, p)
		}
	}
	slices.SortStableFunc(shown, func(a, b IocPair) int {
		last := b.LastSeen.Compare(a.LastSeen)
		hits := cmp.Compare(b.Hits, a.Hits)
		if q.Sort == "hits" {
			return cmp.Or(hits, last, cmp.Compare(a.Dest, b.Dest), cmp.Compare(a.SrcIP, b.SrcIP))
		}
		return cmp.Or(last, hits, cmp.Compare(a.Dest, b.Dest), cmp.Compare(a.SrcIP, b.SrcIP))
	})
	out.Total = len(shown)
	if q.Offset < len(shown) {
		out.Items = shown[max(0, q.Offset):min(len(shown), max(0, q.Offset)+q.Limit)]
	}
	return out, nil
}

// matches says whether the row's device (address or name), destination, listed name or a feed contains needle (lower case).
func (p IocPair) matches(needle string) bool {
	fields := []string{p.SrcIP, p.Dest}
	if p.AssetName != nil {
		fields = append(fields, *p.AssetName)
	}
	if p.ListedAs != nil {
		fields = append(fields, *p.ListedAs)
	}
	fields = append(fields, p.Feeds...)
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

// iocPairs reads the grouped hits since a time, with the device of each source address resolved now (INV-7).
func (s *Service) iocPairs(ctx context.Context, since time.Time) ([]IocPair, error) {
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, iocPairsSQL, store.FormatTS(since))
	if err != nil {
		return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []IocPair
	var ips []string
	for rows.Next() {
		var p IocPair
		var listed, first, last, feeds, via string
		if err := rows.Scan(&p.SrcIP, &p.Dest, &p.DestKind, &listed, &p.Hits, &first, &last, &p.Confidence, &p.Blocked, &feeds, &via, &p.OtherDevices); err != nil {
			return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
		}
		if listed != "" {
			p.ListedAs = &listed
		}
		if p.FirstSeen, err = time.Parse("2006-01-02T15:04:05.000Z", first); err != nil {
			return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
		}
		if p.LastSeen, err = time.Parse("2006-01-02T15:04:05.000Z", last); err != nil {
			return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
		}
		p.Feeds = feedUnion(feeds)
		if err := json.Unmarshal([]byte(via), &p.SeenVia); err != nil || p.SeenVia == nil {
			p.SeenVia = []string{}
		}
		slices.Sort(p.SeenVia)
		out = append(out, p)
		ips = append(ips, p.SrcIP)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logs: reading the bad connections: %w", err)
	}
	devices := s.assetsFor(ctx, ips)
	c := s.credits(ctx)
	for i, p := range out {
		if d, ok := devices[p.SrcIP]; ok && d.ID != "" {
			id, name := d.ID, plainText(d.Name)
			out[i].AssetID, out[i].AssetName = &id, &name
		}
		out[i].Feeds = credited(p.Feeds, c)
	}
	return out, nil
}

// feedUnion is the feed names of a group: a JSON array of the distinct stored feed lists (each a JSON array), merged and sorted.
func feedUnion(lists string) []string {
	var raw []string
	if err := json.Unmarshal([]byte(lists), &raw); err != nil {
		return []string{}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, l := range raw {
		var names []string
		if json.Unmarshal([]byte(l), &names) != nil {
			continue
		}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	return out
}
