package logs

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// seedPairs stores hits as the ingest does (one per pair per 24 hours): 30 source addresses × 40 destinations, each pair hit on
// 1 + (dest % 3) of the last days, plus one hit 9 days old that no range reaches. 192.168.10.1 is the device "FW-HQ" of newEnv.
func seedPairs(t *testing.T, e *env) (pairs, hits int) {
	t.Helper()
	now := e.svc.now()
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		ins := func(id string, ts time.Time, src, dest, via, feeds string, conf float64, blocked bool) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id, blocked) VALUES (?, ?, ?, ?, 'ip', ?, ?, ?, 'ls-x', ?)`,
				id, store.FormatTS(ts), src, dest, via, feeds, conf, blocked)
			return err
		}
		for s := 1; s <= 30; s++ {
			for d := range 40 {
				for day := range 1 + d%3 {
					via, feeds := "syslog:FW-HQ", `["IPsum"]`
					if day == 1 {
						via, feeds = "span_flow", `["IPsum","Feodo"]`
					}
					ts := now.Add(-time.Duration(day)*24*time.Hour - time.Duration(s+d)*time.Minute)
					if err := ins(fmt.Sprintf("h-%d-%d-%d", s, d, day), ts, fmt.Sprintf("192.168.10.%d", s), fmt.Sprintf("198.51.100.%d", d), via, feeds, 0.5+float64(day)/10, day == 2); err != nil {
						return err
					}
					hits++
				}
				pairs++
			}
		}
		return ins("h-old", now.Add(-9*24*time.Hour), "192.168.10.1", "203.0.113.9", "syslog:FW-HQ", `["Old feed"]`, 0.9, false)
	}); err != nil {
		t.Fatal(err)
	}
	return pairs, hits
}

// GET /logs/bad-connections groups the hits of the range by source address and destination in SQL: counts, first and last seen, the
// union of feeds and ways seen, the highest confidence, blocked hits and the other devices of the destination; nothing older than the
// range; 1200 pairs from 2400 hits.
func TestIocPairsGroupManyHits(t *testing.T) {
	t.Parallel()
	e, _, _, _ := iocEnv(t)
	pairs, hits := seedPairs(t, e)
	got, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "7d", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != pairs || got.Hits != hits || len(got.Items) != 200 || !got.IOCMatching {
		t.Fatalf("total %d of %d, hits %d of %d, %d rows, matching %v", got.Total, pairs, got.Hits, hits, len(got.Items), got.IOCMatching)
	}
	all := got.Items
	for off := 200; off < got.Total; off += 200 {
		p, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "7d", Offset: off, Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, p.Items...)
	}
	if len(all) != pairs {
		t.Fatalf("pages hold %d rows", len(all))
	}
	var three *IocPair
	for i, p := range all {
		if p.Dest == "203.0.113.9" {
			t.Fatal("a hit older than the range is listed")
		}
		if i > 0 && all[i-1].LastSeen.Before(p.LastSeen) {
			t.Fatalf("not newest last hit first at %d", i)
		}
		if p.OtherDevices != 29 {
			t.Fatalf("other devices of %s = %d", p.Dest, p.OtherDevices)
		}
		if p.SrcIP == "192.168.10.1" && p.Dest == "198.51.100.2" {
			three = &all[i]
		}
	}
	// 198.51.100.2 (d=2): hit on days 0, 1 and 2
	if three == nil || three.Hits != 3 || three.Blocked != 1 || three.Confidence != 0.7 ||
		!slices.Equal(three.Feeds, []string{"Feodo", "IPsum"}) || !slices.Equal(three.SeenVia, []string{"span_flow", "syslog:FW-HQ"}) ||
		three.AssetName == nil || *three.AssetName != "FW-HQ" || three.LastSeen.Sub(three.FirstSeen) != 48*time.Hour {
		t.Fatalf("%+v", three)
	}
	// 24 hours: only the hits of day 0, one per pair
	day, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if day.Total != pairs || day.Hits != pairs || day.Items[0].Hits != 1 {
		t.Fatalf("24h: %d rows, %d hits", day.Total, day.Hits)
	}
}

// The search runs over every row on the box, then pages: the device's name and address, the destination and the feed names.
func TestIocPairsSearchOrderAndPage(t *testing.T) {
	t.Parallel()
	e, _, _, _ := iocEnv(t)
	seedPairs(t, e)
	q := func(qq IocPairQuery) IocPairs {
		t.Helper()
		qq.Window = "7d"
		r, err := e.svc.IocPairs(t.Context(), qq)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := q(IocPairQuery{Q: "fw-hq"}); r.Total != 40 || *r.Items[0].AssetName != "FW-HQ" {
		t.Fatalf("by device name: %d", r.Total)
	}
	if r := q(IocPairQuery{Q: "192.168.10.3"}); r.Total != 2*40 { // .3 and .30
		t.Fatalf("by device address: %d", r.Total)
	}
	if r := q(IocPairQuery{Q: "198.51.100.39"}); r.Total != 30 {
		t.Fatalf("by destination: %d", r.Total)
	}
	if r := q(IocPairQuery{Q: "FEODO"}); r.Total != 30*(40-14) { // every pair hit on day 1: d % 3 >= 1
		t.Fatalf("by feed: %d", r.Total)
	}
	if r := q(IocPairQuery{Q: "nothing-like-this"}); r.Total != 0 || len(r.Items) != 0 {
		t.Fatalf("no match: %+v", r)
	}
	// The second page of a search is the rest of the same order
	first, second := q(IocPairQuery{Q: "198.51.100.39", Limit: 25}), q(IocPairQuery{Q: "198.51.100.39", Offset: 25, Limit: 25})
	if len(first.Items) != 25 || len(second.Items) != 5 || second.Total != 30 || first.Items[24].SrcIP == second.Items[0].SrcIP {
		t.Fatalf("pages of a search: %d, %d", len(first.Items), len(second.Items))
	}
	// Most hits first
	byHits := q(IocPairQuery{Sort: "hits", Limit: 200})
	for i := 1; i < len(byHits.Items); i++ {
		if byHits.Items[i-1].Hits < byHits.Items[i].Hits {
			t.Fatalf("not most hits first at %d", i)
		}
	}
	if byHits.Items[0].Hits != 3 {
		t.Fatalf("top = %d hits", byHits.Items[0].Hits)
	}
	// A limit above the page maximum is the maximum
	if r := q(IocPairQuery{Limit: 5000}); len(r.Items) != IocPairsPageMax {
		t.Fatalf("limit 5000 = %d rows", len(r.Items))
	}
	// Bad range or order: 400
	for _, bad := range []IocPairQuery{{Window: "1h"}, {Window: "30d"}, {Window: "7d", Sort: "name"}} {
		_, err := e.svc.IocPairs(t.Context(), bad)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Status != 400 {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
}

// PRE-3: with the Feeds module off the list is empty, the hits are kept.
func TestIocPairsFeedsOff(t *testing.T) {
	t.Parallel()
	e, _, ff, _ := iocEnv(t)
	seedPairs(t, e)
	ff.setErr(ErrFeedsOff)
	r, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "7d"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 0 || len(r.Items) != 0 || r.IOCMatching {
		t.Fatalf("%+v", r)
	}
}

// Hits on several sub-domains of one listed name are one row per device, named by the listed name, as in the digest; the other
// devices count every device that reached that listed name.
func TestIocPairsGroupByListedName(t *testing.T) {
	t.Parallel()
	e, _, _, _ := iocEnv(t)
	now := e.svc.now()
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		for i, h := range []struct{ src, dest, listed string }{
			{"192.168.10.1", "a.bad.example", "bad.example"}, {"192.168.10.1", "b.bad.example", "bad.example"},
			{"192.168.10.2", "c.bad.example", "bad.example"}, {"192.168.10.3", "bad.example", ""},
		} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id, blocked, listed_as)
				VALUES (?, ?, ?, ?, 'domain', 'syslog:FW-HQ', '["URLhaus"]', 0.8, 'ls-x', 0, ?)`, fmt.Sprintf("h-%d", i), store.FormatTS(now.Add(-time.Duration(i)*time.Minute)), h.src, h.dest, h.listed); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "24h", Sort: "hits"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 {
		t.Fatalf("one row per device and listed name: %+v", got.Items)
	}
	for _, p := range got.Items {
		if p.OtherDevices != 2 {
			t.Fatalf("other devices of %s from %s = %d", p.Dest, p.SrcIP, p.OtherDevices)
		}
		if p.SrcIP == "192.168.10.1" && (p.Dest != "bad.example" || p.Hits != 2 || p.ListedAs != nil) {
			t.Fatalf("two sub-domains of one listed name: %+v", p)
		}
		if p.SrcIP == "192.168.10.2" && (p.Dest != "c.bad.example" || p.ListedAs == nil || *p.ListedAs != "bad.example") {
			t.Fatalf("one sub-domain keeps its name and the listed one: %+v", p)
		}
	}
}
