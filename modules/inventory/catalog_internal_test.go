package inventory

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

func embeddedCatalog(t *testing.T) *Catalog {
	t.Helper()
	_, list, err := EmbeddedKEV{}.Products(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(catalogdata.Curated, list)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The web catalog (catalog.ts) and this one read the same two data files and must answer alike: the golden file
// is produced by the TypeScript side (catalog.golden.test.ts) and judged here.
func TestContract_INV12_CatalogMatchesTheWebGolden(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../content/catalog/search-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Search []struct {
			Q     string `json:"q"`
			Total int    `json:"total"`
			Items []struct {
				ID       string   `json:"id"`
				KevCount int      `json:"kev_count"`
				Kev      []string `json:"kev"`
			} `json:"items"`
		} `json:"search"`
		Find []struct {
			Text string  `json:"text"`
			ID   *string `json:"id"`
		} `json:"find"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	c := embeddedCatalog(t)
	for _, g := range golden.Search {
		list, total := c.search(g.Q, MaxCatalogHits)
		if total != g.Total || len(list) != len(g.Items) {
			t.Errorf("search %q: total/len = %d/%d, web has %d/%d", g.Q, total, len(list), g.Total, len(g.Items))
			continue
		}
		for i, w := range g.Items {
			e := list[i]
			if e.id != w.ID || e.kevCount != w.KevCount || !slices.Equal(e.kev, w.Kev) {
				t.Errorf("search %q #%d: %s (%d, %v), web has %s (%d, %v)", g.Q, i, e.id, e.kevCount, e.kev, w.ID, w.KevCount, w.Kev)
				break
			}
		}
	}
	for _, g := range golden.Find {
		got := ""
		if e := c.find(g.Text); e != nil {
			got = e.id
		}
		want := ""
		if g.ID != nil {
			want = *g.ID
		}
		if got != want {
			t.Errorf("find %q = %q, web has %q", g.Text, got, want)
		}
	}
}

func TestContract_INV12_CatalogShape(t *testing.T) {
	t.Parallel()
	c := embeddedCatalog(t)
	r := c.Search("")
	if len(r.Items) != MaxCatalogHits || r.Total != len(c.entries) || r.Total < 800 {
		t.Fatalf("empty query: %d items of %d", len(r.Items), r.Total)
	}
	if got := c.Search("forti"); len(got.Items) > MaxCatalogHits || got.Total < len(got.Items) || got.Items[0].ID != "fortigate" {
		t.Fatalf("forti: %d of %d, first %+v", len(got.Items), got.Total, got.Items[0])
	}
	if got := c.Search(strings.Repeat("x", 500)); len(got.Items) != 0 || got.Total != 0 {
		t.Fatalf("garbage query: %+v", got)
	}
	// every KEV pair is in the catalog, with the id the contract defines; curated ids are fixed
	_, kev, _ := EmbeddedKEV{}.Products(context.Background())
	for _, k := range kev {
		if c.byID["kev:"+slug(k.Vendor)+":"+slug(k.Product)] == nil {
			t.Fatalf("KEV pair %s|%s is missing", k.Vendor, k.Product)
		}
	}
	if c.byID["fortigate"] == nil || c.byID["synology-nas-dsm"] == nil {
		t.Fatal("a curated id changed")
	}
	// accents do not matter, so Vietnamese search works
	if got := c.Search("Tường lửa"); len(got.Items) == 0 {
		t.Fatal("no hit for a Vietnamese query")
	}
	// a typed vendor+product matches the exact KEV pair, else every product of the vendor, else a plain key
	if e := c.custom("fortinet", "FortiOS"); !slices.Equal(e.kev, []string{"fortinet|fortios"}) {
		t.Fatalf("exact pair: %v", e.kev)
	}
	if e := c.custom("Fortinet", "Brand New"); len(e.kev) < 5 {
		t.Fatalf("by vendor: %v", e.kev)
	}
	if e := c.custom("Contoso", "Gizmo"); !slices.Equal(e.kev, []string{"contoso|gizmo"}) {
		t.Fatalf("plain key: %v", e.kev)
	}
}

func FuzzParseCSV(f *testing.F) {
	for _, s := range []string{"", "name,ip\r\nfw,192.168.1.1\r\n", "a;b;c\n1;2;3", "\"a\"\"b\",\"c\nd\"\n", "a\tb\n\"unterminated", "\r\r\n\n,,,\n", "\ufeffname\n", "=cmd|' /C calc'!A0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rows := parseCSV(text)
		cells := 0
		for _, r := range rows {
			if r == nil {
				t.Fatal("nil row")
			}
			cells += len(r)
		}
		// never more cells than separators in the input plus one per row
		if cells > len(text)+len(rows)+1 {
			t.Fatalf("%d cells from %d bytes", cells, len(text))
		}
		_ = detectDelimiter(text)
		_ = csvCell(text)
	})
}

func FuzzFold(f *testing.F) {
	for _, s := range []string{"", "FortiGate-60F", "Tường lửa", "đ", "a b", "\x00\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := fold(s)
		if out != fold(out) {
			t.Fatalf("fold is not idempotent: %q -> %q -> %q", s, out, fold(out))
		}
		if strings.HasPrefix(out, " ") || strings.HasSuffix(out, " ") || strings.Contains(out, "  ") {
			t.Fatalf("bad spacing: %q", out)
		}
	})
}

func TestSearchTermsAreCapped(t *testing.T) {
	t.Parallel()
	if got := searchTerms(strings.Repeat("ab ", 50)); len(got) != maxTerms {
		t.Fatalf("%d terms, want %d", len(got), maxTerms)
	}
	if got := searchTerms("forti gate"); len(got) != 2 {
		t.Fatalf("terms = %v", got)
	}
	c := embeddedCatalog(t)
	// the first eight words decide: the rest cannot change the answer or its cost
	a, _ := c.search("forti "+strings.Repeat("x ", 7), 30)
	b, _ := c.search("forti "+strings.Repeat("x ", 70), 30)
	if len(a) != len(b) {
		t.Fatalf("%d vs %d hits", len(a), len(b))
	}
}

func TestRangeOverlapIsNamedLikeTheMock(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   []string
		msg  string
	}{
		{"A before bogus before B names A", []string{"10.0.0.0/24", "bogus", "10.0.0.128/25"}, ""},
		{"the first range names the first", []string{"10.0.0.0/24", "10.0.0.0/8"}, "Range 10.0.0.0/24 overlaps 10.0.0.0/8."},
		{"the nested one is not named first", []string{"10.0.0.0/8", "10.0.0.0/24"}, "Range 10.0.0.0/8 overlaps 10.0.0.0/24."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := checkRanges(tc.in)
			if err == nil || err.Code != "overlap_range" {
				t.Fatalf("err = %v", err)
			}
			want := tc.msg
			if want == "" {
				want = "Range 10.0.0.0/24 overlaps 10.0.0.128/25."
			}
			if !strings.HasPrefix(err.Message, strings.TrimSuffix(want, ".")) {
				t.Fatalf("message = %q, want it to start with %q", err.Message, want)
			}
		})
	}
	// an invalid entry is still reported when nothing overlaps before it
	if _, _, err := checkRanges([]string{"10.0.0.0/24", "bogus"}); err == nil || err.Code != "bad_cidr" {
		t.Fatalf("err = %v", err)
	}
}
