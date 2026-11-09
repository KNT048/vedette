package feeds

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseEPSSAnswer(t *testing.T) {
	t.Parallel()
	d, err := ParseEPSS(fixture(t, "epss.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Accepted != 3 || d.Rejected != 4 || len(d.Scores) != 3 || d.Truncated {
		t.Fatalf("%+v", d.Stats)
	}
	want := []EPSSScore{{"CVE-2026-10001", 0.94321, 0.99876, "2026-11-08"}, {"CVE-2026-10002", 0.00043, 0.08812, "2026-11-08"}, {"CVE-2026-10003", 1, 1, "2026-11-08"}}
	if !reflect.DeepEqual(d.Scores, want) {
		t.Errorf("scores = %+v", d.Scores)
	}
	wantRej := []Reject{
		{4, `epss: "1.5" is not a number from 0 to 1`},
		{5, `cve: "NOT-A-CVE" is not a CVE ID`},
		{6, `epss: "abc" is not a number from 0 to 1`},
		{7, `date: "yesterday" is not a date`},
	}
	if !reflect.DeepEqual(d.Rejects, wantRej) {
		t.Errorf("rejects = %+v", d.Rejects)
	}
	assertSafeReasons(t, "epss", d.Stats)
}

func TestParseEPSSDefensively(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"empty": "", "array": "[]", "no data": `{"status":"OK"}`, "data object": `{"data":{}}`, "error status": `{"status":"ERROR","data":[]}`,
		"status number": `{"status":1,"data":[]}`, "truncated": `{"data":[`, "trailing": `{"data":[]} x`,
	} {
		if _, err := ParseEPSS([]byte(in)); !errors.Is(err, ErrBadSample) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseEPSS(make([]byte, MaxBodyBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Error("size")
	}
	d, err := ParseEPSS([]byte(`{"total":500,"data":[
	 {"cve":"CVE-2026-1111","epss":0.5,"percentile":"0.5"},
	 {"cve":["CVE-2026-1112"],"epss":0.5,"percentile":0.5},
	 {"cve":"CVE-2026-1113","epss":null,"percentile":0.5},
	 {"cve":"CVE-2026-1114","epss":true,"percentile":0.5},
	 {"cve":"CVE-2026-1115","epss":"0x1","percentile":0.5},
	 {"cve":"CVE-2026-1116","epss":"NaN","percentile":0.5},
	 {"cve":"CVE-2026-1117","epss":-0.1,"percentile":0.5},
	 {"cve":"CVE-2026-1118","epss":1e999,"percentile":0.5},
	 {"cve":"CVE-2026-1119","epss":"1e-5","percentile":0.5,"date":null},
	 "text", 7]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Accepted != 2 || d.Rejected != 9 || !d.Truncated || d.Scores[0].Date != "" || d.Scores[1].Score != 1e-5 {
		t.Errorf("%+v %+v", d.Stats, d.Scores)
	}
	assertSafeReasons(t, "epss defensive", d.Stats)
	// A hostile answer cannot flood the reasons.
	var b strings.Builder
	b.WriteString(`{"data":[`)
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, `{"cve":"x\"%d","epss":"1"},`, i)
	}
	b.WriteString(`{}]}`)
	h, err := ParseEPSS([]byte(b.String()))
	if err != nil || len(h.Reasons) > maxReasons+1 || h.Rejected != 20001 {
		t.Errorf("%v reasons=%d rejected=%d", err, len(h.Reasons), h.Rejected)
	}
}

func TestEPSSBatchURLs(t *testing.T) {
	t.Parallel()
	const base = "https://api.first.org/data/v1/epss"
	var ids []string
	for i := 0; i < 250; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2026-%04d", 1000+i))
	}
	ids = append(ids, "cve-2026-1000", " CVE-2026-1001 ") // duplicates in other spellings
	urls, err := EPSSBatchURLs(base, ids, "2026-11-02")
	if err != nil || len(urls) != 3 {
		t.Fatalf("%v %v", err, len(urls))
	}
	total := 0
	for i, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != "api.first.org" || u.Path != "/data/v1/epss" || u.Query().Get("date") != "2026-11-02" {
			t.Fatalf("url %d = %s", i, raw)
		}
		list := strings.Split(u.Query().Get("cve"), ",")
		if len(list) > EPSSBatchSize || len(raw) > EPSSURLMaxLen {
			t.Errorf("batch %d: %d ids, %d bytes", i, len(list), len(raw))
		}
		total += len(list)
	}
	if total != 250 {
		t.Errorf("ids across batches = %d", total)
	}
	now, _ := EPSSBatchURLs(base, []string{"CVE-2026-1000"}, "")
	if len(now) != 1 || strings.Contains(now[0], "date=") {
		t.Errorf("latest = %v", now)
	}
	if none, err := EPSSBatchURLs(base, nil, ""); err != nil || len(none) != 0 {
		t.Errorf("no ids: %v %v", none, err)
	}
	for name, c := range map[string]struct {
		base string
		ids  []string
		date string
	}{
		"bad id":         {base, []string{"CVE-2026-1000", "CVE-2026-1,evil=1"}, ""},
		"injection":      {base, []string{"CVE-2026-1000&x=1"}, ""},
		"bad date":       {base, []string{"CVE-2026-1000"}, "2026-13-01"},
		"date with junk": {base, []string{"CVE-2026-1000"}, "2026-11-01&x=1"},
		"query in base":  {base + "?a=1", []string{"CVE-2026-1000"}, ""},
		"http base":      {"http://api.first.org/x", []string{"CVE-2026-1000"}, ""},
	} {
		if _, err := EPSSBatchURLs(c.base, c.ids, c.date); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Every batch URL passes the fetcher's address rule.
	for _, raw := range urls {
		if err := checkURL(raw, EPSSURLMaxLen); err != nil {
			t.Errorf("fetcher would refuse %s: %v", raw, err)
		}
	}
	if s, _ := BuiltinByID("first-epss"); s.URL != base || s.Decoder != DecoderEPSS || s.Format != FormatJSON {
		t.Errorf("built-in source = %+v", s)
	}
}

func TestEPSSDate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 23, 30, 0, 0, time.FixedZone("x", 10*3600))
	if got := EPSSDate(now, 7); got != "2026-11-02" { // 13:30 UTC on the 9th
		t.Errorf("7 days ago = %s", got)
	}
	if got := EPSSDate(now, 0); got != "2026-11-09" {
		t.Errorf("today = %s", got)
	}
}
