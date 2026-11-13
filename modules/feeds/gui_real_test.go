package feeds

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// Differences between the GUI mock and the real backend found when the GUI ran against this module (feeds-gui-real).

// The CISA notes often link to an anchor (".../CHANGELOG.md#563"). The generated server types links as url.URL; the link
// must reach the GUI exactly as CISA wrote it, fragment and query included.
func TestGUIReal_LinksReachTheGUIUnchanged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	want := []string{"https://github.com/o/r/blob/abc/CHANGELOG.md#563", "https://example.com/a?x=1&y=2#top", "https://example.com/plain"}
	v := vuln("CVE-2026-20001", "Acme", "Widget", "2026-11-03")
	v.Links = want
	applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{v}, false)
	c, b := e.get("/feeds/cve/CVE-2026-20001")
	if c != 200 {
		t.Fatalf("GET /feeds/cve = %d %v", c, b)
	}
	got, _ := at(b, "links").([]any)
	if len(got) != len(want) {
		t.Fatalf("links = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %q, want %q", i, got[i], want[i])
		}
	}
	// the same links in the text search
	_, s := e.get("/feeds/search?q=Widget")
	if l, _ := at(s, "vulns", 0, "links", 0).(string); l != want[0] {
		t.Errorf("search link = %q, want %q", l, want[0])
	}
}

// The parsing editor promises samples up to 5 MB ("Limits: 5 MB and 50,000 rows"); the server default of 1 MiB per request
// would cut that at a fifth. With BodyLimits (as cmd/vedette wires it) a 3 MB sample parses; a far larger body is still refused.
func TestGUIReal_ParseTestTakesTheSampleSizeTheGUIPromises(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := slog.New(slog.DiscardHandler)
	h, err := server.New(server.Config{API: composite{server.Fallback{Log: log}, NewHandlers(e.svc)}, Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: e.gate, Log: log, BodyLimits: BodyLimits})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	body := func(sample string) string {
		b, _ := json.Marshal(map[string]any{"kind": "ioc", "parser": map[string]any{"format": "lines", "records_path": "", "delimiter": ",", "has_header": true,
			"fields": map[string]any{"indicator": map[string]any{"source": "", "regex": "", "trim": true, "lowercase": false, "date_format": "auto"}}}, "sample": sample})
		return string(b)
	}
	c, out, raw := e.do("POST", "/feeds/parse-test", "admin", body(strings.Repeat("1.2.3.4\n", 400_000))) // 3.2 MB of text, 3.6 MB as JSON
	if c != 200 || at(out, "truncated") != true {
		t.Fatalf("3 MB sample = %d %.200s, want 200 truncated at the row limit", c, raw)
	}
	if c, _, raw := e.do("POST", "/feeds/parse-test", "admin", body(strings.Repeat("1.2.3.4\n", 2_000_000))); c != 413 && c != 400 { // 16 MB of text
		t.Fatalf("16 MB sample = %d %.200s, want a refusal", c, raw)
	}
	if c, _, _ := e.do("POST", "/feeds/sources/ipsum/fetch", "admin", strings.Repeat(" ", 2<<20)); c != 413 { // other operations keep the 1 MiB default
		t.Fatalf("2 MiB body on another operation = %d, want 413", c)
	}
}

// Only https links are ever stored (D-484), so only https links can reach the GUI (contract.ts: links match ^https?://).
func TestGUIReal_OnlyHTTPSLinksAreStored(t *testing.T) {
	t.Parallel()
	got := kevLinks("javascript:alert(1) ; data:text/html,x ; https://example.com/a#frag ; http://example.com/b ; HTTPS://example.com/c")
	if len(got) != 2 || got[0] != "https://example.com/a#frag" || got[1] != "HTTPS://example.com/c" {
		t.Fatalf("kevLinks = %v", got)
	}
}

// CONTRACT: the EPSS scores are pulled right after a KEV load. That held for the scheduled tick only; a manual
// "Fetch now" on the CISA list left every score empty and "FIRST EPSS: OK, 0 records" until someone fetched EPSS too.
func TestGUIReal_ManualKEVFetchPullsEPSSToo(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev", "first-epss")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.mirror("first-epss", o.url("/epss"))
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	maxIDs := 0
	epssOrigin(o, &maxIDs)
	if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "status") != "ok" {
		t.Fatalf("manual KEV fetch = %d %v", c, b)
	}
	if o.count("/epss") == 0 {
		t.Fatal("no EPSS request after a manual KEV load")
	}
	v, _, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001")
	if v.EPSS == nil || *v.EPSS != 0.8 {
		t.Errorf("score after a manual KEV load: %v", v.EPSS)
	}
	if r := e.feed("first-epss").Records; r == nil || *r != 3 {
		t.Errorf("FIRST EPSS records = %v, want 3", r)
	}
	// a feed that is off is not pulled behind the owner's back
	e.put("first-epss", `{"enabled":false}`)
	before := o.count("/epss")
	e.fetch("cisa-kev")
	if o.count("/epss") != before {
		t.Error("EPSS pulled while its feed is off")
	}
}
