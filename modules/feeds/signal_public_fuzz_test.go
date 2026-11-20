package feeds

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// checkPublicIndex is what must hold for any index a public-exploit decoder accepts: one signal per CVE, sorted; a CVE id, a date, a
// link of the source's own site (or none) and a small JSON detail.
func checkPublicIndex(t *testing.T, idx publicIndex, prefix string) {
	t.Helper()
	for i, g := range idx.Signals {
		if !cveRE.MatchString(g.CVE) || (i > 0 && idx.Signals[i-1].CVE >= g.CVE) {
			t.Fatalf("signal %d: CVE %q out of order or not a CVE", i, g.CVE)
		}
		if g.Date.IsZero() || (g.URL != "" && !strings.HasPrefix(g.URL, prefix)) || strings.ContainsAny(g.URL, " \"<>\\") {
			t.Fatalf("signal %+v", g)
		}
		if g.Detail != "" && (!json.Valid([]byte(g.Detail)) || len(g.Detail) > 200) {
			t.Fatalf("detail %q", g.Detail)
		}
		if g.Qualifies != (!g.Rule.IsZero() || !g.Stars.IsZero()) {
			t.Fatalf("qualifies %+v", g)
		}
	}
	if idx.Accepted < 0 || idx.Rejected < 0 {
		t.Fatalf("stats %+v", idx.Stats)
	}
}

func FuzzParseMetasploitModules(f *testing.F) {
	f.Add([]byte(`{"a":{"fullname":"exploit/linux/http/a","mod_time":"2026-11-18 10:00:00 +0000","references":["CVE-2026-1111"]}}`))
	f.Add([]byte(`{"a":{"fullname":"exploit/../a","mod_time":"x","references":["CVE-2026-1111","cve-2026-2"]},"b":[]}`))
	f.Add([]byte(`{"a":{"references":null}} trailing`))
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseMetasploitModules(bytes.NewReader(data))
		if err == nil {
			checkPublicIndex(t, idx, metasploitModuleURL)
		}
	})
}

func FuzzParseExploitDBIndex(f *testing.F) {
	f.Add([]byte("id,date_published,codes\n1,2020-01-01,CVE-2020-1234;OSVDB-1\n"))
	f.Add([]byte("codes,id,date_published\n\"CVE-2020-1234\n;x\",01,2020-13-01\n"))
	f.Add([]byte("id,file,date_published,codes\n9,\"a,b\",2020-01-01\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseExploitDBIndex(bytes.NewReader(data))
		if err == nil {
			checkPublicIndex(t, idx, exploitDBEntryURL)
		}
	})
}

func FuzzPoCSignal(f *testing.F) {
	f.Add([]byte(pocFile(repoJSON("sfewer-r7", "CVE-2026-123007", "2026-11-18T11:16:51Z", 264, false), repoJSON("a", "b", "2026-11-19T00:00:00Z", 1, true))))
	f.Add([]byte(`[{"full_name":"a/..","owner":{"login":"a"},"html_url":"https://github.com/a/..","created_at":"2026-01-01T00:00:00Z"}]`))
	f.Add([]byte(`[{"full_name":"a/b","owner":{"login":"A"},"html_url":"https://github.com/a/b","created_at":"2026-01-01T00:00:00+07:00","stargazers_count":-5}]`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		g, ok, why := pocSignal("CVE-2026-0001", data)
		if ok && why != "" {
			t.Fatalf("both a signal and a reason: %q", why)
		}
		if ok {
			checkPublicIndex(t, publicIndex{Signals: []publicSignal{g}}, "https://github.com/")
		}
	})
}

func FuzzParsePoCInGitHub(f *testing.F) {
	f.Add(pocArchive(f, map[string]string{"2026/CVE-2026-0001.json": pocFile(repoJSON("a", "b", "2026-11-01T00:00:00Z", 60, false)), "README.md": "x"}))
	f.Add([]byte("\x1f\x8b\x08\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParsePoCInGitHub(bytes.NewReader(data))
		if err == nil {
			checkPublicIndex(t, idx, "https://github.com/")
		}
	})
}
