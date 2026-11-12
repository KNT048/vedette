package pack

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/index.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse_Fixture(t *testing.T) {
	t.Parallel()
	ix, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if ix.Version != "2026.11.1" || len(ix.Templates) != 3 {
		t.Fatalf("%+v", ix)
	}
	got := ix.ForCVE("CVE-2022-27593")
	if len(got) != 1 || got[0].Request != "GET /photo/p/api/video.php HTTP/1.1" || got[0].Path != "http/cves/2022/CVE-2022-27593.yaml" {
		t.Fatalf("ForCVE: %+v", got)
	}
	if len(ix.ForCVE("CVE-2021-44228")) != 0 || !ix.Has("CVE-2024-3400") || ix.Has("CVE-2021-44228") {
		t.Fatal("lookups")
	}
}

// Any entry that breaks a rule refuses the whole index (INV-4: only kev/vkev, never dos/intrusive/fuzz).
func TestParse_Refuses(t *testing.T) {
	t.Parallel()
	entry := func(mod func(map[string]any)) string {
		e := map[string]any{"id": "CVE-2022-27593", "cve": "CVE-2022-27593", "path": "http/cves/2022/CVE-2022-27593.yaml", "sha256": sha, "tags": []string{"cve", "kev"}, "request": "GET / HTTP/1.1"}
		mod(e)
		b, _ := json.Marshal(map[string]any{"version": "2026.11.1", "sha256": sha, "templates": []any{e}})
		return string(b)
	}
	cases := map[string]string{
		"not JSON":            "{",
		"unknown field":       `{"version":"2026.11.1","sha256":"` + sha + `","templates":[],"extra":1}`,
		"repeated key":        `{"version":"2026.11.1","version":"2026.11.2","sha256":"` + sha + `","templates":[]}`,
		"no templates":        `{"version":"2026.11.1","sha256":"` + sha + `","templates":[]}`,
		"bad version":         strings.Replace(entry(func(map[string]any) {}), "2026.11.1", "latest", 1),
		"no kev tag":          entry(func(e map[string]any) { e["tags"] = []string{"cve", "rce"} }),
		"dos tag":             entry(func(e map[string]any) { e["tags"] = []string{"kev", "dos"} }),
		"intrusive tag":       entry(func(e map[string]any) { e["tags"] = []string{"vkev", "intrusive"} }),
		"fuzz tag":            entry(func(e map[string]any) { e["tags"] = []string{"kev", "fuzz"} }),
		"oast tag":            entry(func(e map[string]any) { e["tags"] = []string{"kev", "oast"} }),
		"bad tag":             entry(func(e map[string]any) { e["tags"] = []string{"kev", "Bad Tag"} }),
		"no tags":             entry(func(e map[string]any) { e["tags"] = []string{} }),
		"bad cve":             entry(func(e map[string]any) { e["cve"] = "CVE-22-1" }),
		"id with comma":       entry(func(e map[string]any) { e["id"] = "a,b" }),
		"id flag":             entry(func(e map[string]any) { e["id"] = "-code" }),
		"path escapes":        entry(func(e map[string]any) { e["path"] = "http/../../etc/x.yaml" }),
		"absolute path":       entry(func(e map[string]any) { e["path"] = "/etc/x.yaml" }),
		"dns template":        entry(func(e map[string]any) { e["path"] = "dns/x.yaml" }),
		"not yaml":            entry(func(e map[string]any) { e["path"] = "http/x.sh" }),
		"upper-case sha":      entry(func(e map[string]any) { e["sha256"] = strings.ToUpper(sha) }),
		"short sha":           entry(func(e map[string]any) { e["sha256"] = sha[:63] }),
		"request newline":     entry(func(e map[string]any) { e["request"] = "GET / HTTP/1.1\r\nHost: x" }),
		"request not ASCII":   entry(func(e map[string]any) { e["request"] = "GET /é HTTP/1.1" }),
		"request empty":       entry(func(e map[string]any) { e["request"] = "" }),
		"request too long":    entry(func(e map[string]any) { e["request"] = "GET /" + strings.Repeat("a", 200) }),
		"template id twice":   strings.Replace(entry(func(map[string]any) {}), `"templates":[`, `"templates":[{"cve":"CVE-2022-27593","id":"CVE-2022-27593","path":"http/b.yaml","request":"GET / HTTP/1.1","sha256":"`+sha+`","tags":["kev"]},`, 1),
		"over the size cap":   `{"version":"` + strings.Repeat(" ", MaxSize) + `"}`,
		"tags not an array":   entry(func(e map[string]any) { e["tags"] = "kev" }),
		"template not object": `{"version":"2026.11.1","sha256":"` + sha + `","templates":["x"]}`,
	}
	for name, in := range cases {
		if ix, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted %+v", name, ix)
		}
	}
	if _, err := Parse([]byte(entry(func(map[string]any) {}))); err != nil {
		t.Fatalf("the base entry is refused: %v", err)
	}
}

// Parse never panics; an index it accepts holds only safe templates.
func FuzzParse(f *testing.F) {
	f.Add(string(fixture(f)))
	f.Add(`{"version":"2026.11.1","sha256":"` + sha + `","templates":[{"id":"a","cve":"CVE-2000-0001","path":"a.yaml","sha256":"` + sha + `","tags":["kev"],"request":"x"}]}`)
	f.Fuzz(func(t *testing.T, in string) {
		ix, err := Parse([]byte(in))
		if err != nil {
			return
		}
		for _, tp := range ix.Templates {
			if tp.check() != nil {
				t.Fatalf("accepted a template that fails its check: %+v", tp)
			}
		}
	})
}

// L4: the tags the pack refuses are the tags nuclei is told to exclude: one list.
func TestForbiddenTagsAreTheExcludedTags(t *testing.T) {
	t.Parallel()
	args, err := nucleiargv.Build(nucleiargv.Job{Templates: []string{"http/a.yaml"}, Targets: []nucleiargv.Target{{Host: "10.0.0.1", Port: 80, Scheme: "http"}}, Rate: 1, MaxHostErrors: 2})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(args, "-etags")
	if i < 0 || args[i+1] != strings.Join(nucleiargv.ForbiddenTags(), ",") {
		t.Fatalf("-etags %q, pack refuses %v", args, nucleiargv.ForbiddenTags())
	}
	// the list cannot be changed from outside: a caller gets a copy
	got := nucleiargv.ForbiddenTags()
	got[0] = "kev"
	if nucleiargv.ForbiddenTags()[0] != "dos" {
		t.Fatal("ForbiddenTags hands out the shared slice")
	}
}
