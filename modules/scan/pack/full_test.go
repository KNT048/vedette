package pack

import (
	"encoding/json"
	"strings"
	"testing"
)

// D-527: the sets of an entry, what each needs, and the lookups of a full job.
func fullIndex(t *testing.T, entries ...map[string]any) (*Index, error) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": "2026.11.3", "sha256": sha, "templates": entries})
	if err != nil {
		t.Fatal(err)
	}
	return Parse(b)
}

func deepEntry(mod func(map[string]any)) map[string]any {
	e := map[string]any{"id": "git-config", "path": "http/exposures/configs/git-config.yaml", "sha256": sha, "tags": []string{"config", "git", "exposure"},
		"request": "GET {{BaseURL}}/.git/config", "sets": []string{"deep"}, "name": "Git Configuration - Detect", "severity": "medium", "generic": true}
	if mod != nil {
		mod(e)
	}
	return e
}

func TestParse_Sets(t *testing.T) {
	t.Parallel()
	kev := map[string]any{"id": "CVE-2024-3400", "cve": "CVE-2024-3400", "path": "http/cves/2024/CVE-2024-3400.yaml", "sha256": sha, "tags": []string{"cve", "kev"},
		"request": "POST /ssl-vpn/hipreport.esp HTTP/1.1", "sets": []string{"kev", "deep"}, "name": "PAN-OS", "severity": "critical"}
	kevOnly := map[string]any{"id": "CVE-2024-2862", "cve": "CVE-2024-2862", "path": "http/cves/2024/CVE-2024-2862.yaml", "sha256": sha, "tags": []string{"cve", "kev"},
		"request": "PUT /x HTTP/1.1", "sets": []string{"kev"}}
	dos := deepEntry(func(e map[string]any) {
		e["id"], e["tags"], e["sets"], e["generic"], e["cve"] = "slowloris", []string{"dos"}, []string{"disruptive"}, false, "CVE-2007-6750"
	})
	ix, err := fullIndex(t, kev, kevOnly, deepEntry(nil), dos)
	if err != nil {
		t.Fatal(err)
	}
	// the LAN and own_ip lookups see the KEV set only, as before D-527
	if len(ix.ForCVE("CVE-2024-3400")) != 1 || len(ix.ForCVE("CVE-2007-6750")) != 0 {
		t.Error("ForCVE must see the KEV set only")
	}
	if len(ix.FullForCVE("CVE-2024-2862", true)) != 0 || len(ix.FullForCVE("CVE-2024-3400", false)) != 1 {
		t.Error("FullForCVE must see what a full job may run only")
	}
	if len(ix.FullForCVE("CVE-2007-6750", false)) != 0 || len(ix.FullForCVE("CVE-2007-6750", true)) != 1 {
		t.Error("the disruptive set runs only with the tick")
	}
	for id, want := range map[string][3]bool{ // not full, full, full and disruptive
		"CVE-2024-3400": {true, true, true}, "CVE-2024-2862": {true, false, false}, "git-config": {false, true, true}, "slowloris": {false, false, true},
	} {
		tp, ok := ix.Get(id)
		if !ok || tp.RunsAt(false, false) != want[0] || tp.RunsAt(true, false) != want[1] || tp.RunsAt(true, true) != want[2] {
			t.Errorf("%s: RunsAt, want %v", id, want)
		}
	}
	for name, e := range map[string]map[string]any{
		"no sets":             deepEntry(func(e map[string]any) { delete(e, "sets") }),
		"unknown set":         deepEntry(func(e map[string]any) { e["sets"] = []string{"all"} }),
		"deep and disruptive": deepEntry(func(e map[string]any) { e["sets"] = []string{"deep", "disruptive"} }),
		"kev twice":           deepEntry(func(e map[string]any) { e["sets"] = []string{"kev", "kev"} }),
		"kev without a cve":   deepEntry(func(e map[string]any) { e["sets"], e["tags"], e["generic"] = []string{"kev"}, []string{"kev"}, false }),
		"kev without a kev tag": deepEntry(func(e map[string]any) {
			e["sets"], e["cve"], e["generic"] = []string{"kev", "deep"}, "CVE-2024-1", false
		}),
		"deep without a name":     deepEntry(func(e map[string]any) { delete(e, "name") }),
		"deep without a severity": deepEntry(func(e map[string]any) { delete(e, "severity") }),
		"another severity":        deepEntry(func(e map[string]any) { e["severity"] = "urgent" }),
		"a name with a newline":   deepEntry(func(e map[string]any) { e["name"] = "a\nb" }),
		"a long name":             deepEntry(func(e map[string]any) { e["name"] = strings.Repeat("a", maxName+1) }),
		"dos in the deep set":     deepEntry(func(e map[string]any) { e["tags"] = []string{"dos"} }),
		"dos with kev": deepEntry(func(e map[string]any) {
			e["tags"], e["sets"], e["cve"] = []string{"kev", "dos"}, []string{"kev", "disruptive"}, "CVE-2024-1"
		}),
		"brute-force deep":   deepEntry(func(e map[string]any) { e["tags"] = []string{"brute-force"} }),
		"default-login deep": deepEntry(func(e map[string]any) { e["tags"] = []string{"default-login"} }),
		"intrusive disruptive": deepEntry(func(e map[string]any) {
			e["tags"], e["sets"], e["generic"] = []string{"intrusive"}, []string{"disruptive"}, false
		}),
		"fuzz deep":             deepEntry(func(e map[string]any) { e["tags"] = []string{"fuzz"} }),
		"oast deep":             deepEntry(func(e map[string]any) { e["tags"] = []string{"oast"} }),
		"generic disruptive":    deepEntry(func(e map[string]any) { e["sets"] = []string{"disruptive"} }),
		"generic network":       deepEntry(func(e map[string]any) { e["path"] = "network/x.yaml" }),
		"own_ip outside kev":    deepEntry(func(e map[string]any) { e["own_ip"] = true }),
		"a cve that is not one": deepEntry(func(e map[string]any) { e["cve"] = "CVE-1" }),
	} {
		if _, err := fullIndex(t, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The limits hold the measured pack of D-527 (8260 templates, 4.3 MB of index) with room for the next releases of nuclei-templates.
func TestLimitsHoldTheMeasuredPack(t *testing.T) {
	t.Parallel()
	if MaxTemplates < 2*8260 || MaxSize < 2*4302648 {
		t.Fatalf("limits %d templates, %d bytes: below twice the measured pack", MaxTemplates, MaxSize)
	}
	many := make([]map[string]any, MaxTemplates+1)
	for i := range many {
		many[i] = deepEntry(func(e map[string]any) { e["id"] = "t" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + itoa(i) })
	}
	if _, err := fullIndex(t, many...); err == nil {
		t.Fatal("an index over MaxTemplates was accepted")
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestFullText(t *testing.T) {
	t.Parallel()
	ok := "id: x\nhttp:\n  - raw:\n      - |\n        POST /login HTTP/1.1\n        Host: {{Hostname}}\n\n        a=b\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	if err := FullText([]byte(ok), false); err != nil {
		t.Fatalf("a POST check refused: %v", err)
	}
	server := ok + "    matchers:\n      - type: word\n        words:\n          - \"Interactsh Server\"\n"
	if err := FullText([]byte(server), true); err != nil {
		t.Fatalf("a technologies template that recognises an interactsh server refused: %v", err)
	}
	for name, body := range map[string]string{
		"a PUT raw":       strings.Replace(ok, "POST /login", "PUT /login", 1),
		"a DELETE method": strings.Replace(ok, "method: GET", "method: DELETE", 1),
		"a patch method":  strings.Replace(ok, "method: GET", "method: patch", 1),
		"a MKCOL raw":     strings.Replace(ok, "POST /login", "MKCOL /x", 1),
		"interactsh":      strings.Replace(ok, "a=b", "u={{interactsh-url}}", 1),
		"an @Host":        strings.Replace(ok, "      - |\n", "      - |\n        @Host: https://login.microsoftonline.com:443\n", 1),
		"a server match":  server, // review M3: outside the technologies templates it means the target fetched one
	} {
		if FullText([]byte(body), false) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
