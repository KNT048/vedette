package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/pack"
)

// D-527: the deep and disruptive sets next to the KEV set, on fixture templates.
const techTpl = `id: nginx-version

info:
  name: Nginx Version - Detect
  severity: info
  tags: tech,nginx

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - nginx
`

const gitTpl = `id: git-config

info:
  name: Git Configuration - Detect
  severity: medium
  tags: config,git,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
`

const nginxPanel = `id: nginx-admin-panel

info:
  name: Nginx UI Panel
  severity: info
  tags: panel,nginx

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
`

const postVuln = `id: some-sqli

info:
  name: Some SQL injection
  severity: high
  tags: sqli,vuln

http:
  - raw:
      - |
        POST /search HTTP/1.1
        Host: {{Hostname}}

        q=1'
    matchers:
      - type: word
        words:
          - "SQL syntax"
`

const defaultLogin = `id: tomcat-default-login

info:
  name: Tomcat Default Login
  severity: high
  tags: tomcat,default-login

http:
  - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64(username + ':' + password)}}
    attack: pitchfork
    payloads:
      username: [tomcat, admin]
      password: [tomcat, admin]
    matchers:
      - type: status
        status:
          - 200
`

func TestBuildSets(t *testing.T) {
	t.Parallel()
	src, out := t.TempDir(), t.TempDir()
	write(t, src, "http/cves/2024/CVE-2024-3400.yaml", httpKEV)                                                                                                         // kev + deep
	write(t, src, "http/cves/2024/CVE-2024-2862.yaml", strings.ReplaceAll(strings.Replace(httpKEV, "method: GET", "method: PUT", 1), "CVE-2024-3400", "CVE-2024-2862")) // a write: out of every set (D-528)
	write(t, src, "http/technologies/nginx-version.yaml", techTpl)
	write(t, src, "http/exposures/configs/git-config.yaml", gitTpl)
	write(t, src, "http/exposed-panels/nginx-admin-panel.yaml", nginxPanel)
	write(t, src, "http/vulnerabilities/some-sqli.yaml", postVuln)
	write(t, src, "http/default-logins/tomcat-default-login.yaml", defaultLogin)
	write(t, src, "http/vulnerabilities/dos-x.yaml", strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: dos-x", 1), "sqli,vuln", "dos,vuln", 1))
	left := map[string]string{
		"http/vulnerabilities/oast.yaml":      strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: oast-x", 1), "sqli,vuln", "oast,vuln", 1),
		"http/vulnerabilities/ish.yaml":       strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: ish-x", 1), "q=1'", "u={{interactsh-url}}", 1),
		"http/vulnerabilities/put.yaml":       strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: put-x", 1), "POST /search", "PUT /search", 1),
		"http/vulnerabilities/delete.yaml":    strings.Replace(strings.Replace(gitTpl, "id: git-config", "id: delete-x", 1), "method: GET", "method: DELETE", 1),
		"http/vulnerabilities/patch.yaml":     strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: patch-x", 1), "POST /search", "PATCH /search", 1),
		"http/vulnerabilities/intrusive.yaml": strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: intrusive-x", 1), "sqli,vuln", "sqli,intrusive", 1),
		"http/vulnerabilities/fuzz.yaml":      strings.Replace(strings.Replace(postVuln, "id: some-sqli", "id: fuzz-x", 1), "sqli,vuln", "fuzz", 1),
		"http/vulnerabilities/flag.yaml":      strings.Replace(postVuln, "id: some-sqli", "id: -code", 1),
		"http/vulnerabilities/payfile.yaml":   strings.Replace(strings.Replace(defaultLogin, "id: tomcat-default-login", "id: payfile", 1), "[tomcat, admin]", "helpers/wordlists/users.txt", 1),
		"http/osint/someone.yaml":             strings.Replace(gitTpl, "id: git-config", "id: osint-x", 1),
		"http/fuzzing/f.yaml":                 strings.Replace(gitTpl, "id: git-config", "id: fuzzing-x", 1),
	}
	for p, text := range left {
		write(t, src, p, text)
	}
	// only the KEV fixture read by a person: the deep set takes read-only GETs (rule (a)), any other goes behind the tick
	kevRead := func(id, _ string) (bool, bool) { return id == "CVE-2024-3400", false }
	rep, err := buildWith(src, out, "2026.11.3", kevRead)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := pack.Parse(readFile(t, filepath.Join(out, "index.json")))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"CVE-2024-3400":        {"kev", "deep"},
		"nginx-version":        {"deep"},
		"git-config":           {"deep"},
		"nginx-admin-panel":    {"deep"},
		"some-sqli":            {"disruptive"}, // D-528 step 2: a POST nobody reviewed runs only behind the tick
		"tomcat-default-login": {"disruptive"},
		"dos-x":                {"disruptive"},
	}
	if len(ix.Templates) != len(want) {
		t.Errorf("kept %d templates, want %d: %+v", len(ix.Templates), len(want), rep)
	}
	for id, sets := range want {
		tp, ok := ix.Get(id)
		if !ok || !slices.Equal(tp.Sets, sets) {
			t.Errorf("%s: sets %v, want %v", id, tp.Sets, sets)
		}
	}
	git, _ := ix.Get("git-config")
	panel, _ := ix.Get("nginx-admin-panel")
	tech, _ := ix.Get("nginx-version")
	if !git.Generic || panel.Generic || tech.Generic {
		t.Errorf("generic: git %t (want true), a panel tagged with a detected product %t, a technologies template %t", git.Generic, panel.Generic, tech.Generic)
	}
	if git.Name != "Git Configuration - Detect" || git.Severity != "medium" || git.CVE != "" {
		t.Errorf("git-config entry %+v", git)
	}
	if !pack.ProductTags(ix.Templates)["nginx"] {
		t.Error("nginx, a tag a technologies template's id contains, is not a product tag")
	}
	if _, ok := ix.Get("CVE-2024-2862"); ok {
		t.Error("a PUT template is in the pack")
	}
	for _, reason := range []string{"forbidden tag", "interactsh", "full text", "id", "payloads"} {
		if rep.Left[reason] == 0 {
			t.Errorf("nothing left out for %q: %+v", reason, rep.Left)
		}
	}
	if rep.Sets["kev"] != 1 || rep.Sets["deep"] != 4 || rep.Sets["disruptive"] != 3 || rep.Sets["generic"] != 1 {
		t.Errorf("report per set %v", rep.Sets)
	}
}
