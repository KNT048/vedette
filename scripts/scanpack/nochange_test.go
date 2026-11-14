package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// D-528 on fixture KEV templates: a template that changes state, goes to another host or port, or makes anyone reach a third party
// is left out with its reason; the reviewed ones that only look like it stay; and every denylisted id is out of the committed pack.
func TestBuildLeavesOutStateChangesAndOtherDestinations(t *testing.T) {
	t.Parallel()
	post := func(id, raw string) string {
		return "id: " + id + "\n\ninfo:\n  name: x\n  classification:\n    cve-id: CVE-2024-0001\n  tags: cve,kev\n\nhttp:\n  - raw:\n      - |\n" + raw + "\n    matchers:\n      - type: status\n        status:\n          - 200\n"
	}
	ind := func(s string) string { return "        " + strings.ReplaceAll(s, "\n", "\n        ") }
	cases := map[string]struct{ text, why string }{
		"password reset":  {post("CVE-2024-0001", ind("POST /api/changePw HTTP/1.1\nHost: {{Hostname}}\n\n{\"pw\":\"x\"}")), "state change"},
		"signup":          {post("CVE-2024-0002", ind("POST /api/v1/users/signup HTTP/1.1\nHost: {{Hostname}}\n\nu=a")), "state change"},
		"sql insert":      {post("CVE-2024-0003", ind("POST /q HTTP/1.1\nHost: {{Hostname}}\n\nq=1';INSERT INTO users VALUES(1)--")), "state change"},
		"shell write":     {post("CVE-2024-0004", ind("GET /cgi?p=;ls>/www/x; HTTP/1.1\nHost: {{Hostname}}")), "state change"},
		"upload":          {post("CVE-2024-0005", ind("POST /up HTTP/1.1\nHost: {{Hostname}}\nContent-Type: multipart/form-data; boundary=b\n\n--b\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"")), "state change"},
		"PUT":             {post("CVE-2024-0006", ind("PUT /cfg HTTP/1.1\nHost: {{Hostname}}")), "state change"},
		"at host":         {post("CVE-2024-0007", ind("@Host: https://login.microsoftonline.com:443\nGET /x HTTP/1.1\nHost: {{Hostname}}")), "state change"},
		"absolute target": {post("CVE-2024-0008", ind("GET http://example.org/ HTTP/1.1\nHost: {{Hostname}}")), "destination"},
		"third party":     {post("CVE-2024-0009", ind("GET /p?url=https://raw.githubusercontent.com/x HTTP/1.1\nHost: {{Hostname}}")), "third party"},
		"denylisted":      {post("CVE-2022-1903", ind("GET / HTTP/1.1\nHost: {{Hostname}}")), "denylist"},
		"instrusive":      {strings.Replace(post("CVE-2024-0010", ind("GET / HTTP/1.1\nHost: {{Hostname}}")), "tags: cve,kev", "tags: cve,kev,instrusive", 1), "forbidden tag"},
		"other port path": {strings.Replace(httpKEV, "{{BaseURL}}/global-protect/login.esp", "{{BaseURL}}:5814/x", 1), "destination"},
		"network port":    {strings.Replace(tcpKEV, `"{{Hostname}}"`, `"{{Host}}:8009"`, 1), "destination"},
		"open redirect followed": {strings.Replace(strings.Replace(httpKEV, "{{BaseURL}}/global-protect/login.esp", "{{BaseURL}}/r?to=//x", 1), "    matchers:", "    redirects: true\n    matchers:\n      - type: word\n        words:\n          - oast.me\n", 1),
			"third party"},
	}
	for name, c := range cases {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(c.text), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		info, _ := doc["info"].(map[string]any)
		id, _ := doc["id"].(string)
		if why, d := changeReason(id, doc, []byte(c.text), tagsOf(info)); why != c.why {
			t.Errorf("%s: %q (%s), want %q", name, why, d, c.why)
		}
	}
	for name, raw := range map[string]string{
		"F5 Host: localhost": ind("POST /mgmt/tm/util/bash HTTP/1.1\nHost: localhost\nConnection: keep-alive, X-F5-Auth-Token\n\n{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}"),
		"a query target":     ind("GET ?--configPath=/x HTTP/1.1\nHost: {{Hostname}}"),
		"a SOAP namespace":   ind("POST /ws HTTP/1.1\nHost: {{Hostname}}\nSOAPAction: \"http://tempuri.org/Get\"\n\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"/>"),
		"a CORS origin":      ind("GET /api HTTP/1.1\nHost: {{Hostname}}\nOrigin: https://evil.com"),
		"a GET of a reset":   ind("GET /passwordreset/request/ HTTP/1.1\nHost: {{Hostname}}"),
	} {
		text := post("CVE-2024-0100", raw)
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if why, d := changeReason("CVE-2024-0100", doc, []byte(text), []string{"kev"}); why != "" {
			t.Errorf("%s: left out as %q (%s)", name, why, d)
		}
	}
}

// Every denylisted and reviewed id carries its reason, and none of the denylisted ids is in the committed pack.
func TestDenylistIsOutOfTheCommittedPack(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../content/nucleipack/index.json")
	if err != nil {
		t.Fatal(err)
	}
	var ix struct {
		Templates []struct {
			ID string `json:"id"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(raw, &ix); err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, tp := range ix.Templates {
		in[tp.ID] = true
	}
	for id, why := range denylist {
		if len(why) < 10 || in[id] {
			t.Errorf("%s: reason %q, in the pack %t", id, why, in[id])
		}
	}
	for id, e := range reviewed {
		if !in[id] {
			t.Errorf("reviewed %s (%s) is not in the pack", id, e.why)
		}
	}
}
