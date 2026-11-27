package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/modules/scan/pack"
)

// requestsOfYAML is requestsOf of a template's http part.
func requestsOfYAML(t *testing.T, body string) []string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return requestsOf(doc)
}

// Every request an http template can send is listed, in the order of the file, each once: every path: entry of every block, the
// request line of every raw request, payload and plain variable values put in; what cannot be listed is pack.RequestUnknown.
func TestRequestsOfListsEveryRequest(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		body string
		want []string
	}{
		"two paths, the second under a prefix": {`
http:
  - method: GET
    path:
      - "{{BaseURL}}/users/sign_in"
      - "{{BaseURL}}/users/sign_up"
    stop-at-first-match: true
`, []string{"GET {{BaseURL}}/users/sign_in", "GET {{BaseURL}}/users/sign_up"}},
		"every block, method per block, GET when none, each line once": {`
http:
  - path:
      - "{{BaseURL}}/a"
  - method: post
    path:
      - "{{BaseURL}}/b"
      - "{{BaseURL}}/b"
  - path:
      - "{{BaseURL}}/a"
`, []string{"GET {{BaseURL}}/a", "POST {{BaseURL}}/b"}},
		"raw requests: the request line of each, annotations skipped": {`
http:
  - raw:
      - |
        @timeout: 10s
        GET /wp-content/plugins/x/readme.txt HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /wp-admin/admin-post.php?cmd=info HTTP/1.1
        Host: {{Hostname}}
`, []string{"GET /wp-content/plugins/x/readme.txt", "GET /wp-admin/admin-post.php?cmd=info"}},
		"inline payloads and plain variables are put in, every value": {`
variables:
  dir: "/backup"
  token: "{{rand_base(6)}}"
http:
  - method: GET
    path:
      - "{{BaseURL}}{{dir}}/{{file}}"
      - "{{BaseURL}}/{{token}}"
    payloads:
      file:
        - db.sql
        - 7
`, []string{"GET {{BaseURL}}/backup/db.sql", "GET {{BaseURL}}/backup/7", "GET {{BaseURL}}/{{token}}"}},
		"an unsafe raw request that follows redirects": {`
http:
  - raw:
      - |
        GET /a HTTP/1.1
        Host: {{Hostname}}
    unsafe: true
    redirects: true
`, []string{"GET /a", pack.RequestUnknown}},
		"a redirect of nuclei's http client (turned off by -dr) is no unknown": {`
http:
  - path:
      - "{{BaseURL}}/a"
    redirects: true
    host-redirects: true
`, []string{"GET {{BaseURL}}/a"}},
		"a block with neither path nor raw": {`
http:
  - path:
      - "{{BaseURL}}/a"
  - method: GET
`, []string{"GET {{BaseURL}}/a", pack.RequestUnknown}},
		"no http block": {`
tcp:
  - inputs:
      - data: "x"
`, []string{pack.RequestUnknown}},
	}
	for name, c := range cases {
		if got := requestsOfYAML(t, c.body); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// The list is bounded: more than pack.MaxRequests lines (or payload combinations) end in pack.RequestUnknown, and a line over 200
// bytes is cut and ends with an expression, so core judges the path by the part kept and treats the rest as unknown.
func TestRequestsOfIsBounded(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("http:\n  - path:\n")
	for i := range pack.MaxRequests + 5 {
		fmt.Fprintf(&b, "      - \"{{BaseURL}}/p%d\"\n", i)
	}
	got := requestsOfYAML(t, b.String())
	if len(got) != pack.MaxRequests || got[len(got)-1] != pack.RequestUnknown || got[0] != "GET {{BaseURL}}/p0" {
		t.Fatalf("%d lines, last %q", len(got), got[len(got)-1])
	}

	var vals strings.Builder
	for i := range 10 {
		fmt.Fprintf(&vals, "        - v%d\n", i)
	}
	combos := "http:\n  - path:\n      - \"{{BaseURL}}/{{a}}/{{b}}\"\n    payloads:\n      a:\n" + vals.String() + "      b:\n" + vals.String()
	if got := requestsOfYAML(t, combos); !slices.Equal(got, []string{pack.RequestUnknown}) {
		t.Fatalf("100 combinations: %q", got)
	}

	long := "/" + strings.Repeat("a", 300)
	got = requestsOfYAML(t, "http:\n  - path:\n      - \"{{BaseURL}}"+long+"\"\n")
	if len(got) != 1 || len(got[0]) != 200 || !strings.HasSuffix(got[0], cutMark) || !strings.HasPrefix(got[0], "GET {{BaseURL}}/aaa") {
		t.Fatalf("a long line: %q", got)
	}
}

// The builder writes the list on an http template, its first line the probe log's request line.
func TestBuildWritesTheRequestsOfHTTPTemplates(t *testing.T) {
	t.Parallel()
	tpl, why := qualifyWith("http/cves/2024/CVE-2024-3400.yaml", []byte(httpKEV), allowAny)
	if why != "" {
		t.Fatalf("left out: %s", why)
	}
	if len(tpl.Requests) == 0 || tpl.Requests[0] != tpl.Request {
		t.Fatalf("requests %q, request %q", tpl.Requests, tpl.Request)
	}
}
