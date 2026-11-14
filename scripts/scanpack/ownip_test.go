package main

import (
	"strings"
	"testing"
)

// D-520: the own_ip decision of the builder. Only http checks whose every request is GET or HEAD without a body, with no
// credential, command or refused tag, may run on the box's own public IP; anything the builder cannot judge is refused.
func TestOwnIPDecision(t *testing.T) {
	t.Parallel()
	const rawGet = "id: CVE-2021-0001\ninfo:\n  name: t\n  classification:\n    cve-id: CVE-2021-0001\n  tags: cve,kev,lfi\nhttp:\n  - raw:\n      - |\n        GET /icons/.%2e/etc/passwd HTTP/1.1\n        Host: {{Hostname}}\n\n    matchers:\n      - type: regex\n        regex:\n          - \"root:.*:0:0:\"\n"
	allowed := map[string]string{
		"a GET path":    httpKEV,
		"a GET raw":     rawGet,
		"a HEAD method": strings.Replace(httpKEV, "method: GET", "method: HEAD", 1),
	}
	refused := map[string]string{
		"a POST raw after a GET (CVE-2021-41773's shape)": strings.Replace(rawGet, "\n    matchers:", "      - |\n        POST /cgi-bin/.%2e/bin/sh HTTP/1.1\n        Host: {{Hostname}}\n\n        echo; id\n    matchers:", 1),
		"a GET raw with a body":                           strings.Replace(rawGet, "Host: {{Hostname}}\n\n", "Host: {{Hostname}}\n\n        a=b\n", 1),
		"a POST method":                                   strings.Replace(httpKEV, "method: GET", "method: POST", 1),
		"a PATCH raw":                                     strings.Replace(rawGet, "GET /icons", "PATCH /redfish/v1/SessionService/ResetPassword/1/", 1),
		"a body key":                                      strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    body: \"x\"\n", 1),
		"an authorization header":                         strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    headers:\n      Authorization: Basic YWRtaW46YWRtaW4=\n", 1),
		"a cookie in a raw":                               strings.Replace(rawGet, "Host: {{Hostname}}\n", "Host: {{Hostname}}\n        Cookie: sid=1\n", 1),
		"a password variable":                             strings.Replace(httpKEV, "http:\n", "variables:\n  password: admin\nhttp:\n", 1),
		"a password in the query":                         strings.Replace(httpKEV, "login.esp", "login.esp?user=admin&password=admin", 1),
		"a command in the query":                          strings.Replace(httpKEV, "login.esp", "x?c=%60id%60", 1),
		"tag rce":                                         strings.Replace(httpKEV, "tags: cve,", "tags: rce,cve,", 1),
		"tag time-based-sqli":                             strings.Replace(httpKEV, "tags: cve,", "tags: time-based-sqli,cve,", 1),
		"tag authenticated":                               strings.Replace(httpKEV, "tags: cve,", "tags: authenticated,cve,", 1),
		"tag ssrf":                                        strings.Replace(httpKEV, "tags: cve,", "tags: ssrf,cve,", 1),
		"an unknown http key":                             strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    unsafe: true\n", 1),
		"a third-party request":                           strings.Replace(httpKEV, "login.esp", "x?url=http://oast.me", 1),
		"an SQL comment in a path":                        strings.Replace(httpKEV, "login.esp", "x?t=wp_users--%20-", 1),
		"a quote in a raw target":                         strings.Replace(rawGet, "GET /icons/.%2e/etc/passwd", "GET /?x=%27]", 1),
		"a script in a header value":                      strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    headers:\n      Referer: \"<script>\"\n", 1),
		"a crlf tag":                                      strings.Replace(httpKEV, "tags: cve,", "tags: crlf,cve,", 1),
		"a network check":                                 strings.Replace(httpKEV, "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/global-protect/login.esp\"\n", "tcp:\n  - host:\n      - \"{{Hostname}}\"\n    inputs:\n      - data: \"GET / HTTP/1.0\\r\\n\\r\\n\"\n", 1),
	}
	for name, text := range allowed {
		tpl, why := qualify("http/cves/2021/t.yaml", []byte(text))
		if why != "" || !tpl.OwnIP {
			t.Errorf("%s: left out %q or not own_ip", name, why)
		}
	}
	for name, text := range refused {
		path := "http/cves/2021/t.yaml"
		if strings.HasPrefix(text, "id: CVE-2024-3400") && strings.Contains(text, "tcp:") {
			path = "network/cves/2021/t.yaml"
		}
		if tpl, why := qualify(path, []byte(text)); why == "" && tpl.OwnIP {
			t.Errorf("%s: marked own_ip", name)
		}
	}
}
