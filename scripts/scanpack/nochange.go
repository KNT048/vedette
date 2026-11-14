package main

import (
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/modules/scan/pack"
)

// D-528: the state-change, destination and third-party rule of every template the pack takes (review FULL-4b r1 H1, H2, H3, M1, M3).
// changeReason is "" for a template that may go in, else the reason it is left out and the text that decided it.

// denylist are templates read and refused by a person (review FULL-4b r1, 2026-11-14), each with why, kept out whatever the rules
// below say: the upstream tags do not always say what a template does. Re-read it on every NUCLEI_TEMPLATES_VERSION bump.
var denylist = map[string]string{ //nolint:gosec // G101: template ids and reasons that name passwords, not credentials
	"CVE-2021-29203":                  "PATCH ResetPassword: sets the HPE Edgeline Administrator password to a random one",
	"CVE-2024-2862":                   "PUT /api/changePw: resets the LG LED Assistant password",
	"CVE-2024-50334":                  "PUT /api;/config: writes the configuration",
	"CVE-2022-1903":                   "ARMember change-password action: sets the WordPress admin password to a random one",
	"CVE-2024-5276":                   "SQL INSERT INTO DOCTERA_USERS: creates a FileCatalyst admin",
	"CVE-2024-4358":                   "POST /Startup/Register: registers a Telerik Report Server admin",
	"CVE-2024-6396":                   "Aim arbitrary file overwrite, sent to port 43800",
	"CVE-2023-26802":                  "command injection writing a file into the web root (ls>…)",
	"CVE-2023-33629":                  "command injection writing a file into /www",
	"CVE-2022-26960":                  "elFinder writes a file under /var",
	"weaver-group-xml-sqli":           "SQL INTO OUTFILE writes a PHP file into the web root",
	"CVE-2021-24212":                  "file upload",
	"CVE-2022-41352":                  "Zimbra file upload",
	"CVE-2026-25895":                  "file upload",
	"CVE-2024-2863":                   "file upload",
	"CNVD-2023-96945":                 "file upload",
	"thinkphp6-arbitrary-write":       "writes a file",
	"wanhuoa-smartupload-file-upload": "file upload",
	"idocview-2word-fileupload":       "file upload",
	"h3c-cnsss-arbitrary-file-upload": "file upload",
	"CVE-2024-50477":                  "account takeover",
	"CVE-2026-11387":                  "account takeover",
	"gestsup-account-takeover":        "account takeover",
	"dragonfly-public-signup":         "POST /api/v1/users/signup creates an account",
	"CVE-2021-21389":                  "BuddyPress signup creates a user and makes the target mail interact.sh",
	"CVE-2015-2863":                   "makes the target fetch http://oast.me",
	"CVE-2025-47539":                  "makes the target import from oast.fun",
	"CVE-2022-0826":                   "makes the target fetch a third-party URL",
	"CVE-2021-22054":                  "makes the target fetch an interactsh server through a base64 URL",
	"CVE-2021-22873":                  "follows a redirect to interact.sh",
	"CVE-2023-0552":                   "follows a redirect to oast.me",
	"rdap-whois":                      "sends the target's address to rdap.net",
	"azure-domain-tenant":             "sends the target's address to login.microsoftonline.com",
	"google-gemini-key-exposure":      "sends a key read from the target's page to Google",
	"hpe-autopass-panel":              "sends to port 5814, not the job's",
	"CVE-2018-8024":                   "sends to port 4040, not the job's",
	"unifi-nfc-credentials":           "sends to port 9780, not the job's",
	"CVE-2016-10033":                  "PHPMailer: runs touch through the Host header, which writes a file",
	"CVE-2023-6549":                   "a NetScaler denial-of-service CVE, checked with an oversized Host header",
	// read during the D-528 pass over the KEV set (requests naming reset, save, update, install, write, import)
	"CVE-2020-36333": "ThemeGrill: do_reset_wordpress wipes the WordPress database",
	"CVE-2018-19207": "WP GDPR Compliance: save_setting opens registration with the administrator role",
	"CVE-2018-17207": "Duplicator: installer-backup.php rewrites wp-config.php",
	"CVE-2018-25114": "osCommerce: runs install step 4, which rewrites configure.php",
	"CVE-2020-5902":  "F5 TMUI: creates a tmsh alias and saves a file",
	"CVE-2022-0952":  "click5 Sitemap: update_html_option changes a WordPress option",
	"CVE-2022-1020":  "Product Table: wpt_admin_update_notice_option changes a WordPress option",
	"CVE-2020-11515": "Rank Math: updateRedirection creates a redirect",
	"CVE-2018-14933": "NUUO: cmd=writeuploaddir changes the upload directory setting",
	"CVE-2023-1389":  "TP-Link: operation=write sets the router's country",
	"CVE-2021-44077": "ServiceDesk Plus: ImportTechnicians uploads a file",
}

// reviewedOK are templates the state-change patterns would refuse and a person read as making no change (review of D-528,
// 2026-11-14): the password-reset or registration path only carries a read-only command, and no account or password changes. The
// destination and third-party rules still apply to them.
var reviewedOK = map[string]string{
	"CVE-2018-7600":  "Drupal: the register form's AJAX callback renders passthru of cat /etc/passwd; the form fails, no account is made",
	"CVE-2019-15107": "Webmin backdoor: password_change.cgi for a user that does not exist (rootxx) runs cat /etc/passwd; no password changes",
	"CVE-2024-32113": "OFBiz: forgotPassword/../ProgramExport runs id and ipconfig in a Groovy exception; no reset",
	"CVE-2024-36104": "OFBiz: forgotPassword/../ProgramExport runs id and ipconfig in a Groovy exception; no reset",
}

var (
	// netHostOK is a network template's host or ssl address that is the job's own address.
	netHostOK = regexp.MustCompile(`^(tls://)?\{\{(Hostname|Host)\}\}(:\{\{Port\}\})?$`)
	// oobHostRE is an out-of-band or third-party callback host named in a template.
	oobHostRE = regexp.MustCompile(`(?i)interact\.sh|interactsh|oast\.[a-z]+|burpcollaborator`)
)

// part is one piece of what a template sends, and whether it is sent with POST.
type part struct {
	text string
	post bool
}

// changeReason applies D-528 to one parsed template: the denylist, pack.NeverTags, pack.NoChangeText of the whole file (no write
// method, no @Host: annotation, no upload), the destination rule (an http path starts with {{BaseURL}} or {{RootURL}} and names no
// other port; a raw request line names a path; a network host or ssl address is the job's address with no other port), the request
// parts (paths, raw requests but their Origin and Referer headers, bodies, header, payload and variable values) through
// pack.ChangeInRequest and pack.ThirdPartyURL, and redirects followed in a template that names an out-of-band host. A raw Host
// header is not a destination: nuclei connects to the job's address whatever the header says (F5's CVE-2022-1388 needs
// "Host: localhost").
func changeReason(id string, doc map[string]any, body []byte, tags []string) (why, detail string) {
	if d, ok := denylist[id]; ok {
		return "denylist", d
	}
	if i := slices.IndexFunc(tags, func(t string) bool { return slices.Contains(pack.NeverTags, t) }); i >= 0 {
		return "forbidden tag", tags[i]
	}
	if err := pack.NoChangeText(body); err != nil {
		return "state change", err.Error()
	}
	redirects, anyPost := false, false
	var parts []part
	for _, b := range blocks(doc, "http") {
		redirects = redirects || b["redirects"] == true || b["host-redirects"] == true
		method, _ := b["method"].(string)
		method = strings.ToUpper(method)
		if method != "" && !pack.MethodOK(method) {
			return "state change", "method " + method
		}
		post := method == "POST"
		for _, p := range strs(b["path"]) {
			rest, ok := strings.CutPrefix(p, "{{BaseURL}}")
			if !ok {
				rest, ok = strings.CutPrefix(p, "{{RootURL}}")
			}
			if !ok || strings.HasPrefix(rest, ":") {
				return "destination", p
			}
			parts = append(parts, part{p, post})
		}
		for _, r := range strs(b["raw"]) {
			rpost, why, d := rawReason(r)
			if why != "" {
				return why, d
			}
			post = post || rpost
			parts = append(parts, part{rawParts(r), rpost})
		}
		if s, ok := b["body"].(string); ok {
			parts = append(parts, part{s, post})
		}
		if h, ok := b["headers"].(map[string]any); ok {
			for k, v := range h {
				if s, ok := v.(string); ok && !refererLike(k) {
					parts = append(parts, part{s, post})
				}
			}
		}
		if p, ok := b["payloads"].(map[string]any); ok {
			for _, v := range p {
				for _, s := range strs(v) {
					parts = append(parts, part{s, post})
				}
			}
		}
		anyPost = anyPost || post
	}
	for _, b := range blocks(doc, "tcp") {
		for _, h := range strs(b["host"]) {
			if !netHostOK.MatchString(h) {
				return "destination", h
			}
		}
		if in, ok := b["inputs"].([]any); ok {
			for _, x := range in {
				if m, ok := x.(map[string]any); ok {
					if s, ok := m["data"].(string); ok {
						parts = append(parts, part{s, true})
					}
				}
			}
		}
	}
	for _, b := range blocks(doc, "ssl") {
		if a, ok := b["address"].(string); ok && !netHostOK.MatchString(a) {
			return "destination", a
		}
	}
	if v, ok := doc["variables"].(map[string]any); ok {
		for _, x := range v {
			for _, s := range strs(x) {
				parts = append(parts, part{s, anyPost})
			}
		}
	}
	_, reviewed := reviewedOK[id]
	for _, p := range parts {
		if c := pack.ChangeInRequest(p.text, p.post); c != "" && !reviewed {
			return "state change", c + ": " + clip(p.text)
		}
		if u := pack.ThirdPartyURL(p.text); u != "" {
			return "third party", u
		}
	}
	if redirects && oobHostRE.Match(body) {
		return "third party", "follows redirects to " + oobHostRE.FindString(string(body))
	}
	return "", ""
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// rawReason reads a raw request line: post says it is a POST; why is set when the method may not be sent or the target is not a path
// or query on the job's address (an absolute URL would go through the target as a proxy).
func rawReason(r string) (post bool, why, detail string) {
	lines := strings.Split(strings.ReplaceAll(r, "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || strings.HasPrefix(strings.TrimSpace(lines[i]), "@")) {
		i++
	}
	if i == len(lines) {
		return false, "request", "no request line"
	}
	f := strings.Fields(lines[i])
	if len(f) < 2 || !pack.MethodOK(f[0]) {
		return false, "state change", clip(lines[i])
	}
	if !strings.HasPrefix(f[1], "/") && !strings.HasPrefix(f[1], "?") && !strings.HasPrefix(f[1], "*") && !strings.HasPrefix(f[1], "{{") {
		return false, "destination", clip(lines[i])
	}
	return f[0] == "POST", "", ""
}

// rawParts is a raw request as data that is sent: every line but its Origin and Referer headers (a CORS or referrer check names
// another site, which nobody fetches).
func rawParts(r string) string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(r, "\r\n", "\n"), "\n") {
		if name, _, ok := strings.Cut(l, ":"); ok && refererLike(strings.TrimSpace(name)) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func refererLike(header string) bool {
	return strings.EqualFold(header, "origin") || strings.EqualFold(header, "referer")
}

func blocks(doc map[string]any, key string) []map[string]any {
	l, _ := doc[key].([]any)
	var out []map[string]any
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// strs is a YAML string or list of strings (other values are left out).
func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
