package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	// D-528 step 2: named by review kev r1 (H-1, M-1, M-2, L-1) and FULL-4b r2 (H1, M-new, L-a, L-b, L-d); never at any depth
	"CVE-2024-5910":               "Palo Alto Expedition: GET restoreAdmin.php restores the admin password to its default",
	"cacti-weathermap-file-write": "Cacti Weathermap: GET editor.php set_map_properties writes configs/poc.conf",
	"tamronos-user-creation":      "TamronOS: GET /api/manager/submit creates an admin",
	"CVE-2024-2621":               "GET pwd_update.php with an always-true condition sets user 1's password",
	"CVE-2024-29972":              "Zyxel NAS: GET remote_help-cgi enables the NsaRescueAngel backdoor account and SSH",
	"CVE-2019-5129":               "AVideo: the base64Url command writes a file into the web root",
	"una-cms-rce":                 "UNA CMS: the gadget writes a PHP webshell cache_public/sh.phtml and leaves it",
	"CVE-2015-3306":               "ProFTPD mod_copy: site cpto copies files into /tmp and the web root",
	"CVE-2021-25281":              "Salt: pillar_roots.write writes a file",
	"CVE-2023-26469":              "Jorani: writes PHP into the application log, then deletes the log",
	"CVE-2019-11869":              "Yuzo: saves a script into an option shown on every page",
	"CVE-2018-3810":               "Smart Google Code Inserter: savegooglecode stores a script on every page",
	"CVE-2024-34061":              "changedetection.io: POST /settings replaces all settings",
	"CVE-2019-11370":              "Carel pCOWeb: setdb writes the SNMP contact",
	"CVE-2019-16931":              "Visualizer: update-chart changes chart 7",
	"CVE-2021-29441":              "Nacos: publishes a config entry",
	"CVE-2021-20091":              "Buffalo: config injection turns telnetd on",
	"sanhuismg-radius-rce":        "Sanhui SMG: save=1&enable_radius=1 changes the RADIUS settings",
	"CVE-2024-6846":               "WP chatbot: purges the error logs",
	"CVE-2026-2614":               "MLflow: creates a registered model and a version",
	"CVE-2026-88062":              "OmniRoute: creates a persistent agent carrying a command",
	"CVE-2026-82329":              "JFrog: registry/join registers a node and returns a token",
	"CVE-2026-20253":              "Splunk: postgres recovery backup creates or truncates files",
	"CVE-2023-25135":              "vBulletin: user/save may register a user and mail pown.net",
	"CVE-2020-6287":               "SAP RECON: creates an administrator sapRpoc6351 with a published password",
	"CVE-2021-25032":              "PublishPress Capabilities: makes every later signup an administrator",
	"CVE-2023-22463":              "KubePi: creates a user with a forged admin token",
	"CVE-2023-6875":               "POST SMTP: registers a mobile-app device in the plugin's options",
	"CVE-2016-10960":              "wSecure Lite: rewrites the plugin's PHP config with injected code",
	"CVE-2019-10068":              "Kentico: the payload writes an executable's base64 to disk",
	"CVE-2022-0827":               "BestBooks: inserts an accounting transaction",
	"CVE-2025-69200":              "phpMyFAQ: writes a configuration backup ZIP with the DB credentials",
	"CVE-2023-27587":              "ReadToMyShoe: adds an article and makes the target call Google's TTS API",
	"CVE-2023-3277":               "MStore: apple_login may register an unknown e-mail",
	"CVE-2023-22893":              "Strapi: the Cognito callback may create an account",
	"CVE-2022-2461":               "Transposh: stores a translation",
	"CVE-2021-27358":              "Grafana: creates a snapshot",
	"CVE-2023-48022":              "Ray: submits a job whose record persists",
	"CVE-2019-7192":               "QNAP: setSlideshow creates a slideshow share",
	"CVE-2019-7195":               "QNAP: setSlideshow creates a slideshow share",
	"CVE-2024-11972":              "Hunk Companion: plugin install makes WordPress query wordpress.org",
	"CVE-2018-1000861":            "Jenkins: @Grab makes Ivy reach Maven Central",
	"CVE-2023-48788":              "FortiClient EMS: registers or overwrites an endpoint row",
	"CVE-2020-10199":              "Nexus: logs in as admin/admin123 and creates a repository",
	"CVE-2022-0769":               "SQL inside a vote update: sets vote_score",
	"CVE-2021-24442":              "inserts a poll vote",
	"CVE-2024-6028":               "inserts a quiz result",
	"CVE-2025-5287":               "adds a like",
	"CVE-2022-0747":               "an upvote action writes a row",
	"CVE-2022-0760":               "an upvote action writes a row",
	"CVE-2020-27481":              "cancels booking 1337 if it exists",
	"CVE-2022-0846":               "dk_speakout_sendmail sends mail",
	"CVE-2025-2075":               "sets a role to administrator after a login",
	"CVE-2025-1023":               "ChurchCRM: Action=ADD adds a record",
	"CVE-2018-7602":               "Drupal: cancels or deletes a node after a login",
	"CVE-2023-38192":              "SuperWebMailer: tries superadmincreate.php",
	"CVE-2024-1212":               "Kemp: access/set enableapi tries to change a setting",
	"CVE-2018-17283":              "OpManager: setManaged manage=false and reads the API key",
	"CVE-2017-9791":               "Struts showcase: saveGangster saves a record",
	"CVE-2026-23829":              "SMTP: submits a mail through any SMTP service (MAIL FROM, RCPT TO, DATA)",
	"CVE-2021-24943":              "rtec_send_unregister_link mails a random domain",
	"CVE-2022-0954":               "save_option changes an option once credentials exist",
	"CVE-2022-30073":              "creates admin testme2 once credentials exist",
	"CVE-2021-24554":              "action=delete once credentials exist",
	"CVE-2022-0535":               "changes settings once credentials exist",
	"CVE-2022-0949":               "inserts a fingerprint row",
	// D-528 step 2 review r1 (H-1, M-2, M-3): a GET that acts, logins with known or backdoor credentials, a third-party ping
	"CVE-2020-27866": "NETGEAR: GET setup.cgi?todo=debug turns debug mode and telnetd on",
	"CVE-2018-10823": "D-Link: the ping diagnostic makes the device ping 1.1.1.1",
	"CVE-2023-2732":  "MStore API: logs in as WordPress user 1 (and may add a listing)",
	"CVE-2025-13390": "auto-login as WordPress user 1",
	"CVE-2020-29583": "Zyxel: logs in with the published hard-coded admin account zyfwp",
	"CVE-2019-16057": "D-Link DNS-320: logs in as admin with a blank password",
	"CVE-2017-9833":  "Boa: logs in with admin/admin in the query",
	"CVE-2017-7921":  "Hikvision: the magic auth token counts as a failed login on a patched device (lockout)",
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
				s, ok := v.(string)
				if !ok {
					continue
				}
				if hp := hostHeaderParty(k, s); hp != "" {
					return "third party", hp
				}
				if !refererLike(k) {
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
		if p, has := b["port"]; has && fmt.Sprint(p) != "{{Port}}" { // review kev r1 M-3: a fixed port is not the job's port
			return "destination", fmt.Sprintf("port: %v", p)
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
	if v := undefinedCredential(doc, body); v != "" {
		return "undefined credential", v
	}
	sum := sha256.Sum256(body)
	reviewed, _ := reviewedState(id, hex.EncodeToString(sum[:]))
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
	for i++; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		if name, value, ok := strings.Cut(lines[i], ":"); ok {
			if hp := hostHeaderParty(strings.TrimSpace(name), strings.TrimSpace(value)); hp != "" {
				return false, "third party", hp
			}
		}
	}
	return f[0] == "POST", "", ""
}

// hostHeaders name the host a target builds links or routes with: a third party there can be poisoned into a reset link or a
// proxied request (review kev r1 L-4). Their values are read as hosts.
var hostHeaders = []string{"host", "x-forwarded-host", "x-host", "x-original-host", "x-forwarded-server", "forwarded"}

// hostHeaderParty is the value of a host header that names a party on the Internet other than the job's address, or "".
func hostHeaderParty(name, value string) string {
	if !slices.Contains(hostHeaders, strings.ToLower(name)) {
		return ""
	}
	var hosts []string
	if strings.EqualFold(name, "forwarded") {
		for _, kv := range strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' }) {
			if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.EqualFold(k, "host") {
				hosts = append(hosts, strings.Trim(v, `"`))
			}
		}
	} else {
		hosts = strings.Split(value, ",")
	}
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" && pack.ThirdPartyHost(h) {
			return name + ": " + h
		}
	}
	return ""
}

// credVarRE are the user name, password and e-mail expressions of a template: Vedette never supplies them (no -var), so a template
// that uses one it does not define waits for a value a later version might pass (review FULL-4b r2 L-b).
var credVarRE = regexp.MustCompile(`\{\{\s*(username|password|user|pass|email)\s*\}\}`)

// undefinedCredential is the first credential expression a template uses without defining it in variables or payloads, or "".
func undefinedCredential(doc map[string]any, body []byte) string {
	defined := map[string]bool{}
	if v, ok := doc["variables"].(map[string]any); ok {
		for k := range v {
			defined[k] = true
		}
	}
	for _, key := range []string{"http", "tcp"} {
		for _, b := range blocks(doc, key) {
			if p, ok := b["payloads"].(map[string]any); ok {
				for k := range p {
					defined[k] = true
				}
			}
		}
	}
	for _, m := range credVarRE.FindAllStringSubmatch(string(body), -1) {
		if !defined[m[1]] {
			return m[0]
		}
	}
	return ""
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
