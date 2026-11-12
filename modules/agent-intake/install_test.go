package agentintake_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

const (
	// The GUI files this test reads, one literal each: scripts/ci/classify.go names them, so a pull request that changes one runs go.
	guiTS     = "../../web/src/features/inventory/installScripts.ts"
	guiSh     = "../../web/src/features/inventory/scripts/osquery.sh"
	guiPs1    = "../../web/src/features/inventory/scripts/osquery.ps1"
	pinsFile  = "../../deploy/osquery/PINS"
	guiFill   = "const fill = (t: string, box: string, ca: string) => t.replaceAll('@@BOX@@', box).replaceAll('@@VERSION@@', OSQUERY_VERSION).replaceAll('@@CA@@', ca.trim())"
	boxAtPort = "box.corp.example:8443"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a fixed path inside the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// guiVersion is OSQUERY_VERSION of installScripts.ts.
func guiVersion(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`export const OSQUERY_VERSION = '([0-9.]+)'`).FindStringSubmatch(readFile(t, guiTS))
	if m == nil {
		t.Fatal("installScripts.ts has no OSQUERY_VERSION")
	}
	return m[1]
}

// guiScript renders a GUI template the way the GUI does (installScripts.ts fill): the check below holds the placeholder rules to that text.
func guiScript(t *testing.T, file, box, ca string) string {
	t.Helper()
	if !strings.Contains(readFile(t, guiTS), guiFill) {
		t.Fatal("installScripts.ts changed the way it fills the placeholders: update agentintake.fill and this test together")
	}
	s := strings.ReplaceAll(readFile(t, file), "@@BOX@@", box)
	s = strings.ReplaceAll(s, "@@VERSION@@", guiVersion(t))
	return strings.ReplaceAll(s, "@@CA@@", strings.TrimSpace(ca))
}

// get sends an unauthenticated GET (or one as user, a key of servertest.StandardUsers) with the Host header host.
func (w *world) get(path, host, user string) (reply, []byte) {
	w.t.Helper()
	r := httptest.NewRequestWithContext(w.t.Context(), http.MethodGet, server.Prefix+path, nil)
	r.RemoteAddr = "192.0.2.200:40000"
	if host != "" {
		r.Host = host
	}
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	out := reply{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	}
	return out, rec.Body.Bytes()
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// The drift test: the scripts the box serves, and the ones GET /inventory/agents puts in its page, are byte for byte what the GUI renders
// from its own templates, and the SHA-256 the admin reads is the SHA-256 of the served bytes.
func TestInstall_ScriptsEqualTheGUI(t *testing.T) {
	w := newWorld(t)
	const box = "https://" + boxAtPort
	wantSh, wantPs1 := guiScript(t, guiSh, box, testCA), guiScript(t, guiPs1, box, testCA)
	if strings.Contains(wantSh, "@@") || strings.Contains(wantPs1, "@@") {
		t.Fatal("a placeholder is left in a script")
	}
	shRes, sh := w.get("/install/osquery.sh", boxAtPort, "")
	psRes, ps1 := w.get("/install/osquery.ps1", boxAtPort, "")
	if shRes.code != 200 || psRes.code != 200 {
		t.Fatalf("scripts: %d %d", shRes.code, psRes.code)
	}
	if string(sh) != wantSh || string(ps1) != wantPs1 {
		t.Fatal("a served script differs from the one the GUI renders")
	}
	if got := shRes.header.Get("Content-Length"); got != fmt.Sprint(len(wantSh)) {
		t.Errorf("Content-Length %s, want %d", got, len(wantSh))
	}
	if ct := shRes.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("shell script type %q", ct)
	}
	if ct := psRes.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("PowerShell script type %q", ct)
	}
	// the admin's page
	page, _ := w.get("/inventory/agents", boxAtPort, "admin")
	if page.code != 200 {
		t.Fatalf("agents: %d %s", page.code, page.raw)
	}
	inst, _ := page.body["install"].(map[string]any)
	if inst["osquery_version"] != guiVersion(t) || page.body["server_url"] != box {
		t.Fatalf("install %v server_url %v", inst["osquery_version"], page.body["server_url"])
	}
	for _, c := range []struct {
		key, file, want string
	}{{"linux", "osquery.sh", wantSh}, {"windows", "osquery.ps1", wantPs1}} {
		m, _ := inst[c.key].(map[string]any)
		if m["script"] != c.want || m["sha256"] != sum(c.want) || m["url"] != box+"/api/v1/install/"+c.file {
			t.Errorf("%s: the page does not carry the served script, its SHA-256 or its URL", c.key)
		}
	}
}

// OsqueryVersion, the GUI constant and deploy/osquery/PINS are one number; the package names of the mirror are the ones the scripts ask for.
func TestInstall_VersionsAgree(t *testing.T) {
	pins := map[string]string{}
	for _, l := range strings.Split(readFile(t, pinsFile), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.ContainsAny(v, " \t\"'$") {
			t.Fatalf("PINS line %q: KEY=VALUE only, no spaces, quotes or $ (the Containerfile sources the file)", l)
		}
		pins[k] = v
	}
	if pins["OSQUERY_VERSION"] != agentintake.OsqueryVersion || guiVersion(t) != agentintake.OsqueryVersion {
		t.Fatalf("versions: PINS %q, GUI %q, Go %q", pins["OSQUERY_VERSION"], guiVersion(t), agentintake.OsqueryVersion)
	}
	for _, k := range []string{"OSQUERY_DEB_AMD64_SHA256", "OSQUERY_RPM_X86_64_SHA256", "OSQUERY_MSI_SHA256",
		"OSQUERY_LICENSE_SHA256", "OSQUERY_LICENSE_APACHE_SHA256", "OSQUERY_LICENSE_GPL2_SHA256"} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pins[k]) {
			t.Errorf("PINS %s = %q is not a SHA-256", k, pins[k])
		}
	}
	if len(pins) != 7 {
		t.Errorf("PINS has %d keys, want the version, three package hashes and three licence hashes", len(pins))
	}
	sh := readFile(t, "scripts/osquery.sh")
	for _, want := range []string{`FILE="osquery_${OSQ_VERSION}-1.linux_amd64.deb"`, `FILE="osquery-${OSQ_VERSION}-1.linux.x86_64.rpm"`} {
		if !strings.Contains(sh, want) {
			t.Errorf("the Linux script does not ask for %s", want)
		}
	}
	if !strings.Contains(readFile(t, "scripts/osquery.ps1"), `$File = "osquery-$Version.msi"`) {
		t.Error("the Windows script does not ask for osquery-<version>.msi")
	}
}

// A real Debian/Ubuntu/RHEL os-release defines VERSION, NAME, ID...: the script read it with `. /etc/os-release` and its own VERSION was
// overwritten, so osquery_13 (trixie)-1.linux_amd64.deb was asked for on a real Debian 13 (2026-11-12 real run). The file may only be read in
// a subshell, and no variable of the script may share a name with a key of os-release (os-release(5) lists them). The real effect (the
// right package name on Debian 13) was checked on a container; os/exec is not allowed in this module's tests (SYS-1).
func TestInstall_LinuxScriptDoesNotShareNamesWithOsRelease(t *testing.T) {
	keys := map[string]bool{"NAME": true, "VERSION": true, "ID": true, "ID_LIKE": true, "PRETTY_NAME": true, "CPE_NAME": true, "VARIANT": true,
		"VARIANT_ID": true, "VERSION_ID": true, "VERSION_CODENAME": true, "BUILD_ID": true, "IMAGE_ID": true, "IMAGE_VERSION": true,
		"HOME_URL": true, "DOCUMENTATION_URL": true, "SUPPORT_URL": true, "BUG_REPORT_URL": true, "PRIVACY_POLICY_URL": true, "SUPPORT_END": true,
		"LOGO": true, "ANSI_COLOR": true, "DEFAULT_HOSTNAME": true, "ARCHITECTURE": true, "SYSEXT_LEVEL": true, "CONFEXT_LEVEL": true}
	assign := regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*)=`)
	reads := 0
	for _, line := range strings.Split(readFile(t, "scripts/osquery.sh"), "\n") {
		if m := assign.FindStringSubmatch(line); m != nil && keys[m[1]] {
			t.Errorf("the Linux script sets %s, which /etc/os-release also sets: %q", m[1], line)
		}
		if strings.Contains(line, `. "$OSF"`) {
			reads++
			if !strings.Contains(line, "$( . ") {
				t.Errorf("os-release must be read inside a subshell: %q", line)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(line), ". /etc/os-release") || strings.HasPrefix(strings.TrimSpace(line), "source ") {
			t.Errorf("the script sources a file into its own shell: %q", line)
		}
	}
	if reads == 0 {
		t.Error("the script no longer reads os-release")
	}
}

// A normal first install exits 0 once the machine has enrolled: osquery's first report comes up to an hour later and is not waited for
// (S-INV-4, supervisor decision 2026-11-13). The only non-zero end after the install is "did not enrol" (3); success is THIS machine's host_last_seen (status, by host_identifier) appearing or moving
// past what it was before the restart, never the token-wide counts.
func TestInstall_ExitsZeroWhenEnrolledNotWhenFirstReportArrives(t *testing.T) {
	const ok = "Installed and enrolled; the first report arrives within about an hour."
	sh, ps1 := readFile(t, "scripts/osquery.sh"), readFile(t, "scripts/osquery.ps1")
	if !strings.Contains(sh, `echo "`+ok+`"; exit 0`) || !strings.Contains(ps1, `Write-Host '`+ok+`'; return`) {
		t.Error("a script does not end a first install with the enrolled message and success")
	}
	for name, body := range map[string]string{"sh": sh, "ps1": ps1} {
		if !strings.Contains(body, `host_identifier`) || !strings.Contains(body, `host_last_seen`) || strings.Contains(body, `"hosts":`) || strings.Contains(body, `"enrolled":true`) {
			t.Errorf("%s: success must be this machine's host_last_seen appearing or moving, not the token-wide counts", name)
		}
		if strings.Contains(body, "has not received its first report yet") {
			t.Errorf("%s: still reports a missing first report as the end of the install", name)
		}
	}
	if !strings.Contains(sh, "--host_identifier=specified") || !strings.Contains(sh, "--specified_identifier=$HOSTID") ||
		!strings.Contains(ps1, "--host_identifier=specified") || !strings.Contains(ps1, "--specified_identifier=$hostId") {
		t.Error("the machine must enrol under the name the status check asks for (--host_identifier=specified)")
	}
	if !strings.Contains(sh, "systemctl is-active --quiet osqueryd") || !strings.Contains(ps1, "-eq 'Running'") {
		t.Error("success also needs the service to be running")
	}
	if !strings.Contains(sh, "did not enrol") || !strings.HasSuffix(strings.TrimSpace(sh), "exit 3") {
		t.Error("the Linux script must end with exit 3 only when the machine did not enrol")
	}
	if !strings.Contains(ps1, "did not enrol") || !strings.Contains(ps1, "exit 3") {
		t.Error("the Windows script must fail with 3 only when the machine did not enrol")
	}
}

// An arbitrary Host header is never put into a script: only a name the server's allow-list lets in, rebuilt from validated parts, or the
// configured address, or the placeholder.
func TestInstall_HostIsNeverReflected(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct{ host, want string }{
		{"box.corp.example", "https://box.corp.example"},
		{"BOX.Corp.Example.:8443", "https://box.corp.example:8443"},
		{boxAddr + ":8443", boxURL},
		{"x.lab.example:9443", "https://x.lab.example:9443"},
		{"evil.example", boxURL},                   // not on the list: the configured address
		{"evil.example:8443", boxURL},              //
		{"box.corp.example:99999", boxURL},         // not a port
		{"box.corp.example:0x1f", boxURL},          //
		{"a.b.lab.example", boxURL},                // a wildcard covers one label
		{"localhost:8443", boxURL},                 // allowed by the server, but a server cannot reach it
		{"127.0.0.1:8443", boxURL},                 //
		{"[::1]:8443", boxURL},                     //
		{"box.corp.example'; touch pwned", boxURL}, // never reaches a shell
		{"box.corp.example\nX: y", boxURL},         //
		{"", boxURL},                               //
	} {
		res, body := w.get("/install/osquery.sh", c.host, "")
		if res.code != 200 {
			t.Fatalf("Host %q: %d", c.host, res.code)
		}
		if !strings.Contains(string(body), "BOX='"+c.want+"'\n") {
			t.Errorf("Host %q: the script does not carry %s", c.host, c.want)
		}
		if strings.Contains(string(body), "evil") || strings.Contains(string(body), "pwned") {
			t.Errorf("Host %q reached the script", c.host)
		}
	}
	// no configured address and no usable Host: the placeholder, never a guess
	w2 := newWorld(t, func(c *agentintake.Config) { c.BoxURL = "" })
	_, body := w2.get("/install/osquery.ps1", "evil.example", "")
	if !strings.Contains(string(body), "$Box = 'https://<VEDETTE_BOX_IP>:8443'") {
		t.Error("no placeholder when the box does not know its address")
	}
	// a configured address that is not https or holds a quote is not used either
	for _, bad := range []string{"http://192.168.10.250:8443", "https://x'; id", "https://a b"} {
		w3 := newWorld(t, func(c *agentintake.Config) { c.BoxURL = bad })
		_, body := w3.get("/install/osquery.sh", "", "")
		if !strings.Contains(string(body), "BOX='https://<VEDETTE_BOX_IP>:8443'") {
			t.Errorf("configured address %q was used", bad)
		}
	}
	// without an allow-list function the Host is never trusted
	w4 := newWorld(t, func(c *agentintake.Config) { c.HostAllowed = nil })
	_, body = w4.get("/install/osquery.sh", "box.corp.example", "")
	if !strings.Contains(string(body), "BOX='"+boxURL+"'") {
		t.Error("a Host was used with no allow-list")
	}
}

func TestInstall_CertificateServing(t *testing.T) {
	w := newWorld(t)
	res, body := w.get("/intake/ca.pem", "", "")
	if res.code != 200 || string(body) != testCA {
		t.Fatalf("ca.pem: %d %q", res.code, body)
	}
	if got := res.header.Get("Content-Type"); got != "application/x-pem-file" {
		t.Errorf("type %q", got)
	}
	if cc := res.header.Get("Cache-Control"); !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age") {
		t.Errorf("ca.pem must be cacheable, Cache-Control %q", cc)
	}
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("a key in ca.pem")
	}
	// a box with no certificate (plain HTTP on loopback): 404 with a clear code, and the admin's page still works, with a visible placeholder
	none := newWorld(t, func(c *agentintake.Config) {
		c.TrustAnchor = func() ([]byte, error) { return nil, agentintake.ErrNoTrustAnchor }
	})
	for _, p := range []string{"/intake/ca.pem", "/install/osquery.sh", "/install/osquery.ps1"} {
		if r, _ := none.get(p, "", ""); r.code != 404 || r.errCode() != "no_certificate" {
			t.Errorf("%s without a certificate: %d %s", p, r.code, r.raw)
		}
	}
	page, _ := none.get("/inventory/agents", "", "admin")
	linux := page.body["install"].(map[string]any)["linux"].(map[string]any)
	if page.code != 200 || !strings.Contains(linux["script"].(string), "this box has no certificate") {
		t.Fatalf("agents page without a certificate: %d", page.code)
	}
	// the module off: 404 like an unknown route
	w.gate.Set("agent-intake", false)
	unknown, _ := w.get("/intake/nothing", "", "")
	for _, p := range []string{"/intake/ca.pem", "/install/osquery.sh", "/install/osquery.ps1", "/install/osquery/SHA256SUMS"} {
		if r, _ := w.get(p, "", ""); r.code != 404 || r.raw != unknown.raw {
			t.Errorf("%s while off: %d %s", p, r.code, r.raw)
		}
	}
}

// INV-11: only CERTIFICATE blocks leave, re-encoded without headers, whatever cmd/vedette hands over (an owner's -tls-cert may hold the
// key in the same file); nothing that is a certificate = 500, never the bytes as given.
func TestContract_INV11_CaPemServesTheCertificateOnly(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nc2VjcmV0IGtleSBtYXRlcmlhbCwgbmV2ZXIgc2VydmVk\n-----END PRIVATE KEY-----\n"
	withHeader := "-----BEGIN CERTIFICATE-----\nX-Note: hi\n\n" + strings.TrimPrefix(testCA, "-----BEGIN CERTIFICATE-----\n")
	w := newWorld(t, func(c *agentintake.Config) {
		c.TrustAnchor = func() ([]byte, error) { return []byte(key + withHeader + key), nil }
	})
	res, body := w.get("/intake/ca.pem", "", "")
	if res.code != 200 || string(body) != testCA {
		t.Fatalf("ca.pem: %d %q, want the certificate alone", res.code, body)
	}
	for _, p := range []string{"/install/osquery.sh", "/install/osquery.ps1"} {
		if r, b := w.get(p, "", ""); r.code != 200 || strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), "X-Note") || !strings.Contains(string(b), strings.TrimSpace(testCA)) {
			t.Errorf("%s: %d, want the certificate and no key", p, r.code)
		}
	}
	keyOnly := newWorld(t, func(c *agentintake.Config) { c.TrustAnchor = func() ([]byte, error) { return []byte(key), nil } })
	if r, b := keyOnly.get("/intake/ca.pem", "", ""); r.code != 500 || strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("a key alone: %d %q", r.code, b)
	}
}

// ---- the package mirror ----

var mirrorNames = []string{
	"osquery_" + agentintake.OsqueryVersion + "-1.linux_amd64.deb",
	"osquery-" + agentintake.OsqueryVersion + "-1.linux.x86_64.rpm",
	"osquery-" + agentintake.OsqueryVersion + ".msi",
	"SHA256SUMS",
}

func (w *world) fillMirror() map[string]string {
	w.t.Helper()
	content := map[string]string{}
	for i, n := range mirrorNames {
		c := strings.Repeat(fmt.Sprintf("%s-%d|", n, i), 100_000/len(n))                   // about 100 KB each, different for each
		if err := os.WriteFile(filepath.Join(w.mirror, n), []byte(c), 0o644); err != nil { //nolint:gosec // a test file
			w.t.Fatal(err)
		}
		content[n] = c
	}
	return content
}

func TestMirror_ServesTheFourFilesWithTheirLength(t *testing.T) {
	w := newWorld(t)
	content := w.fillMirror()
	for _, n := range mirrorNames {
		res, body := w.get("/install/osquery/"+n, "", "")
		if res.code != 200 || string(body) != content[n] {
			t.Fatalf("%s: %d, %d bytes of %d", n, res.code, len(body), len(content[n]))
		}
		if got := res.header.Get("Content-Length"); got != fmt.Sprint(len(content[n])) {
			t.Errorf("%s: Content-Length %q", n, got)
		}
		if cc := res.header.Get("Cache-Control"); !strings.Contains(cc, "public") {
			t.Errorf("%s: Cache-Control %q", n, cc)
		}
	}
	if res, _ := w.get("/install/osquery/SHA256SUMS", "", ""); !strings.HasPrefix(res.header.Get("Content-Type"), "text/plain") {
		t.Errorf("SHA256SUMS type %q", res.header.Get("Content-Type"))
	}
}

// Only the four names exist. A request's text is a key into a table, never a path: traversal, encoded separators, NUL, other names, other
// cases and files that sit in the folder but are not on the list are all 404.
func TestMirror_AllowListAndTraversal(t *testing.T) {
	w := newWorld(t)
	w.fillMirror()
	secret := filepath.Join(filepath.Dir(w.mirror), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.mirror, "other.deb"), []byte("not on the list"), 0o644); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	for _, name := range []string{
		"..", "../secret.txt", "..%2fsecret.txt", "%2e%2e%2fsecret.txt", "%2e%2e", "..%252fsecret.txt", "%2fetc%2fpasswd", "/etc/passwd", "%5c..%5csecret.txt", "..\\secret.txt",
		"osquery-" + agentintake.OsqueryVersion + ".msi%00.txt", "SHA256SUMS%00", "SHA256SUMS%00.deb", "sha256sums", "Sha256Sums", "SHA256SUMS/", "SHA256SUMS%20", "%20SHA256SUMS",
		"other.deb", "secret.txt", "osquery_" + agentintake.OsqueryVersion + "-1.linux_arm64.deb", "osquery_9.9.9-1.linux_amd64.deb", ".", "%2e", "",
	} {
		res, body := w.get("/install/osquery/"+name, "", "")
		if res.code == 200 || strings.Contains(string(body), "TOPSECRET") || strings.Contains(string(body), "not on the list") {
			t.Errorf("%q: %d", name, res.code)
		}
		if res.code != 404 && res.code != 400 && res.code != 307 {
			t.Errorf("%q: status %d", name, res.code)
		}
		if res.code == 404 && res.errCode() == "" && name != "" {
			t.Errorf("%q: 404 without an error code", name)
		}
	}
	// a link in the folder that points out of it is not followed
	link := filepath.Join(w.mirror, mirrorNames[0])
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skip("no symlinks here:", err)
	}
	if res, body := w.get("/install/osquery/"+mirrorNames[0], "", ""); res.code != 404 || res.errCode() != "mirror_missing" || strings.Contains(string(body), "TOPSECRET") {
		t.Fatalf("a link out of the folder: %d %s", res.code, res.raw)
	}
}

func TestMirror_MissingFolderOrFileIs404WithACodeAndALogLine(t *testing.T) {
	w := newWorld(t) // the folder exists and is empty
	res, _ := w.get("/install/osquery/"+mirrorNames[0], "", "")
	if res.code != 404 || res.errCode() != "mirror_missing" || !strings.Contains(w.logs.String(), "osquery package is not in the folder") {
		t.Fatalf("empty folder: %d %s", res.code, res.raw)
	}
	gone := newWorld(t, func(c *agentintake.Config) { c.MirrorDir = filepath.Join(t.TempDir(), "nope") })
	if res, _ := gone.get("/install/osquery/SHA256SUMS", "", ""); res.code != 404 || res.errCode() != "mirror_missing" {
		t.Fatalf("missing folder: %d %s", res.code, res.raw)
	}
	unset := newWorld(t, func(c *agentintake.Config) { c.MirrorDir = "" })
	if res, _ := unset.get("/install/osquery/SHA256SUMS", "", ""); res.code != 404 || res.errCode() != "mirror_missing" || !strings.Contains(unset.logs.String(), "no osquery package folder") {
		t.Fatalf("no folder configured: %d %s", res.code, res.raw)
	}
	// a directory with the name of a file is not served
	if err := os.Mkdir(filepath.Join(w.mirror, "SHA256SUMS"), 0o750); err != nil {
		t.Fatal(err)
	}
	if res, _ := w.get("/install/osquery/SHA256SUMS", "", ""); res.code != 404 {
		t.Fatalf("a directory: %d", res.code)
	}
}

// L1: anyone can ask for a missing package, so the WARN line is written once a minute, not once per request; the answer stays the same.
func TestMirror_MissingWarnsOncePerMinute(t *testing.T) {
	w := newWorld(t)
	for range 5 {
		if res, _ := w.get("/install/osquery/SHA256SUMS", "", ""); res.code != 404 || res.errCode() != "mirror_missing" {
			t.Fatalf("missing: %d %s", res.code, res.raw)
		}
	}
	if n := strings.Count(w.logs.String(), "osquery package is not in the folder"); n != 1 {
		t.Fatalf("%d WARN lines for 5 requests", n)
	}
	w.clock.Advance(61 * time.Second)
	w.get("/install/osquery/SHA256SUMS", "", "")
	if n := strings.Count(w.logs.String(), "osquery package is not in the folder"); n != 2 {
		t.Fatalf("%d WARN lines after a minute", n)
	}
}

// L2: a certificate that cannot be read does not take the Agents page down (tokens and Wazuh still show); the public files still fail.
func TestInstall_UnreadableCertificateDegradesTheAdminPage(t *testing.T) {
	w := newWorld(t, func(c *agentintake.Config) {
		c.TrustAnchor = func() ([]byte, error) { return nil, errors.New("disk read failed") }
	})
	w.token("srv", 7)
	page, _ := w.get("/inventory/agents", "", "admin")
	linux, _ := page.body["install"].(map[string]any)["linux"].(map[string]any)
	if page.code != 200 || len(tokenList(t, page)) != 1 || !strings.Contains(linux["script"].(string), "this box has no certificate") {
		t.Fatalf("page: %d", page.code)
	}
	if !strings.Contains(w.logs.String(), "could not be read") {
		t.Fatal("the failure was not logged")
	}
	if res, _ := w.get("/intake/ca.pem", "", ""); res.code != 500 {
		t.Fatalf("ca.pem with an unreadable certificate: %d", res.code)
	}
}

// blockedWriter is a client that stops reading: its first Write blocks until release is closed.
type blockedWriter struct {
	h       http.Header
	started chan struct{}
	release chan struct{}
	once    sync.Once
	code    int
}

func (b *blockedWriter) Header() http.Header { return b.h }
func (b *blockedWriter) WriteHeader(c int)   { b.code = c }
func (b *blockedWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return len(p), nil
}

// One download at a time per source address, 8 box-wide; a refused one is told to come back (429, Retry-After 5); SHA256SUMS takes no slot; a
// slot is free again when a download ends.
func TestMirror_ConcurrencyCap(t *testing.T) {
	w := newWorld(t)
	w.fillMirror()
	release := make(chan struct{})
	var done sync.WaitGroup
	var writers []*blockedWriter
	for i := range 8 { // eight different addresses fill the box
		bw := &blockedWriter{h: http.Header{}, started: make(chan struct{}), release: release}
		writers = append(writers, bw)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, server.Prefix+"/install/osquery/"+mirrorNames[2], nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:40000", 100+i)
		done.Add(1)
		go func() { defer done.Done(); w.h.ServeHTTP(bw, r) }()
	}
	for _, bw := range writers {
		<-bw.started
	}
	res, _ := w.get("/install/osquery/"+mirrorNames[2], "", "") // a ninth address
	if res.code != 429 || res.errCode() != "rate_limited" || res.header.Get("Retry-After") != "5" {
		t.Fatalf("ninth download: %d retry-after %q %s", res.code, res.header.Get("Retry-After"), res.raw)
	}
	// unknown names do not take a slot or tell that the box is busy; SHA256SUMS is served while every slot is taken
	if res, _ := w.get("/install/osquery/nope", "", ""); res.code != 404 {
		t.Fatalf("unknown name while busy: %d", res.code)
	}
	if res, body := w.get("/install/osquery/SHA256SUMS", "", ""); res.code != 200 || len(body) == 0 {
		t.Fatalf("SHA256SUMS while busy: %d", res.code)
	}
	close(release)
	done.Wait()
	if res, _ := w.get("/install/osquery/"+mirrorNames[2], "", ""); res.code != 200 {
		t.Fatalf("after the downloads ended: %d %s", res.code, res.raw)
	}
}

// The same address cannot take a second package download, whatever room the box has (IPv6 counts per /64).
func TestMirror_OneDownloadPerAddress(t *testing.T) {
	w := newWorld(t)
	w.fillMirror()
	for _, c := range []struct{ first, second string }{
		{"192.0.2.50:1", "192.0.2.50:2"}, {"[2001:db8:1:2::1]:1", "[2001:db8:1:2:ffff::9]:2"},
	} {
		release := make(chan struct{})
		bw := &blockedWriter{h: http.Header{}, started: make(chan struct{}), release: release}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, server.Prefix+"/install/osquery/"+mirrorNames[0], nil)
		r.RemoteAddr = c.first
		done := make(chan struct{})
		go func() { defer close(done); w.h.ServeHTTP(bw, r) }()
		<-bw.started
		r2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, server.Prefix+"/install/osquery/"+mirrorNames[1], nil)
		r2.RemoteAddr = c.second
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, r2)
		if rec.Code != 429 {
			t.Errorf("%s then %s: second download %d", c.first, c.second, rec.Code)
		}
		close(release)
		<-done
	}
}

// A client that stops reading frees its slot when the write deadline passes (a real server, a raw connection that never reads), and while
// it holds the slot another address still downloads and the same address is refused.
func TestMirror_StalledClientFreesItsSlot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the second client address is 127.0.0.2, which only Linux has on loopback")
	}
	w := newWorld(t)
	w.fillMirror()
	w.svc.SetMirrorWaitsForTest(300*time.Millisecond, 5*time.Second)
	big := filepath.Join(w.mirror, mirrorNames[1]) // the rpm: a sparse file far larger than any socket buffer
	if err := os.Truncate(big, 256<<20); err != nil {
		t.Fatal(err)
	}
	type slotEvent struct {
		key  string
		held bool
	}
	events := make(chan slotEvent, 64)
	w.svc.SetMirrorEventForTest(func(key string, held bool) {
		select {
		case events <- slotEvent{key, held}:
		default:
		}
	})
	srv := httptest.NewServer(w.h)
	t.Cleanup(srv.Close)
	url := func(name string) string { return srv.URL + server.Prefix + "/install/osquery/" + name }
	clientFrom := func(ip string) *http.Client {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true}}
	}
	get := func(c *http.Client, name string) int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url(name), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	stalled, err := new(net.Dialer).DialContext(t.Context(), "tcp", srv.Listener.Addr().String()) // from 127.0.0.1, never reads
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	if _, err := fmt.Fprintf(stalled, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", server.Prefix+"/install/osquery/"+mirrorNames[1], srv.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	first, second := clientFrom("127.0.0.1"), clientFrom("127.0.0.2")
	waitSlot := func(key string, held bool) { // waits on the slot's state, not the clock; the bound only ends a hung run
		t.Helper()
		for {
			select {
			case e := <-events:
				if e == (slotEvent{key, held}) {
					return
				}
			case <-time.After(2 * time.Minute):
				t.Fatalf("slot of %s never became held=%v", key, held)
			}
		}
	}
	waitSlot("127.0.0.1", true) // the stalled download holds its slot
	if code := get(first, mirrorNames[2]); code != 429 {
		t.Fatalf("the same address while it holds a slot: %d", code)
	}
	if code := get(second, mirrorNames[2]); code != 200 {
		t.Fatalf("a second address while the first holds a slot: %d", code)
	}
	waitSlot("127.0.0.1", false) // the write deadline frees it
	if code := get(first, mirrorNames[2]); code != 200 {
		t.Fatalf("the stalled client still holds its slot after the write deadline: %d", code)
	}
}
