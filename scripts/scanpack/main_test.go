package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/pack"
)

const httpKEV = `id: CVE-2024-3400

info:
  name: PAN-OS test
  severity: critical
  classification:
    cve-id: CVE-2024-3400
  tags: cve,cve2024,panos,kev,vkev

http:
  - method: GET
    path:
      - "{{BaseURL}}/global-protect/login.esp"
    matchers:
      - type: status
        status:
          - 200
`

const rawKEV = `id: CVE-2022-27593

info:
  name: QNAP test
  classification:
    cve-id: CVE-2022-27593
  tags: cve,qnap,kev

http:
  - raw:
      - |
        GET /photo/p/api/video.php HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: status
        status:
          - 200
`

const tcpKEV = `id: CVE-2025-14847

info:
  classification:
    cve-id: CVE-2025-14847
  tags: cve,mongodb,kev,vkev

tcp:
  - inputs:
      - data: 3b0000003c30
        type: hex
    host:
      - "{{Hostname}}"
    port: 27017
    matchers:
      - type: word
        words:
          - version
`

// withTag swaps the tags line of httpKEV; withKey appends a top-level key.
func withTags(tags string) string {
	return strings.Replace(httpKEV, "tags: cve,cve2024,panos,kev,vkev", "tags: "+tags, 1)
}

func withKey(key string) string { return httpKEV + "\n" + key + "\n" }

func write(t *testing.T, root, rel, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // a file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// The pack holds exactly the templates of the KEV sets that are plain http, tcp or ssl checks for one CVE, copied byte for byte;
// everything else is left out with a reason, and the index passes the parser core and the worker use.
func TestBuildKeepsOnlySafeKEVTemplates(t *testing.T) {
	t.Parallel()
	src, out := t.TempDir(), t.TempDir()
	write(t, src, "http/cves/2024/CVE-2024-3400.yaml", httpKEV)
	write(t, src, "http/cves/2022/CVE-2022-27593.yaml", rawKEV)
	write(t, src, "network/cves/2025/CVE-2025-14847.yaml", tcpKEV)
	left := map[string]string{
		"not kev":              strings.Replace(httpKEV, "kev,vkev", "vuln", 1),
		"dos":                  withTags("cve,kev,dos"),
		"intrusive":            withTags("cve,kev,intrusive"),
		"fuzz":                 withTags("cve,kev,fuzz"),
		"oast tag":             withTags("cve,kev,oast"),
		"interactsh in body":   strings.Replace(httpKEV, "{{BaseURL}}/global-protect/login.esp", "{{BaseURL}}/x?u={{interactsh-url}}", 1),
		"headless":             withKey("headless:\n  - steps: []"),
		"code":                 withKey("code:\n  - engine: [sh]\n    source: id"),
		"javascript":           withKey("javascript:\n  - code: 1"),
		"file":                 withKey("file:\n  - extensions: [all]"),
		"dns":                  withKey("dns:\n  - name: x"),
		"flow":                 withKey("flow: http(1)"),
		"self-contained":       withKey("self-contained: true"),
		"two cves":             strings.Replace(httpKEV, "cve-id: CVE-2024-3400", "cve-id: CVE-2024-3400, CVE-2024-3401", 1),
		"no cve":               strings.Replace(httpKEV, "    cve-id: CVE-2024-3400\n", "", 1),
		"bad id":               strings.Replace(httpKEV, "id: CVE-2024-3400", "id: -rf", 1),
		"not yaml":             "id: [unclosed",
		"no protocol":          "id: CVE-2024-1111\ninfo:\n  classification:\n    cve-id: CVE-2024-1111\n  tags: kev\n",
		"fuzzing":              strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    fuzzing:\n      - part: query\n", 1),
		"payloads":             strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    attack: pitchfork\n    payloads:\n      a: [x]\n", 1),
		"race":                 strings.Replace(httpKEV, "  - method: GET\n", "  - method: GET\n    race: true\n    race_count: 5\n", 1),
		"control char request": strings.Replace(httpKEV, "{{BaseURL}}/global-protect/login.esp", "{{BaseURL}}/a\\u0001", 1),
	}
	for name, text := range left {
		write(t, src, "http/left/"+strings.ReplaceAll(name, " ", "-")+".yaml", text)
	}
	write(t, src, "http/cves/2024/readme.md", "not a template")
	write(t, src, "LICENSE.md", "MIT License")
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "http", "cves", "2024", "link.yaml")); err != nil {
		t.Fatal(err)
	}

	rep, err := build(src, out, "2026.11.1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kept != 3 {
		t.Fatalf("kept %d templates, report %+v", rep.Kept, rep)
	}
	if b, err := os.ReadFile(filepath.Join(out, "LICENSE-nuclei-templates.md")); err != nil || string(b) != "MIT License" { //nolint:gosec // a test file under t.TempDir()
		t.Errorf("the licence of the templates must travel with them: %q %v", b, err)
	}
	raw := readFile(t, filepath.Join(out, "index.json"))
	ix, err := pack.Parse(raw)
	if err != nil {
		t.Fatalf("the index does not pass pack.Parse: %v", err)
	}
	if ix.Version != "2026.11.1" || len(ix.Templates) != 3 {
		t.Fatalf("index = %+v", ix)
	}
	for _, tpl := range ix.Templates {
		body := readFile(t, filepath.Join(out, "templates", filepath.FromSlash(tpl.Path)))
		if sum(string(body)) != tpl.SHA256 {
			t.Errorf("%s: sha256 in the index is not the file's", tpl.Path)
		}
	}
	if got := ix.ForCVE("CVE-2024-3400"); len(got) != 1 || got[0].Request != "GET {{BaseURL}}/global-protect/login.esp" {
		t.Errorf("request line of the path template = %+v", got)
	}
	if got := ix.ForCVE("CVE-2022-27593"); len(got) != 1 || got[0].Request != "GET /photo/p/api/video.php HTTP/1.1" {
		t.Errorf("request line of the raw template = %+v", got)
	}
	if got := ix.ForCVE("CVE-2025-14847"); len(got) != 1 || !strings.HasPrefix(got[0].Request, "TCP {{Hostname}}:27017") {
		t.Errorf("request line of the tcp template = %+v", got)
	}
	// nothing but regular files and directories (the worker refuses anything else, anywhere in the tree)
	err = filepath.WalkDir(filepath.Join(out, "templates"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			t.Errorf("%s is not a regular file", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Left["http feature"] != 3 {
		t.Errorf("fuzzing, payloads and race templates must each be left out: %+v", rep.Left)
	}
	for _, reason := range []string{"tags", "forbidden tag", "interactsh", "protocol", "cve", "id", "yaml", "request"} {
		if rep.Left[reason] == 0 {
			t.Errorf("no template was left out for %q: %+v", reason, rep.Left)
		}
	}
}

// The same input gives the same bytes: the label of the pack and the index are a function of the files and the version only.
func TestBuildIsDeterministic(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	write(t, src, "http/cves/2024/CVE-2024-3400.yaml", httpKEV)
	write(t, src, "http/cves/2022/CVE-2022-27593.yaml", rawKEV)
	a, b := t.TempDir(), t.TempDir()
	for _, out := range []string{a, b} {
		if _, err := build(src, out, "2026.11.1"); err != nil {
			t.Fatal(err)
		}
	}
	ia, ib := readFile(t, filepath.Join(a, "index.json")), readFile(t, filepath.Join(b, "index.json"))
	if !bytes.Equal(ia, ib) {
		t.Fatal("two builds of the same input differ")
	}
	if _, err := build(src, t.TempDir(), "2026.11"); err == nil {
		t.Fatal("a version that is not AAAA.M.N must be refused")
	}
}

func TestBuildRefusesAnEmptyPackAndAnExistingOutput(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	write(t, src, "http/x.yaml", strings.Replace(httpKEV, "kev,vkev", "vuln", 1))
	if _, err := build(src, filepath.Join(t.TempDir(), "o"), "2026.11.1"); err == nil {
		t.Fatal("a pack with no template is not a pack")
	}
	write(t, src, "http/y.yaml", httpKEV)
	out := t.TempDir()
	write(t, out, "old", "x")
	if _, err := build(src, out, "2026.11.1"); err == nil {
		t.Fatal("the output directory must be empty or new: a stale file would ship")
	}
}

func tarball(t *testing.T, files map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A download that does not hash to the pinned value is refused before anything is read from it, and an archive that tries to
// leave its folder or carries a link is refused.
func TestUnpackChecksTheHashAndThePaths(t *testing.T) {
	t.Parallel()
	good := tarball(t, map[string]string{"nuclei-templates-1/http/a.yaml": httpKEV, "nuclei-templates-1/LICENSE.md": "MIT License"}, nil)
	dir := t.TempDir()
	if err := unpack(good, sum(string(good)), dir); err != nil {
		t.Fatal(err)
	}
	if b := readFile(t, filepath.Join(dir, "http", "a.yaml")); string(b) != httpKEV {
		t.Fatalf("unpacked file: %q", b)
	}
	big := tarball(t, map[string]string{"nuclei-templates-1/http/big.yaml": strings.Repeat("a", maxFile+1), "nuclei-templates-1/http/ok.yaml": httpKEV}, nil)
	bigDir := t.TempDir()
	if err := unpack(big, sum(string(big)), bigDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bigDir, "http", "big.yaml")); err == nil {
		t.Error("an oversized file must be skipped")
	}
	if _, err := os.Stat(filepath.Join(bigDir, "http", "ok.yaml")); err != nil {
		t.Error("the other files of the archive must still be unpacked")
	}
	if err := unpack(good, strings.Repeat("0", 64), t.TempDir()); err == nil {
		t.Fatal("a wrong hash must be refused")
	}
	escape := tarball(t, map[string]string{"nuclei-templates-1/../../evil.yaml": "x"}, nil)
	if err := unpack(escape, sum(string(escape)), t.TempDir()); err == nil {
		t.Fatal("a path that leaves the folder must be refused")
	}
	link := tarball(t, nil, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "nuclei-templates-1/http/l.yaml", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	})
	if err := unpack(link, sum(string(link)), t.TempDir()); err == nil {
		t.Fatal("a link in the archive must be refused")
	}
}
