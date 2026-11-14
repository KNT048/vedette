package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-528 step 2: without the tick a template runs only if it is a read-only GET whose name names no change, or a person reviewed
// that very file (reviewed.tsv, id + sha256).

func getKEV(id, name, req string) string {
	return "id: " + id + "\n\ninfo:\n  name: " + name + "\n  classification:\n    cve-id: CVE-2024-0001\n  tags: cve,kev\n\nhttp:\n  - raw:\n      - |\n" +
		"        " + strings.ReplaceAll(req, "\n", "\n        ") + "\n\n    matchers:\n      - type: status\n        status:\n          - 200\n"
}

func TestNoTickRule(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		text, why string
	}{
		"a read":           {getKEV("CVE-2024-0001", "X - Path Traversal", "GET /a/../../etc/passwd HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: x"), ""},
		"a POST":           {getKEV("CVE-2024-0002", "X - RCE", "POST /a HTTP/1.1\nHost: {{Hostname}}\n\nq=1"), "not reviewed"},
		"a GET restore":    {getKEV("CVE-2024-0003", "X - Info", "GET /OS/startup/restore/restoreAdmin.php HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a GET submit":     {getKEV("CVE-2024-0004", "X - Info", "GET /api/manager/submit?group=1 HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a GET action=set": {getKEV("CVE-2024-0005", "X - Info", "GET /editor.php?mapname=a.conf&action=set_map_properties HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a creation name":  {getKEV("CVE-2024-0006", "X - Arbitrary User Creation", "GET /a HTTP/1.1\nHost: {{Hostname}}"), "state name"},
		"a purge name":     {getKEV("CVE-2024-0007", "X - Unauthenticated Log Purge", "GET /a HTTP/1.1\nHost: {{Hostname}}"), "state name"},
		"a basic login":    {getKEV("CVE-2024-0008", "X - Info", "GET /a HTTP/1.1\nHost: {{Hostname}}\nAuthorization: Basic YWRtaW46YWRtaW4="), "not reviewed"},
		"an injection GET": {getKEV("CVE-2024-0009", "X - SQLi", "GET /a?id=1'%20UNION%20SELECT%201 HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a built command":  {getKEV("CVE-2024-0010", "X - RCE", "GET /a?u={{base64(concat('id',' > ','x.txt'))}} HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"an enabled page":  {getKEV("CVE-2024-0011", "X - Debug Mode Enabled", "GET /debug HTTP/1.1\nHost: {{Hostname}}"), ""},
		"an OOB write":     {getKEV("CVE-2024-0012", "X - Out-of-Bounds Write", "GET /a HTTP/1.1\nHost: {{Hostname}}"), ""},
	} {
		doc := mustYAML(t, c.text)
		info, _ := doc["info"].(map[string]any)
		id, _ := doc["id"].(string)
		n, _ := info["name"].(string)
		if why, _ := changeReason(id, doc, []byte(c.text), tagsOf(info)); why != "" {
			t.Errorf("%s: left out by the step-1 rule as %q", name, why)
			continue
		}
		if why, d := noTickReason(id, n, "http/cves/2024/x.yaml", sum(c.text), doc, false); why != c.why {
			t.Errorf("%s: %q (%s), want %q", name, why, d, c.why)
		}
	}
}

func TestReviewedListFormat(t *testing.T) {
	t.Parallel()
	if len(reviewed) < 4 {
		t.Fatalf("reviewed.tsv holds %d entries", len(reviewed))
	}
	for name, text := range map[string]string{
		"two fields": "CVE-2024-1\t" + strings.Repeat("a", 64) + "\n",
		"bad sha":    "CVE-2024-1\tabc\tchanges nothing on the target at all\n",
		"short why":  "CVE-2024-1\t" + strings.Repeat("a", 64) + "\tok\n",
		"listed twice": "CVE-2024-1\t" + strings.Repeat("a", 64) + "\tchanges nothing on the target at all\n" +
			"CVE-2024-1\t" + strings.Repeat("b", 64) + "\tchanges nothing on the target at all\n",
	} {
		if _, err := parseReviewed(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A reviewed template whose file changed stops the build; a reviewed one that did not change is in although it is a POST; the queue
// lists the POST nobody reviewed, with its method.
func TestReviewedNeedsTheSameFile(t *testing.T) {
	t.Parallel()
	var id, sha string
	for k, e := range reviewed {
		id, sha = k, e.sha
		break
	}
	src := t.TempDir()
	write(t, src, "http/cves/2024/changed.yaml", getKEV(id, "X - RCE", "POST /a HTTP/1.1\nHost: {{Hostname}}\n\nq=1"))
	if _, err := build(src, t.TempDir(), "2026.11.4"); err == nil || !strings.Contains(err.Error(), "read them again") {
		t.Fatalf("a changed reviewed file did not stop the build: %v (listed sha %s)", err, sha)
	}
	if listed, stale := reviewedState(id, sha); !listed || stale {
		t.Fatal("the listed hash is not accepted")
	}
	src, out := t.TempDir(), t.TempDir()
	write(t, src, "http/cves/2024/read.yaml", getKEV("CVE-2024-0001", "X - Path Traversal", "GET /a/../../etc/passwd HTTP/1.1\nHost: {{Hostname}}"))
	write(t, src, "http/cves/2024/post.yaml", getKEV("CVE-2024-0002", "X - RCE", "POST /a HTTP/1.1\nHost: {{Hostname}}\n\nq=1"))
	if _, err := build(src, out, "2026.11.4"); err != nil {
		t.Fatal(err)
	}
	q, err := os.ReadFile(filepath.Join(out, "review-queue.md")) //nolint:gosec // a test's temp dir
	if err != nil || !strings.Contains(string(q), "| CVE-2024-0002 | CVE-2024-0001 | X | POST |") || strings.Contains(string(q), "read.yaml") {
		t.Fatalf("queue %q %v", q, err)
	}
}

// Review kev r1 M-3, L-4 and FULL-4b r2 L-b: a fixed network port, a third party in a host header, and a credential expression the
// template does not define.
func TestDestinationHoles(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ text, why string }{
		"a fixed port":          {tcpKEV, "destination"},
		"the job's port":        {strings.Replace(tcpKEV, "port: 27017", `port: "{{Port}}"`, 1), ""},
		"a third-party Host":    {getKEV("CVE-2024-0020", "X", "GET /a HTTP/1.1\nHost: evil.example.net.attacker.io"), "third party"},
		"X-Forwarded-Host":      {getKEV("CVE-2024-0021", "X", "GET /a HTTP/1.1\nHost: {{Hostname}}\nX-Forwarded-Host: attacker.io"), "third party"},
		"Forwarded host=":       {getKEV("CVE-2024-0022", "X", "GET /a HTTP/1.1\nHost: {{Hostname}}\nForwarded: for=1.2.3.4;host=attacker.io"), "third party"},
		"Host: localhost":       {getKEV("CVE-2024-0023", "X", "GET /a HTTP/1.1\nHost: localhost"), ""},
		"an undefined password": {getKEV("CVE-2024-0024", "X", "GET /login?u={{username}}&p={{password}} HTTP/1.1\nHost: {{Hostname}}"), "undefined credential"},
	} {
		doc := mustYAML(t, c.text)
		info, _ := doc["info"].(map[string]any)
		id, _ := doc["id"].(string)
		if why, d := changeReason(id, doc, []byte(c.text), tagsOf(info)); why != c.why {
			t.Errorf("%s: %q (%s), want %q", name, why, d, c.why)
		}
	}
}
