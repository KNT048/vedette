package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/pack"
)

// D-528 step 2: the KEV set (no tick) takes only templates a person reviewed (reviewed.tsv, id + sha256); rule (a) sorts the queue.

func getKEV(id, name, req string) string {
	return "id: " + id + "\n\ninfo:\n  name: " + name + "\n  classification:\n    cve-id: CVE-2024-0001\n  tags: cve,kev\n\nhttp:\n  - raw:\n      - |\n" +
		"        " + strings.ReplaceAll(req, "\n", "\n        ") + "\n\n    matchers:\n      - type: status\n        status:\n          - 200\n"
}

func TestNoTickRule(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		text, why string
	}{
		"a read":           {getKEV("CVE-2024-0001", "X - Path Traversal", "GET /a/../../etc/passwd HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: x"), "likely read-only"},
		"a Remote-User":    {getKEV("CVE-2024-0013", "X - Info", "GET /a HTTP/1.1\nHost: {{Hostname}}\nRemote-User: admin"), "not reviewed"},
		"a POST":           {getKEV("CVE-2024-0002", "X - RCE", "POST /a HTTP/1.1\nHost: {{Hostname}}\n\nq=1"), "not reviewed"},
		"a GET restore":    {getKEV("CVE-2024-0003", "X - Info", "GET /OS/startup/restore/restoreAdmin.php HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a GET submit":     {getKEV("CVE-2024-0004", "X - Info", "GET /api/manager/submit?group=1 HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a GET action=set": {getKEV("CVE-2024-0005", "X - Info", "GET /editor.php?mapname=a.conf&action=set_map_properties HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a creation name":  {getKEV("CVE-2024-0006", "X - Arbitrary User Creation", "GET /a HTTP/1.1\nHost: {{Hostname}}"), "state name"},
		"a purge name":     {getKEV("CVE-2024-0007", "X - Unauthenticated Log Purge", "GET /a HTTP/1.1\nHost: {{Hostname}}"), "state name"},
		"a basic login":    {getKEV("CVE-2024-0008", "X - Info", "GET /a HTTP/1.1\nHost: {{Hostname}}\nAuthorization: Basic YWRtaW46YWRtaW4="), "not reviewed"},
		"an injection GET": {getKEV("CVE-2024-0009", "X - SQLi", "GET /a?id=1'%20UNION%20SELECT%201 HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"a built command":  {getKEV("CVE-2024-0010", "X - RCE", "GET /a?u={{base64(concat('id',' > ','x.txt'))}} HTTP/1.1\nHost: {{Hostname}}"), "not reviewed"},
		"an enabled page":  {getKEV("CVE-2024-0011", "X - Debug Mode Enabled", "GET /debug HTTP/1.1\nHost: {{Hostname}}"), "likely read-only"},
		"an OOB write":     {getKEV("CVE-2099-0012", "X - Out-of-Bounds Write", "GET /a HTTP/1.1\nHost: {{Hostname}}"), "likely read-only"},
	} {
		doc := mustYAML(t, c.text)
		info, _ := doc["info"].(map[string]any)
		id, _ := doc["id"].(string)
		n, _ := info["name"].(string)
		if why, _ := changeReason(id, doc, []byte(c.text), tagsOf(info)); why != "" {
			t.Errorf("%s: left out by the step-1 rule as %q", name, why)
			continue
		}
		// step-2 review r1: nothing that is not in reviewed.tsv runs without the tick; rule (a) only sorts the queue
		if why, d := noTickReason(id, n, "http/cves/2024/x.yaml", sum(c.text), doc, reviewedState); why != c.why {
			t.Errorf("%s: %q (%s), want %q", name, why, d, c.why)
		}
	}
}

// Review r1 H-2: an own_ip-shaped GET that restores an admin password is not admitted by its shape; only reviewed.tsv admits.
func TestOnlyTheReviewedListAdmits(t *testing.T) {
	t.Parallel()
	text := getKEV("CVE-2024-0003", "X - Info", "GET /OS/startup/restore/restoreAdmin.php HTTP/1.1\nHost: {{Hostname}}")
	doc := mustYAML(t, text)
	if !ownIPSafe("http/cves/2024/x.yaml", doc, []string{"cve", "kev"}, []byte(text)) {
		t.Fatal("the fixture is meant to pass the D-520 own_ip rule")
	}
	if tp, why := qualify("http/cves/2024/x.yaml", []byte(text)); why == "" && (tp.InKEV() || tp.FullSet() == pack.SetDeep) {
		t.Fatalf("runs without the tick: %+v", tp) // (in a full category it may run behind the tick: D-527)
	}
	for id, e := range reviewed {
		if listed, stale := reviewedState(id, e.sha); !listed || stale {
			t.Fatalf("%s: its own hash is not accepted", id)
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
	// review r1 M-4: a reviewed GET whose file changed (a new request line), and a reviewed POST whose new text also fails the
	// step-1 rule (a password change), both stop the build: drift is checked before anything else
	for name, text := range map[string]string{
		"a reviewed GET changed":  getKEV("CVE-2018-13379", "Fortinet - Path Traversal", "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1\nHost: {{Hostname}}\nX-New: 1"),
		"a reviewed POST changed": getKEV("CVE-2019-15107", "Webmin - RCE", "POST /password_change.cgi HTTP/1.1\nHost: {{Hostname}}\n\nuser=root&pam=&old=x&new1=a&new2=a&expired=2"),
	} {
		src := t.TempDir()
		write(t, src, "http/cves/2024/changed.yaml", text)
		if _, err := build(src, t.TempDir(), "2026.11.4"); err == nil || !strings.Contains(err.Error(), "read them again") {
			t.Errorf("%s: the build did not stop: %v", name, err)
		}
	}
	// a reviewed POST ships; an unreviewed read-only GET waits in the "read first" group, an unreviewed POST in the rest
	src, out := t.TempDir(), t.TempDir()
	post := getKEV("CVE-2024-0002", "X - RCE", "POST /a HTTP/1.1\nHost: {{Hostname}}\n\nq=1")
	// (a folder of no full set, so only the KEV rule decides: D-527's deep set would take the read-only GET)
	write(t, src, "http/left/read.yaml", getKEV("CVE-2024-0001", "X - Path Traversal", "GET /a/../../etc/passwd HTTP/1.1\nHost: {{Hostname}}"))
	write(t, src, "http/left/post.yaml", post)
	write(t, src, "http/left/post2.yaml", strings.ReplaceAll(post, "CVE-2024-0002", "CVE-2024-0003"))
	onlyPost := func(id, sha string) (bool, bool) { return id == "CVE-2024-0002" && sha == sum(post), false }
	rep, err := buildWith(src, out, "2026.11.4", onlyPost)
	if err != nil || rep.Kept != 1 {
		t.Fatalf("kept %d, %v", rep.Kept, err)
	}
	q, err := os.ReadFile(filepath.Join(out, "review-queue.md")) //nolint:gosec // a test's temp dir
	first, rest, _ := strings.Cut(string(q), "## The rest")
	if err != nil || !strings.Contains(first, "read.yaml") || !strings.Contains(rest, "| CVE-2024-0003 | CVE-2024-0001 | X | POST |") || strings.Contains(string(q), "post.yaml") {
		t.Fatalf("queue %q %v", q, err)
	}
}

// allowAny reads every fixture template as reviewed: the tests of the other rules build their fixtures with it.
func allowAny(string, string) (bool, bool) { return true, false }

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
