package agentintake_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store/storetest"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

func TestContract_TablesUseThePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "agent-intake", agentintake.Migrations, "intake_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// fullLog is the log of a Linux server as osquery sends it after its first run.
func fullLog(key string) map[string]any {
	return logBody(key,
		snap("os_version", map[string]string{"name": "Ubuntu", "version": "24.04.1 LTS (Noble Numbat)", "major": "24", "minor": "4", "patch": "1", "build": "", "platform": "ubuntu", "arch": "x86_64"}),
		snap("system_info", map[string]string{"hostname": "srv-1", "hardware_vendor": "QEMU", "hardware_model": "Standard PC", "cpu_brand": "ignored", "physical_memory": "1"}),
		snap("interfaces", ifaceRow(macA, peerA), ifaceRow("52:54:00:aa:bb:02", "10.9.9.9")),
		snap("deb_packages", debRow("openssh-server", "1:9.6p1-3ubuntu13.5"), debRow("nginx", "1.24.0-2ubuntu7"), debRow("htop", "3.3.0-4build1")),
		snap("rpm_packages"),
	)
}

func swByProduct(d inventory.Device, product string) (inventory.Software, bool) {
	for _, s := range d.Software {
		if s.Product == product {
			return s, true
		}
	}
	return inventory.Software{}, false
}

// INV-3: the secret is shown once, only its SHA-256 and last four characters are stored, neither the audit nor the list holds it.
func TestContract_INV3_SecretShownOnceHashOnly(t *testing.T) {
	w := newWorld(t)
	tk, secret, err := w.svc.IssueToken(t.Context(), "admin@acme.example", "osquery on SRV-AD", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^vdt_osquery_[a-km-np-z2-9]{32}$`).MatchString(secret) || tk.Last4 != secret[len(secret)-4:] {
		t.Fatalf("secret %q last4 %q", secret, tk.Last4)
	}
	if got := tk.ExpiresAt.Sub(tk.CreatedAt); got != 7*24*time.Hour {
		t.Fatalf("expiry %v", got)
	}
	var stored string
	if err := w.db.Reader().QueryRowContext(t.Context(), `SELECT token_hash FROM intake_agent_tokens WHERE id = ?`, tk.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != fmt.Sprintf("%x", sha256sum(secret)) {
		t.Fatalf("stored %q is not the SHA-256 of the secret", stored)
	}
	list, err := w.svc.ListTokens(t.Context())
	if err != nil || len(list) != 1 || list[0].Last4 != tk.Last4 || list[0].Hosts != 0 {
		t.Fatalf("list %+v %v", list, err)
	}
	w.assertNowhere(secret)
	// two tokens never share a secret
	_, s2 := w.token("second", 0)
	if s2 == secret {
		t.Fatal("two tokens with one secret")
	}
	if tk2 := w.count(`SELECT count(*) FROM intake_agent_tokens WHERE expires_at IS NULL`); tk2 != 1 {
		t.Fatalf("a 0-day token must never expire, %d rows without expiry", tk2)
	}
}

// assertNowhere fails when text is in any column of the module's tables, in the audit log or in the server log (SYS-4, FORBID-2).
func (w *world) assertNowhere(text string) {
	w.t.Helper()
	for _, q := range []string{
		`SELECT group_concat(coalesce(id,'') || coalesce(name,'') || coalesce(token_hash,'') || coalesce(last4,''), '|') FROM intake_agent_tokens`,
		`SELECT group_concat(coalesce(id,'') || coalesce(host_identifier,'') || coalesce(hostname,'') || coalesce(node_key_hash,''), '|') FROM intake_osquery_nodes`,
		`SELECT group_concat(coalesce(user,'') || action || target || coalesce(detail,''), '|') FROM core_audit`,
	} {
		var all *string
		if err := w.db.Reader().QueryRowContext(w.t.Context(), q).Scan(&all); err != nil {
			w.t.Fatal(err)
		}
		if all != nil && strings.Contains(*all, text) {
			w.t.Fatalf("a secret is stored in clear: %s", q)
		}
	}
	if strings.Contains(w.logs.String(), text) {
		w.t.Fatal("a secret is in the server log")
	}
}

func TestContract_TokenNamesExpiryAndCap(t *testing.T) {
	w := newWorld(t)
	for _, name := range []string{"", "   ", strings.Repeat("a", 65), "bad<name>", "tab\tname"} {
		if _, _, err := w.svc.IssueToken(t.Context(), "a@b.example", name, 7); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	for _, days := range []int{-1, 366} {
		if _, _, err := w.svc.IssueToken(t.Context(), "a@b.example", "x", days); err == nil {
			t.Errorf("%d days accepted", days)
		}
	}
	for i := range agentintake.MaxTokens {
		w.token(fmt.Sprintf("t%d", i), 7)
	}
	if _, _, err := w.svc.IssueToken(t.Context(), "a@b.example", "one too many", 7); err == nil || !strings.Contains(err.Error(), "too_many_tokens") {
		t.Fatalf("51st token: %v", err)
	}
	if err := w.svc.RevokeToken(t.Context(), "a@b.example", "tok-nope"); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("revoke unknown: %v", err)
	}
}

// POST-1: one enrolment and one result log put the device in the inventory with its software, source agent; the status answer follows.
func TestContract_POST1_EnrolAndLogShowTheDeviceWithItsSoftware(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	st := w.post("/intake/osquery/status", peerA, nil, "Authorization", "Bearer "+secret)
	if st.code != 200 || st.body["enrolled"] != false || st.body["hosts"] != float64(0) {
		t.Fatalf("status before: %d %s", st.code, st.raw)
	}
	key := w.enroll(secret, "srv-1", peerA)
	cfg := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	sch, _ := cfg.body["schedule"].(map[string]any)
	if cfg.code != 200 || cfg.invalid() || len(sch) != 6 || sch["interfaces"] == nil {
		t.Fatalf("config: %d %s", cfg.code, cfg.raw)
	}
	lr := w.post("/intake/osquery/log", peerA, fullLog(key))
	if lr.code != 200 || lr.invalid() {
		t.Fatalf("log: %d %s", lr.code, lr.raw)
	}
	d, ok := w.device(peerA)
	if !ok {
		t.Fatalf("no device at %s", peerA)
	}
	if d.MAC == nil || *d.MAC != macA || d.Hostname == nil || *d.Hostname != "srv-1" || d.OS == nil || d.OS.Source != "agent" || !strings.HasPrefix(d.OS.Value, "Ubuntu 24.04") {
		t.Fatalf("device %+v mac=%v host=%v os=%+v", d.AssetCore, d.MAC, d.Hostname, d.OS)
	}
	ssh, ok := swByProduct(d, "OpenSSH")
	if !ok || ssh.Vendor != "OpenBSD" || ssh.Version == nil || *ssh.Version != "9.6p1" || ssh.Source != "agent" || len(ssh.Kev) != 1 || ssh.Kev[0] != "openbsd|openssh" {
		t.Fatalf("openssh row %+v", ssh)
	}
	if ng, ok := swByProduct(d, "nginx"); !ok || ng.Vendor != "F5" || *ng.Version != "1.24.0" {
		t.Fatalf("nginx row %+v", ng)
	}
	if h, ok := swByProduct(d, "htop"); !ok || h.Vendor != "htop" || *h.Version != "3.3.0" {
		t.Fatalf("unmapped row %+v", h)
	}
	st = w.post("/intake/osquery/status", peerA, nil, "Authorization", "Bearer "+secret)
	if st.body["enrolled"] != true || st.body["hosts"] != float64(1) {
		t.Fatalf("status after: %s", st.raw)
	}
	list, _ := w.svc.ListTokens(t.Context())
	if list[0].LastReceived.IsZero() || list[0].Hosts != 1 {
		t.Fatalf("token %+v", list[0])
	}
	// The node key is not in the box in clear, nor the token, nor in any log line.
	w.assertNowhere(key)
	w.assertNowhere(secret)
}

// POST-4: an expired token enrols nobody new, a node it already has keeps reporting; the status says so; prune keeps a token that has nodes.
func TestContract_POST4_ExpiryBlocksEnrolmentOnly(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("short", 1)
	key := w.enroll(secret, "srv-1", peerA)
	w.clock.Advance(48 * time.Hour)
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-2")); r.code != 200 || !r.invalid() || r.body["node_key"] != nil {
		t.Fatalf("expired token enrolled: %s", r.raw)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 || r.invalid() {
		t.Fatalf("enrolled node cut by expiry: %s", r.raw)
	}
	if r := w.post("/intake/osquery/log", peerA, fullLog(key)); r.code != 200 || r.invalid() {
		t.Fatalf("log of an enrolled node: %s", r.raw)
	}
	if _, ok := w.device(peerA); !ok {
		t.Fatal("an enrolled node of an expired token was not recorded")
	}
	r := w.post("/intake/osquery/status", peerA, nil, "Authorization", "Bearer "+secret)
	if r.code != 403 || r.errCode() != "token_expired" {
		t.Fatalf("status of an expired token: %d %s", r.code, r.raw)
	}
	w.clock.Advance(40 * 24 * time.Hour)
	if err := w.svc.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := w.count(`SELECT count(*) FROM intake_agent_tokens`); n != 1 {
		t.Fatalf("a token with a node was pruned (%d tokens)", n)
	}
}

// POST-3: revoke cuts the nodes at their next call (200 + node_invalid) and keeps what they delivered.
func TestContract_POST3_RevokeCutsNodesAndKeepsData(t *testing.T) {
	w := newWorld(t)
	id, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	if err := w.svc.RevokeToken(t.Context(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	for _, p := range []struct {
		path string
		body any
	}{{"/intake/osquery/config", map[string]any{"node_key": key}}, {"/intake/osquery/log", fullLog(key)}} {
		if r := w.post(p.path, peerA, p.body); r.code != 200 || !r.invalid() {
			t.Fatalf("%s after revoke: %d %s", p.path, r.code, r.raw)
		}
	}
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-2")); !r.invalid() {
		t.Fatalf("revoked token enrolled: %s", r.raw)
	}
	r := w.post("/intake/osquery/status", peerA, nil, "Authorization", "Bearer "+secret)
	if r.code != 403 || r.errCode() != "invalid_token" {
		t.Fatalf("status after revoke: %d %s", r.code, r.raw)
	}
	if d, ok := w.device(peerA); !ok || len(d.Software) != 3 {
		t.Fatalf("data after revoke: %v %+v", ok, d.Software)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 0 {
		t.Fatalf("%d nodes left", n)
	}
	if !w.auditHas("inventory.agent_token_revoke", "srv") || !w.auditHas("inventory.agent_token_create", "srv") || !w.auditHas("inventory.agent_enroll", "srv-1") {
		t.Fatal("mutations are not audited")
	}
}

func (w *world) auditHas(action, target string) bool {
	return w.count(`SELECT count(*) FROM core_audit WHERE action = ? AND target = ?`, action, target) > 0
}

// INV-13: the wire rules. Credential errors are 200 + node_invalid and say nothing else; a body that is too big, not JSON or not shaped
// like the operation is 413 / 400; unknown outer keys are ignored.
func TestContract_INV13_WireRules(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	for name, body := range map[string]any{
		"unknown token":     enrollBody("vdt_osquery_"+strings.Repeat("a", 32), "h"),
		"malformed token":   enrollBody("not-a-token", "h"),
		"no secret":         map[string]any{"host_identifier": "h"},
		"empty identifier":  enrollBody(secret, ""),
		"dirty identifier":  enrollBody(secret, "h"+string(rune(0x202e))+"x"),
		"control character": enrollBody(secret, "h\x01"),
	} {
		r := w.post("/intake/osquery/enroll", peerA, body)
		if r.code != 200 || !r.invalid() || r.body["node_key"] != nil || len(r.body) != 1 {
			t.Errorf("enroll %s: %d %s", name, r.code, r.raw)
		}
	}
	for _, key := range []string{"", "short", strings.Repeat("A", 43), strings.Repeat("!", 43)} {
		if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 || !r.invalid() {
			t.Errorf("config with key %q: %d %s", key, r.code, r.raw)
		}
		if r := w.post("/intake/osquery/log", peerA, logBody(key)); r.code != 200 || !r.invalid() {
			t.Errorf("log with key %q: %d %s", key, r.code, r.raw)
		}
		w.clock.Advance(time.Hour) // the failures of this loop are not what is tested here
	}
	// unknown outer keys are ignored, also in the enrol request of a good token
	b := enrollBody(secret, "srv-x")
	b["extra"] = map[string]any{"deep": []int{1, 2}}
	if r := w.post("/intake/osquery/enroll", peerA, b); r.code != 200 || r.invalid() {
		t.Fatalf("outer keys refused: %s", r.raw)
	}
	// not JSON, wrong shape
	for _, body := range []string{"not json", "[]", "{", `{"node_key": 5}`} {
		if r := w.post("/intake/osquery/config", peerA, body); r.code != 400 {
			t.Errorf("config body %q: %d %s", body, r.code, r.raw)
		}
	}
	// size caps by operation
	big := `{"node_key":"` + strings.Repeat("a", 5<<10) + `"}`
	if r := w.post("/intake/osquery/config", peerA, big); r.code != 413 || r.errCode() != "too_large" {
		t.Errorf("config 5 KiB: %d %s", r.code, r.raw)
	}
	bigEnroll := `{"host_identifier":"h","enroll_secret":"x","host_details":{"a":"` + strings.Repeat("a", 65<<10) + `"}}`
	if r := w.post("/intake/osquery/enroll", peerA, bigEnroll); r.code != 413 {
		t.Errorf("enroll 65 KiB: %d", r.code)
	}
	bigLog := `{"node_key":"` + strings.Repeat("a", 43) + `","log_type":"result","data":[{"x":"` + strings.Repeat("a", 4<<20) + `"}]}`
	if r := w.post("/intake/osquery/log", peerA, bigLog); r.code != 413 {
		t.Errorf("log over 4 MiB: %d", r.code)
	}
	if r := w.post("/intake/osquery/status", peerA, strings.Repeat("a", 2<<10), "Authorization", "Bearer "+secret); r.code != 413 {
		t.Errorf("status with a 2 KiB body: %d", r.code)
	}
	// the distributed operations do not exist
	for _, p := range []string{"/intake/osquery/distributed_read", "/intake/osquery/distributed_write"} {
		if r := w.post(p, peerA, map[string]any{"node_key": "x"}); r.code != 404 {
			t.Errorf("%s: %d", p, r.code)
		}
	}
}

func TestContract_StatusHeaderForms(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	for _, h := range []string{"", "Bearer", "Bearer ", "bearer " + secret, "Basic " + secret, "Bearer " + secret + "x", "Bearer vdt_osquery_" + strings.Repeat("b", 32)} {
		r := w.post("/intake/osquery/status", peerA, nil, "Authorization", h)
		if r.code != 403 || r.errCode() != "invalid_token" {
			t.Errorf("header %q: %d %s", h, r.code, r.raw)
		}
		w.clock.Advance(time.Hour)
	}
	// the token never works from the URL
	if r := w.post("/intake/osquery/status?token="+secret, peerA, nil); r.code != 403 {
		t.Errorf("token in URL: %d", r.code)
	}
}

// Rate limits: 10 credential failures a minute per source, then 429 + Retry-After that doubles; a refused call is not counted; a good
// call from the blocked source is refused too; another source is not affected; per node 6 config and 12 log calls a minute.
func TestContract_RateLimits(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	bad := enrollBody("vdt_osquery_"+strings.Repeat("c", 32), "h")
	for i := 0; i < 10; i++ {
		if r := w.post("/intake/osquery/enroll", "198.51.100.7", bad); r.code != 200 || !r.invalid() {
			t.Fatalf("failure %d: %d", i, r.code)
		}
	}
	if r := w.post("/intake/osquery/enroll", "198.51.100.7", bad); r.code != 200 { // the eleventh failure is still answered, and blocks
		t.Fatalf("eleventh: %d", r.code)
	}
	r := w.post("/intake/osquery/enroll", "198.51.100.7", enrollBody(secret, "srv-2"))
	if r.code != 429 || r.errCode() != "rate_limited" || r.header.Get("Retry-After") != "30" {
		t.Fatalf("blocked source: %d retry-after=%q %s", r.code, r.header.Get("Retry-After"), r.raw)
	}
	if r := w.post("/intake/osquery/config", "198.51.100.7", map[string]any{"node_key": key}); r.code != 429 {
		t.Fatalf("a blocked source's config: %d", r.code)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 {
		t.Fatalf("another source: %d", r.code)
	}
	w.clock.Advance(31 * time.Second)
	for i := 0; i < 11; i++ {
		w.post("/intake/osquery/enroll", "198.51.100.7", bad)
	}
	if r := w.post("/intake/osquery/enroll", "198.51.100.7", bad); r.code != 429 || r.header.Get("Retry-After") != "60" {
		t.Fatalf("second block: %d retry-after=%q", r.code, r.header.Get("Retry-After"))
	}
	// IPv6: the /64 is one source
	for i := 0; i < 11; i++ {
		w.post("/intake/osquery/enroll", "2001:db8::"+fmt.Sprintf("%x", i+1), bad)
	}
	if r := w.post("/intake/osquery/enroll", "2001:db8::ffff", bad); r.code != 429 {
		t.Fatalf("an IPv6 /64: %d", r.code)
	}
	// per node
	w.clock.Advance(time.Hour)
	for i := 0; i < 6; i++ {
		if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 {
			t.Fatalf("config %d: %d", i, r.code)
		}
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("seventh config in a minute: %d", r.code)
	}
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	for i := 0; i < 12; i++ {
		if r := w.post("/intake/osquery/log", peerA, logBody(key)); r.code != 200 {
			t.Fatalf("log %d: %d", i, r.code)
		}
	}
	if r := w.post("/intake/osquery/log", peerA, logBody(key)); r.code != 429 {
		t.Fatalf("thirteenth log in a minute: %d", r.code)
	}
}

// Re-enrol replaces the row (hosts stays 1, the old key dies), after the 60-second cooldown; the caps give 429 too_many_nodes.
func TestContract_EnrolReplacesCooldownAndCaps(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	k1 := w.enroll(secret, "srv-1", peerA)
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-1")); r.code != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("enrol again at once: %d %s", r.code, r.raw)
	}
	w.clock.Advance(61 * time.Second)
	k2 := w.enroll(secret, "srv-1", peerA)
	if k1 == k2 {
		t.Fatal("same key twice")
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 1 {
		t.Fatalf("%d nodes after a re-enrol", n)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": k1}); !r.invalid() {
		t.Fatalf("old key still valid: %s", r.raw)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": k2}); r.invalid() {
		t.Fatalf("new key refused: %s", r.raw)
	}
	// 500 per token: fill the token, the 501st host is refused, a re-enrol of an existing host is not
	w.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 499)
		INSERT INTO intake_osquery_nodes (id, token_id, node_key_hash, host_identifier, enrolled_at, last_seen)
		SELECT 'fill-' || i, (SELECT id FROM intake_agent_tokens LIMIT 1), printf('%064d', i), 'fill-' || i, '2026-11-11T07:00:00.000Z', '2026-11-11T07:00:00.000Z' FROM n`)
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-501")); r.code != 429 || r.errCode() != "too_many_nodes" {
		t.Fatalf("501st node: %d %s", r.code, r.raw)
	}
	w.clock.Advance(61 * time.Second)
	w.enroll(secret, "srv-1", peerA)
	// 5,000 in all, over several tokens
	_, s2 := w.token("other", 7)
	w.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 4500)
		INSERT INTO intake_osquery_nodes (id, token_id, node_key_hash, host_identifier, enrolled_at, last_seen)
		SELECT 'bulk-' || i, (SELECT id FROM intake_agent_tokens WHERE name = 'other'), printf('%064d', i + 1000), 'bulk-' || i, '2026-11-11T07:00:00.000Z', '2026-11-11T07:00:00.000Z' FROM n`)
	// 500 + 4500 = 5000 rows now (the "other" token holds 4500: a table-level fill, not reachable through enrol); a fresh token is over the total
	_, s3 := w.token("third", 7)
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(s3, "late")); r.code != 429 || r.errCode() != "too_many_nodes" {
		t.Fatalf("5,001st node: %d %s", r.code, r.raw)
	}
	_ = s2
}

// INV-12: the binding rule. A node is written to the inventory only when the connection's address is among the IPv4 it declared, and
// the MAC is the one of that card.
func TestContract_INV12_Binding(t *testing.T) {
	t.Run("spoofed address: the node declares an address that is not its connection's", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", peerA)
		body := logBody(key, snap("interfaces", ifaceRow(macA, "192.0.2.99")), snap("deb_packages", debRow("openssh-server", "1:9.6p1-1")))
		if r := w.post("/intake/osquery/log", peerA, body); r.code != 200 || r.invalid() {
			t.Fatalf("log: %d %s", r.code, r.raw)
		}
		if n := w.deviceCount(); n != 0 {
			t.Fatalf("%d devices from a spoofed address", n)
		}
		if w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE bound_ip IS NOT NULL`) != 0 {
			t.Fatal("a spoofed node got a binding")
		}
		if !strings.Contains(w.logs.String(), "nothing written to the inventory") {
			t.Fatal("no log line for an unmatched node")
		}
	})
	t.Run("wrong MAC: the card of the connection's address gives the MAC", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", peerA)
		body := logBody(key, snap("interfaces", ifaceRow("52:54:00:aa:bb:02", "10.9.9.9"), ifaceRow(macA, peerA)),
			snap("system_info", map[string]string{"hostname": "srv-1"}), snap("deb_packages", debRow("sudo", "1.9.15p5-3ubuntu5")))
		w.post("/intake/osquery/log", peerA, body)
		d, ok := w.device(peerA)
		if !ok || d.MAC == nil || *d.MAC != macA {
			t.Fatalf("device %v mac %v", ok, d.MAC)
		}
		if w.deviceCount() != 1 {
			t.Fatalf("%d devices", w.deviceCount())
		}
	})
	t.Run("IPv6 connection: nothing is written", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", "2001:db8::5")
		body := logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("deb_packages", debRow("sudo", "1.9")))
		w.post("/intake/osquery/log", "2001:db8::5", body)
		w.post("/intake/osquery/log", "::ffff:192.0.2.10", logBody(key, snap("interfaces", ifaceRow(macA, peerA)))) // v4-mapped: it IS 192.0.2.10
		if n := w.deviceCount(); n != 0 {
			t.Fatalf("%d devices from IPv6 / interfaces-only logs", n)
		}
	})
	t.Run("NAT: the connection comes from the NAT address, not one the node declared", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", "203.0.113.1")
		w.post("/intake/osquery/log", "203.0.113.1", logBody(key, snap("interfaces", ifaceRow(macA, "192.168.1.20")), snap("deb_packages", debRow("sudo", "1.9"))))
		if n := w.deviceCount(); n != 0 {
			t.Fatalf("%d devices behind NAT", n)
		}
		r := w.post("/intake/osquery/status", "203.0.113.1", nil, "Authorization", "Bearer "+secret)
		if r.body["enrolled"] != true || r.body["hosts"] != float64(1) {
			t.Fatalf("status of an unmatched node: %s", r.raw) // it is counted as a host and as received, but nothing is written
		}
	})
	t.Run("loopback, link-local and bad MAC rows are not addresses", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", "127.0.0.1")
		body := logBody(key, snap("interfaces", ifaceRow(macA, "127.0.0.1"), ifaceRow("00:00:00:00:00:00", "127.0.0.1"), ifaceRow("zz", "127.0.0.1")), snap("deb_packages", debRow("sudo", "1.9")))
		w.post("/intake/osquery/log", "127.0.0.1", body)
		w.post("/intake/osquery/log", "169.254.1.1", logBody(key, snap("interfaces", ifaceRow(macA, "169.254.1.1"))))
		if n := w.deviceCount(); n != 0 {
			t.Fatalf("%d devices", n)
		}
	})
	t.Run("the binding is stored and re-checked on every result", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		key := w.enroll(secret, "srv-1", peerA)
		w.post("/intake/osquery/log", peerA, fullLog(key))
		if w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE bound_ip = ? AND bound_mac = ?`, peerA, macA) != 1 {
			t.Fatal("binding not stored")
		}
		w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
		// a later result without interfaces, from the same address: written
		w.post("/intake/osquery/log", peerA, logBody(key, snap("deb_packages", debRow("openssh-server", "1:9.7p1-1"))))
		d, _ := w.device(peerA)
		if s, ok := swByProduct(d, "OpenSSH"); !ok || *s.Version != "9.7p1" {
			t.Fatalf("software after a result without interfaces: %+v", d.Software)
		}
		// the same key from another address (a copied key): nothing is written
		w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
		w.post("/intake/osquery/log", "192.0.2.77", logBody(key, snap("deb_packages", debRow("openssh-server", "1:9.8p1-1"))))
		d, _ = w.device(peerA)
		if s, _ := swByProduct(d, "OpenSSH"); *s.Version != "9.7p1" {
			t.Fatalf("a copied key from another address wrote software: %+v", d.Software)
		}
		if _, ok := w.device("192.0.2.77"); ok {
			t.Fatal("a device appeared at the thief's address")
		}
		// an interfaces result that no longer holds the address clears the binding
		w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
		w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, "10.1.1.1")), snap("deb_packages", debRow("openssh-server", "1:9.9p1-1"))))
		d, _ = w.device(peerA)
		if s, _ := swByProduct(d, "OpenSSH"); *s.Version != "9.7p1" {
			t.Fatalf("software written after the binding was lost: %+v", d.Software)
		}
		if w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE bound_ip IS NOT NULL`) != 0 {
			t.Fatal("binding not cleared")
		}
	})
	t.Run("a node that declares another node's address writes nothing for it", func(t *testing.T) {
		w := newWorld(t)
		_, secret := w.token("srv", 7)
		good := w.enroll(secret, "srv-1", peerA)
		evil := w.enroll(secret, "evil", "192.0.2.66")
		w.post("/intake/osquery/log", peerA, fullLog(good))
		w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
		w.post("/intake/osquery/log", "192.0.2.66", logBody(evil, snap("interfaces", ifaceRow("52:54:00:ee:ee:01", peerA)), snap("deb_packages", debRow("openssh-server", "1:0.1-1"))))
		d, _ := w.device(peerA)
		if s, _ := swByProduct(d, "OpenSSH"); *s.Version != "9.6p1" {
			t.Fatalf("the victim's list was replaced: %+v", d.Software)
		}
		if w.deviceCount() != 1 {
			t.Fatalf("%d devices", w.deviceCount())
		}
	})
}

// INV-7 and POST-2 of the plan: hostile content is dropped row by row; an empty package list never wipes the stored one.
func TestContract_INV7_DirtyRowsAndEmptyListNeverWipes(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	// an empty deb list, an unknown query, a differential event, a status type, rows of the wrong type or with unclean text
	hostile := logBody(key,
		snap("interfaces", ifaceRow(macA, peerA)),
		snap("deb_packages"),
		snap("secret_table", map[string]string{"name": "x"}),
		map[string]any{"name": "deb_packages", "action": "added", "columns": map[string]string{"name": "evil"}},
		map[string]any{"name": 5, "action": "snapshot", "snapshot": []any{}},
	)
	if r := w.post("/intake/osquery/log", peerA, hostile); r.code != 200 || r.invalid() {
		t.Fatalf("hostile log: %d %s", r.code, r.raw)
	}
	d, _ := w.device(peerA)
	if len(d.Software) != 3 {
		t.Fatalf("an empty list wiped the software: %d rows", len(d.Software))
	}
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	dirty := logBody(key,
		snap("interfaces", ifaceRow(macA, peerA)),
		map[string]any{"name": "deb_packages", "action": "snapshot", "snapshot": []any{
			map[string]any{"name": "ok-pkg", "version": "1.0-1"},
			map[string]any{"name": 7, "version": "1.0"},                                       // not a string
			map[string]any{"name": "zero" + string(rune(0x200b)) + "width", "version": "1.0"}, // invisible character
			map[string]any{"name": "ctl\x01", "version": "1.0"},                               // control character
			map[string]any{"name": strings.Repeat("n", 300), "version": "1"},                  // over the cap
			map[string]any{"name": "nested", "version": map[string]any{"a": 1}},
			map[string]any{"name": "sudo", "version": "1.9.15p5-3ubuntu5", "unknown_column": strings.Repeat("z", 100)},
		}},
	)
	if r := w.post("/intake/osquery/log", peerA, dirty); r.code != 200 || r.invalid() {
		t.Fatalf("dirty log: %d %s", r.code, r.raw)
	}
	d, _ = w.device(peerA)
	var names []string
	for _, s := range d.Software {
		names = append(names, s.Product)
	}
	if len(d.Software) != 2 || names[0] == "" {
		t.Fatalf("software after the dirty list: %v", names)
	}
	if _, ok := swByProduct(d, "ok-pkg"); !ok {
		t.Fatalf("the clean row was lost with the dirty ones: %v", names)
	}
	if _, ok := swByProduct(d, "Sudo"); !ok {
		t.Fatalf("a row with an unknown column was lost: %v", names)
	}
	// status lines are discarded, differential results ignored
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	st := map[string]any{"node_key": key, "log_type": "status", "data": []any{map[string]any{"message": strings.Repeat("m", 1000), "severity": 0}}}
	if r := w.post("/intake/osquery/log", peerA, st); r.code != 200 || r.invalid() {
		t.Fatalf("status log: %d %s", r.code, r.raw)
	}
}

// INV-8: what a person added by hand is not touched by an agent's list.
func TestContract_INV8_ManualSoftwareStays(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	d, _ := w.device(peerA)
	if _, err := w.inv.AddSoftware(t.Context(), "admin@acme.example", d.ID, inventory.AddInput{Vendor: "Veeam", Product: "Backup & Replication", Version: "12.1"}); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("deb_packages", debRow("htop", "3.3.0-4build1"))))
	d, _ = w.device(peerA)
	var manual, agent int
	for _, s := range d.Software {
		switch s.Source {
		case "manual":
			manual++
		case "agent":
			agent++
		}
	}
	if manual != 1 || agent != 1 {
		t.Fatalf("manual %d agent %d (%+v)", manual, agent, d.Software)
	}
}

// SYS-5: with the module off every route is 404 like an unknown one, and a node's data is kept.
func TestContract_SYS5_ModuleOffIs404(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	w.gate.Set("agent-intake", false)
	unknown := w.post("/intake/osquery/nothing", peerA, map[string]any{})
	for _, p := range []struct {
		path string
		body any
	}{
		{"/intake/osquery/enroll", enrollBody(secret, "x")}, {"/intake/osquery/config", map[string]any{"node_key": key}},
		{"/intake/osquery/log", fullLog(key)}, {"/intake/osquery/status", nil},
	} {
		r := w.post(p.path, peerA, p.body, "Authorization", "Bearer "+secret)
		if r.code != 404 || r.errCode() != "not_found" || r.raw != unknown.raw {
			t.Errorf("%s while off: %d %s", p.path, r.code, r.raw)
		}
	}
	if w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 1 || w.count(`SELECT count(*) FROM intake_agent_tokens`) != 1 {
		t.Fatal("data lost while off")
	}
	w.gate.Set("agent-intake", true)
	w.clock.Advance(6 * time.Minute) // past the 5-minute window of one software replace per source address
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 || r.invalid() {
		t.Fatalf("after turning on again: %d %s", r.code, r.raw)
	}
}

// The node-prune job: a node silent for 90 days goes, an expired token goes only when no node uses it; it is a normal job (D-265 (8)),
// and the 90 days count only while it runs unbroken.
func TestContract_PruneRetention(t *testing.T) {
	w := newWorld(t)
	jobs := w.svc.Jobs()
	if len(jobs) != 1 || jobs[0].Name != "node-prune" || jobs[0].Module != "agent-intake" || jobs[0].Housekeeping {
		t.Fatalf("jobs %+v", jobs)
	}
	_, s1 := w.token("keeps-nodes", 1)
	_, s2 := w.token("no-nodes", 1)
	_ = s2
	w.token("never", 0)
	k := w.enroll(s1, "srv-1", peerA)
	w.pruneFor(33 * 24 * time.Hour)
	if n := w.count(`SELECT count(*) FROM intake_agent_tokens`); n != 2 { // "no-nodes" is gone, "keeps-nodes" has a node, "never" never expires
		t.Fatalf("%d tokens", n)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 1 {
		t.Fatalf("%d nodes", n)
	}
	w.pruneFor(60 * 24 * time.Hour) // 93 days of an unbroken job in all
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 0 {
		t.Fatalf("a node silent for 90 days stayed (%d)", n)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": k}); !r.invalid() {
		t.Fatalf("a pruned node still valid: %s", r.raw)
	}
	if n := w.count(`SELECT count(*) FROM intake_agent_tokens`); n != 1 { // the expired token lost its last node in the same run, so it went too; "never" stays
		t.Fatalf("%d tokens", n)
	}
}

// pruneFor runs node-prune every two hours of the manual clock for d, as the scheduler would while the module is on.
func (w *world) pruneFor(d time.Duration) {
	w.t.Helper()
	for end := w.clock.Now().Add(d); w.clock.Now().Before(end); w.clock.Advance(2 * time.Hour) {
		if err := w.svc.Prune(w.t.Context()); err != nil {
			w.t.Fatal(err)
		}
	}
	if err := w.svc.Prune(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
}

// MEDIUM-1: a box left off for more than 90 days keeps its nodes. The real scheduler does not run a normal job while its module is off,
// and the first run after turning on starts the 90 days again, so no node is cut by the time the module was off.
func TestContract_PruneModuleOffKeepsNodes(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 0)
	key := w.enroll(secret, "srv-1", peerA)
	w.gate.Set("agent-intake", false)
	ran := make(chan struct{}, 4)
	job := w.svc.Jobs()[0]
	run := job.Run
	job.Run = func(ctx context.Context) error { err := run(ctx); ran <- struct{}{}; return err } // signals when a run has finished
	sched := jobs.New(slog.New(slog.DiscardHandler), w.gate, nil)
	if err := sched.Add(job); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { sched.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	w.clock.Advance(91 * 24 * time.Hour)
	select {
	case <-ran:
		t.Fatal("node-prune ran while the module was off")
	case <-time.After(500 * time.Millisecond):
	}
	w.gate.Set("agent-intake", true)
	sched.ModuleChanged("agent-intake", true)
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("node-prune did not run after the module was turned on")
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes`); n != 1 {
		t.Fatalf("the time the module was off cut %d node(s) away", 1-n)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.code != 200 || r.invalid() {
		t.Fatalf("a node after the module came back: %d %s", r.code, r.raw)
	}
}

// HIGH-1 (round 1 review): a node on its own IP that declares another device's MAC must not touch that device: not its IP, name,
// software or KEV match. The MAC is a claim; the hint for the inventory is the connection's address only.
func TestContract_INV12_MACClaimCannotWriteOnAnotherDevice(t *testing.T) {
	w := newWorld(t)
	const victimIP, victimMAC = "192.0.2.50", "52:54:00:de:ad:01"
	hint := observe.AssetHint{IP: netip.MustParseAddr(victimIP), MAC: victimMAC}
	if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: hint, Field: observe.Hostname, Value: "dc01", Source: observe.Agent, Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	err := w.inv.ReplaceSoftware(t.Context(), hint, observe.Agent, []observe.Software{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.0p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95}})
	if err != nil {
		t.Fatal(err)
	}
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "attacker", peerA)
	w.post("/intake/osquery/log", peerA, logBody(key,
		snap("interfaces", ifaceRow(victimMAC, peerA)),
		snap("system_info", map[string]string{"hostname": "pwned"}),
		snap("deb_packages", debRow("htop", "3.3.0-4build1"))))
	v, ok := w.device(victimIP)
	if !ok || v.MAC == nil || *v.MAC != victimMAC || v.Hostname == nil || *v.Hostname != "dc01" {
		t.Fatalf("the victim was changed: %v mac=%v host=%v", ok, v.MAC, v.Hostname)
	}
	if s, ok := swByProduct(v, "OpenSSH"); !ok || len(s.Kev) != 1 || s.Kev[0] != "openbsd|openssh" || *s.Version != "8.0p1" || len(v.Software) != 1 {
		t.Fatalf("the victim's software was replaced: %+v", v.Software)
	}
	a, ok := w.device(peerA)
	if !ok {
		t.Fatal("the attacker's own address has no device")
	}
	if a.MAC != nil && *a.MAC == victimMAC {
		t.Fatal("the attacker's device took the victim's MAC")
	}
	if a.Hostname == nil || *a.Hostname != "pwned" {
		t.Fatalf("what the node says about its own address is not recorded: %v", a.Hostname)
	}
	if _, ok := swByProduct(a, "htop"); !ok || w.deviceCount() != 2 {
		t.Fatalf("attacker software %+v, %d devices", a.Software, w.deviceCount())
	}
}

// MEDIUM-2: nodes enrolled by one machine share its address: one log bucket (12 a minute) and one software replace every 5 minutes.
func TestContract_FiftyNodesOnOneAddressReplaceSoftwareOncePerWindow(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	keys := make([]string, 50)
	for i := range keys {
		keys[i] = w.enroll(secret, fmt.Sprintf("node-%d", i), peerA)
	}
	send := func(i int) reply {
		return w.post("/intake/osquery/log", peerA, logBody(keys[i], snap("interfaces", ifaceRow(macA, peerA)), snap("deb_packages", debRow(fmt.Sprintf("pkg-%d", i), "1.0-1"))))
	}
	products := func() []string {
		d, _ := w.device(peerA)
		var out []string
		for _, s := range d.Software {
			out = append(out, s.Product)
		}
		return out
	}
	for i := 0; i < 12; i++ {
		if r := send(i); r.code != 200 {
			t.Fatalf("log %d: %d %s", i, r.code, r.raw)
		}
	}
	if got := products(); len(got) != 1 || got[0] != "pkg-0" {
		t.Fatalf("software after 12 nodes: %v (only the first replace of the window may land)", got)
	}
	if r := send(12); r.code != 429 {
		t.Fatalf("a 13th log from one address in a minute: %d", r.code)
	}
	if n := strings.Count(w.logs.String(), "second software list from one source address"); n != 1 {
		t.Fatalf("%d warnings in one window, want 1", n)
	}
	w.clock.Advance(90 * time.Second) // the log bucket is free again, the replace window is not
	if r := send(13); r.code != 200 {
		t.Fatalf("log after the bucket emptied: %d", r.code)
	}
	if got := products(); len(got) != 1 || got[0] != "pkg-0" {
		t.Fatalf("software inside the window: %v", got)
	}
	w.clock.Advance(6 * time.Minute)
	send(14)
	if got := products(); len(got) != 1 || got[0] != "pkg-14" {
		t.Fatalf("software after the window: %v", got)
	}
	if strings.Contains(w.logs.String(), "pkg-1") {
		t.Fatal("a package list reached the log")
	}
}

// SYS-4: nothing secret reaches the server log or the audit during a whole life of a node, including the refusals.
func TestContract_SYS4_NoSecretInLogsOrAudit(t *testing.T) {
	w := newWorld(t)
	id, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	w.post("/intake/osquery/log", "192.0.2.77", fullLog(key)) // refused: another address
	w.post("/intake/osquery/enroll", peerA, enrollBody(secret+"x", "h"))
	w.post("/intake/osquery/status", peerA, nil, "Authorization", "Bearer "+secret)
	bogus := strings.Repeat("Z", 43)
	w.post("/intake/osquery/config", peerA, map[string]any{"node_key": bogus})
	if err := w.svc.RevokeToken(t.Context(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	w.assertNowhere(secret)
	w.assertNowhere(key)
	w.assertNowhere(bogus)
	if !strings.Contains(w.logs.String(), "credential refused") {
		t.Fatal("a refused credential leaves no log line")
	}
}
