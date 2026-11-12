package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// moduleSchema reads every table of a database with every wired module's migrations, found in sqlite_master.
func moduleSchema(t *testing.T) map[string][][2]string {
	t.Helper()
	ctx := t.Context()
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rows, err := db.Reader().QueryContext(ctx, `SELECT m.name, p.name, p.type FROM sqlite_master m, pragma_table_info(m.name) p
		WHERE m.type = 'table' AND m.name NOT GLOB 'sqlite_*' AND m.name NOT GLOB 'core_migration_*' ORDER BY m.name, p.cid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][][2]string{}
	for rows.Next() {
		var tbl, col, typ string
		if err := rows.Scan(&tbl, &col, &typ); err != nil {
			t.Fatal(err)
		}
		out[tbl] = append(out[tbl], [2]string{col, typ})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// A full-text index (FTS5, ai_knowledge_chunk_fts) is a virtual table with shadow tables of its own (<name>_data, _idx, _docsize,
	// _config). It holds nothing that its content table does not, and the content table is classified: the index is never exported.
	virt, err := db.Reader().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = virt.Close() }()
	for virt.Next() {
		var v string
		if err := virt.Scan(&v); err != nil {
			t.Fatal(err)
		}
		for tbl := range out {
			if tbl == v || strings.HasPrefix(tbl, v+"_") {
				delete(out, tbl)
			}
		}
	}
	if err := virt.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// M4, enforced by CI: every table.column of every migration of every module (core included) is classified in the export policy
// (modules/core/export_policy.go: export, json, jsonurl, url or skip). A new column fails this test until someone classifies it, in
// review; a column that does not exist any more fails too, so the policy cannot rot. Columns classified as plain "export" or "url"
// that look like a secret by a stricter test of this file must be listed in publicByDecision with a reason: JSON columns are scrubbed
// of secret-looking keys, so they are exempt.
func TestExport_PolicyClassifiesEveryColumn(t *testing.T) {
	t.Parallel()
	schema := moduleSchema(t)
	// Every migration directory on disk is a wired one, so moduleSchema sees all of them.
	wired := map[string]bool{}
	for _, w := range wiredModules() {
		if w.Migrations != nil {
			wired[w.ID] = true
		}
	}
	dirs, err := filepath.Glob("../../modules/*/migrations/sqlite")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no migration directories found: %v", err)
	}
	for _, d := range dirs {
		if id := filepath.Base(filepath.Dir(filepath.Dir(d))); !wired[id] {
			t.Errorf("module %s has migrations but is not in wiredModules: its tables would escape the export policy", id)
		}
	}
	known := map[string]bool{}
	for _, tbl := range core.ExportTables() {
		known[tbl] = true
		if _, ok := schema[tbl]; !ok {
			t.Errorf("the export policy lists the table %s, which no migration creates", tbl)
		}
	}
	looksSecret := regexp.MustCompile(`(?i)secret|passw|token|nonce|cipher|totp|csrf|salt|credential|private|api_?key|hash|seed`)
	// Names that look like secrets and are not: the hash chain of the audit logs (the file verifies offline), the id of a honeytoken row.
	publicByDecision := map[string]bool{
		"core_audit.prev_hash": true, "core_audit.hash": true, "core_chain_anchor.last_pruned_hash": true, "core_chain_head.last_hash": true,
		"resp_log.prev_hash": true, "resp_log.hash": true, "hp_hits.token_id": true,
		// The id of the enrolment token a node belongs to (a row id, not the secret; the token's own hash is skipped).
		"intake_osquery_nodes.token_id": true,
		// The hash chain of the AI activity log (verifiable offline) and the hash of the inputs an AI result was made from: digests, not secrets.
		"ai_activity.prev_hash": true, "ai_activity.hash": true, "ai_activity.input_hash": true, "ai_activity.output_hash": true, "ai_result.inputs_hash": true,
		// Counts of tokens used (the log export keeps them too), not tokens as in credentials.
		"ai_activity.tokens_in": true, "ai_activity.tokens_out": true, "ai_result.tokens_in": true, "ai_result.tokens_out": true,
	}
	for tbl, cols := range schema {
		if !known[tbl] {
			t.Errorf("table %s is not in the export policy: classify every column of it in modules/core/export_policy.go", tbl)
			continue
		}
		inSchema := map[string]bool{}
		for _, c := range cols {
			inSchema[c[0]] = true
			id := tbl + "." + c[0]
			class := core.ExportColumnClass(tbl, c[0])
			switch {
			case class == "":
				t.Errorf("column %s is not classified in the export policy (modules/core/export_policy.go)", id)
			case (class == "export" || class == "url") && looksSecret.MatchString(c[0]) && !publicByDecision[id] && !strings.HasSuffix(c[0], "_last4"):
				t.Errorf("column %s looks like a secret and is exported as %q: skip it, or list it in publicByDecision with the reason", id, class)
			}
			if strings.Contains(strings.ToUpper(c[1]), "BLOB") && class != "skip" {
				t.Errorf("column %s holds bytes and is classified %q; bytes are never exported: skip it", id, class)
			}
		}
		for _, c := range core.ExportPolicyColumns(tbl) {
			if !inSchema[c] {
				t.Errorf("the export policy lists %s.%s, which no migration creates", tbl, c)
			}
		}
	}
	// The whole-skipped tables are the ones that only hold secrets or sign-in state; this list changes only on purpose.
	var skipAll []string
	for tbl := range schema {
		cols := schema[tbl]
		all := true
		for _, c := range cols {
			if core.ExportColumnClass(tbl, c[0]) != "skip" {
				all = false
			}
		}
		if all {
			skipAll = append(skipAll, tbl)
		}
	}
	slices.Sort(skipAll)
	want := []string{"ai_memory_rejected", "core_email_code", "core_email_code_send", "core_secret", "core_sensor_cert", "core_session", "core_user_totp", "notify_slack_button", "notify_slack_final", "notify_slack_team", "notify_tg_button", "oidc_flow", "resp_link_codes", "resp_tokens"}
	if !slices.Equal(skipAll, want) {
		t.Errorf("tables left out of the export whole:\n got %q\nwant %q", skipAll, want)
	}
}

// The real process, end to end: first-run setup over HTTP, data and files next to the database, the export, then the purge. After it
// the module data file, its sidecars and the snapshots are gone, the key and the certificate are not, the session is over, the setup
// code is in the log again, and the process has stopped by itself so that its supervisor starts a fresh one; a second start on the
// same files comes up in first-run setup.
func TestRunPurgeBringsBackAFreshBoxAndStops(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, key := filepath.Join(dir, "vedette.db"), filepath.Join(dir, "vedette.key")
	args := []string{"-db", db, "-key", key, "-listen", "127.0.0.1:0", "-honeypot-dir", filepath.Join(dir, "hp"), "-host-socket", ""}

	boot := func() (addr string, lines <-chan string, done <-chan error, stop func()) {
		ctx, cancel := context.WithCancel(t.Context())
		pr, pw := io.Pipe()
		d := make(chan error, 1)
		go func() { d <- run(ctx, args, io.Discard, pw); _ = pw.Close() }()
		ch := make(chan string, 1024)
		ready := make(chan string, 1)
		go func() {
			sc := bufio.NewScanner(pr)
			for sc.Scan() {
				ch <- sc.Text()
				var l struct{ Msg, Addr string }
				if json.Unmarshal(sc.Bytes(), &l) == nil && l.Msg == "listening" {
					ready <- l.Addr
				}
			}
			close(ch)
		}()
		select {
		case addr = <-ready:
		case <-time.After(90 * time.Second):
			cancel()
			t.Fatal("the process did not start")
		}
		return addr, ch, d, cancel
	}
	setupCode := func(lines <-chan string) string {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatal("log ended without a setup code")
				}
				var e struct {
					Code string `json:"setup_code"`
				}
				if json.Unmarshal([]byte(l), &e) == nil && e.Code != "" {
					return e.Code
				}
			case <-deadline:
				t.Fatal("no setup code in the log")
			}
		}
	}

	addr, lines, done, stop := boot()
	defer stop()
	cookies := map[string]*http.Cookie{}
	// call retries a 503 server_busy (nothing was written: the writer or the password-check queue was full) after its Retry-After, as the GUI
	// does, for at most about 30 s: under a loaded machine the write wait limit (D-246) can fire before this request gets the writer (#320).
	call := func(method, path string, body any) (int, []byte, http.Header) {
		t.Helper()
		var payload []byte
		if body != nil {
			payload, _ = json.Marshal(body)
		}
		deadline := time.Now().Add(90 * time.Second)
		for {
			c, b, hd := callOnce(t, cookies, addr, method, path, payload)
			if c != http.StatusServiceUnavailable || !strings.Contains(string(b), `"server_busy"`) {
				return c, b, hd
			}
			wait := time.Second
			if s, err := strconv.Atoi(hd.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			if time.Now().Add(wait).After(deadline) {
				return c, b, hd
			}
			select {
			case <-t.Context().Done():
				return c, b, hd
			case <-time.After(wait):
			}
		}
	}

	code := setupCode(lines)
	setup := map[string]any{"setup_code": code, "org": "Acme Co", "admin": map[string]any{"name": "Ann", "email": "ann@acme.example", "password": "correct horse battery staple"},
		"lan": []string{"192.168.10.0/24"}, "bundle": "smb", "commitment": true}
	if c, b, _ := call("POST", "/core/setup", setup); c != 200 {
		t.Fatalf("setup = %d %s", c, b)
	}
	// #350: the wizard's range and commitment are the inventory's scope (Devices -> Scope and sensors) in the real process.
	if c, b, _ := call("GET", "/inventory/settings", nil); c != 200 || !strings.Contains(string(b), `"lan_ranges":["192.168.10.0/24"]`) ||
		!strings.Contains(string(b), `"scope_confirmed_by":"ann@acme.example"`) {
		t.Fatalf("inventory settings after setup = %d %s", c, b)
	}
	logsDB := filepath.Join(dir, "logs.db") // the real volume of the logs module, open in the process (not a planted file)
	snap := filepath.Join(dir, "snapshots", "0123456789abcdef0123456789abcdef")
	for _, p := range []string{filepath.Join(snap, "vedette.db")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A received log line in the live logs.db, written through a second handle (the process has its own): after the purge and the restart it
	// must be gone, and nothing the process ingests after the commit may be read back as live.
	side, err := store.Open(t.Context(), logsDB, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := side.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_events (ts, source_id, line) VALUES ('2026-11-09T08:00:00.000Z', 'src-1', 'a received line')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := side.Close(); err != nil {
		t.Fatal(err)
	}

	// The export of the real box: every module's tables, and none of the secret ones.
	c, b, hd := call("GET", "/core/data/export", nil)
	var doc struct {
		Tables    map[string][]map[string]any `json:"tables"`
		Truncated bool                        `json:"truncated"`
	}
	if c != 200 || json.Unmarshal(b, &doc) != nil || doc.Truncated || !strings.HasPrefix(hd.Get("Content-Disposition"), "attachment; filename=vedette-export-") {
		t.Fatalf("export = %d %.200s %v", c, b, hd)
	}
	if len(doc.Tables["core_user"]) != 1 || doc.Tables["core_user"][0]["email"] != "ann@acme.example" || len(doc.Tables["feeds_source"]) == 0 {
		t.Errorf("export tables: %d users", len(doc.Tables["core_user"]))
	}
	for _, name := range []string{"core_secret", "core_session"} {
		if _, has := doc.Tables[name]; has {
			t.Errorf("%s is in the export", name)
		}
	}
	for _, secret := range []string{"correct horse battery staple", cookies[auth.CookieSession].Value, cookies[auth.CookieCSRF].Value, "$argon2"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("the export holds %.10q", secret)
		}
	}

	// A wrong name changes nothing.
	const adminPassword = "correct horse battery staple"
	if c, b, _ := call("POST", "/core/data/purge", map[string]any{"confirm": "acme co", "password": adminPassword}); c != 400 || !strings.Contains(string(b), `"confirm_mismatch"`) {
		t.Fatalf("wrong name = %d %s", c, b)
	}
	// H2: the right name is not enough, the current password is needed too (a stolen session cannot wipe the box).
	if c, b, _ := call("POST", "/core/data/purge", map[string]any{"confirm": "Acme Co", "password": "not the password"}); c != 400 || !strings.Contains(string(b), `"wrong_password"`) {
		t.Fatalf("wrong password = %d %s", c, b)
	}
	if c, _, _ := call("POST", "/core/data/purge", map[string]any{"confirm": "Acme Co"}); c != 400 {
		t.Fatalf("no password = %d, want 400", c)
	}
	if !fileExists(logsDB) {
		t.Fatal("a refused purge removed logs.db")
	}
	// N2: the honeypot's raw log stays (core mounts it read-only and must not write it) and so does the row that holds the read position in it,
	// so the fresh box does not read the old events as new. Plant both through a second handle on the live database.
	hpLog := filepath.Join(dir, "hp", HoneypotLogDir, "opencanary.jsonl")
	if err := os.MkdirAll(filepath.Dir(hpLog), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hpLog, []byte(`{"logtype":4000}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(hpLog), 0o500); err != nil { //nolint:gosec // a directory of this test; read-only for everyone, like the container mount
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(hpLog), 0o700) }) //nolint:gosec // a directory of this test
	// The running honeypot module reads the line and stores its position (offset 17: the bytes of the line); wait for that.
	var tailValue string
	for range 100 {
		if tailValue = rowValue(t, db, `SELECT value FROM hp_config WHERE key = 'tail'`); strings.Contains(tailValue, `"offset":17`) {
			break
		}
		select {
		case <-t.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !strings.Contains(tailValue, `"offset":17`) {
		t.Fatalf("the honeypot did not read the planted log line: tail = %q", tailValue)
	}
	// One more line, written just before the purge and not waited for: the purge must read it itself before it wipes.
	f, err := os.OpenFile(hpLog, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // a path of this test's own temp directory
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"logtype":4000}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(key) //nolint:gosec // a path of this test's own temp directory
	if err != nil {
		t.Fatal(err)
	}

	c, b, _ = call("POST", "/core/data/purge", map[string]any{"confirm": "Acme Co", "password": adminPassword})
	if c != 200 || !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), `"core_user":1`) || !strings.Contains(string(b), `"kept":["host_backups","honeypot_log"]`) {
		t.Fatalf("purge = %d %s (a box without a helper says so in kept)", c, b)
	}
	// H1 (a): the key file is replaced (same mode, nothing staged left), so any old copy opens nothing this box holds.
	if keyAfter, err := os.ReadFile(key); err != nil || len(keyAfter) != len(keyBefore) || bytes.Equal(keyAfter, keyBefore) { //nolint:gosec // a path of this test's own temp directory
		t.Errorf("the key was not replaced: %v", err)
	}
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != 0o600 || fileExists(key+".new") {
		t.Errorf("the new key file: %v %v", info, err)
	}
	for _, p := range []string{logsDB, logsDB + "-wal", logsDB + "-shm", filepath.Join(dir, "snapshots")} {
		if fileExists(p) {
			t.Errorf("%s survived the purge", p)
		}
	}
	for _, p := range []string{db, key} {
		if !fileExists(p) {
			t.Errorf("%s was removed by the purge", p)
		}
	}
	if len(cookies) != 0 {
		t.Errorf("cookies after the purge: %v", cookies)
	}
	if c, _, _ := call("GET", "/me", nil); c != 401 {
		t.Errorf("GET /me after the purge = %d", c)
	}
	if c, b, _ := call("GET", "/setup", nil); c != 200 || !strings.Contains(string(b), `"complete":false`) {
		t.Errorf("GET /setup after the purge = %d %s", c, b)
	}
	if !fileExists(filepath.Join(dir, "purge-compact-pending")) {
		t.Error("no marker for the compaction at the next start")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the process stopped with %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the process did not stop itself after the purge")
	}

	// Every table of every module is what a freshly migrated database has (its seed rows), plus the purge's own audit row and chain head,
	// and one row per module. Nothing else: the database is frozen at the commit (M5), so no job writes a row before the process stops,
	// and the setup code is made by the next start.
	fresh := rowCounts(t, filepath.Join(t.TempDir(), "fresh.db"), true)
	got := rowCounts(t, db, false)
	if b, err := os.ReadFile(hpLog); err != nil || string(b) != strings.Repeat(`{"logtype":4000}`+"\n", 2) { //nolint:gosec // a path of this test's own temp directory
		t.Errorf("the honeypot log was touched by the purge: %q %v", b, err)
	}
	// The line written just before the purge was read by the purge itself (L2): the kept position is past it (offset 34 = both lines).
	if kept := rowValue(t, db, `SELECT value FROM hp_config WHERE key = 'tail'`); !strings.Contains(kept, `"offset":34`) {
		t.Errorf("the honeypot read position after the purge = %q, want it kept past both lines (offset 34)", kept)
	}
	mans, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	nMods := 0
	for _, m := range mans {
		if !m.Component {
			nMods++
		}
	}
	fresh["core_audit"], fresh["core_chain_head"], fresh["core_module"], fresh["hp_config"] = 1, 1, nMods, 1 // hp_config: the read position of the honeypot log, kept
	for tbl, n := range got {
		if n != fresh[tbl] {
			t.Errorf("table %s has %d rows after the purge, a fresh box has %d", tbl, n, fresh[tbl])
		}
	}
	if len(got) != len(fresh) {
		t.Errorf("%d tables after the purge, %d in a fresh box", len(got), len(fresh))
	}

	// The supervisor starts it again: the same files, a fresh box, first-run setup open.
	addr2, lines2, _, stop2 := boot()
	defer stop2()
	addr = addr2
	if c, b, _ := call("GET", "/setup", nil); c != 200 || !strings.Contains(string(b), `"complete":false`) {
		t.Fatalf("GET /setup after the restart = %d %s", c, b)
	}
	code2 := setupCode(lines2)
	if n := rowValue(t, logsDB, `SELECT count(*) FROM logs_events`); n != "0" {
		t.Errorf("the fresh logs.db holds %s lines after the restart, want none", n)
	}
	if code2 == "" || code2 == code {
		t.Errorf("setup code after the restart = %q (before the purge %q)", code2, code)
	}
	if fileExists(filepath.Join(dir, "purge-compact-pending")) {
		t.Error("the compaction marker is still there after the restart")
	}
	setup["setup_code"] = code2
	if c, b, _ := call("POST", "/core/setup", setup); c != 200 {
		t.Fatalf("setup on the purged box = %d %s", c, b)
	}
	if c, b, _ := call("GET", "/me", nil); c != 200 || !strings.Contains(string(b), "ann@acme.example") {
		t.Fatalf("GET /me after the second setup = %d %s", c, b)
	}
}

// M4: secrets are planted in every secret-bearing table and column of the real schema (all modules), and inside JSON columns at several
// depths, then the export of a real signed-in administrator is searched for them. Every planted secret contains "PLANT", and no value
// that is meant to be exported does, so one search covers them all; the values that must survive are checked too.
func TestExport_PlantedSecretsNeverLeave(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := newStack(t)
	api, err := server.New(server.Config{API: newHandler(*s.d), Auth: s.d.Auth.Sessions, Modules: s.d.Reg, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	cookies := map[string]*http.Cookie{}
	call := func(method, path string, body any) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req := httptest.NewRequestWithContext(ctx, method, server.Prefix+path, rd)
		req.RemoteAddr, req.Host = "192.0.2.10:40000", "box.test"
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if c, ok := cookies[auth.CookieCSRF]; ok {
			req.Header.Set(auth.HeaderCSRF, c.Value)
		}
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			cookies[c.Name] = c
		}
		return rec.Code, rec.Body.String()
	}
	code, err := s.d.Core.EnsureSetupCode(ctx)
	if err != nil || code == "" {
		t.Fatalf("setup code: %q %v", code, err)
	}
	if c, b := call("POST", "/core/setup", map[string]any{"setup_code": code, "org": "Acme Co", "admin": map[string]any{"name": "Ann", "email": "ann@acme.example", "password": "correct horse battery staple"},
		"lan": []string{"192.168.10.0/24"}, "bundle": "smb", "commitment": true}); c != 200 {
		t.Fatalf("setup = %d %s", c, b)
	}

	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{"PRAGMA defer_foreign_keys = ON", "PRAGMA ignore_check_constraints = ON"} { // the planted rows need not satisfy the formats of the real ones
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		sealed, _, err := s.d.Secrets.Seal(ctx, tx, "test_plant", []byte("PLANT-SEALED-PLAINTEXT"), true)
		if err != nil {
			return err
		}
		const ts = "2026-11-09T08:00:00.000Z"
		for _, st := range []struct {
			q    string
			args []any
		}{
			{`INSERT INTO notify_channel (type, updated_at, configured, fields, secret_id, secret_last4, bot_token_secret_id, app_token_secret_id) VALUES ('slack', ?, 1, ?, ?, 'wxyz', ?, ?)`,
				[]any{ts, `{"url":"https://hooks.slack.com/services/T0/B0/PLANT-SLACK-PATH","channel":"#ops","token":"PLANT-FIELDS-TOKEN","nested":{"password":"PLANT-NESTED-PW","note":"fine-note"},"inner":"{\"api_key\":\"PLANT-STRING-JSON\"}"}`, sealed, sealed, sealed}},
			{`INSERT INTO notify_channel (type, updated_at, configured, fields) VALUES ('webhook', ?, 1, ?)`,
				[]any{ts, `{"url":"https://user:PLANT-USERINFO@hooks.example.com:8443/path/PLANT-PATH?sig=PLANT-QUERY"}`}},
			{`INSERT INTO ai_profile (id, name, name_key, kind, api_style, base_url, model, secret_id, key_last4, location, daily_cap, created_at, updated_at) VALUES ('ai1', 'Main', 'main', 'cloud', 'openai', ?, 'm', ?, 'abcd', 'cloud', 1, ?, ?)`,
				[]any{"https://user:PLANT-AIURLPW@api.example.com/v1/PLANT-AIPATH", sealed, ts, ts}},
			{`INSERT INTO resp_blocklist (id, token_hash, secret_id, token_last4) VALUES (1, 'PLANT-BLOCK-TOKENHASH', ?, 'abcd')`, []any{sealed}},
			{`INSERT INTO hp_tokens (id, type, name, value, plant_at, created_at, secret_id) VALUES ('t1', 'credential', 'decoy', 'decoyuser', ?, ?, ?)`, []any{ts, ts, sealed}},
			{`INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('e1', 'domain', 'example.com', 'PLANT-EXP-TOKEN', ?)`, []any{ts}},
			{`INSERT INTO notify_tg_button (request_id, nonce_hash, expires_at) VALUES ('r1', 'PLANT-NONCEHASH', ?)`, []any{ts}},
			{`INSERT INTO resp_tokens (token_hash, kind, action_id, user_id, address, channel, expires_at) VALUES ('PLANT-RESPTOKEN-HASH', 'approve', 'a1', 'u1', 'x', 'email', ?)`, []any{ts}},
			{`INSERT INTO core_email_code (user_id, code_hash, expires_at, sent_at) SELECT id, 'PLANT-CODEHASH', ?, ? FROM core_user LIMIT 1`, []any{ts, ts}},
			{`INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('plant.json', ?, ?, 'x')`, []any{`{"api_key":"PLANT-CORESETTING-KEY","ok":1,"deep":[{"secret":"PLANT-DEEP"}]}`, ts}},
			{`INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('plant', ?, ?, 'x')`, []any{`{"password":"PLANT-HP-PW","kept":"hp-kept"}`, ts}},
			{`INSERT INTO ai_setting (key, value, updated_at, updated_by) VALUES ('plant', ?, ?, 'x')`, []any{`{"apikey":"PLANT-AISET"}`, ts}},
			{`INSERT OR REPLACE INTO resp_settings (id, value, updated_at) VALUES (1, ?, ?)`, []any{`{"token":"PLANT-RESPSET"}`, ts}},
			{`INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('s1', 'incident', 'i1', 'slack', ?, ?, 1, 'w', 'l', ?)`,
				[]any{"https://hooks.slack.com/services/PLANT-TO-PATH", ts, `{"text":"hello","webhook":"PLANT-MSG-WEBHOOK","nested":[{"token":"PLANT-MSG-TOKEN"}]}`}},
			{`INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items, approvals) VALUES ('ra1', 'rule', 'p1', 'fw', 'Block', 'low', 'pending', ?, ?, 1, ?, ?)`,
				[]any{ts, ts, `[{"tool":"block","secret":"PLANT-ITEMS-SECRET","args":{"password":"PLANT-ITEMS-PW"}}]`, `[{"user":"u1","session":"PLANT-APPROVAL-SESSION"}]`}},
		} {
			if _, err := tx.ExecContext(ctx, st.q, st.args...); err != nil {
				return fmt.Errorf("%.60s: %w", st.q, err)
			}
		}
		_, err = tx.ExecContext(ctx, "PRAGMA ignore_check_constraints = OFF")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	c, body := call("GET", "/core/data/export", nil)
	if c != 200 {
		t.Fatalf("export = %d %.300s", c, body)
	}
	var doc struct {
		Tables    map[string][]map[string]any `json:"tables"`
		Truncated bool                        `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil || doc.Truncated {
		t.Fatalf("export is not whole JSON: %v", err)
	}
	if i := strings.Index(body, "PLANT"); i >= 0 {
		t.Errorf("a planted secret is in the export: ...%s...", body[max(0, i-60):min(len(body), i+60)])
	}
	secrets := []string{"correct horse battery staple", "$argon2"}
	for _, ck := range []string{auth.CookieSession, auth.CookieCSRF} {
		secrets = append(secrets, cookies[ck].Value)
	}
	for _, sct := range secrets {
		if strings.Contains(body, sct) {
			t.Errorf("the export holds %.10q", sct)
		}
	}
	// What is meant to be exported is there, and webhook addresses are cut to scheme and host.
	for _, want := range []string{`"#ops"`, `"fine-note"`, `"decoyuser"`, `"hp-kept"`, `"abcd"`, `"wxyz"`, `"ann@acme.example"`,
		`https://hooks.slack.com"`, `https://hooks.example.com:8443"`, `https://api.example.com"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the export lacks %s", want)
		}
	}
	for _, name := range []string{"core_secret", "core_session", "notify_tg_button", "resp_link_codes", "resp_tokens", "core_email_code"} {
		if _, has := doc.Tables[name]; has {
			t.Errorf("table %s is in the export", name)
		}
	}
}

// callOnce sends one API request with the test's cookies (and the CSRF header) and keeps the cookies the answer sets or clears.
func callOnce(t *testing.T, cookies map[string]*http.Cookie, addr, method, path string, payload []byte) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+"/api/v1"+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if c, ok := cookies[auth.CookieCSRF]; ok {
		req.Header.Set(auth.HeaderCSRF, c.Value)
	}
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(cookies, c.Name)
		} else {
			cookies[c.Name] = c
		}
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// rowValue reads one text value from the database at path ("" when there is no row).
func rowValue(t *testing.T, path, query string) string {
	t.Helper()
	db, err := store.Open(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v string
	if err := db.Reader().QueryRowContext(t.Context(), query).Scan(&v); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return v
}

// rowCounts counts the rows of every data table of the database at path, with the tables found in sqlite_master.
func rowCounts(t *testing.T, path string, migrate bool) map[string]int {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if migrate {
		if err := migrateAll(ctx, db, wiredModules()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Reader().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB 'core_migration_*'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	out := map[string]int{}
	for _, n := range names {
		var c int
		if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM "`+n+`"`).Scan(&c); err != nil {
			t.Fatal(err)
		}
		out[n] = c
	}
	return out
}
