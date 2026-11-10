package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

// moduleSchema reads every table of a database with every wired module's migrations, found in sqlite_master.
func moduleSchema(t *testing.T) map[string][][2]string {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrateAll(ctx, db, wiredModules()); err != nil {
		t.Fatal(err)
	}
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
	return out
}

// The export leaves out secrets by a rule on names (core.ExportColumnSkipped), so a module that adds a column is covered without
// anyone remembering. This test lists, for the schema of every wired module, what the rule leaves out and fails when a column
// that looks like a secret by a stricter test of its own is exported: whoever adds such a column must decide here, in review.
func TestExport_PolicyCoversEverySchemaColumn(t *testing.T) {
	t.Parallel()
	schema := moduleSchema(t)
	looksSecret := regexp.MustCompile(`(?i)secret|passw|token|nonce|cipher|totp|csrf|salt|credential|private|api_?key|hash|seed`)
	// Names that look like secrets and are not: the hash chain of the audit logs, key fingerprints and key counters, ids of other rows,
	// the last four characters, a pinned public fingerprint, the name of an authentication header, and the like.
	publicByDecision := map[string]bool{
		"core_audit.prev_hash": true, "core_audit.hash": true, "core_chain_anchor.last_pruned_hash": true, "core_chain_head.last_hash": true,
		"resp_log.prev_hash": true, "resp_log.hash": true, "hp_hits.token_id": true,
	}
	var skipped []string
	for tbl, cols := range schema {
		if core.ExportTableSkipped(tbl) {
			continue
		}
		for _, c := range cols {
			id := tbl + "." + c[0]
			switch {
			case core.ExportColumnSkipped(c[0], c[1]):
				skipped = append(skipped, id)
			case looksSecret.MatchString(c[0]) && !publicByDecision[id] && !strings.HasSuffix(c[0], "_last4"):
				t.Errorf("column %s looks like a secret and is exported: leave it out in core.ExportColumnSkipped, or list it in publicByDecision with the reason", id)
			}
		}
	}
	slices.Sort(skipped)
	want := []string{
		"ai_profile.secret_id", "core_connection.secret_id", "core_user.password_hash", "exp_target.token", "feeds_source.secret_id",
		"hp_tokens.secret_id", "notify_channel.app_token_secret_id", "notify_channel.bot_token_secret_id", "notify_channel.secret_id",
		"resp_blocklist.secret_id", "resp_blocklist.token_hash",
	}
	if !slices.Equal(skipped, want) {
		t.Errorf("columns left out of the export:\n got %q\nwant %q", skipped, want)
	}
	var tablesOut []string
	for tbl := range schema {
		if core.ExportTableSkipped(tbl) {
			tablesOut = append(tablesOut, tbl)
		}
	}
	slices.Sort(tablesOut)
	wantTables := []string{"core_email_code", "core_email_code_send", "core_secret", "core_sensor_cert", "core_session", "core_user_totp", "notify_tg_button", "resp_tokens"}
	if !slices.Equal(tablesOut, wantTables) {
		t.Errorf("tables left out of the export:\n got %q\nwant %q", tablesOut, wantTables)
	}
	for _, name := range wantTables {
		if _, ok := schema[name]; !ok {
			t.Errorf("the policy names a table that no module creates: %s", name)
		}
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
	args := []string{"-db", db, "-key", key, "-listen", "127.0.0.1:0"}

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
		case <-time.After(30 * time.Second):
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
	call := func(method, path string, body any) (int, []byte, http.Header) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+"/api/v1"+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		if c, ok := cookies[auth.CookieCSRF]; ok {
			req.Header.Set(auth.HeaderCSRF, c.Value)
		}
		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
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

	code := setupCode(lines)
	setup := map[string]any{"setup_code": code, "org": "Acme Co", "admin": map[string]any{"name": "Ann", "email": "ann@acme.example", "password": "correct horse battery staple"},
		"lan": []string{"192.168.10.0/24"}, "bundle": "smb", "commitment": true}
	if c, b, _ := call("POST", "/core/setup", setup); c != 200 {
		t.Fatalf("setup = %d %s", c, b)
	}
	logsDB := filepath.Join(dir, "logs.db")
	snap := filepath.Join(dir, "snapshots", "0123456789abcdef0123456789abcdef")
	for _, p := range []string{logsDB, logsDB + "-wal", logsDB + "-shm", filepath.Join(snap, "vedette.db")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
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
	if c, b, _ := call("POST", "/core/data/purge", map[string]any{"confirm": "acme co"}); c != 400 || !strings.Contains(string(b), `"confirm_mismatch"`) {
		t.Fatalf("wrong name = %d %s", c, b)
	}
	if !fileExists(logsDB) {
		t.Fatal("a refused purge removed logs.db")
	}

	c, b, _ = call("POST", "/core/data/purge", map[string]any{"confirm": "Acme Co"})
	if c != 200 || !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), `"core_user":1`) {
		t.Fatalf("purge = %d %s", c, b)
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
	newCode := setupCode(lines)
	if newCode == "" || newCode == code {
		t.Errorf("setup code after the purge = %q (before %q)", newCode, code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the process stopped with %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the process did not stop itself after the purge")
	}

	// Every table of every module is what a freshly migrated database has (its seed rows), plus the purge's own audit row and chain head,
	// the new setup code, and one row per module.
	fresh := rowCounts(t, filepath.Join(t.TempDir(), "fresh.db"), true)
	got := rowCounts(t, db, false)
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
	fresh["core_audit"], fresh["core_chain_head"], fresh["core_secret"], fresh["core_module"] = 1, 1, 1, nMods
	for tbl, n := range got {
		// The scheduler keeps running until the process stops half a second later, and records the runs that end in that time (D-154).
		if tbl == "core_job_run" {
			continue
		}
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
	setup["setup_code"] = code2
	if c, b, _ := call("POST", "/core/setup", setup); c != 200 {
		t.Fatalf("setup on the purged box = %d %s", c, b)
	}
	if c, b, _ := call("GET", "/me", nil); c != 200 || !strings.Contains(string(b), "ann@acme.example") {
		t.Fatalf("GET /me after the second setup = %d %s", c, b)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

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
