package ai_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// Slice 4c of WP-25: the knowledge base (S-AI-7, INV-10, D-209). The GUI mock is the contract; the upload carries the file as base64.

const (
	mdFirewall = "# Firewall changes\n\nMọi thay đổi cấu hình tường lửa phải có phiếu duyệt. Tường lửa FortiGate đặt tại phòng server tầng 2.\n"
	mdBackup   = "# Backups\n\nBackups of the file server run every night at 01:00 to the NAS in the basement.\n"
)

func kbBody(name string, data []byte, jobs string) string {
	n, _ := json.Marshal(name)
	b := fmt.Sprintf(`{"name":%s,"size":%d,"content":%q`, n, len(data), base64.StdEncoding.EncodeToString(data))
	if jobs != "" {
		b += `,"jobs":` + jobs
	}
	return b + "}"
}

func (a *api) kbView() map[string]any { return a.want("GET", "/ai/knowledge", "admin", "", 200, "") }

// kbIndexProfile adds an internal profile and chooses it as the index profile.
func (a *api) kbIndexProfile() string {
	a.t.Helper()
	id := a.addProfile(internalBody("Local"))["id"].(string)
	a.want("PUT", "/ai/knowledge/settings", "admin", fmt.Sprintf(`{"index_profile":%q}`, id), 200, "")
	return id
}

// kbAdd uploads a document, waits until it is read and returns what the list shows for it.
func (a *api) kbAdd(name string, data []byte, jobs string) map[string]any {
	a.t.Helper()
	d := a.want("POST", "/ai/knowledge", "admin", kbBody(name, data, jobs), 200, "")
	a.svc.WaitIndexed()
	for _, it := range a.kbView()["items"].([]any) {
		if m := it.(map[string]any); m["id"] == d["id"] {
			return m
		}
	}
	a.t.Fatalf("%v is not in the list", d)
	return nil
}

func (a *api) count(q string) int {
	a.t.Helper()
	var n int
	if err := a.db.Reader().QueryRowContext(a.ctx(), q).Scan(&n); err != nil {
		a.t.Fatal(err)
	}
	return n
}

// kbRun runs one call of the job on the assigned profile and returns what the provider received.
func (a *api) kbRun(job ai.Job, question string) provider.Request {
	a.t.Helper()
	_, err := a.svc.RunJob(a.ctx(), ai.JobSpec{Job: job, Actor: "system", Task: "Do it.", Question: question,
		Data: []ai.DataBlock{{Kind: ai.DataLog, Source: "x", Text: "a log line"}}, Schema: &provider.Schema{Name: "s", JSON: []byte(`{"type":"object"}`)}, MaxTokens: 100})
	if err != nil {
		a.t.Fatal(err)
	}
	return a.fake.lastRequest(a.t)
}

func (a *api) assign(internalOnly bool, job ai.Job, primary, fallback string) {
	a.t.Helper()
	a.want("PUT", "/ai/assignments", "admin", assignBody(internalOnly, map[string][2]string{string(job): {primary, fallback}}), 200, "")
}

func docxOf(paragraphs ...string) []byte {
	var body strings.Builder
	for _, p := range paragraphs {
		body.WriteString("<w:p><w:r><w:t>" + p + "</w:t></w:r></w:p>")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/document.xml")
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`))
	_ = zw.Close()
	return buf.Bytes()
}

func TestKnowledgeRolesAndModuleGate(t *testing.T) {
	gate := servertest.NewGate()
	a := newAPIGate(t, gate)
	routes := [][2]string{{"GET", "/ai/knowledge"}, {"POST", "/ai/knowledge"}, {"PUT", "/ai/knowledge/kd-x"}, {"DELETE", "/ai/knowledge/kd-x"}, {"PUT", "/ai/knowledge/settings"}}
	for _, r := range routes {
		a.want(r[0], r[1], "", "{}", 401, "unauthenticated")
		for _, u := range []string{"viewer", "operator"} {
			a.want(r[0], r[1], u, "{}", 403, "forbidden")
		}
	}
	a.want("GET", "/ai/knowledge", "admin", "", 200, "")
	gate.Set("ai", false)
	for _, r := range routes {
		if status, _, body := a.do(r[0], r[1], "admin", "{}"); status != 404 {
			t.Errorf("%s %s with the module off = %d, want 404: %s", r[0], r[1], status, body)
		}
	}
	gate.Set("ai", true)
	a.want("GET", "/ai/knowledge", "admin", "", 200, "")
}

func TestContract_INV10_AddListEditDelete(t *testing.T) {
	a := newAPI(t)
	if v := a.kbView(); v["index_profile"] != nil || len(v["items"].([]any)) != 0 {
		t.Fatalf("empty view = %v", v)
	}
	a.want("POST", "/ai/knowledge", "admin", kbBody("firewall.md", []byte(mdFirewall), ""), 400, "no_index_profile")
	prof := a.kbIndexProfile()
	if v := a.kbView(); v["index_profile"] != prof {
		t.Fatalf("view = %v", v)
	}
	d := a.want("POST", "/ai/knowledge", "admin", kbBody("firewall.md", []byte(mdFirewall), ""), 200, "")
	id := d["id"].(string)
	if d["name"] != "firewall.md" || d["size"] != float64(len(mdFirewall)) || d["status"] != "uploading" || d["chunks"] != nil || d["uploaded_at"] == "" || id == "" {
		t.Fatalf("added = %v", d)
	}
	if jobs := d["jobs"].([]any); len(jobs) != 2 || jobs[0] != "explain-finding" || jobs[1] != "ask-my-data" {
		t.Fatalf("default jobs = %v", d["jobs"])
	}
	a.svc.WaitIndexed()
	got := a.kbView()["items"].([]any)[0].(map[string]any)
	if got["status"] != "ready" || got["chunks"] != float64(1) {
		t.Fatalf("after indexing = %v", got)
	}
	second := a.kbAdd("Backups notes.TXT", []byte(mdBackup), "[]")["id"].(string)
	if items := a.kbView()["items"].([]any); len(items) != 2 || items[0].(map[string]any)["id"] != second || len(items[0].(map[string]any)["jobs"].([]any)) != 0 {
		t.Fatalf("newest first, jobs [] kept: %v", items)
	}
	e := a.want("PUT", "/ai/knowledge/"+id, "admin", `{"jobs":["log-digest","log-digest","response-plan"]}`, 200, "")
	if jobs := e["jobs"].([]any); len(jobs) != 2 || jobs[0] != "log-digest" || e["status"] != "ready" {
		t.Fatalf("patched = %v", e)
	}
	a.want("PUT", "/ai/knowledge/"+id, "admin", `{"jobs":["not-a-job"]}`, 400, "invalid") // the schema answers first
	a.want("PUT", "/ai/knowledge/kd-missing", "admin", `{"jobs":[]}`, 404, "not_found")
	a.want("PUT", "/ai/knowledge/"+id, "admin", `{}`, 400, "")
	a.want("PUT", "/ai/knowledge/"+id, "admin", `{"jobs":[],"x":1}`, 400, "")
	a.svc = a.newService() // a restart loses nothing
	b := &api{env: a.env, h: a.handler(servertest.NewGate())}
	if items := b.kbView()["items"].([]any); len(items) != 2 {
		t.Fatalf("after a restart: %v", items)
	}
	if status, _, raw := b.do("DELETE", "/ai/knowledge/"+id, "admin", ""); status != 204 {
		t.Fatalf("delete = %d %s", status, raw)
	}
	b.want("DELETE", "/ai/knowledge/"+id, "admin", "", 404, "not_found")
	rows := strings.Join(b.auditRows(), "\n")
	for _, want := range []string{"ai.knowledge.index " + prof, "ai.knowledge.add firewall.md ", "ai.knowledge.indexed firewall.md 1 chunks", "ai.knowledge.jobs firewall.md", "ai.knowledge.remove firewall.md"} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %q: %s", want, rows)
		}
	}
	if strings.Contains(rows, "Tường") || strings.Contains(rows, "FortiGate") {
		t.Errorf("the audit rows carry the text of a document: %s", rows)
	}
}

func TestContract_INV10_UploadChecksInTheMocksOrder(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	ok := []byte("Some notes about the network.")
	long := strings.Repeat("a", 117) + ".txt"
	cases := []struct {
		name, body string
		code       string
	}{
		{"slash", kbBody("a/b.txt", ok, ""), "invalid_name"},
		{"backslash", kbBody(`a\b.txt`, ok, ""), "invalid_name"},
		{"too long", kbBody(long, ok, ""), "invalid"}, // the schema answers first
		{"invisible", kbBody("a\u202Eb.txt", ok, ""), "invalid_name"},
		{"type", kbBody("a.exe", ok, ""), "invalid_type"},
		{"no extension", kbBody("notes", ok, ""), "invalid_type"},
		{"empty", `{"name":"a.txt","size":0,"content":""}`, ""}, // 400 either from the schema or from the size check
		{"size mismatch", `{"name":"a.txt","size":5,"content":"` + base64.StdEncoding.EncodeToString(ok) + `"}`, "invalid_size"},
		{"not base64", `{"name":"a.txt","size":5,"content":"%%%%%"}`, "invalid_size"},
		{"too large", fmt.Sprintf(`{"name":"a.txt","size":%d,"content":"QQ=="}`, ai.MaxDocBytes+1), "too_large"},
		{"jobs", kbBody("a.txt", ok, `["nope"]`), "invalid"},
		{"pdf that is text", kbBody("a.pdf", ok, ""), "invalid_content"},
		{"PDF upper that is text", kbBody("A.PDF", []byte("%PD-1.4"), ""), "invalid_content"},
		{"fake docx", kbBody("a.docx", ok, ""), "invalid_content"},
		{"latin-1 text", kbBody("a.txt", []byte("caf\xe9 \xe0 la carte"), ""), "invalid_content"},
		{"nul text", kbBody("a.md", []byte("a\x00b"), ""), "invalid_content"},
		{"unknown field", `{"name":"a.txt","size":1,"content":"QQ==","extra":1}`, ""},
		{"no content", `{"name":"a.txt","size":1}`, ""},
	}
	for _, c := range cases {
		got, m, raw := a.do("POST", "/ai/knowledge", "admin", c.body)
		if got != 400 || (c.code != "" && errCode(m) != c.code) {
			t.Errorf("%s = %d %s (want 400 %s): %s", c.name, got, errCode(m), c.code, raw)
		}
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_doc`); n != 0 {
		t.Fatalf("%d documents were saved by refused uploads", n)
	}
	// a name is tidied; a UTF-16 text file with a byte order mark is fine
	a.kbAdd("  my   notes.txt ", ok, "")
	if items := a.kbView()["items"].([]any); items[0].(map[string]any)["name"] != "my notes.txt" {
		t.Fatalf("name = %v", items[0])
	}
	utf16 := append([]byte{0xFF, 0xFE}, []byte("N\x00o\x00t\x00e\x00s\x00")...)
	if d := a.kbAdd("u16.txt", utf16, ""); d["chunks"] != float64(1) {
		t.Fatalf("utf-16 text = %v", d)
	}
}

func TestContract_INV10_LimitOf50DocumentsAnd10MB(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	for i := range 50 {
		a.kbAdd(fmt.Sprintf("doc-%d.txt", i), []byte(fmt.Sprintf("Document number %d about the network.", i)), "")
	}
	a.want("POST", "/ai/knowledge", "admin", kbBody("one-more.txt", []byte("One more."), ""), 400, "too_many")
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_doc`); n != 50 {
		t.Fatalf("documents = %d", n)
	}
	// the database says it too (the second lock)
	if err := a.exec(`INSERT INTO ai_knowledge_doc (id, name, size, status, chunks, jobs, uploaded_at) VALUES ('kd-x', 'x.txt', 1, 'ready', 0, '[]', '2026-11-10T03:00:00.000Z')`); err == nil {
		t.Fatal("the 51st document got into the table")
	}
	a.want("DELETE", "/ai/knowledge/"+a.kbView()["items"].([]any)[0].(map[string]any)["id"].(string), "admin", "", 204, "")
	// a file of exactly 10 MB goes through the body limit; only 4 MB of its text is kept
	line := "The backup of the accounting share runs at night and is copied to the NAS.\n"
	big := []byte(strings.Repeat(line, ai.MaxDocBytes/len(line)+1)[:ai.MaxDocBytes])
	d := a.kbAdd("big.txt", big, "")
	bigID := d["id"].(string)
	if d["status"] != "ready" || d["chunks"].(float64) < 1000 || d["size"] != float64(ai.MaxDocBytes) {
		t.Fatalf("the big document = %v", d)
	}
	if rows := strings.Join(a.auditRows(), "\n"); !strings.Contains(rows, "only the first 4 MB of the text was kept") {
		t.Errorf("the cut is not in the audit: %s", rows)
	}
	if n := a.count(`SELECT COALESCE(SUM(length(text)), 0) FROM ai_knowledge_chunk WHERE doc_id = '` + bigID + `'`); n > 4<<20 {
		t.Fatalf("%d characters of text kept", n)
	}
	// more than the limit of the whole request is refused before it is read
	huge := fmt.Sprintf(`{"name":"huge.txt","size":%d,"content":%q}`, ai.MaxDocBytes, strings.Repeat("A", 16<<20))
	if status, _, _ := a.do("POST", "/ai/knowledge", "admin", huge); status != 413 {
		t.Fatalf("a body over the cap = %d, want 413", status)
	}
}

func TestContract_INV10_IndexProfileIsCheckedLikeTheMock(t *testing.T) {
	a := newAPI(t)
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"p-missing"}`, 400, "unknown_profile")
	local := a.addProfile(internalBody("Local"))["id"].(string)
	cloud := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+cloud+`"}`, 200, "") // the index is built on the box: a cloud profile is allowed while the rule is off
	if a.kbView()["index_profile"] != cloud {
		t.Fatal("not saved")
	}
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+local+`"}`, 200, "")
	if a.kbView()["index_profile"] != local {
		t.Fatal("not saved")
	}
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":null}`, 200, "")
	if a.kbView()["index_profile"] != nil {
		t.Fatal("not cleared")
	}
	a.want("PUT", "/ai/knowledge/settings", "admin", `{}`, 400, "")
	// INV-3: with the privacy rule on, only an internal profile
	a.want("PUT", "/ai/assignments", "admin", assignBody(true, map[string][2]string{}), 200, "")
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+cloud+`"}`, 400, "privacy_rule")
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+local+`"}`, 200, "")
	// a choice made while the rule was off stops counting once it is on
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{}), 200, "")
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+cloud+`"}`, 200, "")
	a.want("PUT", "/ai/assignments", "admin", assignBody(true, map[string][2]string{}), 200, "")
	if a.kbView()["index_profile"] != nil {
		t.Fatal("a cloud profile is shown as the index profile under the privacy rule")
	}
	a.want("POST", "/ai/knowledge", "admin", kbBody("a.txt", []byte("Some notes."), ""), 400, "no_index_profile")
	// a profile with no key cannot be chosen; a deleted one is shown as none
	a.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+local+`"}`, 200, "")
	a.want("DELETE", "/ai/profiles/"+local, "admin", "", 200, "")
	if a.kbView()["index_profile"] != nil {
		t.Fatal("a deleted profile is still shown")
	}
}

func TestContract_INV10_StatusesAreKeptWhileTheIndexerIsBusyAndARestartEndsThem(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	release := a.svc.HoldIndexer()
	d := a.want("POST", "/ai/knowledge", "admin", kbBody("waiting.md", []byte(mdBackup), ""), 200, "")
	if d["status"] != "uploading" {
		t.Fatalf("added = %v", d)
	}
	if it := a.kbView()["items"].([]any)[0].(map[string]any); it["status"] != "uploading" || it["chunks"] != nil {
		t.Fatalf("while waiting = %v", it)
	}
	// a second one sits in "indexing": the box restarts before it ends
	if err := a.exec(`INSERT INTO ai_knowledge_doc (id, name, size, status, chunks, jobs, uploaded_at) VALUES ('kd-cut', 'cut.pdf', 100, 'indexing', NULL, '[]', '2026-11-10T03:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	old := a.svc
	a.svc = a.newService() // the restart: nothing is waiting any more
	for _, it := range a.kbView()["items"].([]any) {
		m := it.(map[string]any)
		if m["status"] != "ready" || m["chunks"] != float64(0) {
			t.Errorf("after a restart %v", m)
		}
	}
	rows := strings.Join(a.auditRows(), "\n")
	if !strings.Contains(rows, "ai.knowledge.failed cut.pdf the box restarted") || !strings.Contains(rows, "ai.knowledge.failed waiting.md the box restarted") {
		t.Fatalf("audit = %s", rows)
	}
	release() // the old reader wakes up: its document was ended, so it keeps nothing
	old.WaitIndexed()
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk`); n != 0 {
		t.Fatalf("%d chunks were stored for a document the restart ended", n)
	}
}

func TestContract_INV10_TooManyWaitingUploadsAreRefused(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	release := a.svc.HoldIndexer()
	for i := range 4 {
		a.want("POST", "/ai/knowledge", "admin", kbBody(fmt.Sprintf("w%d.txt", i), []byte("Waiting notes."), ""), 200, "")
	}
	status, m, raw := a.do("POST", "/ai/knowledge", "admin", kbBody("w4.txt", []byte("Waiting notes."), ""))
	if status != 409 || errCode(m) != "busy" {
		t.Fatalf("fifth upload = %d %s", status, raw)
	}
	release()
	a.svc.WaitIndexed()
	a.want("POST", "/ai/knowledge", "admin", kbBody("w4.txt", []byte("Waiting notes."), ""), 200, "")
	a.svc.WaitIndexed()
}

func TestContract_INV10_ADocumentThatCannotBeReadIsReadyWithNoChunks(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	garbage := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{7}, 300)...)
	bad := a.kbAdd("broken.docx", garbage, "")
	if bad["status"] != "ready" || bad["chunks"] != float64(0) {
		t.Fatalf("broken docx = %v", bad)
	}
	empty := a.kbAdd("blank.md", []byte("   \n\n  \u200b\u200b "), "")
	if empty["status"] != "ready" || empty["chunks"] != float64(0) {
		t.Fatalf("blank text = %v", empty)
	}
	rows := strings.Join(a.auditRows(), "\n")
	for _, want := range []string{"ai.knowledge.failed broken.docx it could not be read", "ai.knowledge.failed blank.md no text was found"} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %q: %s", want, rows)
		}
	}
	if sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "network notes"); err != nil || sent != "" || len(used) != 0 {
		t.Fatalf("an unreadable document was retrieved: %q %v %v", sent, used, err)
	}
}

func TestContract_INV10_DeleteRemovesTheChunksAndTheIndex(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	id := a.kbAdd("backups.md", []byte(mdBackup), "")["id"].(string)
	keep := a.kbAdd("firewall.md", []byte(mdFirewall), "")["id"].(string)
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts WHERE ai_knowledge_chunk_fts MATCH 'basement'`); n != 1 {
		t.Fatalf("indexed rows = %d", n)
	}
	a.want("DELETE", "/ai/knowledge/"+id, "admin", "", 204, "")
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts WHERE ai_knowledge_chunk_fts MATCH 'basement'`); n != 0 {
		t.Fatalf("the index still finds a deleted document (%d)", n)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk WHERE doc_id = '` + id + `'`); n != 0 {
		t.Fatalf("%d chunks of a deleted document", n)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts WHERE ai_knowledge_chunk_fts MATCH 'tuong'`); n != 1 {
		t.Fatalf("the other document lost its index entries (%d)", n)
	}
	a.want("DELETE", "/ai/knowledge/"+keep, "admin", "", 204, "")
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts_docsize`); n != 0 {
		t.Fatalf("%d index rows are left", n)
	}
	// a document deleted while it waits is never stored
	release := a.svc.HoldIndexer()
	w := a.want("POST", "/ai/knowledge", "admin", kbBody("late.md", []byte(mdBackup), ""), 200, "")["id"].(string)
	a.want("DELETE", "/ai/knowledge/"+w, "admin", "", 204, "")
	release()
	a.svc.WaitIndexed()
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk`); n != 0 {
		t.Fatalf("%d chunks of a deleted upload", n)
	}
}

func TestContract_INV10_DocxIsReadAndOnlyTextIsKept(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	d := a.kbAdd("policy.docx", docxOf("Chính sách mật khẩu", "Passwords are changed every 90 days."), "")
	if d["chunks"] != float64(1) {
		t.Fatalf("docx = %v", d)
	}
	sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "mat khau passwords")
	if err != nil || len(used) != 1 || !strings.Contains(sent, "Passwords are changed every 90 days.") || !strings.Contains(sent, "Chính sách mật khẩu") {
		t.Fatalf("sent = %q %v %v", sent, used, err)
	}
	// the file itself is nowhere: no column of any table holds its bytes
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk WHERE text LIKE '%PK%' OR text LIKE '%w:document%'`); n != 0 {
		t.Fatal("markup of the file is in the chunks")
	}
}

func TestKnowledgeRetrievalFindsTheRightPieceWithAndWithoutDiacritics(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	fw := a.kbAdd("firewall.md", []byte(mdFirewall), "")["id"].(string)
	bk := a.kbAdd("backups.md", []byte(mdBackup), "")["id"].(string)
	for query, want := range map[string]string{
		"Tường lửa FortiGate":           fw,
		"tuong lua":                     fw,
		"TUONG LUA phong server":        fw,
		"đổi cấu hình tường lửa":        fw,
		"when do the backups run":       bk,
		"BACKUP nightly NAS basement":   bk,
		"the file server at 01:00 time": bk,
	} {
		sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, query)
		if err != nil || len(used) == 0 || !strings.HasPrefix(used[0], want+":") {
			t.Errorf("%q: used %v (%v), want %s first", query, used, err, want)
		}
		if len(used) > 0 && !strings.Contains(sent, "["+used[0]+"]") {
			t.Errorf("%q: the piece is not labelled with its id: %q", query, sent)
		}
	}
	for _, none := range []string{"", "   ", "zzzz qqqq", "!!! ??? ---", "a b c"} {
		if sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, none); err != nil || sent != "" || len(used) != 0 {
			t.Errorf("%q found %q %v %v", none, sent, used, err)
		}
	}
	// the best piece comes first; the pieces are capped
	var paras []string
	for i := range 30 {
		paras = append(paras, fmt.Sprintf("Paragraph %d about the camera VLAN. %s", i, strings.Repeat("filler text for the camera network ", 80)))
	}
	a.kbAdd("cameras.md", []byte(strings.Join(paras, "\n\n")), "")
	sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "camera VLAN")
	if err != nil || len(used) > 4 || len(sent) > 12000+4*100 {
		t.Fatalf("pieces = %d, %d characters (%v)", len(used), len(sent), err)
	}
}

func TestKnowledgeHostileSearchTextNeverBreaksACall(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	a.kbAdd("backups.md", []byte(mdBackup), "")
	for _, q := range []string{
		`NEAR(backups nightly, 3)`, `backups OR`, `"backups`, `backups" OR "`, `text:backups`, `{text}: backups`, `backups AND NOT nightly`,
		`backups*`, `^backups`, `(backups`, `backups)`, `-backups`, `backups NOT`, `NOT`, `OR OR OR`, `"" ""`, `ai_knowledge_chunk_fts:x`,
		`backups; DROP TABLE ai_knowledge_chunk; --`, "backups\x00nightly", "\xff\xfe backups", strings.Repeat("backups ", 5000), strings.Repeat("(", 2000),
		"co*lumn:backups", `"text" : "backups"`, `rank`, `bm25(ai_knowledge_chunk_fts)`,
	} {
		if _, _, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, q); err != nil {
			t.Errorf("%q made the call fail: %v", q, err)
		}
	}
	// operators in the text are words, not syntax: nothing but real words matches
	if _, used, _, _ := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, `NEAR(backups nightly) NOT basement`); len(used) != 1 {
		t.Errorf("operators in the text changed what matches: %v", used)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk`); n != 1 {
		t.Fatal("the table was changed")
	}
}

func TestKnowledgeIsOnlyForAssignedJobsThatCarryInternalData(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	a.kbAdd("only-explain.md", []byte("ONLYEXPLAIN notes about the router firmware."), `["explain-finding"]`)
	every := a.kbAdd("every-job.md", []byte("EVERYJOB notes about the router firmware."), "[]")["id"].(string)
	for _, c := range []struct {
		job     ai.Job
		onlyIn  bool
		everyIn bool
	}{
		{ai.JobExplainFinding, true, true},
		{ai.JobLogDigest, false, true},
		{ai.JobMitigationConfig, false, true},
		{ai.JobCVENews, false, false},           // public text: never
		{ai.JobTranslateAdvisory, false, false}, // public text: never
	} {
		sent, used, _, err := a.svc.KnowledgeForCall(a.ctx(), c.job, "router firmware")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(sent, "ONLYEXPLAIN"); got != c.onlyIn {
			t.Errorf("%s: only-explain used = %v (%v)", c.job, got, used)
		}
		if got := strings.Contains(sent, "EVERYJOB"); got != c.everyIn {
			t.Errorf("%s: every-job used = %v (%v)", c.job, got, used)
		}
	}
	// a real call: the text is a fenced data block of its own, never in the instructions
	id := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.fake.setAnswer(goodExplain)
	a.assign(false, ai.JobExplainFinding, id, "")
	req := a.kbRun(ai.JobExplainFinding, "Tell me about the router firmware.")
	user := req.Messages[0].Text
	at := strings.Index(user, "EVERYJOB")
	if at < 0 || strings.Contains(req.System, "EVERYJOB") || strings.Contains(req.System, "ONLYEXPLAIN") {
		t.Fatalf("knowledge missing from the data, or in the instructions:\n%s\n%s", req.System, user)
	}
	if open := strings.LastIndex(user[:at], "<<<DATA-"); open < 0 || !strings.Contains(user[open:at], "kind=document") || !strings.Contains(user[at:], "<<<END-DATA-") {
		t.Fatalf("not a fenced block of kind document: %s", user)
	}
	// a public-text job never gets it, though the document says "every job"
	a.assign(false, ai.JobCVENews, id, "")
	if user := a.kbRun(ai.JobCVENews, "router firmware").Messages[0].Text; strings.Contains(user, "EVERYJOB") || strings.Contains(user, "kind=document") {
		t.Fatalf("a public-text job carried a document: %s", user)
	}
	// a skill switched off: its job is refused and retrieves nothing
	a.want("PUT", "/ai/skills/explain-finding", "admin", `{"enabled":false}`, 200, "")
	if sent, used, _, _ := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "router firmware"); sent != "" || len(used) != 0 {
		t.Fatalf("a switched-off skill retrieved: %q", sent)
	}
	a.want("PUT", "/ai/skills/explain-finding", "admin", `{"enabled":true}`, 200, "")
	// not the document that is assigned to nobody
	a.want("PUT", "/ai/knowledge/"+every, "admin", `{"jobs":["weekly-report"]}`, 200, "")
	if sent, _, _, _ := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "router firmware"); strings.Contains(sent, "EVERYJOB") {
		t.Fatalf("a document is used by a job it was taken away from: %q", sent)
	}
}

func TestKnowledgePiecesGoThroughTheHooksOneByOne(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	pad := strings.Repeat("The gateway log shows the same login problem again. ", 40)
	text := "FIRSTPIECE router password policy. " + pad + "\n\nSECONDPIECE the router has the serial SERIAL-BLOCKME. " + pad + "\n\nTHIRDPIECE router contact is admin@example.com. " + pad
	a.kbAdd("router.md", []byte(text), "")
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk`); n < 3 {
		t.Fatalf("chunks = %d, the test needs three", n)
	}
	a.addBlockHook("Block serials", "before_ai", "SERIAL-BLOCKME")
	sent, used, left, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "router password serial contact")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sent, "SERIAL-BLOCKME") || strings.Contains(sent, "SECONDPIECE") || len(left) != 1 {
		t.Fatalf("the blocked piece was sent (left %v): %q", left, sent)
	}
	if !strings.Contains(sent, "FIRSTPIECE") || !strings.Contains(sent, "THIRDPIECE") || len(used) != 2 {
		t.Fatalf("the other pieces were not sent: %v %q", used, sent)
	}
	if strings.Contains(sent, "admin@example.com") || !strings.Contains(sent, "THIRDPIECE") {
		t.Fatalf("the email was not masked: %q", sent)
	}
	// the call runs; the row names the pieces by id, never by text
	id := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.fake.setAnswer(goodExplain)
	a.assign(false, ai.JobExplainFinding, id, "")
	req := a.kbRun(ai.JobExplainFinding, "router password serial contact")
	if user := req.Messages[0].Text; strings.Contains(user, "SERIAL-BLOCKME") || !strings.Contains(user, "FIRSTPIECE") {
		t.Fatalf("request = %s", user)
	}
	rows := a.activity()
	last := rows[len(rows)-1]
	if !strings.Contains(last.Summary, "knowledge used: ") || !strings.Contains(last.Summary, "knowledge left out because a hook stopped it: ") || strings.Contains(last.Summary, "FIRSTPIECE") || last.Result != ai.ResultOK {
		t.Fatalf("activity row = %+v", last.ActivityEntry)
	}
	if !strings.Contains(strings.Join(last.Hooks, ","), "Block serials") {
		t.Fatalf("hooks of the row = %v", last.Hooks)
	}
}

func TestContract_INV3_AFallbackInTheCloudNeverGetsTheDocuments(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile() // adds "Local"
	cloud := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	local := a.profileID("Local")
	a.kbAdd("backups.md", []byte(mdBackup), "")
	a.fake.setAnswer(goodExplain)
	a.fake.failWith("Local", &provider.Error{Kind: provider.ErrNetwork})
	// privacy rule off: the cloud profile may answer, with the documents (the same as any other internal data)
	a.assign(false, ai.JobExplainFinding, local, cloud)
	req := a.kbRun(ai.JobExplainFinding, "when do the backups run")
	if !strings.Contains(req.Messages[0].Text, "run every night") {
		t.Fatalf("the fallback did not get the documents with the rule off: %s", req.Messages[0].Text)
	}
	// privacy rule on: only the internal profile is assigned, and gets the documents; nothing goes to the cloud, even with it down
	a.fake.failWith("Local", nil)
	a.assign(true, ai.JobExplainFinding, local, "")
	before, local0 := a.fake.called("Claude"), a.fake.called("Local")
	if user := a.kbRun(ai.JobExplainFinding, "when do the backups run").Messages[0].Text; !strings.Contains(user, "run every night") {
		t.Fatalf("the internal profile did not get the documents: %s", user)
	}
	a.fake.failWith("Local", &provider.Error{Kind: provider.ErrNetwork})
	if _, err := a.svc.RunJob(a.ctx(), ai.JobSpec{Job: ai.JobExplainFinding, Actor: "system", Task: "x", Question: "when do the backups run", MaxTokens: 100}); err == nil {
		t.Fatal("the call went through with the local profile down")
	}
	if a.fake.called("Claude") != before || a.fake.called("Local") <= local0 {
		t.Fatal("a cloud profile was called with the privacy rule on, or the internal one was not")
	}
}

func TestExplainCacheKeyFollowsTheDocuments(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	id := a.addProfile(cloudBody("Claude", keyA))["id"].(string)
	a.fake.setAnswer(goodExplain)
	a.assign(false, ai.JobExplainFinding, id, "")
	got := a.explain("CVE-2022-27593", 200, "")
	if got["cached"] != false {
		t.Fatalf("first = %v", got)
	}
	calls := a.fake.total()
	if again := a.explain("CVE-2022-27593", 200, ""); again["cached"] != true || a.fake.total() != calls {
		t.Fatal("no cache with no documents")
	}
	// a document about the product the CVE is for: the answer is made again, then cached again
	doc := a.kbAdd("photo.md", []byte("The Photo Station runs on NAS-PHOTOS and is updated by the IT team on the first Monday."), `["explain-finding"]`)["id"].(string)
	if c := a.want("GET", "/ai/cve/CVE-2022-27593/cached", "viewer", "", 200, ""); c["explain"] != nil {
		t.Fatal("a cached explanation was served after a document was added")
	}
	made := a.explain("CVE-2022-27593", 200, "")
	if made["cached"] != false || a.fake.total() != calls+1 {
		t.Fatalf("not asked again: %v", made)
	}
	if user := a.fake.lastRequest(t).Messages[0].Text; !strings.Contains(user, "first Monday") {
		t.Fatalf("the document did not reach the explanation: %s", user)
	}
	if again := a.explain("CVE-2022-27593", 200, ""); again["cached"] != true {
		t.Fatal("not cached again")
	}
	rows := a.activity()
	if s := rows[len(rows)-1].Summary; !strings.Contains(s, "knowledge used: "+doc+":1") {
		t.Fatalf("the row does not name the piece: %s", s)
	}
	// changing which jobs use it, or deleting it, is a miss as well
	a.want("PUT", "/ai/knowledge/"+doc, "admin", `{"jobs":["log-digest"]}`, 200, "")
	if c := a.want("GET", "/ai/cve/CVE-2022-27593/cached", "viewer", "", 200, ""); c["explain"] == nil {
		// back to the state with no document: the first explanation is served again
		t.Fatal("the answer made without documents should be found again")
	}
}

func TestKnowledgePrivacyTextsSayWhatIsSent(t *testing.T) {
	// PRIVACY.md itself is not read here: scripts/ci lets a PR that only changes it skip the Go job (guard_test), so the
	// table text is checked in review; the GUI text below is what the Settings page shows.
	core, err := os.ReadFile("../../web/src/locales/en/core.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Privacy struct {
			Flow map[string]struct {
				What string `json:"what"`
			} `json:"flow"`
		} `json:"privacy"`
	}
	if err := json.Unmarshal(core, &doc); err != nil {
		t.Fatal(err)
	}
	what := doc.Privacy.Flow["3"].What
	for _, want := range []string{"knowledge base", "nothing is sent when one is added", "passages"} {
		if !strings.Contains(what, want) {
			t.Errorf("privacy.flow.3.what lacks %q", want)
		}
	}
}

// What core's "Delete all data" does to the full-text index: it empties the shadow tables of the virtual table as if they were
// data tables. Every insert after that fails with an FTS5 corruption error unless the module repairs the index.
func (a *api) purgeLikeCore() {
	a.t.Helper()
	for _, tbl := range []string{"ai_knowledge_chunk", "ai_knowledge_doc", "ai_knowledge_chunk_fts_data", "ai_knowledge_chunk_fts_idx", "ai_knowledge_chunk_fts_docsize", "ai_knowledge_chunk_fts_config"} {
		if err := a.exec("DELETE FROM " + tbl); err != nil {
			a.t.Fatalf("%s: %v", tbl, err)
		}
	}
}

func TestKnowledgeIndexHealsAfterAPurgeThatEmptiedItsShadowTables(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	a.kbAdd("backups.md", []byte(mdBackup), "")
	a.purgeLikeCore()
	d := a.kbAdd("firewall.md", []byte(mdFirewall), "")
	if d["chunks"] != float64(1) {
		t.Fatalf("the document after the purge = %v", d)
	}
	if n := a.count(`SELECT COUNT(*) FROM ai_knowledge_chunk_fts WHERE ai_knowledge_chunk_fts MATCH 'tuong'`); n != 1 {
		t.Fatalf("the index does not find the new document (%d)", n)
	}
	if _, used, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "tuong lua"); err != nil || len(used) != 1 {
		t.Fatalf("retrieval after the purge: %v %v", used, err)
	}
	// reading and deleting after a purge heal as well
	a.purgeLikeCore()
	if _, _, _, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "tuong lua"); err != nil {
		t.Fatalf("read after a purge: %v", err)
	}
	a.kbAdd("backups.md", []byte(mdBackup), "")
	a.purgeLikeCore()
	if err := a.exec(`INSERT INTO ai_knowledge_doc (id, name, size, status, chunks, jobs, uploaded_at) VALUES ('kd-z', 'z.md', 5, 'ready', 0, '[]', '2026-11-10T03:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	a.want("DELETE", "/ai/knowledge/kd-z", "admin", "", 204, "")
	// a restart repairs a damaged index before anybody uses it
	a.kbAdd("backups.md", []byte(mdBackup), "")
	a.purgeLikeCore()
	a.svc = a.newService()
	if err := a.exec(`INSERT INTO ai_knowledge_doc (id, name, size, status, chunks, jobs, uploaded_at) VALUES ('kd-y', 'y.md', 5, 'ready', 1, '[]', '2026-11-10T03:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	if err := a.exec(`INSERT INTO ai_knowledge_chunk (doc_id, seq, text) VALUES ('kd-y', 1, 'restart worked')`); err != nil {
		t.Fatalf("the index was not repaired at start: %v", err)
	}
}

func TestKnowledgeAHeldPieceIsLeftOut(t *testing.T) {
	a := newAPI(t)
	a.kbIndexProfile()
	pad := strings.Repeat("The gateway log shows the same login problem again. ", 40)
	a.kbAdd("router.md", []byte("KEEPPIECE router notes. "+pad+"\n\nHOLDPIECE router approval-needed text. "+pad), "")
	a.want("POST", "/ai/hooks", "admin", hookJSON("Hold approvals", "before_ai", "keywords", "approval-needed", "approve", "A person must approve this."), 200, "")
	sent, used, left, err := a.svc.KnowledgeForCall(a.ctx(), ai.JobExplainFinding, "router notes approval-needed")
	if err != nil || strings.Contains(sent, "HOLDPIECE") || !strings.Contains(sent, "KEEPPIECE") || len(used) != 1 || len(left) != 1 {
		t.Fatalf("held piece: sent %q used %v left %v err %v", sent, used, left, err)
	}
}
