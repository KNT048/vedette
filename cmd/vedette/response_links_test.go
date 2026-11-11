package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http/httptest"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-7 (D-96, response INV-4, POST-5, FORBID-4) in the real wiring: the real response and notify services, a fake SMTP
// server on loopback, the real generated server. A request is created, the approver gets a mail with a link, the link approves once, a
// request from another site is refused, and the token is nowhere in the database.

var approveLinkRE = regexp.MustCompile(`https://box\.example:8443/approve/(v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22})`)

// mailBody is the text of a message the sink kept (the box sends quoted-printable).
func mailBody(t *testing.T, raw string) string {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// public sends a request to the public approval route the way a browser would: no session, headers as given.
func (s *stack) public(method, token, body string, h map[string]string) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(s.t.Context(), method, server.Prefix+"/response/approve/"+token, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			s.t.Fatalf("not JSON: %v: %s", err, w.Body)
		}
	}
	return w.Code, out
}

// dumpDB is every cell of every table as text: a secret that is anywhere is found here.
func (s *stack) dumpDB() string {
	s.t.Helper()
	ctx := s.t.Context()
	rows, err := s.d.DB.Reader().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		s.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			s.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	_ = rows.Close()
	var b strings.Builder
	for _, n := range tables {
		r, err := s.d.DB.Reader().QueryContext(ctx, `SELECT * FROM "`+n+`"`)
		if err != nil {
			s.t.Fatal(err)
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				s.t.Fatal(err)
			}
			for _, v := range vals {
				switch x := v.(type) {
				case []byte:
					b.Write(x)
				default:
					fmt.Fprint(&b, x)
				}
				b.WriteByte('|')
			}
			b.WriteByte('\n')
		}
		_ = r.Close()
	}
	return b.String()
}

// linkSetup builds the stack, an operator who approves by email, the settings and a rule, fires one event and returns the request the box
// made and the link it mailed. The request ends 15 minutes after it was made.
func linkSetup(t *testing.T) (s *stack, clock *manualClock, a response.ActionRequest, token string) {
	t.Helper()
	clock = newManualClock(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC))
	s = newStackWith(t, func(d *deps) { d.Clock = clock.now; d.BaseURL = "https://box.example:8443" })
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	svc := s.d.Response
	boss := response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}
	lan := s.addUser("lan@acme.example", routes.Operator)
	sink := newSMTPSink(t)
	s.email(sink, notify.Approver{UserID: lan.ID, Address: "lan@acme.example"})
	st, err := svc.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := response.SettingsInput{MaxPerHour: st.MaxPerHour, ExpiryMin: 15, ApprovalChannels: []string{"email"}, BreakerMaxPerHour: 100, MultiTargetMax: st.MultiTargetMax, Maintenance: st.Maintenance}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay
	if _, err := svc.SaveSettings(ctx, boss, in); err != nil {
		t.Fatal(err)
	}
	// D-191: Lan proves the address first, with the code notify's code mailer sends (responseMailer).
	me := response.Actor{ID: lan.ID, Email: "lan@acme.example", Via: response.ViaApp}
	if _, err := svc.SendLinkCode(ctx, me, "email"); err != nil {
		t.Fatal(err)
	}
	codeMail := sink.messages()
	if len(codeMail) != 1 || !strings.Contains(mailBody(t, codeMail[0]), "link this email address") {
		t.Fatalf("link code mail: %v", codeMail)
	}
	lc := regexp.MustCompile(`code is (\d{6})`).FindStringSubmatch(mailBody(t, codeMail[0]))
	if lc == nil {
		t.Fatalf("no code in the mail:\n%s", mailBody(t, codeMail[0]))
	}
	if _, err := svc.ConfirmLink(ctx, me, "email", lc[1]); err != nil {
		t.Fatal(err)
	}
	ttl := 60
	ri := response.RuleInput{Name: "Block", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 10,
		Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: &ttl}}}
	rule, err := svc.AddRule(ctx, boss, ri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeRule(ctx, boss, rule.ID, ri); err != nil {
		t.Fatal(err)
	}
	ev := response.Det{ID: "e1", Trigger: "ioc_connection", TS: store.FormatTS(clock.now()), Summary: "PC-SALES-02 connected to 198.51.100.7",
		Fields: map[string]string{"src_ip": "192.168.10.105", "device": "PC-SALES-02", "dest": "198.51.100.7", "dest_kind": "ip", "dest_ip": "198.51.100.7", "dest_domain": "", "feeds": "IPsum", "confidence": "0.92", "switch_port": ""}}
	if err := svc.StoreEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	// The request is sent in the background after it was created: one mail, to the approver only, with a link; sent_to and the log say so.
	var reqs []response.ActionRequest
	for range 1000 {
		reqs, err = svc.Actions(ctx)
		if err == nil && len(reqs) == 1 && len(reqs[0].SentTo) > 0 {
			break
		}
		select {
		case <-t.Context().Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err != nil || len(reqs) != 1 {
		t.Fatalf("requests: %v %+v", err, reqs)
	}
	a = reqs[0]
	msgs := sink.messages()[1:] // after the link code mail
	if len(msgs) != 1 || !strings.Contains(msgs[0], "lan@acme.example") {
		t.Fatalf("%d messages, want 1 to the approver:\n%v", len(msgs), msgs)
	}
	body := mailBody(t, msgs[0])
	m := approveLinkRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no approval link in the mail:\n%s", body)
	}
	if !strings.Contains(body, "198.51.100.7") {
		t.Errorf("the mail does not show the change:\n%s", body)
	}
	return s, clock, a, m[1]
}

func TestWiringApprovalLinkByEmail(t *testing.T) {
	t.Parallel()
	s, _, a, token := linkSetup(t)
	ctx := t.Context()
	svc := s.d.Response
	if len(a.SentTo) != 1 || a.SentTo[0] != "Email" || a.Status != response.StatusPending || len(a.EmailLinks) != 0 {
		t.Fatalf("request after sending: %+v", a)
	}
	if s.count(`SELECT count(*) FROM resp_log WHERE kind = 'request' AND detail LIKE '%Approval request sent to Email%'`) != 1 {
		t.Error("no log line for the send")
	}

	// Opening the link, as many times as a scanner likes, changes nothing.
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}
	for range 5 {
		code, v := s.public("GET", token, "", same)
		if code != 200 || v["state"] != "ready" || v["title"] != a.Title {
			t.Fatalf("GET: %d %v", code, v)
		}
	}
	if got, _ := svc.Actions(ctx); got[0].Status != response.StatusPending || len(got[0].Approvals) != 0 || s.count(`SELECT count(*) FROM resp_tokens WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("a GET changed the request")
	}

	// A request that says it comes from another site, or whose Origin is another site, is refused and decides nothing.
	body1 := `{"decision":"approve"}`
	if code, v := s.public("POST", token, body1, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Errorf("cross-site POST: %d %v", code, v)
	}
	if code, v := s.public("POST", token, body1, map[string]string{"Sec-Fetch-Site": "same-site"}); code != 403 {
		t.Errorf("same-site POST: %d %v", code, v)
	}
	if code, v := s.public("GET", token, "", map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Errorf("cross-site GET: %d %v", code, v)
	}
	if code, v := s.public("POST", token, body1, map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"}); code != 403 {
		t.Errorf("POST with a foreign Origin: %d %v", code, v)
	}
	if got, _ := svc.Actions(ctx); got[0].Status != response.StatusPending || s.count(`SELECT count(*) FROM resp_tokens WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("a cross-site request decided or burned the link")
	}
	// A form post from another site cannot carry the JSON the route needs.
	if code, _ := s.public("POST", token, "decision=approve", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"}); code == 200 {
		t.Error("a form post decided")
	}

	// The link of the page itself: same-origin, JSON. It approves once.
	okHeaders := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}
	code, v := s.public("POST", token, body1, okHeaders)
	if code != 200 || (v["status"] != "executed" && v["status"] != "approved") || at(v, "approvals", 0, "via") != "email" || at(v, "approvals", 0, "email") != "lan@acme.example" {
		t.Fatalf("POST approve: %d %v", code, v)
	}
	if s.count(`SELECT count(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Error("the approved action did not run")
	}
	for range 2 {
		if code, v := s.public("POST", token, body1, okHeaders); code != 409 || at(v, "error", "code") != "used" {
			t.Errorf("second POST: %d %v", code, v)
		}
	}
	if code, v := s.public("GET", token, "", same); code != 200 || v["state"] != "used" || v["title"] != nil {
		t.Errorf("GET after use: %d %v", code, v)
	}
	if s.count(`SELECT count(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Error("the action ran twice")
	}
	// A forged token is the same 404 whatever is wrong with it.
	forged := "v1." + strings.Repeat("A", 22) + "." + strings.Repeat("B", 22)
	for _, tok := range []string{forged, token[:len(token)-1] + "A", "nonsense"} {
		if tok == token {
			continue
		}
		if code, v := s.public("POST", tok, body1, okHeaders); code != 404 || at(v, "error", "code") != "unknown" {
			t.Errorf("forged %q: %d %v", tok, code, v)
		}
	}

	// FORBID-4: the token (and its parts) is in no table, the log and the audit included.
	all := s.dumpDB()
	parts := strings.Split(token, ".")
	for name, secret := range map[string]string{"token": token, "id": parts[1], "mac": parts[2]} {
		if strings.Contains(all, secret) {
			t.Errorf("the %s of the approval link is stored in the database", name)
		}
	}
	if strings.Contains(all, "/approve/v1.") {
		t.Error("an approval URL is stored in the database")
	}
}

// The same link after the request ended is 409 expired, and the page shows nothing of the request.
func TestWiringApprovalLinkExpires(t *testing.T) {
	t.Parallel()
	s, clock, _, token := linkSetup(t)
	clock.advance(16 * time.Minute) // past the request, and so past the link: a link never outlives its request
	h := map[string]string{"Sec-Fetch-Site": "same-origin"}
	if code, v := s.public("GET", token, "", h); code != 200 || v["state"] != "expired" || v["title"] != nil {
		t.Errorf("GET: %d %v", code, v)
	}
	if code, v := s.public("POST", token, `{"decision":"approve"}`, h); code != 409 || at(v, "error", "code") != "expired" {
		t.Errorf("POST: %d %v", code, v)
	}
	if s.count(`SELECT count(*) FROM resp_block_entries`) != 0 {
		t.Error("an expired link ran the action")
	}
}

// SYS-5 and spec 8: while notify is off its channels and approvers do not exist, so a link neither shows the request nor decides; when
// notify is on again the same link works, and a link of a person who was taken off the list reads as no link at all.
func TestWiringApprovalLinkNeedsNotifyOn(t *testing.T) {
	t.Parallel()
	s, _, a, token := linkSetup(t)
	h := map[string]string{"Sec-Fetch-Site": "same-origin"}
	s.setModule("notify", false)
	if code, v := s.public("GET", token, "", h); code != 200 || v["state"] != "unknown" || v["title"] != nil {
		t.Errorf("GET with notify off: %d %v", code, v)
	}
	if code, v := s.public("POST", token, `{"decision":"approve"}`, h); code != 403 || at(v, "error", "code") != "approver_not_listed" {
		t.Errorf("POST with notify off: %d %v", code, v)
	}
	if s.count(`SELECT count(*) FROM resp_tokens WHERE used_at IS NOT NULL`) != 0 || s.count(`SELECT count(*) FROM resp_block_entries`) != 0 {
		t.Fatal("a link decided while notify was off")
	}
	s.setModule("notify", true)
	if code, v := s.public("GET", token, "", h); code != 200 || v["state"] != "ready" || v["title"] != a.Title {
		t.Errorf("GET with notify on again: %d %v", code, v)
	}
	if code, v := s.public("POST", token, `{"decision":"reject"}`, h); code != 200 || v["status"] != "rejected" {
		t.Errorf("POST with notify on again: %d %v", code, v)
	}
}
