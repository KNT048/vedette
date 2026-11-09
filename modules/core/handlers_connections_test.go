package core_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/conn/conntest"
)

// The connection routes (D-93, D-94; INV-23): admin only, the same answers as the mock of the GUI, no secret anywhere.
// Test reaches an in-process fake (conntest).

var connRoutes = []struct{ method, path string }{
	{"GET", "/core/connections"}, {"POST", "/core/connections"}, {"PUT", "/core/connections/cn-1"},
	{"DELETE", "/core/connections/cn-1"}, {"POST", "/core/connections/cn-1/test"},
}

// swapID turns the concrete id of a test path into the {id} of the route table.
func swapID(p string) string { return strings.Replace(p, "cn-1", "{id}", 1) }

func TestConnections_RoutesAreAdminOnly(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	operator, _ := w.signIn("operator@acme.example", "operator")
	viewer, _ := w.signIn("viewer@acme.example", "viewer")
	anon := w.client()
	body := map[string]any{"name": "Lab", "kind": "http", "target": "https://192.168.10.1", "auth_type": "none", "allow": []string{"https://192.168.10.1/"}, "enabled": true}
	for _, rt := range connRoutes {
		found := false
		for _, o := range routes.Operations {
			if o.Method == rt.method && o.Path == swapID(rt.path) {
				found = true
				if o.MinRole != routes.Admin {
					t.Errorf("%s %s: role %s in the route table, want admin", rt.method, rt.path, o.MinRole)
				}
			}
		}
		if !found {
			t.Errorf("%s %s is not in the route table", rt.method, rt.path)
		}
		send := func(c *client) reply {
			if rt.method == "POST" || rt.method == "PUT" {
				return c.request(rt.method, rt.path, body)
			}
			return c.request(rt.method, rt.path, nil)
		}
		if r := send(anon); r.Code != 401 {
			t.Errorf("%s %s anonymous = %d %s", rt.method, rt.path, r.Code, r.Raw)
		}
		for name, c := range map[string]*client{"viewer": viewer, "operator": operator} {
			if r := send(c); r.Code != 403 || r.code() != "forbidden" {
				t.Errorf("%s %s as %s = %d %s, want 403 forbidden", rt.method, rt.path, name, r.Code, r.Raw)
			}
		}
	}
	// Nothing was created by a refused role.
	if n := w.env.Count(t, "SELECT count(*) FROM core_connection"); n != 0 {
		t.Errorf("%d connections after only refused requests", n)
	}
}

// lanAt points the body of connBody at another LAN address: tests that Redirect an address to their own fake need an address of
// their own, because the redirects are process-wide.
func lanAt(ip string) map[string]any {
	return map[string]any{"target": "https://" + ip, "allow": []string{"https://" + ip + "/api/"}}
}

func connBody(name string, over map[string]any) map[string]any {
	b := map[string]any{"name": name, "kind": "http", "target": "https://192.168.10.60", "auth_type": "token", "secret": "par-0123456789-cdef", "allow": []string{"https://192.168.10.60/api/"}, "enabled": true}
	for k, v := range over {
		if v == nil {
			delete(b, k)
			continue
		}
		b[k] = v
	}
	return b
}

// Test (D-94): a connection that is off is 409 connection_off and nothing is sent; an unknown id is 404; one that is on is
// reached for real (an in-process HTTPS fake), its certificate pinned, the result saved and audited, and the secret nowhere.
func TestConnections_TestReachesTheDevice(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin, _ := w.signIn("admin@acme.example", "admin")
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Echo", r.Header.Get("Authorization")) // a careless device that echoes what it was sent
		_, _ = io.WriteString(rw, "{}")
	}))
	f.Redirect(t, "192.168.10.61:443")
	made := admin.post("/core/connections", connBody("Lab", lanAt("192.168.10.61")))
	if made.Code != 201 {
		t.Fatalf("create = %d %s", made.Code, made.Raw)
	}
	id := made.str("id")

	r := admin.post("/core/connections/"+id+"/test", nil)
	if r.Code != 200 || r.JSON["ok"] != true || r.JSON["tools_found"] != float64(2) {
		t.Fatalf("test of a connection that is on = %d %s", r.Code, r.Raw)
	}
	if r.str("connector", "status") != "ok" || r.str("connector", "pin", "kind") != "tls_sha256" || r.str("connector", "pin", "value") != f.SPKISHA256() {
		t.Errorf("the connector in the answer: %s", r.Raw)
	}
	if !regexp.MustCompile(`^Connected\. 2 tools found \(1 can change something\)\. The certificate is now pinned\.$`).MatchString(r.str("message")) {
		t.Errorf("message %q", r.str("message"))
	}
	if reqs := f.Requests(); len(reqs) != 1 || reqs[0].Header.Get("Authorization") != "Bearer par-0123456789-cdef" {
		t.Fatalf("the device saw %+v", reqs)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'connection.test'"); n != 1 {
		t.Errorf("%d connection.test audit rows, want 1", n)
	}
	if strings.Contains(r.Raw, "par-0123456789") || strings.Contains(w.logs.String(), "par-0123456789") {
		t.Error("the secret is in the answer or in the logs")
	}

	// A device that now shows another certificate: 502 pin_mismatch, nothing sent, status error.
	f.Rotate(t)
	if r := admin.post("/core/connections/"+id+"/test", nil); r.Code != 502 || r.code() != "pin_mismatch" {
		t.Errorf("a changed certificate = %d %s, want 502 pin_mismatch", r.Code, r.Raw)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests reached the device, want only the first", n)
	}
	if got := admin.get("/core/connections"); !strings.Contains(got.Raw, `"status":"error"`) {
		t.Errorf("the list after a failed test: %s", got.Raw)
	}

	if r := admin.put("/core/connections/"+id, connBody("Lab", map[string]any{"secret": nil, "enabled": false, "target": "https://192.168.10.61", "allow": []string{"https://192.168.10.61/api/"}})); r.Code != 200 {
		t.Fatalf("turn off = %d %s", r.Code, r.Raw)
	}
	if r := admin.post("/core/connections/"+id+"/test", nil); r.Code != 409 || r.code() != "connection_off" {
		t.Errorf("test of a connection that is off = %d %s, want 409 connection_off", r.Code, r.Raw)
	}
	if r := admin.post("/core/connections/cn-nope/test", nil); r.Code != 404 || r.code() != "not_found" {
		t.Errorf("test of an unknown connection = %d %s", r.Code, r.Raw)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests in all, want 1: nothing goes to a connection that is off", n)
	}
}

// INV-23: Test re-checks the administrator inside its own write transaction: an admin who was demoted after the request passed the
// route check changes nothing.
func TestConnections_TestRechecksAdminInsideTheTransaction(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin, _ := w.signIn("admin@acme.example", "admin")
	second, _ := w.signIn("second@acme.example", "admin")
	var demoted atomic.Bool
	demote := func(ctx context.Context) error {
		return w.env.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "UPDATE core_user SET role = 'viewer' WHERE email = 'second@acme.example'")
			return err
		})
	}
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if demoted.CompareAndSwap(false, true) { // while the device is being read, another admin demotes the caller
			if err := demote(r.Context()); err != nil {
				t.Error(err)
			}
		}
		_, _ = io.WriteString(rw, "{}")
	}))
	f.Redirect(t, "192.168.10.62:443")
	id := admin.post("/core/connections", connBody("Lab", lanAt("192.168.10.62"))).str("id")
	r := second.post("/core/connections/"+id+"/test", nil)
	if r.Code != 403 {
		t.Fatalf("test by an admin demoted meanwhile = %d %s, want 403", r.Code, r.Raw)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'connection.test'"); n != 0 {
		t.Errorf("%d connection.test rows were written by a caller that was no longer an admin", n)
	}
	if got := admin.get("/core/connections"); !strings.Contains(got.Raw, `"status":"untested"`) || strings.Contains(got.Raw, `"pin":{`) {
		t.Errorf("the connection changed: %s", got.Raw)
	}
}

// D-93 (4): delete is 409 in_use while response still has a change in force, and works after.
func TestConnections_DeleteIsRefusedWhileAChangeIsInForce(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin, _ := w.signIn("admin@acme.example", "admin")
	id := admin.post("/core/connections", connBody("Lab", nil)).str("id")
	w.inUse.Store(true)
	r := admin.delete("/core/connections/" + id)
	if r.Code != 409 || r.code() != "in_use" || !strings.Contains(r.str("error", "message"), "still in force") {
		t.Fatalf("delete in force = %d %s", r.Code, r.Raw)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_connection"); n != 1 {
		t.Fatal("a refused delete removed the connection")
	}
	w.inUse.Store(false)
	if r := admin.delete("/core/connections/" + id); r.Code != 204 {
		t.Fatalf("delete = %d %s", r.Code, r.Raw)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'"); n != 0 {
		t.Errorf("%d secrets left after the delete", n)
	}
}

// matrixStep is one step of web/src/features/core/testdata/connections_matrix.json, the script the mock of the GUI answers too
// (web/src/features/core/connections.parity.test.ts).
type matrixStep struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   any    `json:"body"`
	Status int    `json:"status"`
	Error  *struct {
		Code    string `json:"code"`
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"error"`
	Keep           string            `json:"keep"`
	Expect         any               `json:"expect"`
	Matches        map[string]string `json:"matches"`
	MatchesMessage string            `json:"matchesMessage"`
	Absent         []string          `json:"absent"`
	ListHas        []string          `json:"listHas"`
	ListLacks      []string          `json:"listLacks"`
	// During is a request sent while this step's request is still being answered by a device that is slow.
	During *struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   any    `json:"body"`
		Status int    `json:"status"`
	} `json:"during"`
	// Real is what the backend answers where it deliberately differs from the mock.
	Real *struct {
		Status int `json:"status"`
		Error  *struct {
			Code    string `json:"code"`
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"real"`
}

// subset reports why got does not contain want ("" when it does): every key of want is in got with the same value, arrays
// match element by element.
func subset(got, want any, at string) string {
	switch wv := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: got %v, want an object", at, got)
		}
		for k, v := range wv {
			if e := subset(g[k], v, at+"."+k); e != "" {
				return e
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(wv) {
			return fmt.Sprintf("%s: got %v, want %d items", at, got, len(wv))
		}
		for i, v := range wv {
			if e := subset(g[i], v, fmt.Sprintf("%s[%d]", at, i)); e != "" {
				return e
			}
		}
		return ""
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Sprintf("%s: got %v, want %v", at, got, want)
	}
	return ""
}

func fillKeys(v any, keys map[string]string) any {
	switch x := v.(type) {
	case string:
		if k, ok := keys[x]; ok {
			return k
		}
	case []any:
		for i := range x {
			x[i] = fillKeys(x[i], keys)
		}
	case map[string]any:
		for k := range x {
			x[k] = fillKeys(x[k], keys)
		}
	}
	return v
}

// The backend answers the script of the mock: the same status, code, field and message (D-93), except where a step says
// otherwise in `real` (messages of the generated request checks, which the mock mimics only in part; the Test route).
func TestConnections_AnswerLikeTheMock(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "features", "core", "testdata", "connections_matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Steps []matrixStep `json:"steps"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for name, file := range map[string]string{"$KEY_PLAIN": "ed25519", "$KEY_LOCKED": "ed25519-passphrase"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "features", "core", "testdata", "keys", file)) //nolint:gosec // a fixture of the mock of the GUI
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = string(b)
	}
	// The script's connections are saved with LAN addresses; the dial of the Test step goes to an in-process fake instead.
	conntest.NewHTTPS(t, nil).Redirect(t, "192.168.10.64:443")
	// The failure steps type names; the names reach fakes (or, for "rebound", loopback, which the policy refuses at dial time).
	conntest.ResolveName(t, "rebound.device.test", "127.0.0.1")
	conntest.ResolveName(t, "denied.device.test", "192.168.10.91")
	conntest.NewHTTPS(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusUnauthorized) })).Redirect(t, "192.168.10.91:443")
	conntest.ResolveName(t, "slow.device.test", "192.168.10.92")
	arrived, release := make(chan struct{}, 8), make(chan struct{})
	conntest.NewHTTPS(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release // the device answers when the script has made its edit
		_, _ = io.WriteString(rw, "{}")
	})).Redirect(t, "192.168.10.92:443")
	var released bool
	meanwhile, _ := w.signIn("meanwhile@acme.example", "admin")
	clients := map[string]*client{"": w.client()}
	for _, role := range []string{"admin", "operator", "viewer"} {
		clients[role], _ = w.signIn(role+"@acme.example", role)
	}
	kept := map[string]string{}
	placeholder := regexp.MustCompile(`\{(\w+)\}`)
	for _, s := range m.Steps {
		path := placeholder.ReplaceAllStringFunc(s.Path, func(p string) string {
			if id, ok := kept[p[1:len(p)-1]]; ok {
				return id
			}
			return p
		})
		var body any
		if s.Body != nil {
			body = fillKeys(s.Body, keys)
		}
		var r reply
		if s.During == nil {
			r = clients[s.Role].request(s.Method, path, body)
		} else {
			done := make(chan reply, 1)
			go func() { done <- clients[s.Role].request(s.Method, path, body) }()
			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				t.Fatalf("step %s: the device was never reached", s.Name)
			}
			dpath := placeholder.ReplaceAllStringFunc(s.During.Path, func(p string) string {
				if id, ok := kept[p[1:len(p)-1]]; ok {
					return id
				}
				return p
			})
			if d := meanwhile.request(s.During.Method, dpath, fillKeys(s.During.Body, keys)); d.Code != s.During.Status {
				t.Errorf("step %s: the request made meanwhile = %d %s, want %d", s.Name, d.Code, d.Raw, s.During.Status)
			}
			if !released {
				close(release)
				released = true
			}
			r = <-done
		}
		status, errWant := s.Status, s.Error
		if s.Real != nil {
			status, errWant = s.Real.Status, nil
			if s.Real.Error != nil {
				errWant = s.Real.Error
			}
			if status == 0 {
				status = s.Status
			}
		}
		at := "step " + s.Name
		if r.Code != status {
			t.Errorf("%s: status %d %s, want %d", at, r.Code, r.Raw, status)
			continue
		}
		if errWant != nil {
			if r.code() != errWant.Code {
				t.Errorf("%s: code %q (%s), want %q", at, r.code(), r.Raw, errWant.Code)
			}
			if e, _ := r.JSON["error"].(map[string]any); errWant.Field != "" && e["field"] != errWant.Field {
				t.Errorf("%s: field %v, want %q", at, e["field"], errWant.Field)
			}
			if errWant.Message != "" && r.str("error", "message") != errWant.Message {
				t.Errorf("%s: message %q, want %q", at, r.str("error", "message"), errWant.Message)
			}
		}
		if s.MatchesMessage != "" && s.Real == nil && !regexp.MustCompile(s.MatchesMessage).MatchString(r.str("error", "message")) {
			t.Errorf("%s: message %q does not match %s", at, r.str("error", "message"), s.MatchesMessage)
		}
		if s.Real != nil && s.Real.Status != 0 {
			continue // the body of a deliberate difference is not compared
		}
		if s.Expect != nil {
			if e := subset(r.JSON, s.Expect, ""); e != "" {
				t.Errorf("%s: %s (%s)", at, e, r.Raw)
			}
		}
		for p, re := range s.Matches {
			var cur any = r.JSON
			for _, k := range strings.Split(p, ".") {
				mm, _ := cur.(map[string]any)
				cur = mm[k]
			}
			if !regexp.MustCompile(re).MatchString(fmt.Sprint(cur)) {
				t.Errorf("%s: %s = %v, want to match %s", at, p, cur, re)
			}
		}
		for _, a := range s.Absent {
			if strings.Contains(r.Raw, a) {
				t.Errorf("%s: %q is in the answer", at, a)
			}
		}
		if s.Keep != "" {
			kept[s.Keep] = r.str("id")
		}
		listed := func(id string) bool {
			items, _ := r.JSON["items"].([]any)
			for _, it := range items {
				if mm, _ := it.(map[string]any); mm["id"] == id {
					return true
				}
			}
			return false
		}
		for _, k := range s.ListHas {
			if !listed(kept[k]) {
				t.Errorf("%s: %s is not listed", at, k)
			}
		}
		for _, k := range s.ListLacks {
			if listed(kept[k]) {
				t.Errorf("%s: %s is still listed", at, k)
			}
		}
	}

	// SYS-4: the script created connections with secrets and keys; they are in no audit row and no log.
	rows, err := w.env.DB.Reader().QueryContext(t.Context(), `SELECT user || ' ' || action || ' ' || target || ' ' || coalesce(detail, '') FROM core_audit WHERE action LIKE 'connection.%'`)
	if err != nil {
		t.Fatal(err)
	}
	var audited []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		audited = append(audited, line)
	}
	_ = rows.Close()
	if len(audited) < 8 {
		t.Fatalf("%d connection audit rows after the script: %v", len(audited), audited)
	}
	for _, a := range []string{"connection.create", "connection.update", "connection.delete"} {
		if !strings.Contains(strings.Join(audited, "\n"), a) {
			t.Errorf("no %s row in the audit log", a)
		}
	}
	everything := strings.Join(audited, "\n") + w.logs.String()
	for _, leak := range []string{"par-0123456789", "par-9876543210", "BEGIN OPENSSH", "b3BlbnNzaC1rZXk", keys["$KEY_PLAIN"][40:80]} {
		if strings.Contains(everything, leak) {
			t.Errorf("%q is in the audit log or the logs", leak)
		}
	}
}
