package conn_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
)

// The security properties of Test (independent review of slice 13b-5, D-94, core INV-23): trust on first use is for the first Test
// only, one Test trusts one certificate, no secret reaches a message, and nothing a server says can grow the connection.

// H1. The first Test records whether a public authority vouched for the server (pin kind tls_roots); from then on a certificate that
// none vouches for is refused before anything is sent, until "Forget pinned key". A first Test against a public server that saved
// nothing would stay a first use for ever: any later Test behind an interceptor would send the token to it and pin it.
func TestTestFirstSuccessThroughPublicTrustRequiresItEverAfter(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	r.svc.SetRootsForTest(f.Roots()) // what the system roots would do for a public server
	c := r.httpTo(f, "http")

	res, err := r.test(c.ID)
	if err != nil || !strings.HasSuffix(res.Message, "Later tests require a certificate that a public authority vouches for.") {
		t.Fatalf("first test: %v %q", err, res.Message)
	}
	if got := r.get(c.ID); got.Pin == nil || got.Pin.Kind != "tls_roots" || got.Pin.Value != "system roots" {
		t.Fatalf("pin after a first test through public trust: %+v", got.Pin)
	}
	if a := r.auditTests(); len(a) != 1 || !strings.Contains(a[0], "pinned public trust") {
		t.Fatalf("audit %v", a)
	}

	// An interceptor answers with a certificate no authority vouches for: refused, and the token is not sent.
	f.Rotate(t)
	n := len(f.Requests())
	_, err = r.test(c.ID)
	ae := want(t, err, 502, "pin_mismatch", "")
	if !strings.Contains(ae.Message, "is not one that a public certificate authority vouches for, as it was at the first test. Nothing was sent.") {
		t.Fatalf("message %q", ae.Message)
	}
	if len(f.Requests()) != n {
		t.Fatal("a request reached a server that no public authority vouches for, on a connection that was publicly trusted at its first test")
	}
	if got := r.get(c.ID); got.Pin == nil || got.Pin.Kind != "tls_roots" || got.Status != "error" {
		t.Fatalf("a refused test changed the pin: %+v", got.Pin)
	}

	// "Forget pinned key" is the way back to a first use: the next Test trusts what answers and pins its key.
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Allow: c.Allow, Enabled: true, ClearPin: true}
	if _, err := r.update(c.ID, in); err != nil {
		t.Fatal(err)
	}
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.get(c.ID); got.Pin == nil || got.Pin.Kind != "tls_sha256" || got.Pin.Value != f.SPKISHA256() {
		t.Fatalf("pin after forgetting: %+v", got.Pin)
	}
}

// The pin is the hash of the public key, not of the certificate: re-issuing a certificate for the same key keeps it.
func TestTestPinSurvivesAReissueWithTheSameKey(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.httpTo(f, "http")
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	before := r.get(c.ID)
	f.Reissue(t)
	if _, err := r.test(c.ID); err != nil {
		t.Fatalf("a certificate re-issued for the same key was refused: %v", err)
	}
	if after := r.get(c.ID); after.Pin.Value != before.Pin.Value || after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("the pin or updated_at moved: %+v", after.Pin)
	}
}

// M2. One Test is one trust decision, but every request of it is a new handshake: an MCP Test makes three. The certificate of the
// first must hold; a server that shows another to the second request gets nothing more and pins nothing.
func TestTestOneCertificatePerTest(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	var fp atomic.Pointer[conntest.HTTPS]
	var mu sync.Mutex
	var served int
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		defer fp.Load().Rotate(t) // the next connection meets another key
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(req.Body).Decode(&m)
		w.Header().Set("Mcp-Session-Id", "s-1")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"protocolVersion": "2025-06-18"}})
	}))
	fp.Store(f)
	c := r.must(conn.Input{Name: "Shifting MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue(secret1), Allow: []string{f.URL + "/mcp"}, Enabled: true})

	_, err := r.test(c.ID)
	ae := want(t, err, 502, "pin_mismatch", "")
	if !strings.Contains(ae.Message, "changed while the test ran") {
		t.Fatalf("message %q", ae.Message)
	}
	mu.Lock()
	n := served
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the server received %d requests: after its certificate changed nothing more may be sent", n)
	}
	if got := r.get(c.ID); got.Pin != nil || got.Status != "error" {
		t.Fatalf("saved %+v pin %+v: the identity that changed half way must not be pinned", got, got.Pin)
	}
}

// L1. A device that echoes the Authorization header of a Basic sign-in shows base64 of user:password.
func TestTestMessageNeverShowsTheBasicHeaderOfAnEcho(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(req.Body).Decode(&m)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32001, "message": "rejected " + req.Header.Get("Authorization")}})
	}))
	c := r.must(conn.Input{Name: "Echo MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "basic", Username: str("opsadmin"), Secret: secrets.NewValue(secret1), Allow: []string{f.URL + "/mcp"}, Enabled: true})
	_, err := r.test(c.ID)
	ae, ok := apierr.As(err)
	if !ok || ae.Code != "device_error" {
		t.Fatalf("got %v, want 502 device_error", err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("opsadmin:" + secret1))
	if strings.Contains(ae.Message, b64[:20]) || strings.Contains(ae.Message, secret1[:8]) {
		t.Errorf("the message shows the Basic credential: %q", ae.Message)
	}
}

// L2. The secret is removed before the line is cut to 200 characters: a token cut in half by the limit would otherwise survive.
func TestTestMessageRemovesATokenBeforeTheLineLimitCutsIt(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(req.Body).Decode(&m)
		tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		// "the server reported an error (-32001): " is 39 characters; 146 more put the token's 14th character at the cut.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32001, "message": strings.Repeat("x", 146) + tok}})
	}))
	c := r.must(conn.Input{Name: "Echo cut MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue(secret1), Allow: []string{f.URL + "/mcp"}, Enabled: true})
	_, err := r.test(c.ID)
	ae, ok := apierr.As(err)
	if !ok || ae.Code != "device_error" {
		t.Fatalf("got %v, want 502 device_error", err)
	}
	if strings.Contains(ae.Message, secret1[:12]) {
		t.Errorf("the message shows the first characters of the token: %q", ae.Message)
	}
}

// L4. An IPv6 form that carries an IPv4 address reads as one sentence in the message.
func TestTestRefusedEmbeddedIPv4ReadsAsOneSentence(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	host := conntest.ResolveTo(t, "64:ff9b::a9fe:a9fe") // NAT64 form of 169.254.169.254
	target := "https://" + host
	c := r.must(conn.Input{Name: "NAT64 metadata", Kind: "http", Target: target, AuthType: "none", Allow: []string{target + "/"}, Enabled: true})
	_, err := r.test(c.ID)
	ae := want(t, err, 502, "address_refused", "")
	if wantMsg := target + " now points to an IPv6 address that carries an IPv4 address, so Vedette did not connect. Check the name in your DNS."; ae.Message != wantMsg {
		t.Fatalf("message %q, want %q", ae.Message, wantMsg)
	}
}

// L6. The tools of an MCP server are what it lists now, at most 100 in all: a server that renames its tools cannot grow the
// connection from Test to Test, and a tool the administrator set keeps its settings while its name stays.
func TestTestMCPToolsAreReplacedAndCapped(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	var round atomic.Int32
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(req.Body).Decode(&m)
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any = map[string]any{"protocolVersion": "2025-06-18"}
		if m.Method == "tools/list" {
			n := int(round.Add(1))
			tools := []map[string]any{{"name": "stable", "description": "the same in every round"}}
			for i := range 130 { // more than a connection holds
				tools = append(tools, map[string]any{"name": "t" + strconv.Itoa(n) + "_" + strconv.Itoa(i), "description": "x"})
			}
			result = map[string]any{"tools": tools}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
	}))
	c := r.must(conn.Input{Name: "Renaming MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "none", Allow: []string{f.URL + "/mcp"}, Enabled: true})
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	read := "read"
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "none", Allow: c.Allow, Enabled: true, Tools: []conn.ToolInput{{Name: "stable", Enabled: true, Access: &read}}}
	if _, err := r.update(c.ID, in); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := r.test(c.ID); err != nil {
			t.Fatal(err)
		}
	}
	tools := r.get(c.ID).Tools
	if len(tools) != 100 {
		t.Errorf("the connection holds %d tools, want the 100 of one answer and no more", len(tools))
	}
	if tools[0].Name != "stable" || tools[0].Access != "read" || !tools[0].Enabled {
		t.Errorf("a tool that kept its name lost what the administrator set: %+v", tools[0])
	}
	for _, tl := range tools[1:] {
		if !strings.HasPrefix(tl.Name, "t3_") || tl.Enabled || tl.Access != "write" {
			t.Fatalf("tool %+v: the tools of the first rounds must be gone, and the new ones write and off", tl)
		}
	}
}

// L7. A server's description may carry a right-to-left override or zero-width characters and make the card read differently from
// what is stored.
func TestTestToolDescriptionsHoldNoFormatCharacters(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "wipe_config", Description: "Read only \u202eetirw\u202c\u200b status"}}})
	c := r.must(conn.Input{Name: "Bidi MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "none", Allow: []string{f.URL + "/mcp"}, Enabled: true})
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	tools := r.get(c.ID).Tools
	if len(tools) != 1 || tools[0].Description != "Read only etirw status" {
		t.Fatalf("tools %+v", tools)
	}
	for _, tl := range tools {
		if strings.ContainsFunc(tl.Description, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
			t.Errorf("tool %s keeps a format character: %q", tl.Name, tl.Description)
		}
	}
}

// M3. The whole Test has a budget of its own, whatever the request's context says: a device that never answers ends it.
func TestTestHasABudgetOfItsOwn(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { <-req.Context().Done() }))
	r.svc.SetTestBudgetForTest(300 * time.Millisecond)
	c := r.httpTo(f, "http")
	start := time.Now() // the context of the call has no deadline
	_, err := r.test(c.ID)
	_ = want(t, err, 502, "unreachable", "")
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("a device that never answers held the Test for %s", took)
	}
	if got := r.get(c.ID); got.Status != "error" {
		t.Fatalf("status %s: the failure is saved", got.Status)
	}
}

// M3. The budgets: 30 seconds for SSH, HTTP and RESTCONF, 45 for MCP (initialize, notification and the pages of the tool list).
func TestTestBudgetsPerKind(t *testing.T) {
	t.Parallel()
	for kind, d := range map[string]time.Duration{"http": 30, "ssh": 30, "netconf-restconf": 30, "automation": 30, "mcp-http": 45} {
		if got := conn.BudgetOf(kind); got != d*time.Second {
			t.Errorf("%s: %s, want %ds", kind, got, d)
		}
	}
}
