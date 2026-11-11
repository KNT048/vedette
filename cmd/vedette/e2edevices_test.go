package main

// The devices of the box of the real-backend end-to-end run (WP-30 slice 5, D-93/D-94): an HTTPS server, an SSH server and an MCP server in
// this process, on loopback, reachable only under their own names (conntest.AllowLoopback): a connection saved with "devN.device.test" in its
// target reaches the fake, while the address policy still refuses 127.0.0.1 and the box's own address typed by anybody. ready.json carries the
// names, targets and logins; the specs read what each device received and rotate its certificate or host key through the control server:
//
//	GET  /devices/{http|ssh|mcp}/requests  -> what the device received so far (HTTP: method, path, Authorization; SSH: command lines and
//	                                          the count of sign-ins; MCP: the JSON-RPC calls)
//	POST /devices/{http|ssh|mcp}/rotate    -> a new certificate or host key: the pin of the old one no longer matches
//
// The devices belong to TestE2EBox (they live as long as its t); a box without them (the bare box, the harness test) has no such routes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn/conntest"
)

// e2eDeviceLogin is what a spec types into a connection of the device.
type e2eDeviceLogin struct {
	Target   string `json:"target"`
	Username string `json:"username,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

type e2eDevices struct {
	https *conntest.HTTPS
	ssh   *conntest.SSH
	mcp   *conntest.MCP
	t     testing.TB
}

const (
	e2eSSHUser = "e2e-ro"
	e2eSSHPass = "e2e-ssh-pass-0123456789" //nolint:gosec // a test value of the fake device
	e2eToken   = "e2e-api-token-0123456789"
)

// startE2EDevices starts the three fakes. Their names are in the returned map (ready.json "devices").
func startE2EDevices(t testing.TB) (*e2eDevices, map[string]e2eDeviceLogin) {
	d := &e2eDevices{t: t}
	d.https = conntest.NewHTTPS(t, nil)
	d.ssh = conntest.NewSSH(t, conntest.SSHOpts{User: e2eSSHUser, Password: e2eSSHPass, Prompt: "E2E-Switch"})
	d.mcp = conntest.NewMCP(t, conntest.MCPOpts{})
	return d, map[string]e2eDeviceLogin{
		"http": {Target: d.https.URL, Secret: e2eToken},
		"ssh":  {Target: d.ssh.Addr, Username: e2eSSHUser, Secret: e2eSSHPass},
		"mcp":  {Target: d.mcp.URL, Secret: e2eToken},
	}
}

// routes registers the two device calls on the control mux.
func (d *e2eDevices) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /devices/{name}/requests", func(w http.ResponseWriter, r *http.Request) {
		var out any
		switch r.PathValue("name") {
		case "http":
			reqs := []map[string]string{}
			for _, q := range d.https.Requests() {
				reqs = append(reqs, map[string]string{"method": q.Method, "path": q.Path, "authorization": q.Header.Get("Authorization")})
			}
			out = map[string]any{"requests": reqs}
		case "ssh":
			out = map[string]any{"lines": append([]string{}, d.ssh.Lines()...), "logins": d.ssh.Logins(), "auth_calls": d.ssh.AuthCalls()}
		case "mcp":
			calls := []map[string]string{}
			for _, c := range d.mcp.Calls() {
				calls = append(calls, map[string]string{"http": c.HTTPMethod, "rpc": c.RPCMethod, "authorization": c.Authorization})
			}
			out = map[string]any{"calls": calls}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /devices/{name}/rotate", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "http":
			d.https.Rotate(d.t)
		case "ssh":
			d.ssh.RotateHostKey(d.t)
		case "mcp":
			d.mcp.Rotate(d.t)
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// TestE2EDevicesRoutes (runs in CI): the three fakes start, the logins in ready.json name them, the control routes answer, and a rotation
// is accepted. The HTTP fake has not been asked yet, so it has seen nothing.
func TestE2EDevicesRoutes(t *testing.T) {
	d, logins := startE2EDevices(t)
	for _, k := range []string{"http", "ssh", "mcp"} {
		if logins[k].Target == "" || logins[k].Secret == "" {
			t.Fatalf("%s login = %+v", k, logins[k])
		}
	}
	mux := http.NewServeMux()
	d.routes(mux)
	call := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	for _, k := range []string{"http", "ssh", "mcp"} {
		if w := call("GET", "/devices/"+k+"/requests"); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("GET %s requests = %d %q", k, w.Code, w.Body.String())
		}
		if w := call("POST", "/devices/"+k+"/rotate"); w.Code != 204 {
			t.Errorf("POST %s rotate = %d", k, w.Code)
		}
	}
	if w := call("GET", "/devices/nope/requests"); w.Code != 404 {
		t.Errorf("unknown device = %d", w.Code)
	}
}
