// Package read is the only way the AI reaches a device through a connection (D-93 (3), core INV-23, ai INV-14): the read tools of a
// connection, listed and called. It is a reader, not a writer: nothing here can send anything but a GET, one allow-listed command
// line or a call of an MCP tool the administrator marked read, and the `ai` module imports this package and nothing else of
// core/conn that holds a credential (a contract test walks the imports).
//
// The package trusts nothing it is handed. On every call it reloads the connection and refuses, with one and the same error, when
// the id is unknown, the connection is off or not ready, or the tool is unknown, off or not a read tool, so a write tool's name
// learns nothing from the answer. It checks the arguments at the edge (only the declared parameters, their types, sizes, no
// placeholder, no control character), dials through the policy dialer of core/conn/internal/transport with the pin of the first Test
// (never trust on first use, never a redirect), and runs at most one call at a time per connection, sharing the writer's turn so a
// read and a write never interleave on one session. A call has 15 seconds in all. What the device printed comes back cleaned and
// capped at 64 KiB; it is never logged. A failure is one cleaned line without any credential.
package read

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/cliban"
	"github.com/knt048/vedette/core/conn/internal/cred"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// Limits of one call (D-94).
const (
	// CallBudget is the time of one call in all: waiting for the connection's turn, dialling, the device's answer.
	CallBudget = transport.CallTimeout
	// listBudget is the time to ask one MCP server for its tools when listing.
	listBudget = 5 * time.Second
	// MaxOutput is what a call returns to the caller; more is cut and marked.
	MaxOutput = 64 << 10
	// Truncated ends an output that was cut.
	Truncated = "\n[output truncated]"

	maxArgsJSON = 8 << 10 // the arguments of a call, encoded
	maxString   = 2048    // one string of the arguments
	maxPath     = 512
	maxCommand  = 512
	maxQuery    = 16 // keys of the query of an HTTP read
	maxDepth    = 6  // nesting of the arguments of an MCP tool
)

// ErrUnavailable is the one refusal for an id that is not a connection, a connection that is off or not ready, and a tool that is
// unknown, off or not a read tool.
var ErrUnavailable = errors.New("that read tool is not available")

// ReadTool is one thing the AI may read: a read tool that is on, on a connection that is on and ready. It holds no credential, no
// address and no header.
type ReadTool struct { //nolint:revive // the name the ai module asks for (#114): read.ReadTool
	ConnectionID   string          `json:"connection_id"`
	ConnectionName string          `json:"connection_name"`
	Kind           string          `json:"kind"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Schema         json.RawMessage `json:"schema"` // the arguments of CallRead, as a JSON schema (an MCP tool: the server's, capped)
}

// Config wires a Reader.
type Config struct {
	Conns *conn.Service
	Log   *slog.Logger // nil: slog.Default()
}

// Reader lists and calls read tools.
type Reader struct {
	c      *conn.Service
	log    *slog.Logger
	budget time.Duration // CallBudget; tests shorten it
}

// New returns a Reader.
func New(c Config) (*Reader, error) {
	if c.Conns == nil {
		return nil, errors.New("read: Config needs Conns")
	}
	l := c.Log
	if l == nil {
		l = slog.Default()
	}
	return &Reader{c: c.Conns, log: l, budget: CallBudget}, nil
}

type actorKey struct{}

// WithActor says who is calling, for the log line of the call: "ai:<job>".
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

var actorRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}:[A-Za-z0-9_.:-]{1,64}$`)

func actorOf(ctx context.Context) string {
	if a, _ := ctx.Value(actorKey{}).(string); actorRE.MatchString(a) {
		return a
	}
	return "unknown"
}

// readTool is the one read tool of a kind that has a fixed one; an MCP server's tools are its own.
func readTool(kind string) string {
	switch kind {
	case conn.KindHTTP:
		return "fetch_url"
	case conn.KindRESTCONF:
		return "get_config"
	case conn.KindAutomation:
		return "list_jobs"
	case conn.KindSSH:
		return "run_allowed_command"
	}
	return ""
}

const (
	httpSchema = `{"type":"object","properties":{"path":{"type":"string","description":"Path under the connection's address, for example /api/status"},` +
		`"query":{"type":"object","additionalProperties":{"type":"string"},"description":"Query parameters"}},"additionalProperties":false}`
	sshSchema = `{"type":"object","properties":{"command":{"type":"string","description":"One command from the connection's allow list, written exactly"}},` +
		`"required":["command"],"additionalProperties":false}`
	noSchema = `{"type":"object"}`
)

// usable is what the connection must be for anything to be read through it.
func usable(c conn.Connection) bool {
	return c.Enabled && conn.NotReady(c) == "" && c.Pin != nil
}

// readable is the tool t of c when it is a read tool that is on and a tool this package can run; ok false otherwise.
func readable(c conn.Connection, name string) bool {
	if !usable(c) {
		return false
	}
	for _, t := range c.Tools {
		if t.Name != name || t.Access != "read" || !t.Enabled {
			continue
		}
		return c.Kind == conn.KindMCP || name == readTool(c.Kind)
	}
	return false
}

// ListReadTools lists the read tools that are on, on the connections that are on and ready. An MCP tool carries the server's input
// schema, asked for now (at most 5 seconds per server): one the server does not list any more, or a server that does not answer, adds
// nothing, because it could not be called either.
func (r *Reader) ListReadTools(ctx context.Context) ([]ReadTool, error) {
	conns, err := r.c.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("read: connections: %w", err)
	}
	out := []ReadTool{}
	for _, c := range conns {
		if !usable(c) {
			continue
		}
		var live map[string]transport.MCPTool
		for _, t := range c.Tools {
			if !readable(c, t.Name) {
				continue
			}
			rt := ReadTool{ConnectionID: c.ID, ConnectionName: c.Name, Kind: c.Kind, Name: t.Name, Description: t.Description}
			switch c.Kind {
			case conn.KindSSH:
				rt.Schema = json.RawMessage(sshSchema)
			case conn.KindMCP:
				if live == nil {
					live = r.discover(ctx, c)
				}
				m, ok := live[t.Name]
				if !ok {
					continue
				}
				rt.Schema = m.Schema
				if rt.Schema == nil {
					rt.Schema = json.RawMessage(noSchema)
				}
			default:
				rt.Schema = json.RawMessage(httpSchema)
			}
			out = append(out, rt)
		}
	}
	return out, nil
}

// discover asks an MCP server for its tools; nil when it cannot be asked.
func (r *Reader) discover(ctx context.Context, c conn.Connection) map[string]transport.MCPTool {
	ctx, cancel := context.WithTimeout(ctx, listBudget)
	defer cancel()
	release, ok := r.c.LockConn(ctx, cred.Key{}, c.ID)
	if !ok {
		return nil
	}
	defer release()
	if cur, err := r.c.Get(ctx, c.ID); err != nil || cur.Fingerprint() != c.Fingerprint() || !usable(cur) {
		return nil
	}
	secret, err := r.c.OpenCredential(ctx, cred.Key{}, c)
	if err != nil {
		return nil
	}
	cl, auth := r.client(c, secret)
	m := transport.NewMCP(cl, c.Target, auth)
	defer m.Close(context.WithoutCancel(ctx))
	if m.Initialize(ctx) != nil {
		return nil
	}
	tools, err := m.ListTools(ctx)
	if err != nil {
		return nil
	}
	out := map[string]transport.MCPTool{}
	for _, t := range tools {
		out[t.Name] = t
	}
	return out
}

// client is the HTTPS client of a connection: the pin of the first Test or the roots decide, never trust on first use.
func (r *Reader) client(c conn.Connection, secret secrets.Value) (*transport.Client, transport.Auth) {
	acc := r.c.WriteAccess(cred.Key{})
	pin := ""
	if c.Pin != nil && c.Pin.Kind == "tls_sha256" {
		pin = c.Pin.Value
	}
	cl := transport.NewHTTPS(transport.HTTPSConfig{Dialer: acc.Dialer, Pin: pin, TOFU: false, Roots: acc.Roots})
	auth := transport.Auth{Type: c.Auth.Type, Secret: secret}
	if c.Username != nil {
		auth.Username = *c.Username
	}
	return cl, auth
}

// CallRead runs one read tool and returns what it printed, cleaned and capped. It records the connection, the tool and the actor
// ("ai:<job>", from WithActor) in the log, never the arguments or the output.
func (r *Reader) CallRead(ctx context.Context, connID, tool string, args map[string]any) (string, error) {
	start := time.Now()
	out, err := r.call(ctx, connID, tool, args)
	outcome := "ok"
	switch {
	case errors.Is(err, ErrUnavailable):
		outcome = "refused"
	case err != nil:
		outcome = "failed"
	}
	r.log.LogAttrs(ctx, slog.LevelInfo, "conn.read", slog.String("connection_id", logID(connID)), slog.String("tool", logID(tool)),
		slog.String("actor", actorOf(ctx)), slog.String("outcome", outcome), slog.Int("bytes", len(out)), slog.Duration("took", time.Since(start).Round(time.Millisecond)))
	return out, err
}

// logID keeps a caller's text from reshaping a log line.
func logID(s string) string { return transport.CleanLine(s) }

func (r *Reader) call(ctx context.Context, connID, tool string, args map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.budget)
	defer cancel()
	// An id that is not a connection is refused before it can cost a lock.
	c, err := r.c.Get(ctx, connID)
	if err != nil {
		return "", loadFailure(err)
	}
	if !readable(c, tool) {
		return "", ErrUnavailable
	}
	release, ok := r.c.LockConn(ctx, cred.Key{}, connID)
	if !ok {
		return "", errors.New("another call on this connection did not finish in time")
	}
	defer release()
	c, err = r.c.Get(ctx, connID) // fresh: what the connection is now, after waiting for its turn
	if err != nil {
		return "", loadFailure(err)
	}
	if !readable(c, tool) {
		return "", ErrUnavailable
	}
	a, err := normalize(args)
	if err != nil {
		return "", err
	}
	var req request
	switch c.Kind {
	case conn.KindSSH:
		req, err = sshRequest(c, a)
	case conn.KindMCP:
		req = request{args: a}
	default:
		req, err = httpRequest(c, a)
	}
	if err != nil {
		return "", err
	}
	secret, err := r.c.OpenCredential(ctx, cred.Key{}, c)
	if err != nil {
		return "", errors.New("the sign-in of the connection could not be read")
	}
	redact := redactions(c, secret)
	var raw string
	switch c.Kind {
	case conn.KindSSH:
		raw, err = r.ssh(ctx, c, secret, req)
	case conn.KindMCP:
		raw, err = r.mcp(ctx, c, secret, tool, req, redact)
	default:
		raw, err = r.https(ctx, c, secret, req)
	}
	if err != nil {
		return "", failure(err, c, redact)
	}
	text, cut := transport.CleanText(raw, MaxOutput, redact...)
	if cut {
		text += Truncated
	}
	return text, nil
}

func loadFailure(err error) error {
	if e, ok := apierr.As(err); ok && e.Status == http.StatusNotFound {
		return ErrUnavailable
	}
	return errors.New("the connection could not be read")
}

// request is a read that passed the checks of its kind.
type request struct {
	url     string         // HTTP kinds: the whole address
	command string         // SSH: the one line
	args    map[string]any // MCP: the typed arguments
}

var (
	placeholderRE = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*\}|<(seq|previous_vlan|found_id|expiry_s|timeout|rules_before)>`)
	queryKeyRE    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
	encodedRE     = regexp.MustCompile(`(?i)%(2f|5c|2e)`)
)

// shellChars may never be in a command (response INV-14b, SYS-1), the same as the writer's.
const shellChars = ";|&$`<>()\\!~^"

// plainText refuses a string that holds a control character, a bidi override or a zero-width one, a placeholder that was not filled
// in, or more than maxString characters.
func plainText(s string) error {
	switch {
	case len(s) > maxString:
		return fmt.Errorf("a value is longer than %d characters", maxString)
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }):
		return errors.New("a value holds a control character")
	case placeholderRE.MatchString(s):
		return errors.New("a value still holds a placeholder that is not filled in")
	}
	return nil
}

// normalize makes the arguments typed JSON (numbers stay as written) and refuses more than maxArgsJSON bytes.
func normalize(args map[string]any) (map[string]any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, errors.New("the arguments are not JSON")
	}
	if len(b) > maxArgsJSON {
		return nil, fmt.Errorf("the arguments are larger than %d KB", maxArgsJSON>>10)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("the arguments are not a JSON object")
	}
	if err := walk(m, 0); err != nil {
		return nil, err
	}
	return m, nil
}

// walk checks every key and every string of the arguments.
func walk(v any, depth int) error {
	if depth > maxDepth {
		return errors.New("the arguments are nested too deep")
	}
	switch x := v.(type) {
	case string:
		return plainText(x)
	case map[string]any:
		for k, e := range x {
			if err := plainText(k); err != nil {
				return err
			}
			if err := walk(e, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := walk(e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// only refuses an argument that the tool does not declare.
func only(a map[string]any, allowed ...string) error {
	for k := range a {
		ok := false
		for _, n := range allowed {
			ok = ok || n == k
		}
		if !ok {
			return fmt.Errorf("the tool has no argument %q", transport.CleanLine(k))
		}
	}
	return nil
}

// httpRequest builds the address of a read of an HTTP kind: the scheme, host and port are the connection's, the path goes under its
// address, and the result must also be under an entry of the allow-list, by the rule of the writer (conn.AllowsURL). A dot segment,
// an empty segment, a backslash and any percent escape are refused rather than resolved: what is checked is what is sent.
func httpRequest(c conn.Connection, a map[string]any) (request, error) {
	if err := only(a, "path", "query"); err != nil {
		return request{}, err
	}
	p := ""
	if v, ok := a["path"]; ok {
		s, isStr := v.(string)
		if !isStr {
			return request{}, errors.New("path is a string")
		}
		p = s
	}
	var esc strings.Builder
	if p != "" {
		if len(p) > maxPath || p[0] != '/' || strings.ContainsAny(p, `\?#%`) || encodedRE.MatchString(p) {
			return request{}, errors.New("path must start with / and hold no backslash, ?, # or % escape")
		}
		segs := strings.Split(p[1:], "/")
		for i, s := range segs {
			if s == "." || s == ".." || s == "" && i < len(segs)-1 {
				return request{}, errors.New("path holds a dot or an empty segment")
			}
			esc.WriteByte('/')
			esc.WriteString(url.PathEscape(s))
		}
	}
	raw := strings.TrimRight(c.Target, "/") + esc.String()
	if v, ok := a["query"]; ok {
		q, isMap := v.(map[string]any)
		if !isMap || len(q) > maxQuery {
			return request{}, fmt.Errorf("query is an object of at most %d parameters", maxQuery)
		}
		vals := url.Values{}
		for k, e := range q {
			if !queryKeyRE.MatchString(k) {
				return request{}, errors.New("a query parameter name is not valid")
			}
			switch x := e.(type) {
			case string:
				vals.Set(k, x)
			case json.Number:
				vals.Set(k, x.String())
			case bool:
				vals.Set(k, fmt.Sprint(x))
			default:
				return request{}, errors.New("a query parameter is a string, a number or true or false")
			}
		}
		if len(vals) > 0 {
			raw += "?" + vals.Encode()
		}
	}
	if !conn.AllowsURL(c, raw) {
		return request{}, errors.New("the address is outside the connection's address and its allow-list")
	}
	return request{url: raw}, nil
}

// sshRequest checks the one command: a line of printable characters that is exactly an entry of the allow-list, that holds none of
// the characters a command may not hold and that the shared list of commands that change a device does not name.
func sshRequest(c conn.Connection, a map[string]any) (request, error) {
	if err := only(a, "command"); err != nil {
		return request{}, err
	}
	cmd, ok := a["command"].(string)
	if !ok {
		return request{}, errors.New("command is required and is a string")
	}
	switch { // before anything is trimmed: a line break at the end is still a line break
	case strings.ContainsFunc(cmd, unicode.IsControl):
		return request{}, errors.New("the command is one line of printable characters")
	}
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "":
		return request{}, errors.New("the command is empty")
	case len(cmd) > maxCommand:
		return request{}, fmt.Errorf("the command is longer than %d characters", maxCommand)
	case strings.ContainsAny(cmd, shellChars):
		return request{}, errors.New("the command holds a character that a command may not hold")
	}
	listed := false
	for _, e := range c.Allow {
		listed = listed || strings.TrimSpace(e) == cmd
	}
	if !listed {
		return request{}, errors.New("the command is not on the connection's allow-list")
	}
	if bad, err := cliban.ReadOnlyProblem([]string{cmd}); err != nil || bad != "" {
		return request{}, errors.New("the command can change the device")
	}
	return request{command: cmd}, nil
}

// redactions are the strings of the sign-in that must not appear in any text.
func redactions(c conn.Connection, secret secrets.Value) []string {
	user := ""
	if c.Username != nil {
		user = *c.Username
	}
	// The whole Basic header value first: when the user name is a multiple of three bytes long, the base64 of the password alone
	// is also its tail, and replacing that first would leave the head behind.
	var r []string
	if c.Auth.Type == conn.AuthBasic {
		r = append(r, base64.StdEncoding.EncodeToString([]byte(user+":"+secret.Reveal())), user+":")
	}
	return append(r, secret.Reveal(), user)
}

func (r *Reader) https(ctx context.Context, c conn.Connection, secret secrets.Value, req request) (string, error) {
	cl, auth := r.client(c, secret)
	accept := "application/json"
	if c.Kind == conn.KindRESTCONF {
		accept = "application/yang-data+json"
	}
	s, err := cl.Open(ctx, auth, transport.Request{Method: http.MethodGet, URL: req.url, Header: http.Header{"Accept": {accept}}})
	if err != nil {
		return "", err
	}
	defer s.Close()
	if s.Status < 200 || s.Status >= 300 { // a redirect is not followed and its body is not read; an error page says nothing the AI needs
		return "", &transport.DeviceError{Msg: fmt.Sprintf("the device answered HTTP %d", s.Status)}
	}
	body, err := readCapped(s.Body)
	if err != nil {
		return "", err
	}
	return body, nil
}

// readCapped reads what a device printed: up to twice what is returned, so that a secret the device echoes is replaced before the cut.
func readCapped(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 2*MaxOutput))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *Reader) mcp(ctx context.Context, c conn.Connection, secret secrets.Value, tool string, req request, redact []string) (string, error) {
	cl, auth := r.client(c, secret)
	m := transport.NewMCP(cl, c.Target, auth)
	defer m.Close(context.WithoutCancel(ctx))
	if err := m.Initialize(ctx); err != nil {
		return "", err
	}
	// The arguments are held to the schema the server gives now, and a tool the server does not list is not called.
	tools, err := m.ListTools(ctx)
	if err != nil {
		return "", err
	}
	var found *transport.MCPTool
	for i := range tools {
		if tools[i].Name == tool {
			found = &tools[i]
		}
	}
	if found == nil {
		return "", &transport.DeviceError{Msg: "the server does not offer this tool"}
	}
	if err := checkSchema(found.Schema, req.args); err != nil {
		return "", &argError{err}
	}
	out, err := m.CallTool(ctx, tool, req.args)
	if err != nil {
		return "", err
	}
	if out.IsError {
		return "", &transport.DeviceError{Msg: "the server reported an error: " + transport.CleanLine(out.Text, redact...)}
	}
	return strings.TrimRight(out.Text, "\n"), nil // CallTool ends each text part with a line break
}

// argError is an argument refused: nothing was sent for it, and its text is ours.
type argError struct{ error }

func (r *Reader) ssh(ctx context.Context, c conn.Connection, secret secrets.Value, req request) (string, error) {
	cfg := transport.SSHConfig{Dialer: r.c.WriteAccess(cred.Key{}).Dialer, TOFU: false}
	if c.Username != nil {
		cfg.Username = *c.Username
	}
	if c.Auth.Type == conn.AuthKey {
		cfg.Key = secret
	} else {
		cfg.Password = secret
	}
	if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
		cfg.HostKey = c.Pin.Value
	}
	if cfg.HostKey == "" {
		return "", errors.New("the host key of the device is not pinned yet")
	}
	sess, err := transport.DialSSH(ctx, c.Target, cfg)
	if err != nil {
		return "", err
	}
	defer sess.Close()
	return sess.Run(ctx, req.command) // one line, then the session closes
}

// failure turns an error into one cleaned line without any credential.
func failure(err error, c conn.Connection, redact []string) error {
	var re *transport.RefusedError
	var de *transport.DeviceError
	var ae *argError
	switch {
	case errors.As(err, &ae):
		return errors.New(transport.CleanLine(ae.Error(), redact...))
	case errors.As(err, &re):
		return errors.New(transport.CleanLine(re.Error(), redact...))
	case errors.Is(err, transport.ErrPinMismatch):
		what := "certificate"
		if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
			what = "host key"
		}
		return fmt.Errorf("the %s of the device is not the one pinned at the first test, so nothing was sent", what)
	case errors.Is(err, transport.ErrUnverified):
		return errors.New("the certificate of the device is not trusted and nothing is pinned for it, so nothing was sent")
	case errors.As(err, &de):
		return errors.New(transport.CleanLine(de.Msg, redact...))
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return errors.New("timed out")
	}
	if e := transport.CleanLine(err.Error(), redact...); e != "" {
		return errors.New(e)
	}
	return errors.New("the device could not be reached")
}
