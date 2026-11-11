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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
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
	// CallBudget is the time of one call in all: waiting for the connection's turn, dialling, the device's answer, closing.
	CallBudget = transport.CallTimeout
	// ListBudget is the time of one ListReadTools in all: the MCP servers are asked in parallel under it.
	ListBudget = 8 * time.Second
	// CacheTTL is how long the tools an MCP server listed are remembered.
	CacheTTL = 60 * time.Second
	// MaxOutput is what a call returns to the caller; more is cut and marked.
	MaxOutput = 64 << 10
	// Truncated ends an output that was cut.
	Truncated = "\n[output truncated]"
	// RateCap is how many calls one connection takes in RateWindow (spec action-templates 9.2).
	RateCap    = 30
	RateWindow = time.Minute

	maxArgsJSON = 8 << 10 // the arguments of a call, encoded
	maxString   = 2048    // one string of the arguments
	maxCommand  = 512
	maxDepth    = 6 // nesting of the arguments of an MCP tool
	closeFloor  = time.Second
)

// ErrUnavailable is the one refusal for an id that is not a connection, a connection that is off or not ready, and a tool that is
// unknown, off or not a read tool. A connection over its rate cap gets the same error (and its own outcome in the log).
var ErrUnavailable = errors.New("that read tool is not available")

// ErrConnectionChanged is a connection edited while the call was being prepared: nothing was sent.
var ErrConnectionChanged = errors.New("connection_changed: the connection was edited while the call was prepared, so nothing was sent")

// rateLimited is ErrUnavailable to the caller and its own outcome to the log.
type rateLimited struct{}

func (rateLimited) Error() string        { return ErrUnavailable.Error() }
func (rateLimited) Is(target error) bool { return target == ErrUnavailable }

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
	c               *conn.Service
	log             *slog.Logger
	budget          time.Duration // CallBudget; tests shorten it
	listBudget      time.Duration // ListBudget; tests shorten it
	afterCredential func()        // tests edit the connection here

	mu    sync.Mutex
	cache map[string]cacheEntry // the tools an MCP server listed, by connection
	hits  map[string][]time.Time
}

// cacheEntry is what discovery learned of an MCP server, kept for CacheTTL while the connection is the same version.
type cacheEntry struct {
	at    time.Time
	fp    string
	tools map[string]liveTool // nil: the server could not be asked
}

// liveTool is a tool as the server lists it now: its identity and the schema the AI is shown.
type liveTool struct {
	ident  string
	schema json.RawMessage
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
	return &Reader{c: c.Conns, log: l, budget: CallBudget, listBudget: ListBudget, cache: map[string]cacheEntry{}, hits: map[string][]time.Time{}}, nil
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

// noArgs is the schema of a tool that takes none (also: a tool whose schema is missing, not an object or too large).
const noArgs = `{"type":"object","properties":{},"additionalProperties":false}`

// enumSchema is the schema of a tool whose one argument is one of an exact list of values.
func enumSchema(arg, desc string, values []string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"type":                 "object",
		"properties":           map[string]any{arg: map[string]any{"type": "string", "enum": values, "description": desc}},
		"required":             []string{arg},
		"additionalProperties": false,
	})
	return b
}

// usable is what the connection must be for anything to be read through it.
func usable(c conn.Connection) bool {
	return c.Enabled && conn.NotReady(c) == "" && c.Pin != nil
}

// readable is whether name is a read tool of c that is on and that this package can run.
func readable(c conn.Connection, name string) bool {
	if !usable(c) {
		return false
	}
	for _, t := range c.Tools {
		if t.Name != name || t.Access != "read" || !t.Enabled {
			continue
		}
		if c.Kind == conn.KindMCP {
			return t.Ident != "" // an MCP tool is vouched for as the Test saw it
		}
		return name == readTool(c.Kind)
	}
	return false
}

// ListReadTools lists the read tools that are on, on the connections that are on and ready. An HTTP tool offers the exact addresses
// of the allow-list, an SSH tool the exact commands. An MCP tool carries the part of the server's input schema that CallRead
// enforces, and is listed only while the server still describes it as it did when the administrator set it to read. The MCP servers
// are asked in parallel under one budget of ListBudget, once per connection, and what they said is remembered for CacheTTL; a server
// that does not answer adds nothing, because it could not be called either.
func (r *Reader) ListReadTools(ctx context.Context) ([]ReadTool, error) {
	conns, err := r.c.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("read: connections: %w", err)
	}
	lctx, cancel := context.WithTimeout(ctx, r.listBudget)
	defer cancel()
	live := map[string]map[string]liveTool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range conns {
		if c.Kind != conn.KindMCP || !usable(c) || !slices.ContainsFunc(c.Tools, func(t conn.Tool) bool { return readable(c, t.Name) }) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := r.discover(lctx, c)
			mu.Lock()
			live[c.ID] = d
			mu.Unlock()
		}()
	}
	wg.Wait()
	out := []ReadTool{}
	for _, c := range conns {
		if !usable(c) {
			continue
		}
		for _, t := range c.Tools {
			if !readable(c, t.Name) {
				continue
			}
			rt := ReadTool{ConnectionID: c.ID, ConnectionName: c.Name, Kind: c.Kind, Name: t.Name, Description: t.Description}
			switch c.Kind {
			case conn.KindSSH:
				cmds := sshRunnable(c)
				if len(cmds) == 0 {
					continue
				}
				rt.Schema = enumSchema("command", "One command that the connection allows, written exactly", cmds)
			case conn.KindMCP:
				m, ok := live[c.ID][t.Name]
				if !ok || m.ident != t.Ident {
					continue
				}
				rt.Schema = m.schema
			default:
				es := httpEntries(c)
				if len(es) == 0 {
					continue
				}
				rels := make([]string, len(es))
				for i, e := range es {
					rels[i] = e.rel
				}
				rt.Schema = enumSchema("path", "One address that the connection allows, written exactly", rels)
			}
			out = append(out, rt)
		}
	}
	return out, nil
}

// discover asks an MCP server for its tools, or answers from what it said less than CacheTTL ago while the connection is the same
// version. It takes no turn on the connection: it only reads the list, and a call must not wait behind a listing. nil: not answered.
func (r *Reader) discover(ctx context.Context, c conn.Connection) map[string]liveTool {
	r.mu.Lock()
	e, ok := r.cache[c.ID]
	r.mu.Unlock()
	if ok && e.fp == c.Fingerprint() && time.Since(e.at) < CacheTTL {
		return e.tools
	}
	tools := r.fetch(ctx, c)
	r.mu.Lock()
	r.cache[c.ID] = cacheEntry{at: time.Now(), fp: c.Fingerprint(), tools: tools}
	r.mu.Unlock()
	return tools
}

func (r *Reader) fetch(ctx context.Context, c conn.Connection) map[string]liveTool {
	secret, err := r.c.OpenCredential(ctx, cred.Grant(), c)
	if err != nil {
		return nil
	}
	cl, auth := r.client(c, secret)
	m := transport.NewMCP(cl, c.Target, auth)
	defer closeMCP(ctx, m)
	if m.Initialize(ctx) != nil {
		return nil
	}
	tools, err := m.ListTools(ctx)
	if err != nil {
		return nil
	}
	redact := redactions(c, secret)
	out := map[string]liveTool{}
	for _, t := range tools {
		if schema, ok := publicSchema(t.Schema, redact); ok {
			out[t.Name] = liveTool{ident: conn.ToolIdent(t.Description, t.Schema), schema: schema}
		}
	}
	return out
}

// closeMCP ends a session within what is left of the call's budget, and at least closeFloor.
func closeMCP(ctx context.Context, m *transport.MCP) {
	left := closeFloor
	if dl, ok := ctx.Deadline(); ok {
		left = max(time.Until(dl), closeFloor)
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), left)
	defer cancel()
	m.Close(c)
}

// client is the HTTPS client of a connection: the pin of the first Test or the roots decide, never trust on first use.
func (r *Reader) client(c conn.Connection, secret secrets.Value) (*transport.Client, transport.Auth) {
	acc := r.c.WriteAccess(cred.Grant())
	pin := ""
	if c.Pin != nil && c.Pin.Kind == "tls_sha256" {
		pin = c.Pin.Value
	}
	cl := transport.NewHTTPS(transport.HTTPSConfig{Dialer: acc.Dialer, Pin: pin, TOFU: false, Roots: acc.Roots})
	auth := transport.Auth{Type: c.Auth.Type, Header: deref(c.Auth.Header), Secret: secret}
	if c.Username != nil {
		auth.Username = *c.Username
	}
	return cl, auth
}

// allowed counts a call against the rate cap of its connection; false is over the cap.
func (r *Reader) allowed(id string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.hits[id][:0]
	for _, t := range r.hits[id] {
		if now.Sub(t) < RateWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) >= RateCap {
		r.hits[id] = kept
		return false
	}
	r.hits[id] = append(kept, now)
	return true
}

// CallRead runs one read tool and returns what it printed, cleaned and capped. It records the connection, the tool and the actor
// ("ai:<job>", from WithActor) in the log, never the arguments or the output.
func (r *Reader) CallRead(ctx context.Context, connID, tool string, args map[string]any) (string, error) {
	start := time.Now()
	out, err := r.call(ctx, connID, tool, args)
	outcome := "ok"
	switch {
	case errors.As(err, new(rateLimited)):
		outcome = "rate_limited"
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
	release, ok := r.c.LockConn(ctx, cred.Grant(), connID)
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
	if !r.allowed(connID) { // only a call that would reach the device counts
		return "", rateLimited{}
	}
	secret, err := r.c.OpenCredential(ctx, cred.Grant(), c)
	if err != nil {
		return "", errors.New("the sign-in of the connection could not be read")
	}
	if r.afterCredential != nil {
		r.afterCredential()
	}
	// The connection may have been edited while the credential was opened: what is sent is what was checked.
	if now, err := r.c.Get(ctx, connID); err != nil {
		return "", loadFailure(err)
	} else if now.Fingerprint() != c.Fingerprint() || !now.Enabled {
		return "", ErrConnectionChanged
	}
	redact := redactions(c, secret)
	var raw string
	var cut bool
	switch c.Kind {
	case conn.KindSSH:
		raw, cut, err = r.ssh(ctx, c, secret, req)
	case conn.KindMCP:
		raw, cut, err = r.mcp(ctx, c, secret, tool, req, redact)
	default:
		raw, cut, err = r.https(ctx, c, secret, req)
	}
	if err != nil {
		if ctx.Err() != nil { // the budget ended: what the transport saw while its session was being closed is a timeout
			return "", errors.New("timed out")
		}
		return "", failure(err, c, redact)
	}
	text, over := transport.CleanText(raw, MaxOutput, redact...)
	if cut || over {
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
	segmentRE     = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	queryRE       = regexp.MustCompile(`^[!-~]*$`)
	propNameRE    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
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
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("the tool has no argument %q", transport.CleanLine(k))
		}
	}
	return nil
}

// entry is an address the allow-list names, as the AI writes it (rel: the path and query after the host) and as it is sent (raw).
type entry struct{ rel, raw string }

// httpEntries are the addresses of c that a read may use: each entry of the allow-list that is under the target and has plain
// segments. A read of an HTTP kind is exactly one of them: some devices change state on a GET, so the administrator names every
// address that is safe to read, and nothing is built from what the AI writes (D-127, H1). The host is the connection's.
func httpEntries(c conn.Connection) []entry {
	t, err := url.Parse(c.Target)
	if err != nil || t.Host == "" {
		return nil
	}
	base := t.Scheme + "://" + t.Host
	var out []entry
	seen := map[string]bool{}
	for _, e := range c.Allow {
		u, err := url.Parse(e)
		if err != nil || u.User != nil || u.Fragment != "" || strings.Contains(e, "#") || !conn.AllowsURL(c, e) {
			continue
		}
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		if !plainPath(p) || !queryRE.MatchString(u.RawQuery) || strings.ContainsAny(u.RawQuery, `\`) {
			continue
		}
		rel := p
		if u.RawQuery != "" {
			rel += "?" + u.RawQuery
		}
		if seen[rel] || !conn.AllowsURL(c, base+rel) {
			continue
		}
		seen[rel] = true
		out = append(out, entry{rel: rel, raw: base + rel})
	}
	return out
}

// plainPath is a path of ASCII segments of [A-Za-z0-9._~-]: no escape, no ;, no whitespace, no empty segment but a last one, no dot
// segment and nothing that starts with "..".
func plainPath(p string) bool {
	if len(p) == 0 || p[0] != '/' {
		return false
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		switch {
		case s == "" && i == len(segs)-1:
		case s == "" || s == "." || strings.HasPrefix(s, ".."), !segmentRE.MatchString(s):
			return false
		}
	}
	return true
}

// httpRequest is the read of an HTTP kind: the one argument path must equal, character for character, one of the addresses of the
// allow-list (httpEntries). A query is allowed only as part of an entry; no key is free.
func httpRequest(c conn.Connection, a map[string]any) (request, error) {
	if err := only(a, "path"); err != nil {
		return request{}, err
	}
	p, ok := a["path"].(string)
	if !ok {
		return request{}, errors.New("path is required and is a string")
	}
	for _, e := range httpEntries(c) {
		if e.rel == p {
			return request{url: e.raw}, nil
		}
	}
	return request{}, errors.New("the path is not one of the addresses that the connection allows")
}

// sshProblem is why a line may not be typed as a read, or nil: one line of printable characters, none of the characters a command may
// not hold, and nothing that the shared list of commands that change a device names.
func sshProblem(cmd string) error {
	switch {
	case strings.ContainsFunc(cmd, unicode.IsControl):
		return errors.New("the command is one line of printable characters")
	case strings.TrimSpace(cmd) == "":
		return errors.New("the command is empty")
	case len(cmd) > maxCommand:
		return fmt.Errorf("the command is longer than %d characters", maxCommand)
	case strings.ContainsAny(cmd, shellChars):
		return errors.New("the command holds a character that a command may not hold")
	case placeholderRE.MatchString(cmd):
		return errors.New("the command still holds a placeholder that is not filled in")
	}
	if bad, err := cliban.ReadOnlyProblem([]string{cmd}); err != nil || bad != "" {
		return errors.New("the command can change the device")
	}
	return nil
}

// sshRunnable are the entries of the allow-list that may be run as a read.
func sshRunnable(c conn.Connection) []string {
	var out []string
	for _, e := range c.Allow {
		if e = strings.TrimSpace(e); sshProblem(e) == nil && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// sshRequest checks the one command: exactly an entry of the allow-list, and a line that sshProblem lets through. Nothing is trimmed
// before the line break check: a line break at the end is still a line break.
func sshRequest(c conn.Connection, a map[string]any) (request, error) {
	if err := only(a, "command"); err != nil {
		return request{}, err
	}
	cmd, ok := a["command"].(string)
	if !ok {
		return request{}, errors.New("command is required and is a string")
	}
	if err := sshProblem(cmd); err != nil {
		return request{}, err
	}
	cmd = strings.TrimSpace(cmd)
	if !slices.Contains(sshRunnable(c), cmd) {
		return request{}, errors.New("the command is not on the connection's allow-list")
	}
	return request{command: cmd}, nil
}

// redactions are the strings of the sign-in that must not appear in any text.
func redactions(c conn.Connection, secret secrets.Value) []string {
	user := ""
	if c.Username != nil {
		user = *c.Username
	}
	return transport.Secrets(c.Auth.Type, user, secret.Reveal())
}

func (r *Reader) https(ctx context.Context, c conn.Connection, secret secrets.Value, req request) (string, bool, error) {
	cl, auth := r.client(c, secret)
	accept := "application/json"
	if c.Kind == conn.KindRESTCONF {
		accept = "application/yang-data+json"
	}
	s, err := cl.Open(ctx, auth, transport.Request{Method: http.MethodGet, URL: req.url, Header: http.Header{"Accept": {accept}}})
	if err != nil {
		return "", false, err
	}
	defer s.Close()
	if s.Status < 200 || s.Status >= 300 { // a redirect is not followed and its body is not read; an error page says nothing the AI needs
		return "", false, &transport.DeviceError{Msg: fmt.Sprintf("the device answered HTTP %d", s.Status)}
	}
	return readCapped(s.Body)
}

// readCapped reads what a device printed: up to twice what is returned, so that a secret the device echoes is replaced before the cut.
// The second result says there was more.
func readCapped(r io.Reader) (string, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, 2*MaxOutput+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > 2*MaxOutput {
		return string(b[:2*MaxOutput]), true, nil
	}
	return string(b), false, nil
}

func (r *Reader) mcp(ctx context.Context, c conn.Connection, secret secrets.Value, tool string, req request, redact []string) (string, bool, error) {
	cl, auth := r.client(c, secret)
	m := transport.NewMCP(cl, c.Target, auth)
	defer closeMCP(ctx, m)
	if err := m.Initialize(ctx); err != nil {
		return "", false, err
	}
	// The tool is the one the administrator vouched for, as the server describes it now; the arguments are held to its schema.
	tools, err := m.ListTools(ctx)
	if err != nil {
		return "", false, err
	}
	var found *transport.MCPTool
	for i := range tools {
		if tools[i].Name == tool {
			found = &tools[i]
		}
	}
	if found == nil {
		return "", false, ErrUnavailable
	}
	for _, t := range c.Tools {
		if t.Name == tool && t.Ident != conn.ToolIdent(found.Description, found.Schema) {
			return "", false, ErrUnavailable // the server changed the tool since: test the connection again and set it again
		}
	}
	if err := checkSchema(found.Schema, req.args); err != nil {
		return "", false, &argError{err}
	}
	out, err := m.CallTool(ctx, tool, req.args)
	if err != nil {
		return "", false, err
	}
	if out.IsError {
		return "", false, &transport.DeviceError{Msg: "the server reported an error: " + transport.CleanLine(out.Text, redact...)}
	}
	return strings.TrimRight(out.Text, "\n"), out.Truncated, nil // CallTool ends each text part with a line break
}

// argError is an argument refused: nothing was sent for it, and its text is ours.
type argError struct{ error }

func (r *Reader) ssh(ctx context.Context, c conn.Connection, secret secrets.Value, req request) (string, bool, error) {
	cfg := transport.SSHConfig{Dialer: r.c.WriteAccess(cred.Grant()).Dialer, TOFU: false}
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
		return "", false, errors.New("the host key of the device is not pinned yet")
	}
	sess, err := transport.DialSSH(ctx, c.Target, cfg)
	if err != nil {
		return "", false, err
	}
	defer sess.Close()
	return sess.RunRead(ctx, req.command, 2*MaxOutput) // one line, pages followed, then the session closes
}

// failure turns an error into one cleaned line without any credential.
func failure(err error, c conn.Connection, redact []string) error {
	var re *transport.RefusedError
	var de *transport.DeviceError
	var ae *argError
	switch {
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrConnectionChanged):
		return err
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
