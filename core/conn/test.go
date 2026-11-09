package conn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// TestResult is what a successful Test answers (web/src/features/core/contract.ts ConnectorTestResult).
type TestResult struct {
	LatencyMS  int
	ToolsFound int
	Message    string
	Connection Connection
}

// dialer is the one way out of the box for a connection (D-94, core INV-23): every address is checked against the policy at the
// moment it is dialled, with the addresses of the box as they are then.
func (s *Service) dialer() *transport.Dialer {
	return &transport.Dialer{Refuse: func(ctx context.Context, a netip.Addr) string {
		var box []netip.Prefix
		if s.cfg.BoxAddrs != nil {
			box = s.cfg.BoxAddrs(ctx)
		}
		return RefusedAddr(a, box)
	}}
}

// outcome is what a probe learned.
type outcome struct {
	pin   *Pin   // the certificate or host key seen at a first use
	tools []Tool // MCP: the tools found
}

// Test reaches the device with one harmless read, over the transport of its kind, and saves what it learned (D-94):
//
//	http        GET the address
//	restconf    GET the RESTCONF root under the address
//	automation  GET the address (the API root)
//	ssh         sign in, open a session and read the prompt
//	mcp-http    initialize, then tools/list
//
// At the first success it pins the certificate that no public authority vouches for, or the host key (trust on first use); from
// then on a different one is refused before anything is sent. An MCP server's tools are saved as write tools that start off.
// The result, good or bad, is saved as status and last_test, with a connection.test audit row.
//
// guard is the caller's check that it may still do this (core: CheckAdmin). It runs before anything is sent, in a read-only
// transaction, and again inside the write transaction that saves the result. No network call happens inside a transaction.
// An unknown id is 404, a connection that is off is 409 connection_off (nothing is sent), a failure is 502: pin_mismatch,
// address_refused, device_error (the device answered, but said no) or unreachable. A connection edited while the test ran
// is 409 connection_changed and nothing is saved.
func (s *Service) Test(ctx context.Context, actor, id string, guard func(ctx context.Context, tx *sql.Tx) error) (TestResult, error) {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	if !cur.Enabled {
		return TestResult{}, connOff()
	}
	if err := s.guardReadOnly(ctx, guard); err != nil {
		return TestResult{}, err
	}
	var secret secrets.Value
	if cur.secretID != nil {
		if secret, err = s.vault.Open(ctx, s.cfg.DB.Reader(), *cur.secretID); err != nil {
			return TestResult{}, fmt.Errorf("conn: open credential: %w", err)
		}
	}

	start := s.now()
	out, perr := s.probe(ctx, cur, secret)
	latency := int(s.now().Sub(start) / time.Millisecond)
	if perr != nil && ctx.Err() != nil {
		return TestResult{}, ctx.Err() // the caller went away: nothing to save
	}
	var failure *apierr.Error
	if perr != nil {
		failure = describe(cur, perr, secret)
	}

	var res TestResult
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := guard(ctx, tx); err != nil {
			return err
		}
		q := coredb.New(tx)
		now, err := get(ctx, q, id)
		if err != nil {
			return err
		}
		switch {
		case !now.Enabled:
			return connOff()
		case now.Fingerprint() != cur.Fingerprint():
			return apierr.New(409, "connection_changed", "This connection was edited while the test ran, so the result was not saved. Test it again.")
		}
		stamp := store.FormatTS(s.now())
		next := now
		next.LastTest = &stamp
		detail := "ok"
		if failure != nil {
			next.Status, detail = "error", "failed: "+failure.Code
		} else {
			next.Status = "ok"
			if out.pin != nil && now.Pin == nil {
				p := *out.pin
				p.FirstSeen = stamp
				next.Pin = &p
				detail += ", pinned " + pinWord(p.Kind)
			}
			if cur.Kind == KindMCP {
				next.Tools = mergeFound(now.Tools, out.tools)
				detail += fmt.Sprintf(", %d tools", len(next.Tools))
			}
		}
		if len(changedSecurityFields(now, next, false)) > 0 {
			next.UpdatedAt = s.nextStamp(now.UpdatedAt) // a new pin or new tools are a new connection to any request that waits on it
		}
		if n, err := q.UpdateConnection(ctx, updateParams(next)); err != nil || n == 0 {
			if err == nil {
				err = notFound()
			}
			return fmt.Errorf("conn: save test result: %w", err)
		}
		if !slices.Equal(now.Tools, next.Tools) {
			if err := q.DeleteConnectionTools(ctx, id); err != nil {
				return fmt.Errorf("conn: tools: %w", err)
			}
			if err := writeTools(ctx, q, id, next.Tools); err != nil {
				return err
			}
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "connection.test", Target: next.Name, Detail: detail}); err != nil {
			return err
		}
		if failure != nil {
			return nil // the failure is saved; it is returned below, after the commit
		}
		saved, err := get(ctx, q, id)
		if err != nil {
			return err
		}
		res = TestResult{LatencyMS: latency, ToolsFound: len(saved.Tools), Connection: saved}
		res.Message = message(saved, now.Pin == nil && saved.Pin != nil)
		return nil
	})
	if err != nil {
		return TestResult{}, err
	}
	if failure != nil {
		return TestResult{}, failure
	}
	return res, nil
}

func connOff() *apierr.Error {
	return apierr.New(409, "connection_off", "This connection is turned off, so nothing is sent to it. Turn it on, then test it.")
}

// guardReadOnly runs the caller's check in a read-only transaction: it must hold before the first byte leaves the box.
func (s *Service) guardReadOnly(ctx context.Context, guard func(ctx context.Context, tx *sql.Tx) error) error {
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("conn: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return guard(ctx, tx)
}

func pinWord(kind string) string {
	if kind == "ssh_hostkey" {
		return "host key"
	}
	return "certificate"
}

// message is the sentence of the answer, as the mock writes it: "Connected. 2 tools found (1 can change something)."
func message(c Connection, pinnedNow bool) string {
	n, w := len(c.Tools), 0
	for _, t := range c.Tools { // "can change something" counts every write tool, on or off
		if t.Access == "write" {
			w++
		}
	}
	noun := "tools"
	if n == 1 {
		noun = "tool"
	}
	msg := fmt.Sprintf("Connected. %d %s found (%d can change something).", n, noun, w)
	if pinnedNow {
		if c.Pin.Kind == "ssh_hostkey" {
			msg += " The host key is now pinned."
		} else {
			msg += " The certificate is now pinned."
		}
	}
	return msg
}

// describe turns what went wrong into the 502 the administrator sees. The words come from this package and from the transport's
// cleaned lines; the credential is removed once more, whatever the transport did.
func describe(c Connection, err error, secret secrets.Value) *apierr.Error {
	var re *transport.RefusedError
	var de *transport.DeviceError
	switch {
	case errors.Is(err, transport.ErrPinMismatch):
		what := "The certificate"
		if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
			what = "The SSH host key"
		}
		return apierr.New(502, "pin_mismatch", fmt.Sprintf(`%s of %s is not the one pinned at the first test. Nothing was sent. If you changed the device, edit this connection, turn on "Forget pinned key", save, then test again.`, what, c.Target))
	case errors.As(err, &re):
		return apierr.New(502, "address_refused", fmt.Sprintf("%s now points to %s, so Vedette did not connect. Check the name in your DNS.", c.Target, re.Why))
	case errors.As(err, &de):
		msg := transport.CleanLine(de.Msg, secret.Reveal(), deref(c.Username))
		return apierr.New(502, "device_error", fmt.Sprintf("%s was reached, but %s.", c.Target, strings.TrimRight(msg, ". ")))
	}
	return apierr.New(502, "unreachable", fmt.Sprintf("Could not connect to %s. Check the address, the box's network and the firewall.", c.Target))
}

// probe makes the read of the kind. It returns what to save on success and a transport error otherwise.
func (s *Service) probe(ctx context.Context, c Connection, secret secrets.Value) (outcome, error) {
	if c.Kind == KindSSH {
		return s.probeSSH(ctx, c, secret)
	}
	cl := transport.NewHTTPS(transport.HTTPSConfig{Dialer: s.dialer(), Pin: tlsPin(c.Pin), TOFU: true})
	auth := transport.Auth{Type: c.Auth.Type, Username: deref(c.Username), Secret: secret}
	var out outcome
	switch c.Kind {
	case KindMCP:
		m := transport.NewMCP(cl, c.Target, auth)
		defer m.Close(ctx)
		if err := m.Initialize(ctx); err != nil {
			return out, err
		}
		found, err := m.ListTools(ctx)
		if err != nil {
			return out, err
		}
		out.tools = discovered(found)
	default:
		url, accept := c.Target, "application/json"
		if c.Kind == KindRESTCONF {
			url, accept = restconfRoot(c.Target), "application/yang-data+json"
		}
		resp, err := cl.Do(ctx, auth, transport.Request{Method: http.MethodGet, URL: url, Header: http.Header{"Accept": {accept}}})
		if err != nil {
			return out, err
		}
		if err := readStatus(resp.Status); err != nil {
			return out, err
		}
	}
	if seen := cl.Seen(); c.Pin == nil && seen.LeafSHA256 != "" && !seen.SystemTrusted {
		out.pin = &Pin{Kind: "tls_sha256", Value: seen.LeafSHA256}
	}
	return out, nil
}

// readStatus is the verdict on the answer of a read: a device that says "not allowed" or "not found" or breaks has not passed.
func readStatus(status int) error {
	switch {
	case status < 400:
		return nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &transport.DeviceError{Msg: fmt.Sprintf("the device refused the sign-in (HTTP %d)", status)}
	}
	return &transport.DeviceError{Msg: fmt.Sprintf("the device answered HTTP %d", status)}
}

// restconfRoot is the RESTCONF root of a target: its own path when that already ends in /restconf, else /restconf under it.
func restconfRoot(target string) string {
	t := strings.TrimRight(target, "/")
	if strings.HasSuffix(t, "/restconf") {
		return t
	}
	return t + "/restconf"
}

func tlsPin(p *Pin) string {
	if p != nil && p.Kind == "tls_sha256" {
		return p.Value
	}
	return ""
}

func (s *Service) probeSSH(ctx context.Context, c Connection, secret secrets.Value) (outcome, error) {
	cfg := transport.SSHConfig{Dialer: s.dialer(), Username: deref(c.Username), TOFU: true}
	if c.Auth.Type == AuthKey {
		cfg.Key = secret
	} else {
		cfg.Password = secret
	}
	if c.Pin != nil && c.Pin.Kind == "ssh_hostkey" {
		cfg.HostKey = c.Pin.Value
	}
	sess, err := transport.DialSSH(ctx, c.Target, cfg)
	if err != nil {
		return outcome{}, err
	}
	defer sess.Close()
	var out outcome
	if c.Pin == nil {
		out.pin = &Pin{Kind: "ssh_hostkey", Value: sess.HostKey}
	}
	return out, nil
}

var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// discovered turns what an MCP server lists into tools: write tools that start off (D-94 (3)). The names and descriptions are the
// server's own words, so a name that is not a plain identifier is dropped, a description is cut to a line of 200 characters.
func discovered(found []transport.MCPTool) []Tool {
	var out []Tool
	seen := map[string]bool{}
	for _, f := range found {
		if !toolNameRE.MatchString(f.Name) || seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		d := transport.CleanLine(f.Description)
		if utf8.RuneCountInString(d) > 200 {
			d = string([]rune(d)[:199]) + "…"
		}
		out = append(out, Tool{Name: f.Name, Access: "write", Description: d})
	}
	return out
}

// mergeFound keeps the tools the connection has, with their switches, and adds the ones found for the first time.
func mergeFound(have, found []Tool) []Tool {
	out := slices.Clone(have)
	for _, f := range found {
		if !slices.ContainsFunc(out, func(t Tool) bool { return t.Name == f.Name }) {
			out = append(out, f)
		}
	}
	return out
}
