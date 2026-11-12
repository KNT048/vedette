package agentintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// The Wazuh pull (S-INV-4, D-33, D-169 (12), (13), D-305..D-309): the box signs in to the customer's own Wazuh server API with a
// read-only account and reads the agents and their syscollector inventory into the inventory, as source agent. The password is in
// core/secrets and only this file opens it; the certificate is the public roots' or pinned at Save (trust on first use); every address
// goes through core/conn's policy; nothing is ever written to Wazuh (FORBID-4).

// wazuhPurpose is the core_secret purpose of the password. Like every other module's secret (ai, feeds, logs, notify, oidc) it is sealed
// and opened through core/secrets with this purpose; the vault sees only the ciphertext and the AAD binds it to this purpose.
const wazuhPurpose = "intake_wazuh.password"

const (
	wazuhTestBudget = 30 * time.Second // the whole Test or Save probe
	wazuhPullBudget = 10 * time.Minute // the whole pull (plan 3.1); under the JWT's default life of 900 s
	pinSystem       = "system"         // tls_pin when a public authority vouched for the certificate
)

// WazuhIntervals are the pull intervals of the GUI, in minutes.
var WazuhIntervals = []int{5, 15, 60, 360, 1440}

var wazuhUserRE = regexp.MustCompile(`^[\w.@-]{1,64}$`) // the mock's rule

// WazuhInput is the form of the Wazuh card (WazuhInput in contract.ts). An empty Password keeps the saved one.
type WazuhInput struct {
	URL, Username   string
	Password        secrets.Value
	IntervalMinutes int
}

// WazuhConnection is the saved connection without its password (WazuhConnection in contract.ts).
type WazuhConnection struct {
	URL, Username, PasswordLast4 string
	IntervalMinutes              int
	Status                       string // never, connected, error
	LastSync                     time.Time
	Agents, Packages             int
	Error                        string // "" = none
}

// WazuhTestResult is what a successful Test answers.
type WazuhTestResult struct {
	Version string
	Agents  int
}

func bad400(code, msg string) *apierr.Error { return apierr.New(400, code, msg) }

func (e *wazuhErr) api() *apierr.Error { return apierr.New(e.status, e.code, e.msg) }

func wazuhOff() *apierr.Error {
	return apierr.New(501, apierr.CodeNotImplemented, "The Wazuh pull is not available in this build.")
}

// origin checks the typed address and returns its https://host[:port] form, lower-case, without a trailing slash. A path, a query, a
// user name or anything but https is bad_url; so is a host the address policy of core/conn refuses (loopback, link-local, the box).
func (s *Service) origin(ctx context.Context, raw string) (string, *apierr.Error) {
	const msg = "Enter the Wazuh server API address starting with https://, for example https://wazuh-manager:55000. Do not put the user name or password in it."
	raw = strings.TrimSpace(raw)
	if utf8.RuneCountInString(raw) > 200 {
		return "", bad400("bad_url", msg)
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return "", bad400("bad_url", msg)
	}
	o := "https://" + strings.ToLower(u.Host)
	if why := s.cfg.Conn.HTTPSTargetProblem(ctx, o); why != "" {
		return "", bad400("bad_url", why)
	}
	return o, nil
}

// hostPort is the identity of a server: host and port, 443 when none is written. The saved password belongs to it (core/conn rule).
func hostPort(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	p := u.Port()
	if p == "" {
		p = "443"
	}
	return strings.ToLower(u.Hostname()) + ":" + p
}

// saved is the stored row.
type savedWazuh struct {
	WazuhConnection
	secretID, pin, resumeAfter string
	generation                 int64
	nextPull                   time.Time
}

func (s *Service) loadWazuh(ctx context.Context, q querier) (*savedWazuh, error) {
	var w savedWazuh
	var last, next sql.NullString
	var errText, resume sql.NullString
	err := q.QueryRowContext(ctx, `SELECT url, username, secret_id, password_last4, interval_minutes, tls_pin, generation, status, last_sync, next_pull, agents, packages, error, resume_after FROM intake_wazuh WHERE id = 1`).
		Scan(&w.URL, &w.Username, &w.secretID, &w.PasswordLast4, &w.IntervalMinutes, &w.pin, &w.generation, &w.Status, &last, &next, &w.Agents, &w.Packages, &errText, &resume)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agentintake: read wazuh: %w", err)
	}
	w.LastSync, w.nextPull, w.Error, w.resumeAfter = parseTS(last), parseTS(next), errText.String, resume.String
	return &w, nil
}

// Wazuh returns the saved connection without its password, nil when none is saved (GET /inventory/agents, slice 3).
func (s *Service) Wazuh(ctx context.Context) (*WazuhConnection, error) {
	w, err := s.loadWazuh(ctx, s.db.Reader())
	if err != nil || w == nil {
		return nil, err
	}
	c := w.WazuhConnection
	return &c, nil
}

// WazuhConnected says whether a Wazuh connection is saved: Settings → Privacy flow 14 is on while one is (and the module is on).
func (s *Service) WazuhConnected(ctx context.Context) (bool, error) {
	w, err := s.loadWazuh(ctx, s.db.Reader())
	return w != nil, err
}

// checked is a validated form: the origin, and the password to use (typed, or the saved one when the field was blank).
type checked struct {
	origin, user string
	pass         secrets.Value
	typed        bool // the password came in the form
	interval     int
	prev         *savedWazuh
}

func (s *Service) checkWazuh(ctx context.Context, in WazuhInput) (checked, error) {
	if s.cfg.Conn == nil || s.cfg.Secrets == nil {
		return checked{}, wazuhOff()
	}
	o, e := s.origin(ctx, in.URL)
	if e != nil {
		return checked{}, e
	}
	user := strings.TrimSpace(in.Username)
	if !wazuhUserRE.MatchString(user) {
		return checked{}, bad400("bad_username", "Enter the read-only API user name (letters, digits, dot, dash, underscore; up to 64 characters).")
	}
	// The row and its password are read in one read-only transaction: the password is always the one of the address it is checked
	// against, even when another Save commits in between (round 2, LOW-A).
	tx, err := s.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return checked{}, fmt.Errorf("agentintake: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	prev, err := s.loadWazuh(ctx, tx)
	if err != nil {
		return checked{}, err
	}
	c := checked{origin: o, user: user, interval: in.IntervalMinutes, prev: prev, typed: in.Password.IsSet()}
	switch {
	case c.typed && utf8.RuneCountInString(in.Password.Reveal()) > 200:
		return checked{}, bad400("bad_password", "The password is too long (up to 200 characters).")
	case c.typed:
		c.pass = in.Password
	case prev == nil:
		return checked{}, bad400("password_required", "Enter the password of the read-only API user.")
	case hostPort(prev.URL) != hostPort(o):
		// The saved password belongs to the server it was typed for: it never goes to another address without being typed again.
		return checked{}, bad400("password_required", "The address changed. Enter the password of the read-only API user again.")
	}
	if !slices.Contains(WazuhIntervals, c.interval) {
		return checked{}, bad400("bad_interval", "Choose how often to sync: every 5, 15, 60, 360 or 1440 minutes.")
	}
	if !c.typed {
		raw, err := s.cfg.Secrets.Open(ctx, tx, prev.secretID, wazuhPurpose)
		if err != nil {
			return checked{}, fmt.Errorf("agentintake: open wazuh password: %w", err)
		}
		c.pass = secrets.NewValue(string(raw))
	}
	return c, nil
}

func (s *Service) newWazuhClient(origin, user string, pass secrets.Value, o conn.HTTPSOptions) *wazuhClient {
	o.Roots = s.wazuhRoots
	return &wazuhClient{http: s.cfg.Conn.NewHTTPS(o), origin: origin, user: user, pass: pass, sleep: s.wazuhSleep, pace: s.wazuhPace}
}

// probe signs in and reads what the Test shows: the API version, the agent count, and one syscollector page of the manager (agent
// 000 always exists) so that an account without syscollector:read fails here and not at the first pull.
func (s *Service) probe(ctx context.Context, c *wazuhClient) (WazuhTestResult, error) {
	ctx, cancel := context.WithTimeout(ctx, wazuhTestBudget)
	defer cancel()
	if err := c.login(ctx); err != nil {
		return WazuhTestResult{}, err
	}
	v, err := c.version(ctx)
	if err != nil {
		return WazuhTestResult{}, err
	}
	n, err := c.agentCount(ctx)
	if err != nil {
		return WazuhTestResult{}, err
	}
	if _, _, err := syscollPage[wzAddr](ctx, c, "000", "netaddr", "iface,address,proto", 0); err != nil {
		return WazuhTestResult{}, err
	}
	return WazuhTestResult{Version: v, Agents: n}, nil
}

func asAPI(err error) error {
	var we *wazuhErr
	if errors.As(err, &we) {
		return we.api()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apierr.New(502, "wazuh_unreachable", "The Wazuh server did not answer in time. Check the address and the network path from the box.")
	}
	return err
}

// TestWazuh signs in with the form values and reads without saving anything (POST /inventory/agents/wazuh/test). A typed password is
// sent under trust on first use, like Save; the saved password (blank field) only ever goes to the pinned key: a certificate that changed
// is wazuh_tls and nothing is sent.
func (s *Service) TestWazuh(ctx context.Context, in WazuhInput) (WazuhTestResult, error) {
	c, err := s.checkWazuh(ctx, in)
	if err != nil {
		return WazuhTestResult{}, err
	}
	o := conn.HTTPSOptions{TOFU: true}
	if !c.typed {
		o = pinOptions(c.prev.pin)
	}
	res, err := s.probe(ctx, s.newWazuhClient(c.origin, c.user, c.pass, o))
	return res, asAPI(err)
}

func pinOptions(pin string) conn.HTTPSOptions {
	if pin == pinSystem {
		return conn.HTTPSOptions{} // a public authority must keep vouching for it
	}
	return conn.HTTPSOptions{Pin: pin}
}

// SaveWazuh verifies the form (the same calls as Test, PRE-2), then stores it: the password sealed in core/secrets, the trust decision
// of this handshake (public roots, or the key pinned: Save is the act of trusting, D-308), and the next pull due now.
func (s *Service) SaveWazuh(ctx context.Context, actor string, in WazuhInput) (WazuhConnection, error) {
	c, err := s.checkWazuh(ctx, in)
	if err != nil {
		return WazuhConnection{}, err
	}
	// Save is the act of trusting a certificate (D-308), but only with a password typed for it: the saved password only ever goes to
	// the pinned key (or to a certificate a public authority vouches for, when that is the saved rule). A changed certificate with the
	// password field left blank asks for the password again (round 1, MEDIUM-1).
	o := conn.HTTPSOptions{TOFU: true}
	if !c.typed {
		o = pinOptions(c.prev.pin)
	}
	cl := s.newWazuhClient(c.origin, c.user, c.pass, o)
	if _, err := s.probe(ctx, cl); err != nil {
		var we *wazuhErr
		if !c.typed && errors.As(err, &we) && we.code == "wazuh_tls" {
			return WazuhConnection{}, bad400("password_required", "The Wazuh certificate changed. Type the password again to trust the new certificate, then press Save.")
		}
		return WazuhConnection{}, asAPI(err)
	}
	spki, trusted := cl.http.Seen()
	pin, pinWords := pinSystem, "a public authority vouches for the certificate"
	if !trusted {
		pin, pinWords = spki, "certificate key pinned "+spki[:16]+"…"
	}
	now := s.now()
	ts := store.FormatTS(now)
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		cur, err := s.loadWazuh(ctx, tx)
		if err != nil {
			return err
		}
		if !c.typed && (cur == nil || c.prev == nil || cur.generation != c.prev.generation) {
			return apierr.New(409, "wazuh_changed", "The Wazuh connection was changed or removed while this was checked. Enter the password and save again.")
		}
		switch cur {
		case nil:
			id, last4, err := s.cfg.Secrets.Seal(ctx, tx, wazuhPurpose, []byte(c.pass.Reveal()), true)
			if err != nil {
				return fmt.Errorf("agentintake: seal wazuh password: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh (id, url, username, secret_id, password_last4, interval_minutes, tls_pin, tls_pin_first_seen, next_pull, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				c.origin, c.user, id, last4, c.interval, pin, ts, ts, ts); err != nil {
				return fmt.Errorf("agentintake: insert wazuh: %w", err)
			}
		default:
			last4 := cur.PasswordLast4
			if c.typed {
				if last4, err = s.cfg.Secrets.Replace(ctx, tx, cur.secretID, wazuhPurpose, []byte(c.pass.Reveal()), true); err != nil {
					return fmt.Errorf("agentintake: replace wazuh password: %w", err)
				}
			}
			status := "never"
			if !cur.LastSync.IsZero() {
				status = "connected" // the probe just worked; the next pull says more
			}
			firstSeen := ts
			if pin == cur.pin {
				firstSeen = "" // kept below
			}
			if _, err := tx.ExecContext(ctx, `UPDATE intake_wazuh SET url = ?, username = ?, password_last4 = ?, interval_minutes = ?, tls_pin = ?,
				tls_pin_first_seen = COALESCE(NULLIF(?, ''), tls_pin_first_seen), generation = generation + 1, status = ?, error = NULL, next_pull = ?, resume_after = NULL, pass_packages = 0, updated_at = ? WHERE id = 1`,
				c.origin, c.user, last4, c.interval, pin, firstSeen, status, ts, ts); err != nil {
				return fmt.Errorf("agentintake: update wazuh: %w", err)
			}
		}
		return s.auditTx(ctx, tx, actor, "inventory.wazuh_connect", c.origin, fmt.Sprintf("user %s, every %d min, %s", c.user, c.interval, pinWords))
	})
	if err != nil {
		return WazuhConnection{}, err
	}
	w, err := s.Wazuh(ctx)
	if err != nil || w == nil {
		return WazuhConnection{}, errors.Join(err, errors.New("agentintake: the saved wazuh connection is gone"))
	}
	return *w, nil
}

// DeleteWazuh removes the connection and its password in one transaction (INV-6). Data already pulled stays in the inventory.
func (s *Service) DeleteWazuh(ctx context.Context, actor string) error {
	if s.cfg.Conn == nil || s.cfg.Secrets == nil {
		return wazuhOff()
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		cur, err := s.loadWazuh(ctx, tx)
		if err != nil {
			return err
		}
		if cur == nil {
			return apierr.New(404, "not_found", "Wazuh is not connected.")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_wazuh WHERE id = 1`); err != nil {
			return fmt.Errorf("agentintake: delete wazuh: %w", err)
		}
		if err := s.cfg.Secrets.Delete(ctx, tx, cur.secretID); err != nil {
			return fmt.Errorf("agentintake: delete wazuh password: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.wazuh_disconnect", "Wazuh", cur.URL)
	})
}

// ---- the pull ----

// wazuhPullEvery is the tick of the job; the interval the administrator chose decides when a tick pulls (D-169 (13)).
const wazuhPullEvery = time.Minute

// staleAgent is how long a disconnected agent's inventory is still believed: Wazuh keeps disconnected agents for ever, and a machine
// reinstalled under a new id leaves the old one behind with an address DHCP may since have given to another device (D-307).
const staleAgent = 7 * 24 * time.Hour

// WazuhPull is the wazuh-pull job: nothing unless a connection is saved and its next pull is due. The next pull is set before the pull
// starts, so a failing pull never pulls more often than the interval (POST-2: a failure keeps the data, sets status=error). A pass
// over many agents that does not fit in the 10-minute budget goes on at the next tick from the agent after the last one done
// (resume_after), so a large fleet is read in full over a few ticks, at most 4 calls a second.
func (s *Service) WazuhPull(ctx context.Context) error {
	if s.cfg.Conn == nil || s.cfg.Secrets == nil {
		return nil
	}
	now := s.now()
	var w *savedWazuh
	var raw []byte
	var due bool
	// One write transaction: read the row, claim the tick (next_pull) and open the password, so the password is always the one of the
	// row whose address and pin the pull uses, even when a Save commits a moment later (round 1, MEDIUM-2).
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if w, err = s.loadWazuh(ctx, tx); err != nil || w == nil || now.Before(w.nextPull) {
			return err
		}
		next := now.Add(time.Duration(w.IntervalMinutes) * time.Minute)
		if _, err := tx.ExecContext(ctx, `UPDATE intake_wazuh SET next_pull = ? WHERE id = 1`, store.FormatTS(next)); err != nil {
			return fmt.Errorf("agentintake: wazuh next pull: %w", err)
		}
		if raw, err = s.cfg.Secrets.Open(ctx, tx, w.secretID, wazuhPurpose); err != nil {
			return fmt.Errorf("agentintake: open wazuh password: %w", err)
		}
		due = true
		return nil
	})
	if err != nil || !due {
		return err
	}
	pctx, cancel := s.wazuhBudget(ctx)
	defer cancel()
	c := s.newWazuhClient(w.URL, w.Username, secrets.NewValue(string(raw)), pinOptions(w.pin))
	res, perr := s.pull(pctx, c, w)
	if ctx.Err() != nil {
		return ctx.Err() // the module was turned off, or the box is stopping: nothing more is written
	}
	if pctx.Err() != nil && errors.Is(perr, context.Canceled) {
		perr = fmt.Errorf("%w: %w", context.DeadlineExceeded, perr) // only the budget ends pctx and not ctx (a test's budget is a cancel)
	}
	if errors.Is(perr, errSuperseded) {
		return nil // a Save or a Delete came in: the pull stopped and writes nothing
	}
	s.cfg.Log.InfoContext(ctx, "agent-intake: wazuh pull", "agents", res.agents, "written", res.written, "packages", res.packages,
		"skipped_unbound_or_stale", res.unbound, "skipped_forbidden_or_unreadable", res.failed, "calls", c.calls, "ok", perr == nil, "resume_after", res.last)
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		var q string
		var args []any
		switch {
		case perr == nil && res.unbound > 0 && w.LastSync.IsZero():
			// The first pull after Save met an agent whose syscollector has not reported its addresses yet (agent just installed): read
			// again at the next tick, once, so the device appears in about a minute and not after a whole interval. Only the first pull
			// does this (last_sync is empty only until it succeeds), so a NAT agent that never binds costs one extra pull, not one a minute.
			q, args = `UPDATE intake_wazuh SET status = 'connected', error = NULL, last_sync = ?, agents = ?, packages = pass_packages + ?, resume_after = NULL, pass_packages = 0, next_pull = ? WHERE id = 1 AND generation = ?`,
				[]any{store.FormatTS(s.now()), res.agents, res.packages, store.FormatTS(s.now().Add(wazuhPullEvery)), w.generation}
		case perr == nil:
			q, args = `UPDATE intake_wazuh SET status = 'connected', error = NULL, last_sync = ?, agents = ?, packages = pass_packages + ?, resume_after = NULL, pass_packages = 0 WHERE id = 1 AND generation = ?`,
				[]any{store.FormatTS(s.now()), res.agents, res.packages, w.generation}
		case errors.Is(perr, context.DeadlineExceeded) && res.last != "":
			// Progress, not a failure: the pass goes on at the next tick from the agent after res.last.
			q, args = `UPDATE intake_wazuh SET status = 'connected', error = NULL, resume_after = ?, pass_packages = pass_packages + ?, next_pull = ? WHERE id = 1 AND generation = ?`,
				[]any{res.last, res.packages, store.FormatTS(s.now().Add(wazuhPullEvery)), w.generation}
		default:
			q, args = `UPDATE intake_wazuh SET status = 'error', error = ? WHERE id = 1 AND generation = ?`, []any{pullError(perr), w.generation}
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	})
}

// pullError is the text of the card for a failed pull: the code's own words, in the card's language.
func pullError(err error) string {
	var we *wazuhErr
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "The Wazuh server answered too slowly: not one agent was read in 10 minutes. Check the server's load and the network path."
	case errors.As(err, &we) && we.code == "wazuh_tls":
		return "The Wazuh certificate changed. Open Edit, type the password again and press Save to trust the new one."
	case errors.As(err, &we):
		return we.msg
	}
	return "The pull failed on the box. The details are in the box log."
}

type pullResult struct {
	agents, written, packages, unbound, failed int
	last                                       string // the id of the last agent done in this tick
}

var errSuperseded = errors.New("agentintake: the wazuh connection changed during the pull")

// current says whether the saved connection is still the one the pull started with.
func (s *Service) current(ctx context.Context, generation int64) (bool, error) {
	var g int64
	err := s.db.Reader().QueryRowContext(ctx, `SELECT generation FROM intake_wazuh WHERE id = 1`).Scan(&g)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && g == generation, err
}

// pull reads the agents (from the one after resume_after) and hands each one to the inventory in its own calls (each its own short
// transaction there): the single writer is never held across the network or across agents (lesson 3 of slice 2). Before each agent it
// checks that no Save or Delete came in, so the old server's data stops at once.
func (s *Service) pull(ctx context.Context, c *wazuhClient, w *savedWazuh) (pullResult, error) {
	var res pullResult
	if err := c.login(ctx); err != nil {
		return res, err
	}
	agents, err := c.agents(ctx)
	if err != nil {
		return res, err
	}
	res.agents = len(agents)
	after, _ := strconv.Atoi(w.resumeAfter) // "" = from the first agent
	for _, a := range usableAgents(agents, s.now()) {
		if id, _ := strconv.Atoi(a.ID); w.resumeAfter != "" && id <= after {
			continue
		}
		ok, err := s.current(ctx, w.generation)
		if err != nil {
			return res, err // a deadline here keeps the cursor like any other (round 2, LOW-B)
		}
		if !ok {
			return res, errSuperseded
		}
		n, err := s.pullAgent(ctx, c, a)
		var we *wazuhErr
		switch {
		case err == nil:
			res.written++
			res.packages += n
		case errors.As(err, &we) && !we.fatal():
			res.failed++
		case errors.Is(err, errUnbound):
			res.unbound++
		default:
			return res, err
		}
		res.last = a.ID
	}
	return res, nil
}

// usableAgents keeps the agents worth reading, in id order: each id once; not the manager's own loopback entry; not a disconnected
// agent last heard of more than staleAgent ago; and of several agents on one address only the one heard of last (a reinstall leaves
// the old id behind with the same address).
func usableAgents(agents []wzAgent, now time.Time) []wzAgent {
	byIP := map[string]int{}
	var out []wzAgent
	seen := map[string]bool{}
	for _, a := range agents {
		if !agentIDRE.MatchString(a.ID) || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		if ip, err := netip.ParseAddr(a.IP); err == nil && ip.IsLoopback() {
			continue // the manager (agent 000) reports 127.0.0.1: nothing to bind (deferred: inventory the manager itself)
		}
		heard, err := time.Parse(time.RFC3339, a.LastKeepAlive)
		if a.Status != "active" && (err != nil || now.Sub(heard) > staleAgent) {
			continue
		}
		if i, ok := byIP[a.IP]; ok {
			if prev, _ := time.Parse(time.RFC3339, out[i].LastKeepAlive); a.Status == "active" && out[i].Status != "active" || heard.After(prev) {
				out[i] = a
			}
			continue
		}
		byIP[a.IP] = len(out)
		out = append(out, a)
	}
	slices.SortFunc(out, func(x, y wzAgent) int { a, _ := strconv.Atoi(x.ID); b, _ := strconv.Atoi(y.ID); return a - b })
	return out
}

var errUnbound = errors.New("agentintake: the agent's address is not among its own")

// agentIP is the address the inventory gets as the device hint (D-307): the agent's ip (where it talks to the manager from) only when
// it is a unicast IPv4 that the agent itself reports on one of its interfaces. Behind NAT the manager sees the router, and writing the
// server's packages onto the router would be wrong: such an agent is skipped (fail closed, like INV-12). The MAC of that interface is
// only an observation (0.9): syscollector data is the agent's own claim, and the inventory resolves a device by MAC first (D-265 (4)).
func agentIP(a wzAgent, addrs []wzAddr, ifaces []wzIface) (netip.Addr, string, bool) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, "", false
	}
	for _, ad := range addrs {
		if ad.Proto != "ipv4" {
			continue
		}
		if got, err := netip.ParseAddr(ad.Address); err != nil || got != ip {
			continue
		}
		var rows []row
		for _, f := range ifaces {
			if f.Name == ad.Iface {
				rows = append(rows, row{"address": ad.Address, "mac": f.MAC})
			}
		}
		mac := ""
		if l := parseInterfaces(rows); len(l) > 0 {
			mac = l[0].mac
		}
		return ip, mac, true
	}
	return netip.Addr{}, "", false
}

// pullAgent reads one agent's interfaces and packages and delivers them. It returns the number of packages written.
func (s *Service) pullAgent(ctx context.Context, c *wazuhClient, a wzAgent) (int, error) {
	if !agentIDRE.MatchString(a.ID) { // never put text the server sent into a path unless it is the documented id format (usableAgents checks too)
		return 0, errBadReply("an agent id")
	}
	addrs, _, err := syscollPage[wzAddr](ctx, c, a.ID, "netaddr", "iface,address,proto", 0)
	if err != nil {
		return 0, err
	}
	ifaces, _, err := syscollPage[wzIface](ctx, c, a.ID, "netiface", "name,mac", 0)
	if err != nil {
		return 0, err
	}
	ip, mac, ok := agentIP(a, addrs, ifaces)
	if !ok {
		return 0, errUnbound
	}
	pkgs, err := c.packages(ctx, a.ID)
	if err != nil {
		return 0, err
	}
	hint := observe.AssetHint{IP: ip}
	if obs := observations(hint, wazuhFacts(a), mac); len(obs) > 0 {
		if err := s.record(ctx, obs); err != nil {
			return 0, err
		}
	}
	items, dropped := mapPackages(wazuhSnaps(pkgs))
	if dropped > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: wazuh rows dropped", "agent", a.ID, "rows_not_fitting", dropped)
	}
	if len(items) == 0 { // an agent whose syscollector is off or empty never wipes what is known (D-169 (13))
		return 0, nil
	}
	if err := s.cfg.Software.ReplaceSoftware(ctx, hint, observe.Agent, items); err != nil {
		if transient(err) {
			return 0, fmt.Errorf("agentintake: software: %w", err)
		}
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused a wazuh software list", "agent", a.ID, "error", err.Error())
		return 0, nil
	}
	return len(items), nil
}

// wazuhFacts turns the agent row into the os_version and system_info rows the osquery mapper reads (one mapper, plan 3.1).
func wazuhFacts(a wzAgent) map[string][]row {
	clean := func(s string) string { v, _ := cleanValue(s, maxValue); return v }
	return map[string][]row{
		"os_version":  {{"name": clean(a.OS.Name), "version": clean(a.OS.Version), "platform": clean(a.OS.Platform)}},
		"system_info": {{"hostname": clean(a.Name)}},
	}
}

// wazuhSnaps sorts the packages into the osquery tables the mapper knows: deb as deb_packages (the version keeps epoch and revision,
// the mapper drops them), rpm as rpm_packages with the upstream version (Wazuh writes version-release, osquery only the version), win
// as programs (vendor is the publisher). Other formats (snap, apk, pacman, macOS) are outside the supported servers (INV-2) and dropped.
func wazuhSnaps(pkgs []wzPackage) map[string][]row {
	out := map[string][]row{}
	for _, p := range pkgs {
		name, ok1 := cleanValue(p.Name, maxValue)
		version, ok2 := cleanValue(p.Version, maxValue)
		vendor, _ := cleanValue(p.Vendor, maxValue)
		source, _ := cleanValue(p.Source, maxValue)
		if !ok1 || !ok2 || name == "" {
			continue
		}
		switch p.Format {
		case "deb":
			out["deb_packages"] = append(out["deb_packages"], row{"name": name, "version": version, "source": source})
		case "rpm":
			out["rpm_packages"] = append(out["rpm_packages"], row{"name": name, "version": debUpstream(version)})
		case "win":
			out["programs"] = append(out["programs"], row{"name": name, "version": version, "publisher": vendor})
		}
	}
	return out
}
