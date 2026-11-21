package agentintake

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
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

// The Wazuh pull (S-INV-4, (13)): the box signs in to the customer's own Wazuh server API with a
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

// wazuhLostMsg is the card's error and the Test/Save answer when the saved password is sealed under another master key: a backup
// restored without its decryption key, or a key file made again (#847). The password is gone for good; typing it again seals it
// under this box's key and the pull starts again.
const wazuhLostMsg = "The saved Wazuh password was not restored (the backup was restored without its decryption key, or the box key changed). Open Edit, enter the password again and press Save. Nothing is pulled until then."

// wazuhNever is the next_pull of a connection whose password cannot be opened: no tick pulls until a Save sets it to now, or until a
// tick finds that the password opens again (the original key file was put back).
var wazuhNever = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

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
		if secrets.IsWrongKey(err) {
			return checked{}, apierr.New(409, conn.CodeSecretLost, wazuhLostMsg)
		}
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
// of this handshake (public roots, or the key pinned: Save is the act of trusting), and the next pull due now.
func (s *Service) SaveWazuh(ctx context.Context, actor string, in WazuhInput) (WazuhConnection, error) {
	c, err := s.checkWazuh(ctx, in)
	if err != nil {
		return WazuhConnection{}, err
	}
	// Save is the act of trusting a certificate, but only with a password typed for it: the saved password only ever goes to
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
			// A new connection's generation never repeats one of a deleted connection (a row of 1 would be the default's again): a
			// pull of the old connection still running would otherwise pass current() and write as the new one (review #855 r2 L2).
			gen, err := newGeneration()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh (id, url, username, secret_id, password_last4, interval_minutes, tls_pin, tls_pin_first_seen, next_pull, updated_at, generation) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				c.origin, c.user, id, last4, c.interval, pin, ts, ts, ts, gen); err != nil {
				return fmt.Errorf("agentintake: insert wazuh: %w", err)
			}
			// A new connection starts again at generation 1: no row of an earlier one may count as its agent (#855 r1 M1).
			if _, err := tx.ExecContext(ctx, `DELETE FROM intake_wazuh_agent`); err != nil {
				return fmt.Errorf("agentintake: forget wazuh agents: %w", err)
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
		// Where the deleted connection's agents were is kept no longer: it names no device and has no other use (#855 r1 M1).
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_wazuh_agent`); err != nil {
			return fmt.Errorf("agentintake: forget wazuh agents: %w", err)
		}
		if err := s.cfg.Secrets.Delete(ctx, tx, cur.secretID); err != nil {
			return fmt.Errorf("agentintake: delete wazuh password: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.wazuh_disconnect", "Wazuh", cur.URL)
	})
}

// ---- the pull ----

// wazuhPullEvery is the tick of the job; the interval the administrator chose decides when a tick pulls.
const wazuhPullEvery = time.Minute

// staleAgent is how long a disconnected agent's inventory is still believed: Wazuh keeps disconnected agents for ever, and a machine
// reinstalled under a new id leaves the old one behind with an address DHCP may since have given to another device.
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
	var due, lost bool
	// One write transaction: read the row, claim the tick (next_pull) and open the password, so the password is always the one of the
	// row whose address and pin the pull uses, even when a Save commits a moment later (round 1, MEDIUM-2).
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if w, err = s.loadWazuh(ctx, tx); err != nil || w == nil {
			return err
		}
		// A pull stopped on a password it could not open (below) only checks, locally, whether the password opens again (the original
		// key file was put back): nothing is sent, written or logged until it does, and then this tick pulls.
		stopped := !w.nextPull.Before(wazuhNever)
		if !stopped && now.Before(w.nextPull) {
			return nil
		}
		raw, err = s.cfg.Secrets.Open(ctx, tx, w.secretID, wazuhPurpose)
		if stopped && secrets.IsWrongKey(err) {
			return nil
		}
		next := now.Add(time.Duration(w.IntervalMinutes) * time.Minute)
		if _, err := tx.ExecContext(ctx, `UPDATE intake_wazuh SET next_pull = ? WHERE id = 1`, store.FormatTS(next)); err != nil {
			return fmt.Errorf("agentintake: wazuh next pull: %w", err)
		}
		if secrets.IsWrongKey(err) {
			// Sealed under another master key (#847): no pull can ever sign in with it. The card says so and the pull waits for the
			// password to be typed again (Save sets next_pull to now), instead of failing at every tick.
			lost = true
			_, err = tx.ExecContext(ctx, `UPDATE intake_wazuh SET status = 'error', error = ?, next_pull = ?, resume_after = NULL, pass_packages = 0 WHERE id = 1`,
				wazuhLostMsg, store.FormatTS(wazuhNever))
			return err
		}
		if err != nil {
			return fmt.Errorf("agentintake: open wazuh password: %w", err)
		}
		due = true
		return nil
	})
	if lost && err == nil {
		s.cfg.Log.WarnContext(ctx, "agent-intake: the saved Wazuh password cannot be opened with this box's master key (restored without the decryption key, or the key file was made again); the pull waits until it is typed again")
	}
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
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		if perr != nil {
			return nil
		}
		// A completed pass: the agents the server no longer lists (or lists as stale), and every row of an older connection, name no
		// device any more (#849). The agents' ids come from this tick's full list, so a pass spread over several ticks keeps them all.
		keep, _ := json.Marshal(res.usable)
		_, err := tx.ExecContext(ctx, `DELETE FROM intake_wazuh_agent WHERE generation <> ? OR agent_id NOT IN (SELECT value FROM json_each(?))`, w.generation, string(keep))
		return err
	})
}

// wazuhAgentSeen records the address and card the pull just delivered an agent's data to (#849: the Devices list tells Wazuh from
// osquery by them), and when Wazuh last heard from the agent, which the device's agent is judged by (NodeHealth): the pull's time while
// Wazuh lists the agent active (Wazuh itself says it hears from it, by its own clock, so the manager's clock never meets the box's), its
// lastKeepAlive while Wazuh lists it disconnected (never after the pull; the pull's time when it does not parse), so a disconnected
// agent the pull still lists turns quiet.
func (s *Service) wazuhAgentSeen(ctx context.Context, id string, generation int64, ip netip.Addr, mac, status, keepAlive string) error {
	heard := s.now()
	if t, err := time.Parse(time.RFC3339, keepAlive); err == nil && status != "active" && t.Before(heard) {
		heard = t.UTC()
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		// Only for the connection saved now: a pull of a deleted or replaced one writes nothing here (review #855 r2 L2).
		_, err := tx.ExecContext(ctx, `INSERT INTO intake_wazuh_agent (agent_id, generation, ip, mac, seen_at)
			SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM intake_wazuh WHERE id = 1 AND generation = ?2)
			ON CONFLICT (agent_id) DO UPDATE SET generation = excluded.generation, ip = excluded.ip, mac = excluded.mac, seen_at = excluded.seen_at`,
			id, generation, ip.String(), mac, store.FormatTS(heard))
		if err != nil {
			return fmt.Errorf("agentintake: wazuh agent: %w", err)
		}
		return nil
	})
}

// newGeneration is the generation of a newly saved connection: random, positive, below 2^53 (edits add one), so it never repeats one
// of a deleted connection in practice.
func newGeneration() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("agentintake: wazuh generation: %w", err)
	}
	return int64(binary.BigEndian.Uint64(b[:])>>11) + 2, nil
}

// WazuhAgentAddresses lists the addresses and MACs (aa:bb:cc:dd:ee:ff) of the agents the saved Wazuh connection's pulls delivered to
// the inventory; none when no connection is saved (#849, inventory Config.WazuhAgents). Read-only.
func (s *Service) WazuhAgentAddresses(ctx context.Context) (ips, macs []string, err error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT ip, mac FROM intake_wazuh_agent WHERE generation = (SELECT generation FROM intake_wazuh WHERE id = 1) ORDER BY agent_id`)
	if err != nil {
		return nil, nil, fmt.Errorf("agentintake: read wazuh agents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var ip, mac string
		if err := rows.Scan(&ip, &mac); err != nil {
			return nil, nil, fmt.Errorf("agentintake: read wazuh agents: %w", err)
		}
		ips = append(ips, ip)
		if mac != "" {
			macs = append(macs, mac)
		}
	}
	return ips, macs, rows.Err()
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
	last                                       string   // the id of the last agent done in this tick
	usable                                     []string // the ids of the agents worth reading this tick (usableAgents), all of them
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
	usable := usableAgents(agents, s.now())
	for _, a := range usable {
		res.usable = append(res.usable, a.ID)
	}
	for _, a := range usable {
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
		n, err := s.pullAgent(ctx, c, a, w.generation)
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

// agentIP is the address the inventory gets as the device hint: the agent's ip (where it talks to the manager from) only when
// it is a unicast IPv4 that the agent itself reports on one of its interfaces. Behind NAT the manager sees the router, and writing the
// server's packages onto the router would be wrong: such an agent is skipped (fail closed, like INV-12). The MAC of that interface is
// only an observation (0.9): syscollector data is the agent's own claim, and the inventory resolves a device by MAC first.
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
func (s *Service) pullAgent(ctx context.Context, c *wazuhClient, a wzAgent, generation int64) (int, error) {
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
	if err := s.wazuhAgentSeen(ctx, a.ID, generation, ip, mac, a.Status, a.LastKeepAlive); err != nil {
		return 0, err
	}
	items, dropped := mapPackages(withWindows(wazuhSnaps(pkgs, wazuhKernel(a)), wazuhWindows(a)), maxRows)
	if dropped > 0 {
		s.cfg.Log.InfoContext(ctx, "agent-intake: wazuh rows dropped", "agent", a.ID, "rows_not_fitting", dropped)
	}
	written, err := s.wazuhSoftware(ctx, hint, a.ID, items)
	if err != nil {
		return 0, err
	}
	// The ports after the packages, so a failed ports read (a 429, the server gone) never costs the agent its packages (#933 review L5).
	if err := s.wazuhServices(ctx, c, a.ID, hint); err != nil {
		return written, err
	}
	return written, nil
}

// wazuhSoftware writes an agent's package list. An empty one (syscollector off or empty) never wipes what is known; a list
// the inventory refused is logged and dropped; a transient error is returned. written is the number of packages stored.
func (s *Service) wazuhSoftware(ctx context.Context, hint observe.AssetHint, id string, items []observe.Software) (written int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	if err := s.cfg.Software.ReplaceSoftware(ctx, hint, observe.Wazuh, nil, items); err != nil {
		if transient(err) {
			return 0, fmt.Errorf("agentintake: software: %w", err)
		}
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused a wazuh software list", "agent", id, "error", err.Error())
		return 0, nil
	}
	return len(items), nil
}

// wazuhServices delivers an agent's open ports (INV-22): its syscollector ports that listen (TCP in state listening, UDP with no peer),
// through the same mapper as osquery's. An agent whose ports scan is off or not done yet gives no row, and a read cut at maxPortRows is
// no whole list: what is known stays (as for packages). A ports read that fails (forbidden, not understood, a 429, the server gone)
// skips the ports of that agent only and is logged: the agent's packages are already written and the pull goes on (the next call
// meets a server that is gone on its own). Only the store being busy or the pull being stopped is returned.
func (s *Service) wazuhServices(ctx context.Context, c *wazuhClient, id string, hint observe.AssetHint) error {
	if s.cfg.Services == nil {
		return nil
	}
	rows, complete, err := c.ports(ctx, id)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.InfoContext(ctx, "agent-intake: the ports of a wazuh agent were not read; its open ports stay as they were", "agent", id, "error", err.Error())
		return nil
	}
	if !complete {
		s.cfg.Log.InfoContext(ctx, "agent-intake: a wazuh agent lists more sockets than one read holds; its open ports stay as they were", "agent", id, "rows", len(rows))
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.cfg.Services.ReplaceServices(ctx, hint, observe.Agent, mapServices(wazuhListening(rows))); err != nil {
		if transient(err) {
			return fmt.Errorf("agentintake: services: %w", err)
		}
		s.cfg.Log.ErrorContext(ctx, "agent-intake: the inventory refused a wazuh list of open ports", "agent", id, "error", err.Error())
	}
	return nil
}

// wazuhListening keeps the listening rows of an agent's syscollector ports.
func wazuhListening(rows []wzPort) []listening {
	out := make([]listening, 0, len(rows))
	for _, r := range rows {
		proto := strings.TrimSuffix(r.Protocol, "6")
		switch {
		case proto == "tcp" && r.State == "listening", proto == "udp" && r.Remote.Port == 0:
			out = append(out, listening{port: r.Local.Port, proto: proto, addr: r.Local.IP, program: r.Process})
		}
	}
	return out
}

// wazuhFacts turns the agent row into the os_version and system_info rows the osquery mapper reads (one mapper, plan 3.1).
func wazuhFacts(a wzAgent) map[string][]row {
	clean := func(s string) string { v, _ := cleanValue(s, maxValue); return v }
	return map[string][]row{
		"os_version":  {{"name": clean(a.OS.Name), "version": clean(a.OS.Version), "platform": clean(a.OS.Platform)}},
		"system_info": {{"hostname": clean(a.Name)}},
	}
}

// wazuhWindows is the Windows release of a Wazuh agent with its update revision, when its os version carries one
// ("10.0.20348.2700"), and the NVD target_hw of its os.arch ("x86_64" → x64; review M1); zero otherwise.
func wazuhWindows(a wzAgent) winOS {
	name, ok := cleanValue(a.OS.Name, maxValue)
	if a.OS.Platform != "windows" || !ok || !fits(name) || !winFullRE.MatchString(a.OS.Version) {
		return winOS{}
	}
	return winOS{name: name, version: a.OS.Version, target: winTarget(a.OS.Arch)}
}

// wazuhKernel is the running kernel release of a Wazuh agent: the third "|"-separated field of its uname ("Linux |host
// |7.0.0-43-generic |#43-Ubuntu SMP … |x86_64"), "" when the field is missing or not clean.
func wazuhKernel(a wzAgent) string {
	parts := strings.Split(a.OS.Uname, "|")
	if len(parts) < 3 {
		return ""
	}
	k, ok := cleanValue(parts[2], maxValue)
	if !ok {
		return ""
	}
	return k
}

// wazuhSnaps sorts the packages into the osquery tables the mapper knows: deb as deb_packages (the version keeps epoch and revision,
// the mapper drops them), rpm as rpm_packages with the upstream version (Wazuh writes version-release, osquery only the version), win
// as programs (vendor is the publisher). Other formats (snap, apk, pacman, macOS) are outside the supported servers (INV-2) and dropped.
//
// kernel is the running kernel release of the agent (wazuhKernel), put on every deb row as osquery's query does; "" when unknown.
func wazuhSnaps(pkgs []wzPackage, kernel string) map[string][]row {
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
			out["deb_packages"] = append(out["deb_packages"], row{"name": name, "version": version, "source": source, "kernel": kernel})
		case "rpm":
			out["rpm_packages"] = append(out["rpm_packages"], row{"name": name, "version": debUpstream(version)})
		case "win":
			out["programs"] = append(out["programs"], row{"name": name, "version": version, "publisher": vendor})
		}
	}
	return out
}
