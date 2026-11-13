package response

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The block list the customer's firewall pulls (INV-17, docs/specs/blocklist-format.md): plain text, one address per line,
// on an address that holds a token. The token is the only credential. Its SHA-256 matches a request; the token itself is
// sealed in core_secret so an admin can copy the address again. Regenerating it kills the old address at once.

const (
	tokenPurpose  = "response.blocklist.token"
	apiPrefix     = "/api/v1"
	fetchPerMin   = 60 // pulls per source address per minute
	badTokenPerMi = 20 // wrong tokens per source address per minute before 429

	maxBlockEntries = 10000 // blocklist-format section 7: at the limit a new entry is refused, never silently cut
	maxFetchKeys    = 10000 // sources the rate limit remembers at once
)

var tokenRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("response: token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ensureToken returns the token, creating the first one when there is none. tx is a write transaction.
func (s *Service) ensureToken(ctx context.Context, tx *sql.Tx) (token, last4 string, err error) {
	var secretID string
	err = tx.QueryRowContext(ctx, `SELECT secret_id, token_last4 FROM resp_blocklist WHERE id = 1`).Scan(&secretID, &last4)
	if err == nil {
		pt, oerr := s.cfg.Secrets.Open(ctx, tx, secretID, tokenPurpose)
		if oerr != nil {
			return "", "", fmt.Errorf("response: open the block list token: %w", oerr)
		}
		return string(pt), last4, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("response: read the block list token: %w", err)
	}
	return s.newTokenRow(ctx, tx, "")
}

// newTokenRow makes a token and stores it, replacing the old secret when oldSecret is set.
func (s *Service) newTokenRow(ctx context.Context, tx *sql.Tx, oldSecret string) (string, string, error) {
	token, err := newToken()
	if err != nil {
		return "", "", err
	}
	id, _, err := s.cfg.Secrets.Seal(ctx, tx, tokenPurpose, []byte(token), false)
	if err != nil {
		return "", "", fmt.Errorf("response: seal the block list token: %w", err)
	}
	last4 := token[len(token)-4:]
	if _, err := tx.ExecContext(ctx, `INSERT INTO resp_blocklist (id, token_hash, secret_id, token_last4) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, secret_id = excluded.secret_id, token_last4 = excluded.token_last4, last_fetch_at = NULL, last_fetch_from = NULL`,
		hashToken(token), id, last4); err != nil {
		return "", "", fmt.Errorf("response: save the block list token: %w", err)
	}
	if oldSecret != "" {
		if err := s.cfg.Secrets.Delete(ctx, tx, oldSecret); err != nil {
			return "", "", fmt.Errorf("response: delete the old block list token: %w", err)
		}
	}
	return token, last4, nil
}

func (s *Service) blockURL(token string) string {
	base := ""
	if s.cfg.BaseURL != nil {
		base = s.cfg.BaseURL()
	}
	return strings.TrimRight(base, "/") + apiPrefix + "/response/blocklist/" + token + ".txt"
}

// notPublishable are the blocks no public list may carry: every block of the IANA IPv4 and IPv6 Special-Purpose Address
// Registries that is not globally reachable (https://www.iana.org/assignments/iana-ipv4-special-registry and
// https://www.iana.org/assignments/iana-ipv6-special-registry), plus multicast and the deprecated site-local block. A poisoned
// feed must not be able to lock the customer's own network out (blocklist-format section 5). The documentation blocks of IPv4
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are left out on purpose: they are not routed on the internet, the examples, the
// fixtures and the tests use them as public addresses, and none of them is a network a customer runs; their IPv6 block
// (2001:db8::/32) is listed because the registry says so and no fixture needs it.
var notPublishable = mustPrefixes(
	// IPv4
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	// IPv6
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:db8::/32",
	"2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

func mustPrefixes(l ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(l))
	for i, s := range l {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// publishable reports whether an address may be on the published list: a public address, one that is in none of notPublishable
// (an IPv4-mapped IPv6 address counts as its IPv4 address).
func publishable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() {
		return false
	}
	return !slices.ContainsFunc(notPublishable, func(p netip.Prefix) bool { return p.Contains(a) })
}

// codeNotPublishable is the refusal of a block the list could never publish (D-469). Not not_public: exposure uses that for the box's own
// address, with another meaning.
const codeNotPublishable = "not_publishable"

// notPublicMsg is the reason a block on ip is refused with not_publishable (D-469), "" when ip is publishable. The list is pulled by
// the customer's firewall and blocks traffic to what it holds: a private or reserved address would never be published, and a
// device inside the LAN is isolated with a device action, not through this list (blocklist-format section 1).
func notPublicMsg(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && publishable(a) {
		return ""
	}
	return oneLine(ip, 64) + " is not a public address (private, loopback, link-local, carrier-grade NAT 100.64.0.0/10, multicast or reserved). " +
		"The block list only carries public addresses, so your firewall never blocks your own network. To stop a device on your LAN, use a device action (for example, shut its switch port). Nothing was changed."
}

// dropUnpublishable removes, once per start, the entries a block made before D-469 left on addresses the list never publishes (they
// were never served, the admin view never listed them), with one log and audit line giving the count. tx is a write transaction.
func (s *Service) dropUnpublishable(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT value FROM resp_block_entries`)
	if err != nil {
		return err
	}
	var bad []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return err
		}
		if notPublicMsg(v) != "" {
			bad = append(bad, v)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, v := range bad {
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_block_entries WHERE value = ?`, v); err != nil {
			return err
		}
	}
	if len(bad) == 0 {
		return nil
	}
	what := itoa(len(bad)) + " block list entries"
	if len(bad) == 1 {
		what = "1 block list entry"
	}
	return s.step(ctx, tx, "response.blocklist.cleanup", "response", LogRefused, codeNotPublishable+": removed "+what+
		" on addresses the list never publishes (private or reserved; D-469). They were never served to the firewall.", "system")
}

// blockListFull is true when value would be a new entry and the list already holds maxBlockEntries entries in force.
func (s *Service) blockListFull(ctx context.Context, value string) (bool, error) {
	var n, same int
	now := store2(s.now())
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*), ifnull(sum(value = ?), 0) FROM resp_block_entries WHERE expires_at IS NULL OR expires_at > ?`, value, now).Scan(&n, &same); err != nil {
		return false, err
	}
	return same == 0 && n >= maxBlockEntries, nil
}

// blockEntries are the entries in force that may be published, newest first, at most maxBlockEntries. An entry whose time
// to live ended no longer counts, whether or not the sweep has removed it; an entry on the never-touch list is never
// listed (INV-10, FORBID-7); neither is an address that is not public (publishable).
func (s *Service) blockEntries(ctx context.Context, q dbq) ([]BlockEntry, error) {
	never, err := s.neverTouch(ctx, q)
	if err != nil {
		return nil, err
	}
	// Parsed once, not once per entry (firstTouched would parse the list for each of up to maxBlockEntries values).
	var nev []entry
	for _, n := range never {
		if pe, ok := parseEntry(n.Value); ok {
			nev = append(nev, pe)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT value, source, reason, added_at, expires_at FROM resp_block_entries WHERE expires_at IS NULL OR expires_at > ? ORDER BY added_at DESC, rowid DESC`, store2(s.now()))
	if err != nil {
		return nil, fmt.Errorf("response: read the block list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []BlockEntry{}
	for rows.Next() {
		var e BlockEntry
		var exp sql.NullString
		if err := rows.Scan(&e.Value, &e.Source, &e.Reason, &e.AddedAt, &exp); err != nil {
			return nil, err
		}
		e.ExpiresAt = ptrOrNilNS(exp)
		if a, err := netip.ParseAddr(e.Value); err != nil || !publishable(a) {
			continue
		}
		if v, ok := parseEntry(e.Value); ok && slices.ContainsFunc(nev, func(n entry) bool { return touchesParsed(n, v) }) {
			continue
		}
		if out = append(out, e); len(out) >= maxBlockEntries {
			break
		}
	}
	return out, rows.Err()
}

// Blocklist is GET /response/blocklist (admin): the address with its token, the entries, the last pull.
func (s *Service) Blocklist(ctx context.Context) (BlocklistView, error) {
	var v BlocklistView
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		token, last4, err := s.ensureToken(ctx, tx)
		if err != nil {
			return err
		}
		v.URL, v.TokenLast4 = s.blockURL(token), last4
		if v.Entries, err = s.blockEntries(ctx, tx); err != nil {
			return err
		}
		var at, from sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT last_fetch_at, last_fetch_from FROM resp_blocklist WHERE id = 1`).Scan(&at, &from); err != nil {
			return err
		}
		if at.Valid {
			v.LastFetch = &LastFetch{At: at.String, From: from.String}
		}
		return nil
	})
	return v, err
}

// RegenerateToken is POST /response/blocklist/token: the old address stops working at once.
func (s *Service) RegenerateToken(ctx context.Context, who Actor) (BlocklistView, error) {
	s.mu.Lock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM resp_blocklist WHERE id = 1`).Scan(&old); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, _, err := s.newTokenRow(ctx, tx, old); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.blocklist.token", "response", LogBlocklistToken, "The block list token was regenerated; the old address no longer works", who.Email)
	})
	s.mu.Unlock()
	if err != nil {
		return BlocklistView{}, err
	}
	return s.Blocklist(ctx)
}

// addBlockEntry puts the address of an executed blocklist_add item on the list, in the transaction that records the item.
func (s *Service) addBlockEntry(ctx context.Context, tx *sql.Tx, r request, it itemRec) error {
	ip := it.Values[PIP]
	if _, ok := CheckValue(PIP, ip); !ok {
		return fmt.Errorf("response: a block list item has no valid address")
	}
	source := "AI request"
	switch r.Source {
	case "rule":
		source = "Rule: " + deref2(r.RuleName)
	case sourcePerson:
		source = "Asked from an incident"
	}
	_, reason, _ := strings.Cut(it.Change.After, "Reason: ")
	if reason == "" {
		reason = r.Title
	}
	_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO resp_block_entries (value, request_id, item_id, source, reason, added_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ip, r.ID, it.ID, cleanComment(source, 120), cleanComment(reason, 200), deref2(it.ExecutedAt), deref(it.RemoveAt))
	if err != nil {
		return fmt.Errorf("response: add a block list entry: %w", err)
	}
	return nil
}

// cleanComment makes text safe for a comment line of the list: every control character becomes a space and "|" becomes
// "/", so a reason built from attacker data can never start a new line (blocklist-format 4.2).
func cleanComment(s string, limit int) string {
	return strings.ReplaceAll(oneLine(s, limit), "|", "/")
}

// renderBlocklist is the plain-text list (one address per line). Domains never appear in it. The three comment lines carry
// only the name of the list, the time and the count: the file is public to anyone who holds the address (the token), so it
// names no device, rule, event or reason (blocklist-format 12 (a)).
func (s *Service) renderBlocklist(entries []BlockEntry) []byte {
	var lines []string
	seen := map[string]bool{}
	for _, e := range entries {
		a, err := netip.ParseAddr(e.Value)
		if err != nil || seen[e.Value] {
			continue
		}
		seen[e.Value] = true
		lines = append(lines, a.String())
	}
	var b strings.Builder
	b.WriteString("# vedette blocklist\n# generated " + store2(s.now()) + "\n# entries " + itoa(len(lines)) + "\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return []byte(b.String())
}

// sourceKey is the key the rate limit uses for a source address: the address for IPv4, the /64 for IPv6 (one host owns a whole
// /64 and can rotate addresses inside it), the cut text for anything that is not an address.
func sourceKey(from string) string {
	a, err := netip.ParseAddr(from)
	if err != nil {
		if ap, err2 := netip.ParseAddrPort(from); err2 == nil {
			a, err = ap.Addr(), nil
		}
	}
	if err != nil {
		return oneLine(from, 64)
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// errListUnavailable is 503 with Retry-After: when the store cannot be read the answer is an error, never an empty list (a
// firewall keeps its old list on an error and drops every entry on an empty one: blocklist-format section 6, fail-static).
func errListUnavailable() error {
	return fail(http.StatusServiceUnavailable, "server_busy", "The block list cannot be read just now. Keep the list you have and try again shortly.").With("retry_after", 60)
}

// FetchBlocklist answers a pull of the public address. A wrong token is a plain 404 (it looks like a wrong path);
// a source address that pulls too often, or guesses tokens, gets 429. A store that cannot be read gives 503, never an empty
// list. from is the source address of the request; the limit is per address, per /64 for IPv6.
func (s *Service) FetchBlocklist(ctx context.Context, token, from string) ([]byte, error) {
	key := sourceKey(from)
	if !s.allowFetch("bad:"+key, badTokenPerMi, false) || !s.allowFetch("ok:"+key, fetchPerMin, false) {
		return nil, fail(http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again in a minute.").With("retry_after", 60)
	}
	var stored string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT token_hash FROM resp_blocklist WHERE id = 1`).Scan(&stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.cfg.Log.ErrorContext(ctx, "response: read the block list token", "error", err)
		return nil, errListUnavailable()
	}
	if !tokenRE.MatchString(token) || errors.Is(err, sql.ErrNoRows) || subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(stored)) != 1 {
		s.allowFetch("bad:"+key, badTokenPerMi, true)
		return nil, fail(http.StatusNotFound, "not_found", "This item no longer exists.")
	}
	s.allowFetch("ok:"+key, fetchPerMin, true)
	var out []byte
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE resp_blocklist SET last_fetch_at = ?, last_fetch_from = ? WHERE id = 1`, s.ts(), oneLine(from, 64)); err != nil {
			return err
		}
		es, err := s.blockEntries(ctx, tx)
		if err != nil {
			return err
		}
		out = s.renderBlocklist(es)
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "response: serve the block list", "error", err)
		return nil, errListUnavailable()
	}
	return out, nil
}

// allowFetch is a sliding one-minute window per key: it reports whether another event still fits; record adds one. The
// table holds at most maxFetchKeys sources: when it is full a source it does not know yet is refused (429) until old ones age out.
func (s *Service) allowFetch(key string, limit int, record bool) bool {
	return s.allowIn(s.fetchTimes, key, limit, record)
}

// allowLink is the same window for the approval link routes, in a table of its own and keyed by the whole address (a /128 for IPv6,
// linkKey): the block list limit is per /64 and a link flood must not eat it, nor the other way round.
func (s *Service) allowLink(key string, limit int, record bool) bool {
	return s.allowIn(s.linkTimes, key, limit, record)
}

func (s *Service) allowIn(table map[string][]time.Time, key string, limit int, record bool) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := s.now()
	times, known := table[key]
	keep := times[:0]
	for _, t := range times {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= limit {
		table[key] = keep
		return false
	}
	if record {
		if !known && len(table) >= maxFetchKeys {
			purgeWindow(table, now)
			if len(table) >= maxFetchKeys {
				return false
			}
		}
		keep = append(keep, now)
	}
	if len(keep) == 0 {
		delete(table, key)
	} else {
		table[key] = keep
	}
	return true
}

// purgeWindow forgets the sources with nothing in the last minute. The caller holds limitMu.
func purgeWindow(table map[string][]time.Time, now time.Time) {
	for k, l := range table {
		if len(l) == 0 || now.Sub(l[len(l)-1]) >= time.Minute {
			delete(table, k)
		}
	}
}
