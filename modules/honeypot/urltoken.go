package honeypot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// URLTokenIDLen is the length of the id at the end of a URL token, /t/<id> (AddToken: 10 characters of a-z0-9).
const URLTokenIDLen = 10

// maxUserAgent bounds the User-Agent kept with a URL token hit; it comes from whoever opened the link (INV-12).
const maxUserAgent = 200

// ValidURLTokenID says whether id has the shape AddToken gives the end of a URL token. It says nothing about whether such a
// token exists: the HTTP answer of /t/<id> must be the same either way (D-507).
func ValidURLTokenID(id string) bool {
	if len(id) != URLTokenIDLen {
		return false
	}
	for i := range len(id) {
		if !strings.ContainsRune(lower, rune(id[i])) {
			return false
		}
	}
	return true
}

// Budgets of OpenURLToken. Each step has its own, on a context detached from the caller's (a visitor who hangs up does not
// cancel the record), and the publish never shares the write's: under a busy writer the hit may take most of its budget, and
// the incident must still be opened (D-507, review M2).
const (
	urlTokenWriteWait   = 5 * time.Second
	urlTokenPublishWait = 30 * time.Second
)

// UnknownSource is what a URL token hit names as its source when the address the box saw is not the visitor's: on a
// container-only install the published port reaches core through a port proxy, so every visitor arrives from the proxy's
// address, which must never be named as the machine to unplug (D-507). It is also the stored src_ip of a hit from an IPv6
// address (hp_hits keeps IPv4 only); the event and the line of the hit then carry the address.
const UnknownSource = "unknown"

// proxiedSource is the source the hit event and the incident name for a proxied open.
const proxiedSource = UnknownSource + " (container-only port proxy)"

// URLTokenOpen is one request to /t/<id>.
type URLTokenOpen struct {
	ID        string         // the path segment after /t/
	Src       netip.AddrPort // the peer of the connection, never a forwarded header
	UserAgent string         // untrusted: cut and cleaned (INV-12)
	// Proxied: Src is the port proxy of a container-only install, not the visitor (UnknownSource).
	Proxied bool
	// RepeatOK is asked only for a repeat open (a hit of the same token, source and 10-minute window already exists): false
	// records nothing. The first open of a window always records (review M1: a rate limit asked before the token is known lets
	// anyone silence the real link with made-up ids). nil allows every repeat.
	RepeatOK func() bool
}

// OpenURLToken records an open of a URL token's link (POST-2, POST-4, D-507). The planted link is the Box address at the time
// it was made + /t/<id>, so a token is found by its path alone: changing the Box address later does not stop an old link from
// firing. A real hit goes through the same path as a bait account or file touched in the trap log (upsert: one hit per token,
// source and 10-minute window, the per-hour cap; honeypot.hit.created after the commit, so notify opens the Critical incident
// and response sees the trigger). Nothing is recorded, and no error is returned, when the module is off, the id is malformed or
// names no URL token (INV-10: a deleted token never fires), the source is the box itself (loopback, or the box's address as the
// inventory knows it, INV-3) or no address, or a repeat open is over the limit (RepeatOK).
func (s *Service) OpenURLToken(ctx context.Context, o URLTokenOpen) error {
	ctx = store.LimitWriteWait(context.WithoutCancel(ctx), 0) // detached, and no request's write wait limit (review M2)
	ip := o.Src.Addr().Unmap().WithZone("")
	if !s.on() || !ValidURLTokenID(o.ID) || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return nil
	}
	tok, found, err := s.urlToken(ctx, o.ID)
	if err != nil || !found {
		return err
	}
	env, err := s.newIngest(ctx)
	if err != nil {
		return err
	}
	if !o.Proxied && env.w.box.IP.IsValid() && ip == env.w.box.IP.Unmap() {
		return nil // INV-3: the box itself
	}
	shown, stored := ip.String(), ip.String() // what the event names; what hp_hits keeps (IPv4 only)
	switch {
	case o.Proxied:
		shown, stored = proxiedSource, UnknownSource
	case !ip.Is4():
		stored = UnknownSource
	}
	from := ip.String()
	if o.Src.Port() != 0 {
		from = o.Src.String()
	}
	if o.Proxied {
		from = proxiedSource
	}
	window := strconv.FormatInt(env.now.Truncate(hitWindow).Unix(), 10)
	key := connKey("token", tok.ID, shown, window)
	if o.RepeatOK != nil {
		var one int
		switch err := s.db.Reader().QueryRowContext(ctx, `SELECT 1 FROM hp_hits WHERE conn_key = ?`, key).Scan(&one); {
		case err == nil:
			if !o.RepeatOK() {
				return nil
			}
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("honeypot: find hit: %w", err)
		}
	}
	ts := store.FormatTS(env.now)
	label := tokenLabel(TokenURL) + " " + tok.Name
	ua := clean(o.UserAgent, maxUserAgent)
	line := label + " was opened from " + from
	excerpt := "The link " + tok.Value + " was opened. This link exists only as bait."
	if ua != "" {
		line += ", User-Agent: " + ua
		excerpt += " User-Agent: " + ua
	}
	h := storedHit{
		Hit:    Hit{TS: ts, Kind: KindToken, Label: label, SrcIP: stored, Excerpt: excerpt},
		trapIP: tok.Value, trapHostname: label, tokenID: tok.ID, connKey: key,
		events: []HitEvent{{TS: ts, Source: "honeypot", Text: line, Mark: true}},
	}
	wctx, cancel := context.WithTimeout(ctx, urlTokenWriteWait)
	defer cancel()
	err = s.db.Write(wctx, func(tx *sql.Tx) error {
		env.newHits, env.st = nil, Stats{}
		return s.upsert(wctx, tx, env, h, line, "")
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.hourStart.Equal(env.now.Truncate(time.Hour)) { // the same count Poll keeps (newIngest), so the per-hour cap covers both
		s.hourNew += len(env.newHits)
	}
	s.stats.Suppressed += env.st.Suppressed
	s.stats.Hits += len(env.newHits)
	s.mu.Unlock()
	if env.st.Suppressed > 0 && s.due("hits-suppressed") {
		s.cfg.Log.WarnContext(ctx, "honeypot: too many new hits; some were counted but not stored", "suppressed", env.st.Suppressed, "max_per_poll", maxNewPerPoll, "max_per_hour", maxNewPerHour)
	}
	if s.cfg.Events == nil || len(env.newHits) == 0 {
		return nil
	}
	// A fresh budget, not what the write left: notify's incident write may queue behind a busy writer.
	pctx, pcancel := context.WithTimeout(ctx, urlTokenPublishWait)
	defer pcancel()
	for _, e := range env.newHits {
		e.SrcIP = shown
		if err := s.cfg.Events.Publish(pctx, Event{Name: EventHitCreated, Data: e}); err != nil {
			s.cfg.Log.WarnContext(ctx, "honeypot: publish hit", "error", err)
		}
	}
	return nil
}

// urlToken is the URL token whose link ends in /t/<id>.
func (s *Service) urlToken(ctx context.Context, id string) (Token, bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, name, value FROM hp_tokens WHERE type = ?`, string(TokenURL))
	if err != nil {
		return Token{}, false, fmt.Errorf("honeypot: read URL tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Value); err != nil {
			return Token{}, false, fmt.Errorf("honeypot: read URL tokens: %w", err)
		}
		if strings.HasSuffix(t.Value, "/t/"+id) {
			t.Type = TokenURL
			return t, true, rows.Err()
		}
	}
	return Token{}, false, rows.Err()
}
