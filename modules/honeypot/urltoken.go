package honeypot

import (
	"context"
	"database/sql"
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

// OpenURLToken records that src opened /t/<id> on the box (POST-2, D-507). The planted link of a URL token is the Box address
// at the time it was made + /t/<id>, so a token is found by its path alone: changing the Box address later does not stop an
// old link from firing. A real hit goes through the same path as a bait account or file touched in the trap log (upsert:
// one hit per token, source and 10-minute window, the per-hour cap, honeypot.hit.created after the commit, so notify opens
// the Critical incident and response sees the trigger). Nothing is recorded, and no error is returned, when the module is
// off, the id is malformed or names no URL token (INV-10: a deleted token never fires), or the source is the box itself
// (loopback) or no address. userAgent is untrusted: cut and cleaned (INV-12).
func (s *Service) OpenURLToken(ctx context.Context, id string, src netip.AddrPort, userAgent string) error {
	ip := src.Addr().Unmap()
	if !s.on() || !ValidURLTokenID(id) || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return nil
	}
	tok, found, err := s.urlToken(ctx, id)
	if err != nil || !found {
		return err
	}
	env, err := s.newIngest(ctx)
	if err != nil {
		return err
	}
	ts := store.FormatTS(env.now)
	from := ip.String()
	if src.Port() != 0 {
		from += ":" + strconv.Itoa(int(src.Port()))
	}
	label := tokenLabel(TokenURL) + " " + tok.Name
	ua := clean(userAgent, maxUserAgent)
	line := label + " was opened from " + from
	excerpt := "The link " + tok.Value + " was opened. This link exists only as bait."
	if ua != "" {
		line += ", User-Agent: " + ua
		excerpt += " User-Agent: " + ua
	}
	window := strconv.FormatInt(env.now.Truncate(hitWindow).Unix(), 10)
	h := storedHit{
		Hit:    Hit{TS: ts, Kind: KindToken, Label: label, SrcIP: ip.String(), Excerpt: excerpt},
		trapIP: tok.Value, trapHostname: label, tokenID: tok.ID,
		connKey: connKey("token", tok.ID, ip.String(), window),
		events:  []HitEvent{{TS: ts, Source: "honeypot", Text: line, Mark: true}},
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		env.newHits, env.st = nil, Stats{}
		return s.upsert(ctx, tx, env, h, line, "")
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
	if s.cfg.Events != nil {
		for _, e := range env.newHits {
			if err := s.cfg.Events.Publish(ctx, Event{Name: EventHitCreated, Data: e}); err != nil {
				s.cfg.Log.WarnContext(ctx, "honeypot: publish hit", "error", err)
			}
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
