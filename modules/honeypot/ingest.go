package honeypot

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

const (
	pollBytes      = 4 << 20 // at most this much of the log per poll
	batchSize      = 500     // lines per transaction
	maxPerSrcBatch = 200     // lines of one source taken per poll: a flood from one address cannot fill the table
	maxExcerpt     = 600
	scanBucket     = 10 * time.Minute
)

// Stats counts what the reader did, for the log and the tests.
type Stats struct {
	Lines     int // usable lines read
	Unusable  int // lines that are not JSON, have no source, ...
	TooLong   int // lines over MaxLine, dropped
	Ignored   int // lines from the scanner of the box (INV-3)
	Skipped   int // broadcasts and logtypes the module does not map
	Flooded   int // lines over the per-source cap of one poll
	Hits      int // new hits stored
	Rotations int
}

// Stats returns the counters since start.
func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	if s.tl != nil {
		st.TooLong, st.Rotations = s.tl.dropped, s.tl.rotations
	}
	return st
}

func (s *Service) restoreTail(ctx context.Context) error {
	var pos tailPos
	if err := loadJSON(ctx, s.db.Reader(), "tail", &pos); err != nil {
		return err
	}
	s.mu.Lock()
	s.tl = &tailer{path: s.cfg.LogPath, max: s.cfg.MaxLine, pos: pos}
	s.mu.Unlock()
	return nil
}

// Poll reads the new lines of the OpenCanary log and turns them into hits (D-89). Every byte is untrusted: lines are
// cut, decoded strictly into the few fields used, and stored as text. The read position is saved after the hits.
func (s *Service) Poll(ctx context.Context) error {
	if s.cfg.LogPath == "" {
		return nil
	}
	s.pollMu.Lock()
	defer s.pollMu.Unlock()
	if s.tl == nil {
		if err := s.restoreTail(ctx); err != nil {
			return err
		}
	}
	tl := s.tl
	before, wasDiscarding := tl.pos, tl.discarding
	var recs []Record
	unusable := 0
	changed, err := tl.poll(pollBytes, func(line []byte) {
		r, err := ParseLine(line)
		if err != nil {
			unusable++
			return
		}
		recs = append(recs, r)
	})
	restore := func() { tl.pos, tl.discarding = before, wasDiscarding }
	if err != nil {
		restore()
		return err
	}
	s.mu.Lock()
	s.stats.Unusable += unusable
	s.mu.Unlock()
	if len(recs) > 0 {
		if err := s.ingest(ctx, recs); err != nil {
			restore()
			return err
		}
	}
	if changed {
		err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.saveJSON(ctx, tx, "tail", tl.pos, "system") })
		if err != nil {
			return err
		}
	}
	return nil
}

type ingestEnv struct {
	w       *world
	creds   map[string]Token // lower-case bait user name → token
	files   map[string]Token // lower-case bait file name → token
	now     time.Time
	perSrc  map[netip.Addr]int
	newHits []HitEventData
	ignored int
	st      Stats
}

func (s *Service) ingest(ctx context.Context, recs []Record) error {
	w, err := s.load(ctx)
	if err != nil {
		return err
	}
	toks, err := s.loadTokens(ctx, s.db.Reader())
	if err != nil {
		return err
	}
	env := &ingestEnv{w: w, creds: map[string]Token{}, files: map[string]Token{}, now: s.now(), perSrc: map[netip.Addr]int{}}
	for _, t := range toks {
		switch t.Type {
		case TokenCredential:
			env.creds[strings.ToLower(t.Value)] = t.Token
		case TokenFile:
			env.files[strings.ToLower(t.Value)] = t.Token
		}
	}
	var created []HitEventData
	for len(recs) > 0 {
		n := min(batchSize, len(recs))
		batch := recs[:n]
		recs = recs[n:]
		env.newHits, env.ignored = nil, 0
		err := s.db.Write(ctx, func(tx *sql.Tx) error {
			for _, r := range batch {
				if err := s.ingestOne(ctx, tx, env, r); err != nil {
					return err
				}
			}
			if env.ignored > 0 {
				_, err := tx.ExecContext(ctx, `INSERT INTO hp_ignored_day (day, count) VALUES (?, ?) ON CONFLICT (day) DO UPDATE SET count = count + excluded.count`, s.dayOf(ctx, env.now), env.ignored)
				if err != nil {
					return fmt.Errorf("honeypot: count ignored: %w", err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		created = append(created, env.newHits...)
	}
	s.mu.Lock()
	s.stats.Lines += env.st.Lines
	s.stats.Ignored += env.st.Ignored
	s.stats.Skipped += env.st.Skipped
	s.stats.Flooded += env.st.Flooded
	s.stats.Hits += len(created)
	s.mu.Unlock()
	if s.cfg.Events != nil { // after the commit (core/events): a rolled-back hit is never announced
		for _, e := range created {
			if err := s.cfg.Events.Publish(ctx, Event{Name: EventHitCreated, Data: e}); err != nil {
				s.cfg.Log.WarnContext(ctx, "honeypot: publish hit", "error", err)
			}
		}
	}
	return nil
}

// classify maps an OpenCanary logtype to the service (or scan) it belongs to.
func classify(lt int) (svc ServiceName, scan, ok bool) {
	switch {
	case lt >= ltSSHNew && lt <= ltSSHLogin:
		return SSH, false, true
	case lt == ltRDP:
		return RDP, false, true
	case lt == ltMSSQLSQL || lt == ltMSSQLWin:
		return MSSQL, false, true
	case lt == ltHTTPGet || lt == ltHTTPLogin:
		return HTTP, false, true
	case lt == ltSMBFile:
		return SMB, false, true
	case lt >= ltPortSYN && lt <= ltPortNmapEnd:
		return "", true, true
	}
	return "", false, false
}

// detail is the line shown for what this log line did; it holds no password (a typed password may be a real one).
func detail(r Record, svc ServiceName) string {
	q := func(s string) string { return `"` + s + `"` }
	switch r.LogType {
	case ltSSHNew:
		return "new connection"
	case ltSSHVersion:
		return "client version " + q(r.RemoteVersion)
	case ltSSHLogin, ltMSSQLSQL, ltMSSQLWin, ltRDP:
		s := "login attempt, account " + q(r.User)
		if r.Hostname != "" {
			s += ", from host name " + q(r.Hostname)
		}
		return s
	case ltHTTPGet:
		return "request GET " + r.Path + userAgent(r)
	case ltHTTPLogin:
		return "login attempt, account " + q(r.User) + " on " + r.Path + userAgent(r)
	case ltSMBFile:
		return "file opened " + q(r.Filename)
	}
	return string(svc) + " activity"
}

func userAgent(r Record) string {
	if r.UserAgent == "" {
		return ""
	}
	return ", User-Agent: " + r.UserAgent
}

func connKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func (s *Service) ingestOne(ctx context.Context, tx *sql.Tx, env *ingestEnv, r Record) error {
	w := env.w
	// INV-3: the scanner of the box itself is no hit; a broadcast or multicast packet is not a connection either.
	if w.box.IP.IsValid() && r.Src == w.box.IP {
		env.ignored++
		env.st.Ignored++
		return nil
	}
	if isBroadcast(w.lan, r.Src) || r.Dst.IsValid() && isBroadcast(w.lan, r.Dst) {
		env.st.Skipped++
		return nil
	}
	svc, scan, ok := classify(r.LogType)
	if !ok {
		env.st.Skipped++
		return nil
	}
	if env.perSrc[r.Src]++; env.perSrc[r.Src] > maxPerSrcBatch {
		env.st.Flooded++
		return nil
	}
	env.st.Lines++
	ts := r.TS
	if ts.IsZero() || ts.After(env.now.Add(time.Minute)) {
		ts = env.now
	}
	tsText := store.FormatTS(ts)
	src, dst := r.Src.String(), ""
	if r.Dst.IsValid() {
		dst = r.Dst.String()
	}
	hour := strconv.FormatInt(ts.Truncate(time.Hour).Unix(), 10)
	trapIP := dst
	if trapIP == "" {
		trapIP = w.cfg.SecondaryIP
	}
	if scan {
		label := "Port scan on decoy " + dst
		if dst == "" {
			label = "Port scan on a decoy IP"
		}
		return s.upsert(ctx, tx, env, storedHit{
			Hit:    Hit{TS: tsText, Kind: KindScan, Label: label, SrcIP: src, Excerpt: "TCP probe of a decoy IP"},
			trapIP: trapIP, trapHostname: "Decoy sweep",
			connKey: connKey("scan", src, dst, strconv.FormatInt(ts.Truncate(scanBucket).Unix(), 10)),
			events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: label + " from " + src, Mark: true}},
		}, "")
	}
	port := r.DstPort
	if port == 0 {
		port = svc.Port()
	}
	det := detail(r, svc)
	conn := connKey("service", string(svc), src, strconv.Itoa(r.SrcPort), dst, strconv.Itoa(port), hour)
	first := fmt.Sprintf("%s trap: %s connected to %s:%d", svc.Label(), src, trapIP, port)
	svcCopy := svc
	if err := s.upsert(ctx, tx, env, storedHit{
		Hit:    Hit{TS: tsText, Kind: KindService, Service: &svcCopy, Label: svc.Label(), Port: &port, SrcIP: src, Excerpt: det},
		trapIP: trapIP, trapHostname: w.cfg.Hostname, connKey: conn,
		events: []HitEvent{{TS: tsText, Source: "honeypot", Text: first, Mark: true}},
	}, svc.Label()+" trap: "+det); err != nil {
		return err
	}
	// POST-2: a bait account or file touched. Only a token that still exists counts (INV-10).
	var tok Token
	var found bool
	switch r.LogType {
	case ltSSHLogin, ltHTTPLogin, ltMSSQLSQL, ltMSSQLWin, ltRDP:
		tok, found = env.creds[strings.ToLower(r.User)]
	case ltSMBFile:
		name := strings.ReplaceAll(r.Filename, `\`, "/")
		tok, found = env.files[strings.ToLower(path.Base(name))]
	}
	if !found {
		return nil
	}
	label := tokenLabel(tok.Type) + " " + tok.Name
	ex := fmt.Sprintf("%s login attempt for %q. This account exists only as bait.", svc.Label(), tok.Value)
	if tok.Type == TokenFile {
		ex = fmt.Sprintf("File %q was opened on the SMB share. This file exists only as bait.", tok.Value)
	}
	return s.upsert(ctx, tx, env, storedHit{
		Hit:    Hit{TS: tsText, Kind: KindToken, Label: label, SrcIP: src, Excerpt: ex},
		trapIP: tok.Value, trapHostname: label, tokenID: tok.ID,
		connKey: connKey("token", tok.ID, src, strconv.Itoa(r.SrcPort), dst, strconv.Itoa(port), hour),
		events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: label + " was used from " + src, Mark: true}},
	}, "")
}

func isBroadcast(lan netip.Prefix, a netip.Addr) bool {
	if a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.IsMulticast() {
		return true
	}
	return lan.IsValid() && lan.Bits() < 31 && a == lastAddr(lan)
}

// upsert stores a new connection as one hit, or adds a line to the hit of the same connection (a repeated line changes
// nothing). more is the line to add on a repeat, "" for none.
func (s *Service) upsert(ctx context.Context, tx *sql.Tx, env *ingestEnv, h storedHit, more string) error {
	var id, excerpt, evJSON string
	err := tx.QueryRowContext(ctx, `SELECT id, excerpt, events FROM hp_hits WHERE conn_key = ?`, h.connKey).Scan(&id, &excerpt, &evJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		h.ID = store.NewID("hit")
		h.Excerpt = clean(h.Excerpt, maxExcerpt)
		if more != "" {
			h.events = append(h.events, HitEvent{TS: h.TS, Source: "honeypot", Text: clean(more, 300), Mark: true})
		}
		for i := range h.events {
			h.events[i].Text = clean(h.events[i].Text, 300)
		}
		if err := s.insertHit(ctx, tx, h); err != nil {
			return err
		}
		d := HitEventData{ID: h.ID, TS: h.TS, Kind: h.Kind, SrcIP: h.SrcIP, Label: h.Label}
		if h.Service != nil {
			d.Service = string(*h.Service)
		}
		if h.Port != nil {
			d.Port = *h.Port
		}
		env.newHits = append(env.newHits, d)
		return nil
	case err != nil:
		return fmt.Errorf("honeypot: find hit: %w", err)
	}
	if more == "" {
		return nil
	}
	var evs []HitEvent
	if err := json.Unmarshal([]byte(evJSON), &evs); err != nil {
		evs = nil
	}
	more = clean(more, 300)
	for _, e := range evs {
		if e.Text == more {
			return nil
		}
	}
	if len(evs) >= maxEvents {
		return nil
	}
	evs = append(evs, HitEvent{TS: h.TS, Source: "honeypot", Text: more, Mark: true})
	if tail := strings.TrimPrefix(more, h.Label+" trap: "); !strings.Contains(excerpt, tail) {
		excerpt = clean(excerpt+"; "+tail, maxExcerpt)
	}
	raw, err := json.Marshal(evs)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hp_hits SET events = ?, excerpt = ? WHERE id = ?`, string(raw), excerpt, id); err != nil {
		return fmt.Errorf("honeypot: update hit: %w", err)
	}
	return nil
}

// Prune removes what the retention allows (DATA_MODEL 4.7): test hits after 7 days, real hits after 365, the daily
// ignored counts after 30. It is the only thing that deletes hits (FORBID-5 is about the API).
func (s *Service) Prune(ctx context.Context) (int, error) {
	now := s.now()
	var n int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `DELETE FROM hp_hits WHERE (is_test = 1 AND ts < ?) OR ts < ?`, store.FormatTS(now.AddDate(0, 0, -7)), store.FormatTS(now.AddDate(0, 0, -365)))
		if err != nil {
			return fmt.Errorf("honeypot: prune hits: %w", err)
		}
		n, _ = r.RowsAffected()
		if _, err := tx.ExecContext(ctx, `DELETE FROM hp_ignored_day WHERE day < ?`, s.dayOf(ctx, now.AddDate(0, 0, -30))); err != nil {
			return fmt.Errorf("honeypot: prune ignored: %w", err)
		}
		return nil
	})
	return int(n), err
}
