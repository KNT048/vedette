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
	maxPerSrcBatch = 200     // lines of one source taken per poll: bounds the work one address can cause
	maxNewPerPoll  = 500     // new hits one poll may store; the rest is counted as suppressed
	maxNewPerHour  = 2000    // new hits one clock hour may store
	maxExcerpt     = 600
	hitWindow      = 10 * time.Minute // one hit per (source, service, trap IP) in this window; later connections add to it
	maxLineAge     = 24 * time.Hour   // a line older than this is not a live connection
	maxLineFuture  = 5 * time.Minute  // nor is one from the future
	warnEvery      = time.Minute      // the same warning is logged at most this often
)

// Stats counts what the reader did, for the log and the tests.
type Stats struct {
	Lines        int   // usable lines read
	Unusable     int   // lines that are not JSON, have no source, ...
	TooLong      int   // lines over MaxLine, dropped
	Ignored      int   // lines from the scanner of the box (INV-3)
	Skipped      int   // broadcasts and logtypes the module does not map
	Flooded      int   // lines over the per-source cap of one poll
	Implausible  int   // lines no connection to a trap can have produced (source, target, trap off, time)
	Suppressed   int   // new hits not stored because of the per-poll or per-hour cap (the alert flood guard)
	Hits         int   // new hits stored
	Rotations    int   // log files replaced
	NotRegular   int   // polls that found a FIFO, device or directory at the log name
	SkippedBytes int64 // bytes of log jumped over: the reader was more than 64 MiB behind
}

// Stats returns the counters since start.
func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// due says whether the warning with this key may be logged now: at most once per warnEvery, because a hostile container
// can make the same thing happen every second and must not be able to fill the log of core with it.
func (s *Service) due(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if last, seen := s.lastWarn[key]; seen && now.Sub(last) < warnEvery {
		return false
	}
	if s.lastWarn == nil {
		s.lastWarn = map[string]time.Time{}
	}
	s.lastWarn[key] = now
	return true
}

func (s *Service) restoreTail(ctx context.Context) error {
	var pos tailPos
	if err := loadJSON(ctx, s.db.Reader(), "tail", &pos); err != nil {
		return err
	}
	s.mu.Lock()
	s.tl = &tailer{dir: s.cfg.LogDir, name: defaultLogFile, max: s.cfg.MaxLine, pos: pos}
	s.mu.Unlock()
	return nil
}

type tailItem struct {
	rec Record
	end int64 // offset just after the line in the log
}

// Poll reads the new lines of the OpenCanary log and turns them into hits (D-89). Every byte is untrusted: lines are
// cut, decoded strictly into the few fields used, and stored as text. Each batch of lines is stored together with the
// read position after it in one transaction, and its hit events are published right after that commit, so a failing
// batch never loses the alerts of the batches before it and never makes them twice. It never blocks on the file.
func (s *Service) Poll(ctx context.Context) error {
	if s.cfg.LogDir == "" {
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
	before, wasDiscarding, droppedBefore, rotBefore := tl.pos, tl.discarding, tl.dropped, tl.rotations
	defer func() {
		s.mu.Lock()
		s.stats.TooLong, s.stats.Rotations, s.stats.NotRegular, s.stats.SkippedBytes = tl.dropped, tl.rotations, tl.notRegular, tl.skippedBytes
		s.mu.Unlock()
	}()
	var items []tailItem
	unusable := 0
	changed, err := tl.poll(pollBytes, func(line []byte, end int64) {
		r, err := ParseLine(line)
		if err != nil {
			unusable++
			return
		}
		items = append(items, tailItem{rec: r, end: end})
	})
	saved, savedDiscarding := before, wasDiscarding // what the database holds
	restore := func() {
		tl.pos, tl.discarding, tl.dropped, tl.rotations = saved, savedDiscarding, droppedBefore, rotBefore
	}
	if errors.Is(err, errNotRegular) {
		if s.due("log-not-regular") {
			s.cfg.Log.WarnContext(ctx, "honeypot: the trap log name is not a regular file; it is skipped", "dir", s.cfg.LogDir, "name", defaultLogFile)
		}
		return nil
	}
	if err != nil {
		restore()
		return err
	}
	if tl.skippedBytes > 0 && changed && s.due("log-behind") {
		s.cfg.Log.WarnContext(ctx, "honeypot: the trap log was more than 64 MiB ahead of the reader; the unread part was skipped", "skipped_bytes", tl.skippedBytes)
	}
	final := tl.pos
	var env *ingestEnv
	if len(items) > 0 {
		if env, err = s.newIngest(ctx); err != nil {
			restore()
			return err
		}
	}
	for len(items) > 0 {
		n := min(batchSize, len(items))
		batch := items[:n]
		items = items[n:]
		pos := final
		if len(items) > 0 { // the head of the file is the same all along; the offset is that of this batch's last line
			pos = tailPos{Offset: batch[n-1].end, HeadLen: final.HeadLen, Head: final.Head}
		}
		if err := s.ingestBatch(ctx, env, batch, pos); err != nil {
			restore()
			return err
		}
		saved, savedDiscarding = pos, false // a batch ends after a complete line
		if len(items) == 0 {
			savedDiscarding = tl.discarding
		}
	}
	if changed && saved != final {
		if err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.saveJSON(ctx, tx, "tail", final, "system") }); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.stats.Unusable += unusable
	s.mu.Unlock()
	return nil
}

type ingestEnv struct {
	w       *world
	creds   map[string]Token // lower-case bait user name → token
	files   map[string]Token // lower-case bait file name → token
	now     time.Time
	trapIPs map[netip.Addr]bool // the addresses the traps listen on now
	perSrc  map[netip.Addr]int
	pollNew int // new hits stored by this poll's earlier batches
	hourNew int // new hits stored in this clock hour before this batch
	// of the batch in progress
	newHits []HitEventData
	ignored int
	st      Stats
}

func (s *Service) newIngest(ctx context.Context) (*ingestEnv, error) {
	w, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	toks, err := s.loadTokens(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	env := &ingestEnv{w: w, creds: map[string]Token{}, files: map[string]Token{}, now: s.now(), trapIPs: map[netip.Addr]bool{}, perSrc: map[netip.Addr]int{}}
	for _, t := range toks {
		switch t.Type {
		case TokenCredential:
			env.creds[strings.ToLower(t.Value)] = t.Token
		case TokenFile:
			env.files[strings.ToLower(t.Value)] = t.Token
		}
	}
	ips, _, _ := w.desired()
	for _, ip := range ips {
		env.trapIPs[ip] = true
	}
	hour := env.now.Truncate(time.Hour)
	s.mu.Lock()
	if !s.hourStart.Equal(hour) {
		s.hourStart, s.hourNew = hour, 0
	}
	env.hourNew = s.hourNew
	s.mu.Unlock()
	return env, nil
}

// ingestBatch stores one batch and the read position after it in a single transaction, then publishes the events of the
// hits it made (core/events: after the commit, a rolled-back hit is never announced).
func (s *Service) ingestBatch(ctx context.Context, env *ingestEnv, batch []tailItem, pos tailPos) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		env.newHits, env.ignored, env.st = nil, 0, Stats{}
		for _, it := range batch {
			if err := s.ingestOne(ctx, tx, env, it.rec); err != nil {
				return err
			}
		}
		if env.ignored > 0 {
			_, err := tx.ExecContext(ctx, `INSERT INTO hp_ignored_day (day, count) VALUES (?, ?) ON CONFLICT (day) DO UPDATE SET count = count + excluded.count`, s.dayOf(ctx, env.now), env.ignored)
			if err != nil {
				return fmt.Errorf("honeypot: count ignored: %w", err)
			}
		}
		return s.saveJSON(ctx, tx, "tail", pos, "system")
	})
	if err != nil {
		return err
	}
	created := env.newHits
	env.pollNew += len(created)
	env.hourNew += len(created)
	s.mu.Lock()
	s.hourNew = env.hourNew
	s.stats.Lines += env.st.Lines
	s.stats.Ignored += env.st.Ignored
	s.stats.Skipped += env.st.Skipped
	s.stats.Flooded += env.st.Flooded
	s.stats.Implausible += env.st.Implausible
	s.stats.Suppressed += env.st.Suppressed
	s.stats.Hits += len(created)
	s.mu.Unlock()
	if env.st.Suppressed > 0 && s.due("hits-suppressed") {
		s.cfg.Log.WarnContext(ctx, "honeypot: too many new hits; some were counted but not stored", "suppressed", env.st.Suppressed, "max_per_poll", maxNewPerPoll, "max_per_hour", maxNewPerHour)
	}
	if s.cfg.Events != nil {
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

// plausible says whether a log line can come from a connection to a trap: the source is no address the box or the traps
// own, no loopback and no network address; the target is a trap address that listens now; the service has its trap on;
// the time is within a day in the past and a few minutes in the future. A compromised container can still forge a line
// that passes (CONTRACT, "Giới hạn").
func (env *ingestEnv) plausible(r Record, svc ServiceName, scan bool) bool {
	w := env.w
	switch {
	case r.Src.IsLoopback(), env.trapIPs[r.Src], w.lan.IsValid() && w.lan.Bits() < 31 && r.Src == w.lan.Masked().Addr():
		return false
	case r.Dst.IsValid() && !env.trapIPs[r.Dst]:
		return false
	case !scan && !w.traps[svc].enabled, scan && len(env.trapIPs) == 0:
		return false
	case !r.TS.IsZero() && (r.TS.Before(env.now.Add(-maxLineAge)) || r.TS.After(env.now.Add(maxLineFuture))):
		return false
	}
	return true
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
	if !env.plausible(r, svc, scan) {
		env.st.Implausible++
		return nil
	}
	if env.perSrc[r.Src]++; env.perSrc[r.Src] > maxPerSrcBatch {
		env.st.Flooded++
		return nil
	}
	env.st.Lines++
	ts := r.TS
	if ts.IsZero() {
		ts = env.now
	}
	tsText := store.FormatTS(ts)
	src, dst := r.Src.String(), ""
	if r.Dst.IsValid() {
		dst = r.Dst.String()
	}
	window := strconv.FormatInt(ts.Truncate(hitWindow).Unix(), 10)
	from := src
	if r.SrcPort > 0 { // makes the line of a connection different from another one of the same window
		from += ":" + strconv.Itoa(r.SrcPort)
	}
	trapIP := dst
	if trapIP == "" {
		trapIP = w.cfg.SecondaryIP
	}
	if scan {
		label := "Port scan on decoy " + dst
		if dst == "" {
			label = "Port scan on a decoy IP"
		}
		line := label + " from " + from
		return s.upsert(ctx, tx, env, storedHit{
			Hit:    Hit{TS: tsText, Kind: KindScan, Label: label, SrcIP: src, Excerpt: "TCP probe of a decoy IP"},
			trapIP: trapIP, trapHostname: "Decoy sweep",
			connKey: connKey("scan", src, dst, window),
			events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: line, Mark: true}},
		}, line, "")
	}
	port := r.DstPort
	if port == 0 {
		port = svc.Port()
	}
	det := detail(r, svc)
	first := fmt.Sprintf("%s trap: %s connected to %s:%d", svc.Label(), src, trapIP, port)
	more := svc.Label() + " trap: " + det + " [from port " + strconv.Itoa(r.SrcPort) + "]"
	svcCopy := svc
	if err := s.upsert(ctx, tx, env, storedHit{
		Hit:    Hit{TS: tsText, Kind: KindService, Service: &svcCopy, Label: svc.Label(), Port: &port, SrcIP: src, Excerpt: det},
		trapIP: trapIP, trapHostname: w.cfg.Hostname, connKey: connKey("service", string(svc), src, dst, strconv.Itoa(port), window),
		events: []HitEvent{{TS: tsText, Source: "honeypot", Text: first, Mark: true}},
	}, more, det); err != nil {
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
	line := label + " was used from " + from
	return s.upsert(ctx, tx, env, storedHit{
		Hit:    Hit{TS: tsText, Kind: KindToken, Label: label, SrcIP: src, Excerpt: ex},
		trapIP: tok.Value, trapHostname: label, tokenID: tok.ID,
		connKey: connKey("token", tok.ID, src, window),
		events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: line, Mark: true}},
	}, line, "")
}

func isBroadcast(lan netip.Prefix, a netip.Addr) bool {
	if a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.IsMulticast() {
		return true
	}
	return lan.IsValid() && lan.Bits() < 31 && a == lastAddr(lan)
}

func hasEvent(evs []HitEvent, text string) bool {
	for _, e := range evs {
		if e.Text == text {
			return true
		}
	}
	return false
}

// upsert stores the first connection of a window as one hit and, for the later connections of the same window (same
// source, service and trap IP), raises conn_count and adds a line to the hit instead of making a row: a brute force
// is one hit, not a row per attempt. line is the text of this connection (a repeated log line, same text, changes
// nothing); excerpt, when not empty, is added to the excerpt of the hit. A new hit past the per-poll or per-hour cap is
// counted as suppressed and not stored.
func (s *Service) upsert(ctx context.Context, tx *sql.Tx, env *ingestEnv, h storedHit, line, excerptAdd string) error {
	var id, excerpt, evJSON string
	err := tx.QueryRowContext(ctx, `SELECT id, excerpt, events FROM hp_hits WHERE conn_key = ?`, h.connKey).Scan(&id, &excerpt, &evJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if env.pollNew+len(env.newHits) >= maxNewPerPoll || env.hourNew+len(env.newHits) >= maxNewPerHour {
			env.st.Suppressed++
			return nil
		}
		h.ID = store.NewID("hit")
		h.Excerpt = clean(h.Excerpt, maxExcerpt)
		for i := range h.events {
			h.events[i].Text = clean(h.events[i].Text, 300)
		}
		if l := clean(line, 300); l != "" && !hasEvent(h.events, l) {
			h.events = append(h.events, HitEvent{TS: h.TS, Source: "honeypot", Text: l, Mark: true})
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
	var evs []HitEvent
	if err := json.Unmarshal([]byte(evJSON), &evs); err != nil {
		evs = nil
	}
	line = clean(line, 300)
	if hasEvent(evs, line) {
		return nil
	}
	if len(evs) < maxEvents {
		evs = append(evs, HitEvent{TS: h.TS, Source: "honeypot", Text: line, Mark: true})
	}
	if excerptAdd = clean(excerptAdd, maxExcerpt); excerptAdd != "" && !strings.Contains(excerpt, excerptAdd) {
		excerpt = clean(excerpt+"; "+excerptAdd, maxExcerpt)
	}
	raw, err := json.Marshal(evs)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hp_hits SET events = ?, excerpt = ?, conn_count = conn_count + 1 WHERE id = ?`, string(raw), excerpt, id); err != nil {
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
