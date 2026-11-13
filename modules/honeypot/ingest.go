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
	"slices"
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
		if err := s.db.Write(ctx, func(tx *sql.Tx) error { return s.saveJSON(ctx, tx, "tail", final) }); err != nil {
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
	// at is the Trap IP at each of those addresses and order the addresses in creation order (D-466: a hit carries the name
	// of the Trap IP that was hit); openPorts says the host cannot keep an address to its own services (every address answers them all).
	at        map[netip.Addr]*trapIPRow
	order     []netip.Addr
	openPorts bool
	perSrc    map[netip.Addr]int
	// touch: this batch is made of attempts the host recorded (PollTouches): new hits draw from touchLeft, not the listener caps.
	touch     bool
	touchLeft int
	pollNew   int // new hits stored by this poll's earlier batches
	hourNew   int // new hits stored in this clock hour before this batch
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
	env := &ingestEnv{w: w, creds: map[string]Token{}, files: map[string]Token{}, now: s.now(), trapIPs: map[netip.Addr]bool{}, at: map[netip.Addr]*trapIPRow{},
		perSrc: map[netip.Addr]int{}, openPorts: s.hostView().openPorts}
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
		env.at[ip] = w.trapIPAt(ip)
	}
	env.order = ips
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
		return s.saveJSON(ctx, tx, "tail", pos)
	})
	if err != nil {
		return err
	}
	s.afterBatch(ctx, env)
	return nil
}

// afterBatch counts and publishes what a committed batch made (core/events: after the commit, a rolled-back hit is never announced).
func (s *Service) afterBatch(ctx context.Context, env *ingestEnv) {
	created := env.newHits
	env.pollNew += len(created)
	env.hourNew += len(created)
	s.mu.Lock()
	if env.touch {
		s.touchHourNew += len(created) // their own budget: never the listener's (B2 review M2)
	} else {
		s.hourNew += len(created) // a delta: a URL token hit stored meanwhile is not lost (B2 review L3)
	}
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
}

// classify maps an OpenCanary line to the service (or scan) it belongs to: by logtype, and for the web lines by port (the HTTPS
// trap logs the HTTP logtypes).
func classify(r Record) (svc ServiceName, scan, ok bool) {
	switch lt := r.LogType; {
	case lt >= ltSSHNew && lt <= ltSSHLogin:
		return SSH, false, true
	case lt == ltRDP:
		return RDP, false, true
	case lt == ltMSSQLSQL || lt == ltMSSQLWin:
		return MSSQL, false, true
	case lt >= ltHTTPGet && lt <= ltHTTPRedirect:
		if r.DstPort == HTTPS.Port() {
			return HTTPS, false, true
		}
		return HTTP, false, true
	case lt == ltSMBFile:
		return SMB, false, true
	case lt >= ltPortSYN && lt <= ltPortNmapEnd:
		return "", true, true
	case lt == ltFTPLogin || lt == ltFTPAuthStart:
		return FTP, false, true
	case lt == ltTelnetLogin || lt == ltTelnetNew:
		return Telnet, false, true
	case lt == ltProxyLogin:
		return HTTPProxy, false, true
	case lt == ltMySQLLogin || lt == ltMySQLNew:
		return MySQL, false, true
	case lt == ltTFTP:
		return TFTP, false, true
	case lt == ltNTPMonlist:
		return NTP, false, true
	case lt == ltVNC:
		return VNC, false, true
	case lt == ltSIP:
		return SIP, false, true
	case lt == ltGit:
		return Git, false, true
	case lt == ltRedis:
		return Redis, false, true
	case lt >= ltBannerNew && lt <= ltBannerEnd:
		return TCPBanner, false, true
	case lt == ltMongoDB:
		return MongoDB, false, true
	}
	return "", false, false
}

// loginLine says whether a line is a login attempt that names an account: a bait account used on it fires its token (POST-2).
func loginLine(r Record) bool {
	switch r.LogType {
	case ltSSHLogin, ltHTTPLogin, ltMSSQLSQL, ltMSSQLWin, ltRDP, ltFTPLogin, ltTelnetLogin, ltProxyLogin, ltMySQLLogin:
		return true
	case ltMongoDB:
		return r.MongoAction == "mongodb.auth_attempt"
	}
	return false
}

// ntlmToken is how OpenCanary's proxy trap logs an NTLM Proxy-Authorization: the raw token, base64 of "NTLMSSP". It can carry the
// answer to the challenge, which is password material: never stored.
const ntlmSSPBase64 = "TlRMTVNT"

// detail is the line shown for what this log line did. It holds no password and nothing derived from one (a typed password may be
// a real one): OpenCanary's PASSWORD, the VNC answer and its guess, Redis's arguments (AUTH carries the password), MongoDB's
// auth_data and an NTLM token are never read into it.
func detail(r Record, svc ServiceName) string {
	q := func(s string) string { return `"` + s + `"` }
	login := func() string {
		s := "login attempt, account " + q(r.User)
		if r.Hostname != "" && r.LogType != ltHTTPLogin {
			s += ", from host name " + q(r.Hostname)
		}
		return s
	}
	switch r.LogType {
	case ltSSHNew, ltTelnetNew, ltMySQLNew, ltBannerNew:
		return "new connection"
	case ltSSHVersion:
		return "client version " + q(r.RemoteVersion)
	case ltSSHLogin, ltMSSQLSQL, ltMSSQLWin, ltRDP, ltFTPLogin, ltTelnetLogin, ltMySQLLogin:
		return login()
	case ltFTPAuthStart:
		return "login started"
	case ltProxyLogin:
		if strings.HasPrefix(r.User, ntlmSSPBase64) {
			return "proxy login attempt (NTLM)"
		}
		return "proxy login attempt, account " + q(r.User)
	case ltHTTPGet:
		return "request GET " + r.Path + userAgent(r)
	case ltHTTPRedirect:
		return "request GET " + r.Path + " (redirected to the login page)" + userAgent(r)
	case ltHTTPOther:
		return "request with a method the page refuses, " + r.Path + userAgent(r)
	case ltHTTPLogin:
		return "login attempt, account " + q(r.User) + " on " + r.Path + userAgent(r)
	case ltSMBFile:
		if r.Filename == "" || r.Filename == "/" { // Samba's "connect": the client opened the share itself
			return "share opened"
		}
		return "file opened " + q(r.Filename)
	case ltTFTP:
		op := "request"
		switch r.Opcode {
		case "READ":
			op = "read request"
		case "WRITE":
			op = "write request"
		}
		return op + " for file " + q(r.Filename)
	case ltNTPMonlist:
		return "monlist request (a list of the server's recent clients, used for reconnaissance and amplification)"
	case ltVNC:
		return "login attempt (answered the VNC password challenge)"
	case ltSIP:
		return "SIP request"
	case ltGit:
		return "clone request for repository " + q(r.Repo)
	case ltRedis:
		if r.Error != "" {
			return "malformed request: " + r.Error
		}
		return "command " + q(r.Cmd)
	case ltMongoDB:
		switch r.MongoAction {
		case "mongodb.connection":
			return "new connection"
		case "mongodb.auth_attempt":
			return login()
		case "mongodb.command":
			return "command " + q(r.Cmd)
		case "mongodb.disconnect":
			return "connection closed"
		}
		return "malformed request"
	}
	if r.LogType > ltBannerNew && r.LogType <= ltBannerEnd {
		return "data received"
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
	case !scan && !env.serves(r.Dst, svc), scan && len(env.trapIPs) == 0:
		return false
	case !r.TS.IsZero() && (r.TS.Before(env.now.Add(-maxLineAge)) || r.TS.After(env.now.Add(maxLineFuture))):
		return false
	}
	return true
}

// serves says whether a connection to svc on dst can be real: the Trap IP at dst has the service (the host closes the other
// ports, D-466). A line without a target address needs some Trap IP with the service; a host that cannot close ports
// (openPorts) lets every address answer every service that runs.
func (env *ingestEnv) serves(dst netip.Addr, svc ServiceName) bool {
	if dst.IsValid() && !env.openPorts {
		d := env.at[dst]
		return d != nil && d.has(svc)
	}
	return env.first(svc) != nil
}

// first is the oldest Trap IP handed to the host that has svc, nil when none has.
func (env *ingestEnv) first(svc ServiceName) *trapIPRow {
	for _, ip := range env.order {
		if d := env.at[ip]; d != nil && d.has(svc) {
			return d
		}
	}
	return nil
}

// nameAt is the name of the Trap IP at the address of a hit ("" when none).
func (env *ingestEnv) nameAt(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil {
		if d := env.at[a]; d != nil {
			return d.Name
		}
	}
	return ""
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
	svc, scan, ok := classify(r)
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
	if trapIP == "" && !scan { // a line without the target address: the oldest Trap IP with that service
		if d := env.first(svc); d != nil {
			trapIP = d.IP
		}
	}
	if scan {
		label := "Port scan on decoy " + dst
		if dst == "" {
			label = "Port scan on a decoy IP"
		}
		line := label + " from " + from
		return s.upsert(ctx, tx, env, storedHit{
			Hit:     Hit{TS: tsText, Kind: KindScan, Label: label, SrcIP: src, Excerpt: "TCP probe of a decoy IP", TrapIP: trapIP, TrapHostname: "Decoy sweep"},
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
	more := svc.Label() + " trap: " + det
	if r.SrcPort != 0 { // the SMB lines have no source port (OpenCanary writes -1): no "[from port 0]"
		more += " [from port " + strconv.Itoa(r.SrcPort) + "]"
	}
	svcCopy := svc
	if err := s.upsert(ctx, tx, env, storedHit{
		Hit:     Hit{TS: tsText, Kind: KindService, Service: &svcCopy, Label: svc.Label(), Port: &port, SrcIP: src, Excerpt: det, TrapIP: trapIP, TrapHostname: env.nameAt(trapIP)},
		connKey: connKey("service", string(svc), src, dst, strconv.Itoa(port), window),
		events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: first, Mark: true}},
	}, more, det); err != nil {
		return err
	}
	// A UDP line has no target address (OpenCanary's UDP listeners report 0.0.0.0): the Trap IP named above is a guess, so it is
	// not fed to the sweep, which counts Trap IPs; the host's record of the attempts (PollTouches) has the real target.
	if r.Dst.IsValid() || svc.Proto() != "udp" {
		if err := s.sweep(ctx, tx, env, r.Src, trapIP, ts); err != nil {
			return err
		}
	}
	// POST-2: a bait account or file touched. Only a token that still exists counts (INV-10).
	var tok Token
	var found bool
	switch {
	case loginLine(r):
		tok, found = env.creds[strings.ToLower(r.User)]
	case r.LogType == ltSMBFile:
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
		Hit:     Hit{TS: tsText, Kind: KindToken, Label: label, SrcIP: src, Excerpt: ex, TrapIP: tok.Value, TrapHostname: label},
		tokenID: tok.ID,
		connKey: connKey("token", tok.ID, src, window),
		events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: line, Mark: true}},
	}, line, "")
}

// sweepWindow: one source that touches two or more Trap IPs within this time is scanning the network (W1-13, S-HP-2).
const sweepWindow = time.Minute

// connectedWindow: a completed connection from a source vouches for its address on scan hits this close to it, before or after (W6-4;
// the window response uses to confirm a scan source, D-509).
const connectedWindow = time.Hour

// maxSweepSources bounds the memory of who touched what: past it the record starts over. ponytail: a flood of sources
// can make a real sweep in that poll go unseen as a scan (each of its hits still alerts); the upgrade is an LRU.
const maxSweepSources = 4096

// sweep records that src touched the Trap IP at trapIP at ts and, once src touched two or more Trap IPs within
// sweepWindow, stores one scan hit for src per hit window (later Trap IPs it touches in that window are added to the same
// hit, not a new alert). The record is memory only: a sweep that a restart of core cuts in two is not seen as one.
func (s *Service) sweep(ctx context.Context, tx *sql.Tx, env *ingestEnv, src netip.Addr, trapIP string, ts time.Time) error {
	from, to := store.FormatTS(ts.Add(-connectedWindow)), store.FormatTS(ts.Add(connectedWindow))
	if !env.touch { // a real connection from src proves its address: no scan hit of src near it calls it forged, whichever came first (W6-4)
		if _, err := tx.ExecContext(ctx, `UPDATE hp_hits SET excerpt = REPLACE(excerpt, ?, '') WHERE kind = 'scan' AND src_ip = ? AND ts BETWEEN ? AND ?`,
			forgedNote, src.String(), from, to); err != nil {
			return fmt.Errorf("honeypot: update scan hit: %w", err)
		}
	}
	ip, err := netip.ParseAddr(trapIP)
	if err != nil || env.at[ip] == nil {
		return nil
	}
	if s.touches == nil || len(s.touches) > maxSweepSources {
		s.touches = map[netip.Addr]map[netip.Addr]time.Time{}
	}
	seen := s.touches[src]
	if seen == nil {
		seen = map[netip.Addr]time.Time{}
		s.touches[src] = seen
	}
	if old, ok := seen[ip]; !ok || ts.After(old) {
		seen[ip] = ts
	}
	var near []netip.Addr
	for a, at := range seen {
		switch d := ts.Sub(at); {
		case d > sweepWindow:
			delete(seen, a) // too old for any later line (the log is in time order, give or take a second)
		case d >= -sweepWindow:
			near = append(near, a)
		}
	}
	if len(near) < 2 {
		return nil
	}
	slices.SortFunc(near, func(a, b netip.Addr) int { return a.Compare(b) })
	var ips, names, both []string
	for _, a := range near {
		name := env.nameAt(a.String())
		ips, names, both = append(ips, a.String()), append(names, name), append(both, name+" ("+a.String()+")")
	}
	tsText := store.FormatTS(ts)
	line := src.String() + " touched " + env.nameAt(trapIP) + " (" + trapIP + ")"
	key := connKey("sweep", src.String(), strconv.FormatInt(ts.Truncate(hitWindow).Unix(), 10))
	note := ""
	if env.touch { // only attempts: forged unless src completed a connection near it (the rule response uses, SourceConnected, D-509)
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hp_hits WHERE src_ip = ? AND is_test = 0 AND kind = 'service' AND ts BETWEEN ? AND ?`,
			src.String(), from, to).Scan(&n); err != nil {
			return fmt.Errorf("honeypot: read the hits of a source: %w", err)
		}
		if n == 0 {
			note = forgedNote
		}
	}
	if err := s.upsert(ctx, tx, env, storedHit{
		Hit: Hit{TS: tsText, Kind: KindScan, Label: "Scan across the Trap IPs", SrcIP: src.String(),
			Excerpt: "Touched " + strings.Join(both, ", ") + " within a minute" + note, TrapIP: joinMax(ips, maxTrapIPText), TrapHostname: joinMax(names, maxTrapNameText)},
		connKey: key,
		events:  []HitEvent{{TS: tsText, Source: "honeypot", Text: line, Mark: true}},
	}, line, env.nameAt(trapIP)+" ("+trapIP+")"); err != nil {
		return err
	}
	return s.widenSweep(ctx, tx, env, key, near)
}

// The column limits of hp_hits trap_ip and trap_hostname (migration 0001).
const (
	maxTrapIPText   = 400
	maxTrapNameText = 200
)

// widenSweep keeps the Trap IP columns of a scan hit naming every Trap IP the source touched in its window: a Trap IP touched
// later in the same window (a third, a fourth) joins the columns, not only the excerpt and the lines (B2 review).
func (s *Service) widenSweep(ctx context.Context, tx *sql.Tx, env *ingestEnv, key string, near []netip.Addr) error {
	var have string
	switch err := tx.QueryRowContext(ctx, `SELECT trap_ip FROM hp_hits WHERE conn_key = ?`, key).Scan(&have); {
	case errors.Is(err, sql.ErrNoRows):
		return nil // over the flood cap: not stored
	case err != nil:
		return fmt.Errorf("honeypot: find scan hit: %w", err)
	}
	all := slices.Clone(near)
	for _, part := range strings.Split(have, ", ") {
		if a, err := netip.ParseAddr(part); err == nil && !slices.Contains(all, a) {
			all = append(all, a)
		}
	}
	slices.SortFunc(all, func(a, b netip.Addr) int { return a.Compare(b) })
	ips, names := make([]string, 0, len(all)), make([]string, 0, len(all))
	for _, a := range all {
		name := env.nameAt(a.String())
		if name == "" {
			name = a.String()
		}
		ips, names = append(ips, a.String()), append(names, name)
	}
	if ipText := joinMax(ips, maxTrapIPText); ipText != have {
		if _, err := tx.ExecContext(ctx, `UPDATE hp_hits SET trap_ip = ?, trap_hostname = ? WHERE conn_key = ?`, ipText, joinMax(names, maxTrapNameText), key); err != nil {
			return fmt.Errorf("honeypot: update scan hit: %w", err)
		}
	}
	return nil
}

func isBroadcast(lan netip.Prefix, a netip.Addr) bool {
	if a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.IsMulticast() {
		return true
	}
	return lan.IsValid() && lan.Bits() < 31 && a == lastAddr(lan)
}

// hasEvent says whether evs has a line of this time and text: the same log line read twice. A later connection that logs the same
// text (a second SMB visit within the hit window: no source port, the same "share opened") is a new line (M5-188). ts "" compares
// the text only: a scan hit has one line per Trap IP touched, not one per connection.
func hasEvent(evs []HitEvent, ts, text string) bool {
	for _, e := range evs {
		if (ts == "" || e.TS == ts) && e.Text == text {
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
		if env.touch && len(env.newHits) >= env.touchLeft ||
			!env.touch && (env.pollNew+len(env.newHits) >= maxNewPerPoll || env.hourNew+len(env.newHits) >= maxNewPerHour) {
			env.st.Suppressed++
			return nil
		}
		h.ID = store.NewID("hit")
		h.Excerpt = clean(h.Excerpt, maxExcerpt)
		for i := range h.events {
			h.events[i].Text = clean(h.events[i].Text, 300)
		}
		if l := clean(line, 300); l != "" && !hasEvent(h.events, h.TS, l) {
			h.events = append(h.events, HitEvent{TS: h.TS, Source: "honeypot", Text: l}) // INV-9: only the hit's own line is marked
		}
		if err := s.insertHit(ctx, tx, h); err != nil {
			return err
		}
		d := HitEventData{ID: h.ID, TS: h.TS, Kind: h.Kind, SrcIP: h.SrcIP, Label: h.Label, Decoy: h.TrapHostname}
		if d.Decoy == "" {
			d.Decoy = h.TrapIP
		}
		if dev := env.w.byIP(h.SrcIP); dev != nil { // INV-8: the source device as the inventory knows it now
			d.SrcAssetID, d.SrcName = dev.ID, clean(dev.Name, 120)
		}
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
	at := h.TS
	if h.Kind == KindScan {
		at = ""
	}
	if hasEvent(evs, at, line) { // the same log line read again (a batch that failed): nothing new
		return nil
	}
	if len(evs) < maxEvents {
		evs = append(evs, HitEvent{TS: h.TS, Source: "honeypot", Text: line}) // INV-9: a later connection is not the hit's line
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

// touchEvery is how often the host's record of connection attempts is read (B2 review M2). The host takes 60 reads a minute for
// all of core; a sweep is judged on the attempts' own times, so a poll every 15 s still sees two Trap IPs within a minute.
const touchEvery = 15 * time.Second

// touchTTL is how long the host keeps a (source, Trap IP) attempt (host-api 6.6 set touched): the same attempt read again before it
// expires is not fed twice.
const touchTTL = 2 * time.Minute

// maxTouchKeys bounds the memory of attempts already fed (the host's set holds at most 1024).
const maxTouchKeys = 4096

// maxTouchScansPerHour is the budget of new scan hits from attempts that completed no handshake (their source can be forged): a
// flood of forged sources stops here, never drawing from maxNewPerHour, so the listener hits keep alerting (B2 review M2).
const maxTouchScansPerHour = 20

// forgedNote ends the excerpt of a scan hit made from attempts the host recorded.
const forgedNote = " The handshake was not completed, so the source address may be forged."

// PollTouches feeds the host's record of new TCP/UDP attempts to the Trap IPs into the sweep detection (B2 review M2: a SYN scan,
// nmap's default, completes no connection, so OpenCanary logs nothing). Only the sweep: a single attempt is no hit (the listener
// hits stay the per-touch alerts). The source must be plausible as for a log line (not the box, a Trap IP, loopback, the network
// or a broadcast address) and the target a Trap IP handed to the host. Each attempt is fed once while the host keeps it.
func (s *Service) PollTouches(ctx context.Context) error {
	r, ok := s.cfg.Host.(touchReporter)
	if !ok || !s.on() {
		return nil
	}
	list, err := r.Touches(ctx)
	if err != nil || len(list) == 0 {
		return err
	}
	s.pollMu.Lock()
	defer s.pollMu.Unlock()
	now := s.now()
	if s.fedTouches == nil || len(s.fedTouches) > maxTouchKeys {
		s.fedTouches = map[string]time.Time{}
	}
	for k, until := range s.fedTouches {
		if now.After(until) {
			delete(s.fedTouches, k)
		}
	}
	var fresh []Touch
	for _, t := range list {
		key := t.Src.String() + "|" + t.Dst.String()
		if until, seen := s.fedTouches[key]; seen && now.Before(until) {
			continue
		}
		s.fedTouches[key] = t.At.Add(touchTTL + touchEvery)
		fresh = append(fresh, t)
	}
	if len(fresh) == 0 {
		return nil
	}
	slices.SortFunc(fresh, func(a, b Touch) int { return a.At.Compare(b.At) }) // sweep reads them in time order, as log lines
	env, err := s.newIngest(ctx)
	if err != nil {
		return err
	}
	hour := now.Truncate(time.Hour)
	s.mu.Lock()
	if !s.touchHourStart.Equal(hour) {
		s.touchHourStart, s.touchHourNew = hour, 0
	}
	env.touch, env.touchLeft = true, maxTouchScansPerHour-s.touchHourNew
	s.mu.Unlock()
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		env.newHits, env.ignored, env.st = nil, 0, Stats{}
		for _, t := range fresh {
			if !env.touchPlausible(t) { // the box, a Trap IP, broadcast...: not counted as an implausible log line (B2 review L2)
				continue
			}
			if err := s.sweep(ctx, tx, env, t.Src, t.Dst.String(), t.At); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		for _, t := range fresh { // not stored: feed them again next time
			delete(s.fedTouches, t.Src.String()+"|"+t.Dst.String())
		}
		return err
	}
	s.afterBatch(ctx, env)
	return nil
}

// touchPlausible is plausible (ingest) for an attempt the host recorded: the source is not the box, a Trap IP, loopback, the
// network or a broadcast address; the target is a Trap IP handed to the host; the time is within the host's record.
func (env *ingestEnv) touchPlausible(t Touch) bool {
	w := env.w
	switch {
	case !t.Src.Is4() || t.Src.IsLoopback() || t.Src.IsMulticast() || t.Src.IsUnspecified(), env.trapIPs[t.Src]:
		return false
	case w.box.IP.IsValid() && t.Src == w.box.IP, isBroadcast(w.lan, t.Src), w.lan.IsValid() && w.lan.Bits() < 31 && t.Src == w.lan.Masked().Addr():
		return false
	case !env.trapIPs[t.Dst]:
		return false
	}
	return !t.At.Before(env.now.Add(-touchTTL-touchEvery)) && !t.At.After(env.now.Add(maxLineFuture))
}
