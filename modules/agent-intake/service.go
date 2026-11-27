package agentintake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/observe"
	coreschedule "github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// Caps and timings of the intake.
const (
	MaxTokens        = 500
	MaxNodesPerToken = 500
	MaxNodes         = 5000
	enrollCooldown   = 60 * time.Second // the same (token, host_identifier) cannot enrol again sooner
	auditEnrollEvery = 24 * time.Hour   // one enrol audit row per node per day
	touchEvery       = time.Minute      // last_seen is written at most this often per node (log path)
	configTouch      = 10 * time.Second // the same on the config path (a restart is seen quickly)
	NodeSilentDays   = 90               // a node silent this long is deleted by the node-prune job
	freshTokenAge    = time.Hour        // Remove unused tokens leaves a token younger than this alone: its command may be on screen
	unusedTokenLife  = 24 * time.Hour   // a token that has enrolled no machine this long after it was made expires
	systemActor      = "system"
)

// Config is what New needs. DB, Audit, Sink, Software and Approver are required. Secrets and Conn are the Wazuh pull's (slice 4):
// without both, its routes answer 501 and its job does nothing.
type Config struct {
	DB       *store.DB
	Audit    *audit.Log
	Sink     observe.Sink         // the inventory: device observations (core/observe)
	Software observe.SoftwareSink // the inventory: the software list of a device
	Approver observe.Approver     // the inventory: the enrolment approves the device a node reports on
	Services observe.ServiceSink  // the inventory: the open ports a machine's agent reports (INV-22); nil: they are not recorded
	// Removed says whether an enrolment (EnrolKey) belongs to a device a person removed with its agent stopped (the inventory's
	// RemovedAgent): that enrolment is refused (INV-27). nil: none is.
	Removed func(ctx context.Context, key string) (bool, error)
	Secrets *secrets.Store // the Wazuh password (purpose intake_wazuh.password)
	Conn    *conn.Service  // the HTTPS client and address policy for the Wazuh server
	// Schedules keeps the Wazuh pull's schedule in step with the connection form (core/schedule Service.SaveTx); nil: the form's interval is not stored.
	Schedules interface {
		SaveTx(ctx context.Context, tx *sql.Tx, key string, st coreschedule.Setting, by string) error
	}
	Clock func() time.Time
	Log   *slog.Logger

	// The install scripts, the certificate and the package mirror (slice 3). All optional: without TrustAnchor, ca.pem and the scripts
	// answer 404 no_certificate; without MirrorDir the package files answer 404 mirror_missing; without HostAllowed the request's Host is
	// never used for the box address.
	TrustAnchor func() ([]byte, error) // the PEM certificates osquery pins (cmd/vedette trustAnchor); ErrNoTrustAnchor when the box has no certificate
	HostAllowed func(host string) bool // the Host allow-list of the server (server.HostMatcher): the only Hosts the scripts may carry
	BoxURL      func() string          // the Box address as https://host[:port], read at every use; nil or "" when there is none
	MirrorDir   string                 // the folder of the image that holds the pinned osquery packages
}

// Service is the osquery intake. Create it with New.
type Service struct {
	cfg  Config
	db   *store.DB
	fail *failLimiter
	node *nodeLimiter

	warnMu   sync.Mutex // guards lastWarn and replaced
	lastWarn map[string]time.Time
	replaced map[string]*replaceState // by list kind and source address: the last replace (ingest.go allowReplace)

	wazuhRoots  *x509.CertPool // nil: the system's (tests replace it)
	wazuhSleep  func(ctx context.Context, d time.Duration) error
	wazuhPace   time.Duration
	wazuhBudget func(ctx context.Context) (context.Context, context.CancelFunc) // one pull's time (wazuhPullBudget; tests end it themselves)

	mirror      chan struct{}   // one slot per running package download, box-wide (install.go)
	mirrorBy    map[string]bool // the source addresses (srcKey) that hold a slot: one download each
	mirrorMu    sync.Mutex
	chunkWait   time.Duration // mirrorChunkWait, mirrorMaxTime (tests shorten them)
	maxDownload time.Duration
	mirrorEvent func(key string, held bool) // tests only: called when a source address takes or gives back its slot
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Sink == nil || cfg.Software == nil || cfg.Approver == nil {
		return nil, errors.New("agentintake: New needs DB, Audit, Sink, Software and Approver")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	s := &Service{cfg: cfg, db: cfg.DB, lastWarn: map[string]time.Time{}, replaced: map[string]*replaceState{}, mirror: make(chan struct{}, maxMirrorDownloads), mirrorBy: map[string]bool{}, chunkWait: mirrorChunkWait, maxDownload: mirrorMaxTime}
	s.fail = newFailLimiter(s.now)
	s.node = newNodeLimiter(s.now)
	s.wazuhSleep, s.wazuhPace = sleepCtx, wazuhPace
	s.wazuhBudget = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, wazuhPullBudget)
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }

// errNodeInvalid is every credential failure: an unknown, revoked or expired token, a key that is not (or no longer) a node's, a request
// that is not shaped like one of ours. The handler answers 200 + node_invalid for it and never says which.
var errNodeInvalid = errors.New("agentintake: node invalid")

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// sameHash compares two hex hashes in constant time.
func sameHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func newNodeKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentintake: node key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil // 256 bits, 43 characters
}

func rateLimited(wait time.Duration) *apierr.Error {
	secs := max(1, int((wait+time.Second-1)/time.Second))
	return apierr.New(429, "rate_limited", "Too many requests. Try again later.").With("retry_after", secs)
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("agentintake: audit: %w", err)
	}
	return nil
}

// warnUnmatched logs that a node's connection address is not among the IPv4 it declared, for a node at most once an hour: a node that
// stays unmatched must not fill the log.
func (s *Service) warnUnmatched(ctx context.Context, key string, args ...any) {
	if s.warnDue(time.Hour, key) {
		s.cfg.Log.WarnContext(ctx, "agent-intake: a node's address is not among the IPv4 it declared; nothing written to the inventory unless a sensor saw the node's device at that address", args...)
	}
}

// warnDue says whether a WARN line for key may be written now: at most once per every. What anyone can trigger without a credential must
// not fill the log.
func (s *Service) warnDue(every time.Duration, key string) bool {
	now := s.now()
	s.warnMu.Lock()
	if len(s.lastWarn) > limiterKeys {
		clear(s.lastWarn)
	}
	last, seen := s.lastWarn[key]
	due := !seen || now.Sub(last) >= every
	if due {
		s.lastWarn[key] = now
	}
	s.warnMu.Unlock()
	return due
}

// ---- tokens: look-up ----

// tokenRow is the row of a token found by its secret.
type tokenRow struct {
	id, name string
	expires  time.Time // zero = never
	received time.Time // zero = never
	used     bool      // a machine has enrolled with it
}

// effectiveExpiry is when a token stops enrolling machines: its set expiry, or, while no machine has enrolled with it, a day after it was made
// when that is sooner. The set expiry is the normal lifetime (default 7 days) a token keeps once it has enrolled a machine.
func effectiveExpiry(set, created time.Time, used bool) time.Time {
	if used || created.IsZero() {
		return set
	}
	if short := created.Add(unusedTokenLife); set.IsZero() || short.Before(set) {
		return short
	}
	return set
}

func parseTS(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// tokenBySecret finds the token whose secret hashes to secret's hash; errNodeInvalid when there is none.
func (s *Service) tokenBySecret(ctx context.Context, q querier, secret string) (tokenRow, error) {
	want := hashHex(secret)
	var t tokenRow
	var got string
	var exp, rec, first sql.NullString
	var created string
	err := q.QueryRowContext(ctx, `SELECT id, name, token_hash, expires_at, last_received, created_at, first_enrolled_at FROM intake_agent_tokens WHERE token_hash = ?`, want).Scan(&t.id, &t.name, &got, &exp, &rec, &created, &first)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenRow{}, errNodeInvalid
	}
	if err != nil {
		return tokenRow{}, fmt.Errorf("agentintake: read token: %w", err)
	}
	if !sameHash(got, want) {
		return tokenRow{}, errNodeInvalid
	}
	t.expires, t.received = effectiveExpiry(parseTS(exp), parseTS(sql.NullString{String: created, Valid: true}), first.Valid), parseTS(rec)
	t.used = first.Valid
	return t, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (t tokenRow) expired(now time.Time) bool { return !t.expires.IsZero() && !now.Before(t.expires) }

// ---- enrol ----

// Enroll exchanges an enrolment token for a node key. The key is returned once and only its hash is kept. A bad token is
// errNodeInvalid and counts against the source (429 after 10 a minute); the same (token, host_identifier) cannot enrol again within
// 60 seconds; the caps are 500 nodes per token and 5,000 in all (429 too_many_nodes).
func (s *Service) Enroll(ctx context.Context, src netip.Addr, in enrollIn) (string, error) {
	key := srcKey(src)
	if w := s.fail.blocked(key); w > 0 {
		return "", rateLimited(w)
	}
	bad := func() (string, error) {
		s.fail.fail(key)
		s.logReject(ctx, "enroll", src, "credential")
		return "", errNodeInvalid
	}
	t, err := s.tokenBySecret(ctx, s.db.Reader(), in.secret)
	if errors.Is(err, errNodeInvalid) || (err == nil && t.expired(s.now())) {
		return bad()
	}
	if err != nil {
		return "", err
	}
	if s.cfg.Removed != nil { // a machine whose device a person removed with its agent stopped (INV-27): refused, not counted as a guess
		removed, err := s.cfg.Removed(ctx, EnrolKey(t.id, in.hostIdentifier))
		if err != nil {
			return "", err
		}
		if removed {
			s.logReject(ctx, "enroll", src, "removed")
			return "", errNodeInvalid
		}
	}
	nodeKey, err := newNodeKey()
	if err != nil {
		return "", err
	}
	invalid := false
	var replaced string
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		t, err := s.tokenBySecret(ctx, tx, in.secret) // again under the writer: a revoke may have come in between
		if err != nil || t.expired(s.now()) {
			invalid = true
			return nil
		}
		replaced, err = s.enrollTx(ctx, tx, t, in, nodeKey)
		return err
	})
	switch {
	case err != nil:
		return "", err
	case invalid:
		return bad()
	}
	if replaced != "" {
		s.releaseNodes(ctx, []string{replaced})
	}
	return nodeKey, nil
}

// enrollTx stores the node; it returns the id of the node it replaced (the same token and host_identifier), "" when none.
func (s *Service) enrollTx(ctx context.Context, tx *sql.Tx, t tokenRow, in enrollIn, nodeKey string) (string, error) {
	now := s.now()
	var oldID, oldEnrolled string
	err := tx.QueryRowContext(ctx, `SELECT id, enrolled_at FROM intake_osquery_nodes WHERE token_id = ? AND host_identifier = ?`, t.id, in.hostIdentifier).Scan(&oldID, &oldEnrolled)
	replaced := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("agentintake: read node: %w", err)
	}
	var oldAt time.Time
	if replaced {
		oldAt, _ = time.Parse(time.RFC3339Nano, oldEnrolled)
		if wait := enrollCooldown - now.Sub(oldAt); wait > 0 {
			return "", rateLimited(wait)
		}
	}
	var perToken, total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE token_id = ?), count(*) FROM intake_osquery_nodes WHERE id <> ?`, t.id, oldID).Scan(&perToken, &total); err != nil {
		return "", fmt.Errorf("agentintake: count nodes: %w", err)
	}
	if perToken >= MaxNodesPerToken || total >= MaxNodes {
		return "", apierr.New(429, "too_many_nodes", "This enrollment token already has the most machines it can have. Revoke it and make a new one.").With("retry_after", 3600)
	}
	if replaced {
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE id = ?`, oldID); err != nil {
			return "", fmt.Errorf("agentintake: replace node: %w", err)
		}
	}
	ts := store.FormatTS(now)
	if _, err := tx.ExecContext(ctx, `UPDATE intake_agent_tokens SET first_enrolled_at = ? WHERE id = ? AND first_enrolled_at IS NULL`, ts, t.id); err != nil {
		return "", fmt.Errorf("agentintake: mark token used: %w", err)
	}
	// The rhythm it was told: osquery fetches its config every configRefresh; the package reporter (it enrols without an osquery version)
	// runs once an hour and fetches no config.
	every := configRefresh
	if in.osqueryVersion == "" {
		every = reporterEvery
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO intake_osquery_nodes (id, token_id, node_key_hash, host_identifier, hostname, platform, osquery_version, enrolled_at, last_seen, last_call_at, call_every_s) VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?)`,
		store.NewID("node"), t.id, hashHex(nodeKey), in.hostIdentifier, in.hostname, in.platform, in.osqueryVersion, ts, ts, ts, int64(every/time.Second)); err != nil {
		return "", fmt.Errorf("agentintake: insert node: %w", err)
	}
	if replaced && now.Sub(oldAt) < auditEnrollEvery { // one audit row per node per day (a flapping client must not fill core_audit)
		return oldID, nil
	}
	return oldID, s.auditTx(ctx, tx, systemActor, "inventory.agent_enroll", in.hostIdentifier, fmt.Sprintf("token %q, host %q", t.name, in.hostname))
}

// releaseNodes tells the inventory these nodes are gone: the devices bound to them may be bound by the next node. It runs after
// the deleting transaction committed; a failure is logged, never returned: the device then stays found by address until a later release.
func (s *Service) releaseNodes(ctx context.Context, ids []string) {
	r, ok := s.cfg.Approver.(observe.AgentReleaser)
	if !ok || len(ids) == 0 {
		return
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = nodeAgent(id)
	}
	if err := r.ReleaseAgents(context.WithoutCancel(ctx), keys); err != nil {
		s.cfg.Log.WarnContext(ctx, "agent-intake: the inventory did not release deleted nodes", "nodes", len(ids), "error", err.Error())
	}
}

// logReject is the server-side line of a refused credential: a reason code and the source address, never the secret or the key.
func (s *Service) logReject(ctx context.Context, op string, src netip.Addr, reason string) {
	s.cfg.Log.InfoContext(ctx, "agent-intake: credential refused", "op", op, "reason", reason, "src", src.String())
}

// ---- nodes: look-up and liveness ----

type nodeRow struct {
	id, tokenID string
	lastSeen    time.Time
	lastCall    time.Time     // its last call (last_call_at), from which the next call's gap is measured
	lastResult  time.Time     // its last result post (last_result_at), zero when none: a last call equal to it was a result post
	callEvery   time.Duration // how often it was told to call (call_every_s)
	callGap     time.Duration // its own smoothed gap between calls (call_gap_s), 0 until learned
	reportEvery time.Duration // the longest interval of the schedule the box last gave it, without its speed-ups (report_every_s)
	enrolledAt  time.Time
	boundIP     netip.Addr
	boundMAC    string
	reported    string    // the answers of the first report the inventory took (schedule.go firstReport), comma-separated
	approved    bool      // the enrolment's approval was done
	kernel      string    // the running kernel release the node last reported (kernel_info), "" until it has
	win         winOS     // the Windows release and update revision the node last reported (os_revision), zero until it has
	hostname    string    // the host name osquery gave at enrolment (host_details.system_info), "" when none
	hostID      string    // the host_identifier it enrolled under (the install scripts send the machine's host name, --host_identifier=specified)
	askedAt     time.Time // when a person last asked it to send its software now (report.go), zero when never
	softwareAt  time.Time // when the inventory last took a software list from it that closed an ask (report.go), zero when never
	osAt        time.Time // when its own OS answer (kernel_info, os_revision) last came while an ask was open (report.go), zero when never
	platform    string    // osquery's platform at enrolment ("windows", "ubuntu", ...), "" when not given
}

// nodeByKey finds the node whose key hashes to the hash of key; errNodeInvalid when there is none.
func (s *Service) nodeByKey(ctx context.Context, key string) (nodeRow, error) {
	want := hashHex(key)
	var n nodeRow
	var got, seen, enrolled, asked, taken, osTaken, call, result string
	var every, gap, report int64
	var ip, mac sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id, token_id, node_key_hash, last_seen, enrolled_at, bound_ip, bound_mac, reported, approved_at IS NOT NULL, kernel,
		win_name, win_version, win_target, ifnull(hostname, ''), host_identifier, ifnull(report_asked_at, ''), ifnull(software_taken_at, ''),
		ifnull(os_taken_at, ''), ifnull(platform, ''), ifnull(last_call_at, last_seen), call_every_s, ifnull(call_gap_s, 0), report_every_s, ifnull(last_result_at, '')
		FROM intake_osquery_nodes WHERE node_key_hash = ?`, want).Scan(&n.id, &n.tokenID, &got, &seen, &enrolled, &ip, &mac,
		&n.reported, &n.approved, &n.kernel, &n.win.name, &n.win.version, &n.win.target, &n.hostname, &n.hostID, &asked, &taken, &osTaken, &n.platform,
		&call, &every, &gap, &report, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return nodeRow{}, errNodeInvalid
	}
	if err != nil {
		return nodeRow{}, fmt.Errorf("agentintake: read node: %w", err)
	}
	if !sameHash(got, want) {
		return nodeRow{}, errNodeInvalid
	}
	n.lastSeen, _ = time.Parse(time.RFC3339Nano, seen)
	n.enrolledAt, _ = time.Parse(time.RFC3339Nano, enrolled)
	n.askedAt, _ = time.Parse(time.RFC3339Nano, asked)
	n.softwareAt, _ = time.Parse(time.RFC3339Nano, taken)
	n.osAt, _ = time.Parse(time.RFC3339Nano, osTaken)
	n.lastCall, _ = time.Parse(time.RFC3339Nano, call)
	n.lastResult, _ = time.Parse(time.RFC3339Nano, result)
	n.callEvery, n.callGap, n.reportEvery = time.Duration(every)*time.Second, time.Duration(gap)*time.Second, time.Duration(report)*time.Second
	if ip.Valid {
		n.boundIP, _ = netip.ParseAddr(ip.String)
		n.boundMAC = mac.String
	}
	return n, nil
}

// authNode is the common start of config and log: the source is not blocked, the key is a node's, the node is within its rate.
func (s *Service) authNode(ctx context.Context, op string, src netip.Addr, key string, kind string, perMin int) (nodeRow, error) {
	sk := srcKey(src)
	if w := s.fail.blocked(sk); w > 0 {
		return nodeRow{}, rateLimited(w)
	}
	n, err := s.nodeByKey(ctx, key)
	if errors.Is(err, errNodeInvalid) {
		s.fail.fail(sk)
		s.logReject(ctx, op, src, "node key")
		return nodeRow{}, errNodeInvalid
	}
	if err != nil {
		return nodeRow{}, err
	}
	if ok, wait := s.node.allow(n.id, kind, perMin); !ok {
		return nodeRow{}, rateLimited(wait)
	}
	return n, nil
}

// Config answers a config request: errNodeInvalid for an unknown key, else the schedule of this node (schedule.go nodeSchedule: a node
// in its first hour asks every minute for the answers of its first report the inventory has not taken yet).
func (s *Service) Config(ctx context.Context, src netip.Addr, nodeKey string) (*oas.InventoryPostIntakeOsqueryConfigOK, error) {
	n, err := s.authNode(ctx, "config", src, nodeKey, "config", configPerMin)
	if err != nil {
		return nil, err
	}
	// osquery fetches its config at start and every config_refresh (the installer sets 300 s): write last_seen at most every configTouch so
	// that a restart (the installer's) is seen within the installer's wait, not up to a minute later (the log path keeps touchEvery).
	now := s.now()
	intervals := nodeSchedule(n, now, src)
	if err := s.touch(ctx, n, configTouch, steadyEvery()); err != nil {
		return nil, err
	}
	return configResponse(intervals), nil
}

// steadyEvery is the longest interval of the schedule without its speed-ups (the first report, a person's ask): a node delivers results
// at least that often once it runs the schedule, whether or not it fetches its config again.
func steadyEvery() time.Duration {
	m := 0
	for _, q := range schedule {
		m = max(m, q.interval)
	}
	return time.Duration(m) * time.Second
}

// touch records that the node called (a config fetch), at most once per every, with the gap since its last call (nextGap) and the
// longest interval of the schedule it is given (report_every_s, steadyEvery).
func (s *Service) touch(ctx context.Context, n nodeRow, every, report time.Duration) error {
	now := s.now()
	if now.Sub(n.lastSeen) < every && (report == 0 || report == n.reportEvery) {
		return nil
	}
	// Learned only between two config fetches in a row: when the call before was a result post, the gap says nothing about the config
	// refresh (an agent without it fetches its config only when its service starts, often minutes after a result). Written only when
	// learned: otherwise the column is left as it is now, never set back to a value read before (a result post at the same time may have
	// forgotten it).
	var learned any                                                               // nil: call_gap_s unchanged
	if report != 0 && (n.lastResult.IsZero() || n.lastCall.After(n.lastResult)) { // a config fetch (the log path's touch is no fetch)
		if gap := nextGap(n.callGap, now.Sub(n.lastCall), n.callEvery); gap != n.callGap {
			learned = gapSeconds(gap)
		}
	}
	if report == 0 {
		report = n.reportEvery
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET last_seen = ?1, last_call_at = ?1, call_gap_s = coalesce(?2, call_gap_s), report_every_s = ?3 WHERE id = ?4`,
			store.FormatTS(now), learned, int64(report/time.Second), n.id); err != nil {
			return fmt.Errorf("agentintake: touch node: %w", err)
		}
		return nil
	})
}

// gapSeconds is the stored call_gap_s of a learned gap (NULL while nothing is learned).
func gapSeconds(d time.Duration) any {
	if d <= 0 {
		return nil
	}
	return max(int64(d/time.Second), 1)
}

// ---- status ----

// Status answers the install script's "has THIS machine enrolled yet" (host: its name; seen is that machine's last_seen under this token, "" when none) (token in the Authorization header). A bad token counts
// against the source like an enrol does. The errors are 403 invalid_token and token_expired as the approved mock has them: the caller
// holds the token and is the person who made it, and the answer carries no data.
func (s *Service) Status(ctx context.Context, src netip.Addr, secret, host string) (enrolled bool, hosts int, seen string, err error) {
	key := srcKey(src)
	if w := s.fail.blocked(key); w > 0 {
		return false, 0, "", rateLimited(w)
	}
	t, err := s.tokenBySecret(ctx, s.db.Reader(), secret)
	if errors.Is(err, errNodeInvalid) {
		s.fail.fail(key)
		s.logReject(ctx, "status", src, "credential")
		return false, 0, "", apierr.New(403, "invalid_token", "This enrollment token is not valid. Create a new one in Vedette.")
	}
	if err != nil {
		return false, 0, "", err
	}
	if t.expired(s.now()) {
		s.fail.fail(key)
		return false, 0, "", apierr.New(403, "token_expired", "This enrollment token has expired. Create a new one in Vedette.")
	}
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM intake_osquery_nodes WHERE token_id = ?`, t.id).Scan(&hosts); err != nil {
		return false, 0, "", fmt.Errorf("agentintake: count hosts: %w", err)
	}
	if host != "" { // this machine only, among the machines of this token: the token already lets its holder enrol under any name
		var ls string
		err := s.db.Reader().QueryRowContext(ctx, `SELECT last_seen FROM intake_osquery_nodes WHERE token_id = ? AND (lower(host_identifier) = lower(?) OR lower(hostname) = lower(?)) ORDER BY last_seen DESC LIMIT 1`, t.id, host, host).Scan(&ls)
		switch {
		case err == nil:
			seen = ls
		case !errors.Is(err, sql.ErrNoRows):
			return false, 0, "", fmt.Errorf("agentintake: host last seen: %w", err)
		}
	}
	return !t.received.IsZero(), hosts, seen, nil
}
