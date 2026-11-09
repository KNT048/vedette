package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/peer"
)

// maxAuditLine bounds one line of audit.jsonl; entries stay far below it (args_redacted is capped).
const maxAuditLine = 32 << 10

// ErrAuditBroken means the chain on disk does not verify (or a write failed); nothing is appended after it.
var ErrAuditBroken = errors.New("host: audit chain is broken")

// Audit results (spec section 9).
const (
	resultOK       = "ok"
	resultRefused  = "refused"
	resultFailed   = "failed"
	resultReverted = "reverted"
)

// auditEntry is what the server records for one command.
type auditEntry struct {
	ID           string
	RequestID    string
	Actor        string
	Peer         peer.Info
	Command      string
	ArgsDigest   string
	ArgsRedacted any
	Result       string
	Code         string
	RunID        string
}

// auditLog is the append-only, hash-chained audit.jsonl (spec section 9, D-57 (14), SYS-3).
// The chain formula is core/chain's: hash = SHA-256(prev_hash "\n" canon(entry)).
type auditLog struct {
	mu     sync.RWMutex
	path   string
	f      *os.File
	seq    int64
	last   string
	broken error
	now    func() time.Time
}

// openAudit opens (creating it 0600) and verifies the file. A chain that does not verify is not an
// error here: the log is returned in the broken state, appends are refused, and Broken says why.
// An error means the file itself cannot be used.
func openAudit(path string, owner int, now func() time.Time) (*auditLog, error) {
	a := &auditLog{path: path, last: chain.Genesis, now: now}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // path is the -audit-log flag chosen by the operator
	if err != nil {
		return nil, fmt.Errorf("host: open audit log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("host: stat audit log: %w", err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); st.Mode().Perm()&0o077 != 0 || !st.Mode().IsRegular() || !ok || int(sys.Uid) != owner {
		_ = f.Close()
		return nil, fmt.Errorf("host: audit log %s must be a regular file with mode 0600 owned by uid %d", path, owner)
	}
	a.f = f
	a.seq, a.last, a.broken = verifyAuditFile(f)
	return a, nil
}

func (a *auditLog) close() error {
	if err := a.f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// ok reports whether appends are accepted.
func (a *auditLog) ok() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.broken == nil
}

// brokenErr returns why appends are refused, nil when healthy.
func (a *auditLog) brokenErr() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.broken
}

// verifyAuditFile walks the whole file once. It returns the last seq and hash and the first problem.
func verifyAuditFile(f *os.File) (seq int64, last string, broken error) {
	last = chain.Genesis
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, last, fmt.Errorf("%w: seek: %w", ErrAuditBroken, err)
	}
	v := chain.NewVerifier("")
	rd := bufio.NewReaderSize(f, 64<<10)
	for line := 1; ; line++ {
		b, err := readLine(rd)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return seq, last, fmt.Errorf("%w: line %d: %w", ErrAuditBroken, line, err)
		}
		rec, entry, err := parseAuditLine(b)
		if err != nil {
			return seq, last, fmt.Errorf("%w: line %d: %w", ErrAuditBroken, line, err)
		}
		again, err := chain.HashCanonical(rec.PrevHash, entry)
		if err != nil {
			return seq, last, fmt.Errorf("%w: line %d: %w", ErrAuditBroken, line, err)
		}
		v.Add(rec.ID, rec.PrevHash, rec.Hash, again)
		if res := v.Result(); !res.OK {
			return seq, last, fmt.Errorf("%w: hash chain breaks at line %d (id %s)", ErrAuditBroken, res.BrokenAt, res.EntryID)
		}
		if rec.Seq != seq+1 {
			return seq, last, fmt.Errorf("%w: line %d has seq %d, want %d", ErrAuditBroken, line, rec.Seq, seq+1)
		}
		seq, last = rec.Seq, rec.Hash
	}
	return seq, last, nil
}

// readLine returns one newline-terminated line without the newline. A last line without a newline
// is an error (a torn write), never silently accepted.
func readLine(rd *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		part, err := rd.ReadSlice('\n')
		buf = append(buf, part...)
		if len(buf) > maxAuditLine {
			return nil, errors.New("line is too long")
		}
		switch {
		case err == nil:
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(buf) == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("last line has no newline (torn write)")
		default:
			return nil, err
		}
	}
}

// parseAuditLine decodes a line into the typed view and the generic entry (without hash) the chain hashes.
func parseAuditLine(b []byte) (api.AuditRecord, map[string]any, error) {
	var rec api.AuditRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, nil, errors.New("not valid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil || generic == nil {
		return rec, nil, errors.New("not a JSON object")
	}
	norm, err := normalise(generic)
	if err != nil {
		return rec, nil, err
	}
	entry, _ := norm.(map[string]any)
	delete(entry, "hash")
	if rec.Hash == "" || rec.PrevHash == "" {
		return rec, nil, errors.New("missing hash or prev_hash")
	}
	return rec, entry, nil
}

// normalise turns json.Number into int64 so core/chain can canonicalise the tree.
func normalise(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return nil, errors.New("a number is not an integer")
		}
		return n, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			n, err := normalise(e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			n, err := normalise(e)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	}
	return v, nil
}

// append writes one record, fsyncs, and advances the chain. Any failure puts the log in the broken
// state: after an unknown write outcome nothing more is appended until a person looks.
func (a *auditLog) append(e auditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.broken != nil {
		return a.broken
	}
	var code, runID any
	if e.Code != "" {
		code = e.Code
	}
	if e.RunID != "" {
		runID = e.RunID
	}
	entry := map[string]any{
		"seq":           a.seq + 1,
		"id":            e.ID,
		"ts":            a.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"request_id":    e.RequestID,
		"actor":         e.Actor,
		"peer":          map[string]any{"uid": e.Peer.UID, "pid": e.Peer.PID, "unit": e.Peer.Unit},
		"command":       e.Command,
		"args_digest":   e.ArgsDigest,
		"args_redacted": e.ArgsRedacted,
		"result":        e.Result,
		"code":          code,
		"run_id":        runID,
	}
	hash, err := chain.HashCanonical(a.last, entry)
	if err != nil {
		return fmt.Errorf("host: audit entry: %w", err) // a bad entry is a bug, not a broken file
	}
	entry["prev_hash"], entry["hash"] = a.last, hash
	line, err := chain.Canon(entry)
	if err != nil {
		return fmt.Errorf("host: audit entry: %w", err)
	}
	line = append(line, '\n')
	if n, err := a.f.Write(line); err != nil || n != len(line) {
		a.broken = fmt.Errorf("%w: write failed", ErrAuditBroken)
		return a.broken
	}
	if err := a.f.Sync(); err != nil {
		a.broken = fmt.Errorf("%w: sync failed", ErrAuditBroken)
		return a.broken
	}
	a.seq++
	a.last = hash
	return nil
}

// page returns records with seq > since, at most limit, and the cursor for the next page.
func (a *auditLog) page(since int64, limit int) (api.AuditPage, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	f, err := os.Open(a.path)
	if err != nil {
		return api.AuditPage{}, fmt.Errorf("host: read audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	rd := bufio.NewReaderSize(f, 64<<10)
	page := api.AuditPage{Records: []api.AuditRecord{}}
	for {
		b, err := readLine(rd)
		if errors.Is(err, io.EOF) {
			return page, nil
		}
		if err != nil {
			return page, fmt.Errorf("host: read audit log: %w", err)
		}
		var rec api.AuditRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return page, fmt.Errorf("host: read audit log: %w", err)
		}
		if rec.Seq <= since {
			continue
		}
		if len(page.Records) == limit {
			page.Next = strconv.FormatInt(page.Records[len(page.Records)-1].Seq, 10)
			return page, nil
		}
		page.Records = append(page.Records, rec)
	}
}

// auditThrottle keeps floods that need no authentication (a stranger on the socket, a rate-limited
// caller) from filling the disk: at most one line per key per interval. Events inside the window are
// counted; when the window ends, expire returns one summary line per key that skipped events (with
// the distinct pids seen) and drops the entry, so the table only ever holds keys of the current
// window. Callers key by uid so one noisy uid cannot hide another. If the table is full, further
// keys share an "overflow" entry whose summary lists the uids it could not track (bounded).
type auditThrottle struct {
	mu       sync.Mutex
	interval time.Duration
	state    map[string]*throttleState
}

type throttleState struct {
	last    time.Time
	skipped int
	pids    []int
	uids    []int // overflow entry only: uids that had no entry of their own
	tmpl    auditEntry
}

const (
	throttleMaxKeys = 256
	throttleMaxPIDs = 8
	throttleMaxUIDs = 32
	overflowKey     = "overflow"
)

func newAuditThrottle(interval time.Duration) *auditThrottle {
	return &auditThrottle{interval: interval, state: map[string]*throttleState{}}
}

// allow reports whether to write a line for this event now (the first of the window). tmpl is the
// line to write (also remembered for the summary). Events inside the window are counted and
// reported by expire.
func (t *auditThrottle) allow(key string, now time.Time, tmpl auditEntry) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropIdleLocked(now)
	st, ok := t.state[key]
	overflowed := false
	if !ok && len(t.state) >= throttleMaxKeys {
		key, overflowed = overflowKey, true
		st, ok = t.state[key]
	}
	if !ok {
		st = &throttleState{}
		t.state[key] = st
	}
	st.tmpl = tmpl
	if overflowed && !slices.Contains(st.uids, tmpl.Peer.UID) && len(st.uids) < throttleMaxUIDs {
		st.uids = append(st.uids, tmpl.Peer.UID)
	}
	if !st.last.IsZero() && now.Sub(st.last) < t.interval {
		st.skipped++
		if p := tmpl.Peer.PID; p > 0 && len(st.pids) < throttleMaxPIDs && !slices.Contains(st.pids, p) {
			st.pids = append(st.pids, p)
		}
		return false
	}
	st.last = now
	return true
}

// dropIdleLocked evicts entries whose window ended with nothing to report.
func (t *auditThrottle) dropIdleLocked(now time.Time) {
	for k, v := range t.state {
		if v.skipped == 0 && now.Sub(v.last) >= t.interval && k != overflowKey {
			delete(t.state, k)
		}
	}
}

// expire returns the summary lines of every entry whose window ended with skipped events, and
// evicts all entries whose window ended.
func (t *auditThrottle) expire(now time.Time) []auditEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []auditEntry
	for k, v := range t.state {
		if now.Sub(v.last) < t.interval {
			continue
		}
		if v.skipped > 0 || (k == overflowKey && len(v.uids) > 0) {
			e := v.tmpl
			e.ArgsRedacted = throttleDetail(v.skipped, v.pids, v.uids)
			out = append(out, e)
		}
		delete(t.state, k)
	}
	return out
}

// throttleDetail is the args_redacted of a throttled line.
func throttleDetail(skipped int, pids, uids []int) map[string]any {
	toAny := func(in []int) []any {
		out := make([]any, 0, len(in))
		for _, v := range in {
			out = append(out, v)
		}
		return out
	}
	d := map[string]any{"skipped": skipped, "pids": toAny(pids)}
	if len(uids) > 0 {
		d["uids"] = toAny(uids)
	}
	return d
}

// digestRaw is the args digest when the args could not be decoded into the command's type.
func digestRaw(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// digestArgs is the args digest of decoded args: SHA-256 of their JSON encoding. A struct encodes
// its fields in declaration order and a map by sorted key, so equal args give equal digests.
func digestArgs(args any) (string, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("host: encode args: %w", err)
	}
	return digestRaw(b), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
