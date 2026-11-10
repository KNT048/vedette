package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/host/api"
)

// Retention and event limits (spec sections 4 and 10).
const (
	runRetention   = 90 * 24 * time.Hour
	runKeep        = 500
	idemRetention  = 30 * 24 * time.Hour
	maxEvents      = 10_000
	maxEventLine   = 2 << 10
	maxEventBytes  = 8 << 20 // ponytail: total cap per run so 500 runs cannot fill the disk; raise if apt output needs it
	maxResultBytes = 256 << 10
	maxFileBytes   = 32 << 20
)

var (
	runIDRE  = regexp.MustCompile(`^rn_[0-9a-f]{16}$`)
	reqIDRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	actorRE  = regexp.MustCompile(`^[a-zA-Z0-9_.@:-]{1,64}$`)
	runFile  = regexp.MustCompile(`^(rn_[0-9a-f]{16})\.json$`)
	idemFile = regexp.MustCompile(`^([0-9a-f-]{36})\.json$`)
)

func newID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("host: random id: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// storedRun is the file format of one run: the public Run plus what only the host needs.
type storedRun struct {
	Run        api.Run `json:"run"`
	ArgsDigest string  `json:"args_digest"`
	Write      bool    `json:"write"`
	// AcceptedAuditID is the audit line written when the run started (peer and redacted args);
	// recovery after a crash points at it.
	AcceptedAuditID string `json:"accepted_audit_id,omitempty"`
}

// idemRecord remembers one write request for 30 days (spec section 4).
type idemRecord struct {
	RequestID  string    `json:"request_id"`
	Command    string    `json:"command"`
	ArgsDigest string    `json:"args_digest"`
	RunID      string    `json:"run_id"`
	At         time.Time `json:"at"`
}

// runStore keeps runs and idempotency records: one JSON file each under the state dir, written
// atomically (temp file then rename, 0600), mirrored in memory.
type runStore struct {
	mu    sync.Mutex
	dir   string // <state>/runs
	idem  string // <state>/idem
	runs  map[string]*storedRun
	idems map[string]idemRecord
	log   *slog.Logger
}

func openRunStore(stateDir string, owner int, log *slog.Logger) (*runStore, error) {
	s := &runStore{
		dir: filepath.Join(stateDir, "runs"), idem: filepath.Join(stateDir, "idem"),
		runs: map[string]*storedRun{}, idems: map[string]idemRecord{}, log: log,
	}
	for _, d := range []string{s.dir, s.idem} {
		if err := ensureDir(d, owner); err != nil {
			return nil, err
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *runStore) load() error {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("host: read runs dir: %w", err)
	}
	for _, e := range ents {
		m := runFile.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		var sr storedRun
		if err := readJSONFile(filepath.Join(s.dir, e.Name()), &sr); err != nil || sr.Run.RunID != m[1] {
			s.log.Warn("skipping unreadable run file", "file", e.Name())
			continue
		}
		s.runs[m[1]] = &sr
	}
	ents, err = os.ReadDir(s.idem)
	if err != nil {
		return fmt.Errorf("host: read idempotency dir: %w", err)
	}
	for _, e := range ents {
		m := idemFile.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		var rec idemRecord
		if err := readJSONFile(filepath.Join(s.idem, e.Name()), &rec); err != nil || rec.RequestID != m[1] || !reqIDRE.MatchString(rec.RequestID) {
			s.log.Warn("skipping unreadable idempotency file", "file", e.Name())
			continue
		}
		s.idems[rec.RequestID] = rec
	}
	return nil
}

// get returns a copy of the run.
func (s *runStore) get(id string) (api.Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr, ok := s.runs[id]
	if !ok {
		return api.Run{}, false
	}
	return sr.Run, true
}

// put stores (creating or replacing) the run on disk and in memory.
func (s *runStore) put(sr storedRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(sr)
}

func (s *runStore) putLocked(sr storedRun) error {
	if !runIDRE.MatchString(sr.Run.RunID) {
		return errors.New("host: bad run id")
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, sr.Run.RunID+".json"), sr); err != nil {
		return err
	}
	cp := sr
	s.runs[sr.Run.RunID] = &cp
	return nil
}

// list returns the newest runs first.
func (s *runStore) list(limit int) []api.Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]api.Run, 0, len(s.runs))
	for _, sr := range s.runs {
		all = append(all, sr.Run)
	}
	slices.SortFunc(all, func(a, b api.Run) int {
		if c := b.StartedAt.Compare(a.StartedAt); c != 0 {
			return c
		}
		return strings.Compare(b.RunID, a.RunID)
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

func (s *runStore) idemGet(id string) (idemRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.idems[id]
	return r, ok
}

func (s *runStore) idemPut(rec idemRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeJSONAtomic(filepath.Join(s.idem, rec.RequestID+".json"), rec); err != nil {
		return err
	}
	s.idems[rec.RequestID] = rec
	return nil
}

func (s *runStore) idemDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.idems, id)
	if err := os.Remove(filepath.Join(s.idem, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("could not remove idempotency record", "request_id", id)
	}
}

// nonTerminal returns runs that were in progress (used at start-up).
func (s *runStore) nonTerminal() []storedRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []storedRun
	for _, sr := range s.runs {
		if !sr.Run.Status.Terminal() {
			out = append(out, *sr)
		}
	}
	return out
}

// prune drops terminal runs older than 90 days or beyond the newest 500, their event files, and
// idempotency records older than 30 days or whose run is gone. ponytail: a run pruned by the
// 500 cap takes its idempotency record with it even if younger than 30 days; only more than 500
// runs inside 30 days can notice, and the write rate limit makes that an attack, not use.
func (s *runStore) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	terminal := make([]*storedRun, 0, len(s.runs))
	for _, sr := range s.runs {
		if sr.Run.Status.Terminal() {
			terminal = append(terminal, sr)
		}
	}
	slices.SortFunc(terminal, func(a, b *storedRun) int { return b.Run.StartedAt.Compare(a.Run.StartedAt) })
	for i, sr := range terminal {
		if i >= runKeep || now.Sub(sr.Run.StartedAt) > runRetention {
			s.removeRunLocked(sr.Run.RunID)
		}
	}
	for id, rec := range s.idems {
		if _, ok := s.runs[rec.RunID]; !ok || now.Sub(rec.At) > idemRetention {
			delete(s.idems, id)
			_ = os.Remove(filepath.Join(s.idem, id+".json"))
		}
	}
}

func (s *runStore) removeRunLocked(id string) {
	delete(s.runs, id)
	for _, name := range []string{id + ".json", id + ".events.json"} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("could not remove run file", "file", name)
		}
	}
}

// eventsPath is where a finished run's events are kept.
func (s *runStore) eventsPath(id string) string { return filepath.Join(s.dir, id+".events.json") }

// ensureDir creates path with mode 0700 if absent and insists that it is a real directory (not a
// symlink) owned by uid owner and no more open than 0700.
func ensureDir(path string, owner int) error {
	const mode os.FileMode = 0o700
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return fmt.Errorf("host: create %s: %w", path, err)
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("host: chmod %s: %w", path, err)
		}
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("host: stat %s: %w", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return fmt.Errorf("host: %s is not a directory", path)
	case !ok || int(sys.Uid) != owner:
		return fmt.Errorf("host: %s must be owned by uid %d", path, owner)
	case st.Mode().Perm()&^mode != 0:
		return fmt.Errorf("host: %s has mode %o, more open than %o", path, st.Mode().Perm(), mode)
	}
	return nil
}

// writeJSONAtomic writes v to path through a temp file in the same directory, fsyncs, renames, 0600.
func writeJSONAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("host: encode %s: %w", filepath.Base(path), err)
	}
	if len(data) > maxFileBytes {
		return fmt.Errorf("host: %s is too large", filepath.Base(path))
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("host: write %s: %w", filepath.Base(path), err)
	}
	ok = true
	if d, err := os.Open(filepath.Dir(path)); err == nil { // make the rename durable; failure here is not fatal
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func readJSONFile(path string, v any) error {
	f, err := os.Open(path) //nolint:gosec // path is built from a validated id inside the state dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxFileBytes {
		return errors.New("file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// eventLog is the event stream of one run: bounded, with a broadcast channel replaced on each append.
type eventLog struct {
	mu      sync.Mutex
	events  []api.Event
	next    uint64 // seq of the next event, starting at 1
	dropped int
	bytes   int
	wake    chan struct{}
	done    bool
	now     func() time.Time
	// persist, when set (while a run awaits confirmation), saves the log after every event so a
	// restart resumes from the true last seq. saveMu orders the writes: the last write is always
	// the newest snapshot, so a late save can never overwrite the final one with an older one.
	persist func()
	saveMu  sync.Mutex
}

func newEventLog(now func() time.Time) *eventLog {
	return &eventLog{next: 1, wake: make(chan struct{}), now: now}
}

// eventsFile is the persisted form.
type eventsFile struct {
	Next    uint64      `json:"next"`
	Dropped int         `json:"dropped"`
	Events  []api.Event `json:"events"`
}

func (l *eventLog) add(ev api.Event) {
	l.mu.Lock()
	if p := l.persist; p != nil && !l.done {
		defer p() // runs after the unlock below (defers run last-in first-out)
	}
	defer l.mu.Unlock()
	if l.done {
		return
	}
	ev.Seq, ev.TS = l.next, l.now().UTC()
	ev.Line = cleanLine(ev.Line)
	ev.Truncated = false
	l.next++
	l.events = append(l.events, ev)
	l.bytes += 64 + len(ev.Line)
	for len(l.events) > maxEvents || l.bytes > maxEventBytes {
		l.bytes -= 64 + len(l.events[0].Line)
		l.events = l.events[1:]
		l.dropped++
	}
	close(l.wake)
	l.wake = make(chan struct{})
}

// save writes the log to path; calls are serialised and each writes the log as it is at that moment.
func (l *eventLog) save(path string) error {
	l.saveMu.Lock()
	defer l.saveMu.Unlock()
	return writeJSONAtomic(path, l.snapshot())
}

// setPersist turns saving after every event on (path != "") or off.
func (l *eventLog) setPersist(path string, log func(error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if path == "" {
		l.persist = nil
		return
	}
	l.persist = func() {
		if err := l.save(path); err != nil {
			log(err)
		}
	}
}

// finish marks the stream complete and wakes every reader.
func (l *eventLog) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return
	}
	l.done = true
	close(l.wake)
}

// since returns the events with seq > after, the channel that closes at the next change, and
// whether the stream is complete (no change will come).
func (l *eventLog) since(after uint64) ([]api.Event, <-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []api.Event
	for _, ev := range l.events {
		if ev.Seq > after {
			ev.Truncated = l.dropped > 0
			out = append(out, ev)
		}
	}
	return out, l.wake, l.done
}

func (l *eventLog) snapshot() eventsFile {
	l.mu.Lock()
	defer l.mu.Unlock()
	return eventsFile{Next: l.next, Dropped: l.dropped, Events: slices.Clone(l.events)}
}

// loadEventLog reads a finished run's events; a run without a file (refused, recovered) gets one
// state event synthesised from the run itself.
func loadEventLog(s *runStore, run api.Run, now func() time.Time) *eventLog {
	l := newEventLog(now)
	var ef eventsFile
	if err := readJSONFile(s.eventsPath(run.RunID), &ef); err == nil && ef.Next > 0 {
		l.events, l.next, l.dropped = ef.Events, ef.Next, ef.Dropped
	} else {
		ts := run.StartedAt
		if run.FinishedAt != nil {
			ts = *run.FinishedAt
		}
		l.events = []api.Event{{Seq: 1, TS: ts, Kind: api.KindState, Status: run.Status}}
		l.next = 2
	}
	l.done = true
	close(l.wake)
	return l
}

// cleanLine makes one log line safe: valid UTF-8, no control characters, at most 2 KiB.
func cleanLine(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxEventLine {
		s = s[:maxEventLine]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
