package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
)

// The install run as the GUI sees it (OsRun). The host keeps the durable record of every run and its output
// (90 days, host-api 4), so core keeps only a small in-memory copy of the latest run, fed by ONE server-sent
// event stream per run (the host rate-limits requests to 60 a minute; a page polling every second must not
// reach it), plus a few lines in core_setting key os.run (which run, its scope, who started it, which snapshot
// to delete, whether the end was audited). After a restart the copy is rebuilt from the host (ListRuns and the
// run's events) the first time somebody asks.
const (
	keyOSRun       = "os.run"
	keyOSSettings  = "os.settings"
	maxRunLines    = 500
	runTimeout     = 70 * time.Minute // os.install's own limit is 60 minutes
	followRetry    = 5 * time.Second
	listRunsWindow = 50
	// loadTimeout bounds one read of the host that other callers share (the rebuild of the run after a restart,
	// the state of the box): a request leaves at its own deadline, the shared read is given up after this.
	loadTimeout = 30 * time.Second
	// resumeTries is how many times, followRetry apart, the start-up pass asks the host about the stored run.
	resumeTries = 24
)

// osRunMeta is what core_setting os.run holds.
type osRunMeta struct {
	RunID    string `json:"run_id"`
	Scope    string `json:"scope"`
	User     string `json:"user"`
	Snapshot string `json:"snapshot,omitempty"`
	Audited  bool   `json:"audited"`
}

// osRunState is the in-memory copy of one install run; every field is guarded by OSHandlers.runMu.
type osRunState struct {
	meta     osRunMeta
	started  time.Time
	finished *time.Time
	status   api.Status
	lines    []string
	result   *api.OSRunResult
}

func (r *osRunState) running() bool { return !r.status.Terminal() }

func (r *osRunState) view() osRunView {
	v := osRunView{ID: r.meta.RunID, Scope: r.meta.Scope, Status: "done", StartedAt: r.started, FinishedAt: r.finished, User: r.meta.User, Lines: append([]string{}, r.lines...)}
	if r.running() {
		v.Status = "running"
	}
	if r.result != nil {
		rv := &osRunResultView{Installed: r.result.Installed, Security: r.result.Security, Backup: r.result.Backup, RebootRequired: r.result.RebootRequired, Health: []osHealthView{}}
		for _, h := range r.result.Health {
			rv.Health = append(rv.Health, osHealthView{Name: h.Name, OK: h.OK})
		}
		v.Result = rv
	}
	return v
}

func (r *osRunState) addLine(s string) {
	r.lines = append(r.lines, s)
	if len(r.lines) > maxRunLines {
		r.lines = append(r.lines[:0], r.lines[len(r.lines)-maxRunLines:]...)
	}
}

// flight is one read of the host that every caller arriving meanwhile shares (singleflight from the standard
// library's parts): the read runs on its own context, each waiter leaves at its own deadline.
type flight[T any] struct {
	done chan struct{}
	val  T
	err  error
}

func newFlight[T any]() *flight[T] { return &flight[T]{done: make(chan struct{})} }

func (f *flight[T]) wait(ctx context.Context) (T, error) {
	select {
	case <-f.done:
		return f.val, f.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// failure is what a caller of a shared read answers when it failed: an API error stays, a host error is mapped.
func (h *OSHandlers) failure(ctx context.Context, err error) error {
	if _, ok := apierr.As(err); ok {
		return err
	}
	return hostErr(ctx, h.log, err)
}

// timedOut turns the end of a shared read's own time limit (core is not shutting down) into 503 host_unreachable.
func (h *OSHandlers) timedOut(lctx context.Context, err error) error {
	if err != nil && h.ctx.Err() == nil && lctx.Err() != nil {
		return apierr.New(503, CodeHostUnreachable, "The operating system helper (vedette-host) took too long to answer. Try again in a minute.")
	}
	return err
}

// current returns the latest install run (nil before the first one), rebuilding it from the host once after a
// start. The rebuild runs outside runMu and is shared by whoever asks meanwhile; the host being unreachable
// at that moment is an error and is tried again next time.
func (h *OSHandlers) current(ctx context.Context) (*osRunState, error) {
	h.runMu.Lock()
	if h.run != nil || h.loaded {
		rs := h.run
		h.runMu.Unlock()
		return rs, nil
	}
	f := h.loading
	if f == nil {
		f = newFlight[*osRunState]()
		h.loading = f
		h.wg.Add(1)
		go h.load(f) //nolint:contextcheck // the read is shared: it runs on the handlers' lifetime, each waiter leaves at its own deadline
	}
	h.runMu.Unlock()
	rs, err := f.wait(ctx)
	if err != nil {
		return nil, h.failure(ctx, err)
	}
	return rs, nil
}

func (h *OSHandlers) load(f *flight[*osRunState]) {
	defer h.wg.Done()
	ctx, cancel := context.WithTimeout(h.ctx, h.loadTimeout)
	defer cancel()
	rs, err := h.loadRun(ctx)
	err = h.timedOut(ctx, err)
	h.runMu.Lock()
	if err == nil {
		if h.run == nil { // an install that started meanwhile has set it already
			h.run = rs
		}
		h.loaded = true
	}
	f.val, f.err = h.run, err
	h.loading = nil
	h.runMu.Unlock()
	close(f.done)
}

func (h *OSHandlers) loadRun(ctx context.Context) (*osRunState, error) {
	runs, err := h.host.ListRuns(ctx, listRunsWindow)
	if err != nil {
		return nil, err
	}
	for _, r := range runs { // newest first
		if r.Command == api.CmdOSInstall {
			return h.rebuild(ctx, r)
		}
	}
	return nil, nil
}

// resume is the start-up pass: when the stored run is not settled (still running, or ended while core was down
// and its snapshot with the key is still on disk) it rebuilds it now instead of waiting for somebody to ask, so
// the end is audited and the snapshot goes at once, whatever its age. The host may still be starting: it tries
// again for about two minutes.
func (h *OSHandlers) resume() {
	defer h.wg.Done()
	for range resumeTries {
		if _, err := h.current(h.ctx); err == nil || h.ctx.Err() != nil {
			return
		}
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(followRetry):
		}
	}
}

// rebuild makes the in-memory copy of a run the host knows: a finished one from its stored events (settled at
// once: audit and snapshot), a running one by following it from the start. It does not touch runMu: the copy
// is not published yet.
func (h *OSHandlers) rebuild(ctx context.Context, r api.Run) (*osRunState, error) {
	meta, _ := h.loadRunMeta(ctx) // missing or for another run: the host's own record is enough
	if meta.RunID != r.RunID {
		meta = osRunMeta{RunID: r.RunID, Scope: "all", User: r.Actor, Audited: r.Status.Terminal()}
	}
	rs := &osRunState{meta: meta, started: r.StartedAt, status: r.Status}
	if r.Status.Terminal() {
		st := h.host.Events(ctx, r.RunID, 0)
		defer st.Close()
		for {
			ev, err := st.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if ev.Kind == api.KindLog {
				rs.addLine(ev.Line)
			}
		}
		h.applyFinal(rs, r)
		h.settle(ctx, rs, r)
		return rs, nil
	}
	h.wg.Add(1)
	go h.follow(rs)
	return rs, nil
}

// applyFinal copies the end of a run into the copy: status, time, result and, when it did not succeed, one last
// line that says why (the contract's OsRun has no error field; the lines are where the page shows it).
func (h *OSHandlers) applyFinal(rs *osRunState, r api.Run) {
	rs.status = r.Status
	fin := h.now()
	if r.FinishedAt != nil {
		fin = *r.FinishedAt
	}
	rs.finished = &fin
	if len(r.Result) > 0 {
		var res api.OSRunResult
		if json.Unmarshal(r.Result, &res) == nil {
			rs.result = &res
		}
	}
	if r.Status != api.StatusSucceeded {
		why := string(r.Status)
		if r.Error != nil {
			why += ": " + r.Error.Code + ": " + r.Error.Message
		}
		rs.addLine("[vedette-host] run " + why)
	}
}

// follow reads the events of one run into its copy until the run ends, resuming after a lost connection, then
// settles it (finish). It stops early when core shuts down; a run that never ends within runTimeout of its start
// is closed as failed so the page does not say "busy" forever.
func (h *OSHandlers) follow(rs *osRunState) {
	defer h.wg.Done()
	h.runMu.Lock()
	id, started := rs.meta.RunID, rs.started
	h.runMu.Unlock()
	var after uint64
	for h.ctx.Err() == nil {
		st := h.host.Events(h.ctx, id, after)
		for {
			ev, err := st.Next()
			if err != nil {
				break
			}
			after = ev.Seq
			if ev.Kind == api.KindLog {
				h.runMu.Lock()
				rs.addLine(ev.Line)
				h.runMu.Unlock()
			}
		}
		st.Close()
		if run, err := h.host.GetRun(h.ctx, id); err == nil && run.Status.Terminal() {
			h.finish(h.ctx, rs, run)
			return
		}
		if h.now().Sub(started) > runTimeout {
			h.finish(h.ctx, rs, api.Run{RunID: id, Status: api.StatusFailed, Error: &api.RunError{Code: api.CodeTimeout, Message: "lost contact with vedette-host"}})
			return
		}
		select {
		case <-h.ctx.Done():
		case <-time.After(followRetry):
		}
	}
}

// finish settles a run that ended: the copy, then settle.
func (h *OSHandlers) finish(parent context.Context, rs *osRunState, r api.Run) {
	h.runMu.Lock()
	h.applyFinal(rs, r)
	h.runMu.Unlock()
	h.settle(parent, rs, r)
}

// settle does the rest of the end of a run: the snapshot directory that backed it (the host copied it during
// the run) goes, the cached state of the box is dropped, and one core_audit row is written, once (os.run says
// whether it was).
func (h *OSHandlers) settle(parent context.Context, rs *osRunState, r api.Run) {
	h.runMu.Lock()
	meta, res := rs.meta, rs.result
	status := rs.status
	h.runMu.Unlock()
	h.removeSnapshot(meta.Snapshot)
	h.invalidateState()
	if meta.Audited {
		return
	}

	detail := "run " + string(status)
	if r.Error != nil {
		detail += " (" + r.Error.Code + ")"
	}
	if res != nil {
		detail = fmt.Sprintf("%s: %d installed, %d security, backup %s, reboot required %t", detail, res.Installed, res.Security, res.Backup, res.RebootRequired)
	}
	meta.Audited, meta.Snapshot = true, ""
	// The process may be shutting down: the write still gets its own short deadline.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.audit.Append(ctx, tx, audit.Entry{User: meta.User, Action: "os.install_done", Target: meta.Scope, Detail: cutAtRune(detail, auditMaxDetail)}); err != nil {
			return err
		}
		return h.putSetting(ctx, tx, keyOSRun, meta, meta.User)
	})
	if err != nil {
		h.log.ErrorContext(ctx, "core: the end of an install run could not be audited", "run", meta.RunID, "error", err)
		return
	}
	h.runMu.Lock()
	rs.meta.Audited, rs.meta.Snapshot = true, ""
	h.runMu.Unlock()
}

func (h *OSHandlers) removeSnapshot(id string) {
	if snapshotIDRE.MatchString(id) {
		snapshot{ID: id, dir: filepath.Join(h.snaps.dir, id)}.remove()
	}
}

// busy reports whether an install run is in progress. A host that cannot be asked counts as not busy: the host
// itself answers busy to a second write.
func (h *OSHandlers) busy(ctx context.Context) bool {
	rs, err := h.current(ctx)
	if err != nil || rs == nil {
		return false
	}
	h.runMu.Lock()
	defer h.runMu.Unlock()
	return rs.running()
}

// Busy reports whether an operating system install run of this core is in progress (the factory reset refuses to start then).
func (h *OSHandlers) Busy(ctx context.Context) bool {
	if h.host == nil { // a box without a helper has no install run
		return false
	}
	return h.busy(ctx)
}

func (h *OSHandlers) loadRunMeta(ctx context.Context) (osRunMeta, error) {
	var m osRunMeta
	raw, err := coredb.New(h.db.Reader()).GetSetting(ctx, keyOSRun)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal([]byte(raw), &m)
	return m, err
}

// putSetting stores one JSON object under a core_setting key in the caller's transaction.
func (h *OSHandlers) putSetting(ctx context.Context, tx *sql.Tx, key string, v any, by string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("core: encode setting %s: %w", key, err)
	}
	if err := coredb.New(tx).UpsertSetting(ctx, coredb.UpsertSettingParams{Key: key, Value: string(b), UpdatedAt: store.FormatTS(h.now()), UpdatedBy: by}); err != nil {
		return fmt.Errorf("core: write setting %s: %w", key, err)
	}
	return nil
}

// loadJSON decodes the JSON object stored under key into `into`; a missing key leaves `into` as it was.
func (h *OSHandlers) loadJSON(ctx context.Context, key string, into any) error {
	raw, err := coredb.New(h.db.Reader()).GetSetting(ctx, key)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("core: read setting %s: %w", key, err)
	}
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("core: setting %s is not valid: %w", key, err)
	}
	return nil
}
