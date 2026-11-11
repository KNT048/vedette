package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Config is what NewService needs. Config is the main database (configuration, audit), Volume is logs.db (lines and
// counters): they must be two different databases, each with its own writer. Inventory and Box may be nil (no device
// names, no box address).
type Config struct {
	Config    *store.DB
	Volume    *store.DB
	Audit     *audit.Log
	Inventory Inventory
	Box       Box
	Log       *slog.Logger
	Clock     func() time.Time // nil: time.Now
}

// Service owns logs_sources and logs_retention (main database) and logs_events and the counters (logs.db). Every
// mutation of the configuration runs in one transaction with its core_audit row (SYS-3).
type Service struct {
	cfg Config
	now func() time.Time
	// maxBytes is MaxEventBytes and exportBytes is ExportMaxBytes; variables so that a test can lower them.
	maxBytes, exportBytes int64
	// purging is true while a purge that Ingest started is under way: at most one at a time.
	purging atomic.Bool
	// chunk is purgeChunk; afterChunk, when set by a test, runs after every purge transaction (the writer is free then).
	chunk int
	// searchSem holds MaxSearches tokens; searchTimeout is SearchTimeout (a field so that a test can shorten it).
	searchSem     chan struct{}
	searchTimeout time.Duration
	afterChunk    func()
	// afterStart, when set by a test, runs right after the "logs.purge_started" row is written.
	afterStart func()
}

// NewService returns the service. Config, Volume, Audit and Log are required, and Config and Volume must differ.
func NewService(cfg Config) (*Service, error) {
	if cfg.Config == nil || cfg.Volume == nil || cfg.Audit == nil || cfg.Log == nil {
		return nil, errors.New("logs: creating service: Config, Volume, Audit and Log are required")
	}
	if cfg.Config == cfg.Volume {
		return nil, errors.New("logs: creating service: the volume must be a database of its own, not the main one")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, now: now, maxBytes: MaxEventBytes, exportBytes: ExportMaxBytes, chunk: purgeChunk, searchSem: make(chan struct{}, MaxSearches), searchTimeout: SearchTimeout}, nil
}

func (s *Service) ts() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

func notFound() error { return apierr.New(404, "not_found", "No such log source.") }

type sourceRow struct {
	ID, Kind, Name, SenderIP, Proto string
	Port                            int
	CreatedAt                       time.Time
}

func (s *Service) loadSources(ctx context.Context) ([]sourceRow, error) {
	rows, err := s.cfg.Config.Reader().QueryContext(ctx, `SELECT id, kind, name, sender_ip, proto, port, created_at FROM logs_sources ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("logs: reading sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sourceRow
	for rows.Next() {
		var r sourceRow
		var created string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.SenderIP, &r.Proto, &r.Port, &created); err != nil {
			return nil, fmt.Errorf("logs: reading sources: %w", err)
		}
		if r.CreatedAt, err = time.Parse("2006-01-02T15:04:05.000Z", created); err != nil {
			return nil, fmt.Errorf("logs: reading sources: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Sources lists the declared sources with their state, the box address and the retention (GET /logs/sources).
func (s *Service) Sources(ctx context.Context) (SourcesView, error) {
	rows, err := s.loadSources(ctx)
	if err != nil {
		return SourcesView{}, err
	}
	out := SourcesView{Sources: make([]Source, 0, len(rows))}
	if out.RetentionDays, err = s.Retention(ctx); err != nil {
		return SourcesView{}, err
	}
	if out.Box, err = s.box(ctx); err != nil {
		return SourcesView{}, err
	}
	seen, err := s.lastReceived(ctx)
	if err != nil {
		return SourcesView{}, err
	}
	perHour, err := s.linesSince(ctx, s.now().Add(-time.Hour))
	if err != nil {
		return SourcesView{}, err
	}
	devices, err := s.devicesFor(ctx, rows)
	if err != nil {
		return SourcesView{}, err
	}
	now := s.now()
	for _, r := range rows {
		src := Source{ID: r.ID, Kind: r.Kind, Name: r.Name, SenderIP: r.SenderIP, Proto: r.Proto, Port: r.Port, CreatedAt: r.CreatedAt, LinesPerHour: perHour[r.ID], State: "never"}
		if t, ok := seen[r.ID]; ok {
			src.LastReceived = &t
			src.State = "receiving"
			if now.Sub(t) > silentAfter {
				src.State = "silent"
			}
		}
		if d, ok := devices[r.SenderIP]; ok {
			id, name := d.ID, d.Name
			src.AssetID, src.AssetName = &id, &name
		}
		out.Sources = append(out.Sources, src)
	}
	return out, nil
}

func (s *Service) box(ctx context.Context) (BoxInfo, error) {
	if s.cfg.Box == nil {
		return BoxInfo{Hostname: "vedette"}, nil
	}
	b, err := s.cfg.Box.Info(ctx)
	if err != nil {
		return BoxInfo{}, fmt.Errorf("logs: reading the box address: %w", err)
	}
	return b, nil
}

func (s *Service) devicesFor(ctx context.Context, rows []sourceRow) (map[string]Device, error) {
	if s.cfg.Inventory == nil || len(rows) == 0 {
		return nil, nil
	}
	ips := make([]string, len(rows))
	for i, r := range rows {
		ips[i] = r.SenderIP
	}
	d, err := s.cfg.Inventory.DevicesByIP(ctx, ips)
	if err != nil {
		return nil, fmt.Errorf("logs: reading devices: %w", err)
	}
	return d, nil
}

func (s *Service) lastReceived(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT source_id, last_received FROM logs_source_seen`)
	if err != nil {
		return nil, fmt.Errorf("logs: reading last received: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]time.Time{}
	for rows.Next() {
		var id, ts string
		if err := rows.Scan(&id, &ts); err != nil {
			return nil, fmt.Errorf("logs: reading last received: %w", err)
		}
		t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
		if err != nil {
			return nil, fmt.Errorf("logs: reading last received: %w", err)
		}
		out[id] = t
	}
	return out, rows.Err()
}

// linesSince sums the counters of every source from the bucket that contains since.
func (s *Service) linesSince(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT source_id, sum(lines) FROM logs_source_buckets WHERE bucket > ? GROUP BY source_id`, since.Unix()/bucketSeconds)
	if err != nil {
		return nil, fmt.Errorf("logs: reading counters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("logs: reading counters: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// view builds the API row of one source just written.
func (s *Service) view(ctx context.Context, id string) (Source, error) {
	v, err := s.Sources(ctx)
	if err != nil {
		return Source{}, err
	}
	for _, src := range v.Sources {
		if src.ID == id {
			return src, nil
		}
	}
	return Source{}, notFound()
}

func duplicate() error {
	return apierr.New(409, "duplicate", "There is already a log source with this IP address. Edit that one instead of adding a new one.")
}

// AddSource declares a source (POST /logs/sources). One source per sender address.
func (s *Service) AddSource(ctx context.Context, user string, in Input) (Source, error) {
	in, err := in.normalize()
	if err != nil {
		return Source{}, err
	}
	id := store.NewID("ls")
	err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		if err := s.checkSender(ctx, tx, in.SenderIP, ""); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, in.Kind, in.Name, in.SenderIP, in.Proto, in.Port, store.FormatTS(s.now())); err != nil {
			if store.IsUniqueViolation(err) {
				return duplicate()
			}
			return fmt.Errorf("logs: adding a source: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.source_add", Target: in.Name, Detail: fmt.Sprintf("%s %s %s/%d", in.Kind, in.SenderIP, in.Proto, in.Port)})
	})
	if err != nil {
		return Source{}, err
	}
	return s.view(ctx, id)
}

// checkSender answers 409 when another source already has this sender address.
func (s *Service) checkSender(ctx context.Context, tx *sql.Tx, ip, selfID string) error {
	var other string
	err := tx.QueryRowContext(ctx, `SELECT id FROM logs_sources WHERE sender_ip = ? AND id <> ?`, ip, selfID).Scan(&other)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("logs: checking the sender address: %w", err)
	}
	return duplicate()
}

// UpdateSource edits a source (PUT /logs/sources/{id}). A missing source is 404 before the input is judged, as in the mock.
func (s *Service) UpdateSource(ctx context.Context, user, id string, in Input) (Source, error) {
	var exists int
	if err := s.cfg.Config.Reader().QueryRowContext(ctx, `SELECT count(*) FROM logs_sources WHERE id = ?`, id).Scan(&exists); err != nil {
		return Source{}, fmt.Errorf("logs: reading a source: %w", err)
	}
	if exists == 0 {
		return Source{}, notFound()
	}
	in, err := in.normalize()
	if err != nil {
		return Source{}, err
	}
	err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		if err := s.checkSender(ctx, tx, in.SenderIP, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE logs_sources SET kind = ?, name = ?, sender_ip = ?, proto = ?, port = ? WHERE id = ?`, in.Kind, in.Name, in.SenderIP, in.Proto, in.Port, id)
		if err != nil {
			if store.IsUniqueViolation(err) {
				return duplicate()
			}
			return fmt.Errorf("logs: editing a source: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return notFound() // deleted between the check and the write
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.source_edit", Target: in.Name, Detail: fmt.Sprintf("%s %s %s/%d", in.Kind, in.SenderIP, in.Proto, in.Port)})
	})
	if err != nil {
		return Source{}, err
	}
	return s.view(ctx, id)
}

// DeleteSource removes a source (DELETE /logs/sources/{id}). The lines it sent are kept until retention expires (INV-4).
func (s *Service) DeleteSource(ctx context.Context, user, id string) error {
	return s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `SELECT name FROM logs_sources WHERE id = ?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return fmt.Errorf("logs: reading a source: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM logs_sources WHERE id = ?`, id); err != nil {
			return fmt.Errorf("logs: deleting a source: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.source_delete", Target: name, Detail: "logs already received are kept for the retention period"})
	})
}

// Retention returns how many days received lines are kept.
func (s *Service) Retention(ctx context.Context) (int, error) {
	var days int
	if err := s.cfg.Config.Reader().QueryRowContext(ctx, `SELECT days FROM logs_retention WHERE id = 1`).Scan(&days); err != nil {
		return 0, fmt.Errorf("logs: reading retention: %w", err)
	}
	return days, nil
}

// SetRetention changes the retention (PUT /logs/retention). The next purge applies it (POST-3).
func (s *Service) SetRetention(ctx context.Context, user string, days int) (int, error) {
	if !slices.Contains(RetentionChoices, days) {
		return 0, apierr.New(400, "bad_days", "Retention must be 7, 30, 90 or 180 days.")
	}
	err := s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE logs_retention SET days = ? WHERE id = 1`, days); err != nil {
			return fmt.Errorf("logs: saving retention: %w", err)
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "logs.retention", Target: "retention", Detail: fmt.Sprintf("%d days", days)})
	})
	if err != nil {
		return 0, err
	}
	return days, nil
}

// Digest is the answer of GET /logs/digest (L1: the line count of the last 24 hours; see Digest).
func (s *Service) Digest(ctx context.Context) (Digest, error) {
	lines, err := s.linesSince(ctx, s.now().Add(-24*time.Hour))
	if err != nil {
		return Digest{}, err
	}
	total := 0
	for _, n := range lines {
		total += n
	}
	return Digest{GeneratedAt: s.ts(), Lines24h: total, BaselineDays: 7, New: []struct{}{}, Spikes: []struct{}{}, BadConnections: []struct{}{}}, nil
}
