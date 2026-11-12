package ai

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The record of the reads the box made through a connection (slice 7, D-311, D-119). A read tool that merely exists proves nothing:
// response accepts a config_read as evidence of an AI proposal only when it names a row of ai_read, which the tool runner writes after a
// read answered (never from the model's text), at most ReadMaxAge old. The model never sees these ids in "Ask your data"; the plan job
// lists the box's own rows to it and response looks every cited id up again.

// ReadMaxAge is how long a read counts as evidence.
const ReadMaxAge = 24 * time.Hour

// readKeep is how many rows are kept at most; older rows than ReadMaxAge are removed too, whenever a read is recorded.
const readKeep = 500

// ReadRecord is one read the box made. Summary is written by the box from the connection's name and the tool's name.
type ReadRecord struct {
	ID, TS, ConnectionID, ConnectionName, Tool, Summary string
}

func readSummary(r ReadRecord) string {
	return cleanLine(`Read "`+r.Tool+`" on the connection "`+r.ConnectionName+`" at `+r.TS, 200)
}

// recordRead stores one read that answered. It returns the id, or "" when the row could not be written: the read then cannot be cited
// (fail closed), and the answer still goes to the person who asked.
func (s *Service) recordRead(ctx context.Context, job Job, connID, connName, tool string) string {
	ctx, cancel := detached(ctx)
	defer cancel()
	now := s.cfg.Clock()
	id := store.NewID("rd")
	name, t := cleanLine(sanitizeWeb(connName), 60), cleanLine(sanitizeWeb(tool), 60)
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_read (id, ts, connection_id, connection_name, tool, job) VALUES (?, ?, ?, ?, ?, ?)`,
			id, FormatTS(now), connID, name, t, string(job)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ai_read WHERE ts < ?`, FormatTS(now.Add(-ReadMaxAge))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM ai_read WHERE rowid NOT IN (SELECT rowid FROM ai_read ORDER BY ts DESC, rowid DESC LIMIT ?)`, readKeep)
		return err
	})
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "ai: could not record a connection read", "connection", connID, "error", err)
		return ""
	}
	return id
}

// ConfigRead looks a read up by its id: found only when the box recorded it, at most ReadMaxAge ago, and the module is on. This is the
// lookup behind response's Evidence.ConfigRead (D-311); a lookup of known-bad connections (logs, Evidence.IocHit) has the same shape.
func (s *Service) ConfigRead(ctx context.Context, id string) (ReadRecord, bool, error) {
	if !s.moduleOn() || !idRE.MatchString(id) {
		return ReadRecord{}, false, nil
	}
	r := ReadRecord{ID: id}
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT ts, connection_id, connection_name, tool FROM ai_read WHERE id = ? AND ts >= ?`,
		id, FormatTS(s.cfg.Clock().Add(-ReadMaxAge))).Scan(&r.TS, &r.ConnectionID, &r.ConnectionName, &r.Tool)
	if errors.Is(err, sql.ErrNoRows) {
		return ReadRecord{}, false, nil
	}
	if err != nil {
		return ReadRecord{}, false, fmt.Errorf("ai: look up a read: %w", err)
	}
	r.Summary = readSummary(r)
	return r, true, nil
}

// maxCitedReads is how many reads the plan job lists to the model.
const maxCitedReads = 10

// RecentReads lists the newest reads (at most 10, at most ReadMaxAge old) made through one of the given connections, for the plan job.
func (s *Service) RecentReads(ctx context.Context, connIDs []string) ([]ReadRecord, error) {
	if !s.moduleOn() || len(connIDs) == 0 {
		return nil, nil
	}
	args := []any{FormatTS(s.cfg.Clock().Add(-ReadMaxAge))}
	for _, c := range connIDs {
		args = append(args, c)
	}
	args = append(args, maxCitedReads)
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, connection_id, connection_name, tool FROM ai_read WHERE ts >= ? AND connection_id IN (?`+
		strings.Repeat(",?", len(connIDs)-1)+`) ORDER BY ts DESC, rowid DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("ai: list the reads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ReadRecord
	for rows.Next() {
		var r ReadRecord
		if err := rows.Scan(&r.ID, &r.TS, &r.ConnectionID, &r.ConnectionName, &r.Tool); err != nil {
			return nil, err
		}
		r.Summary = readSummary(r)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ProposalRecord is what the box sent to response for one plan, and what came of it (D-312): Input and Output are hashed, never stored.
type ProposalRecord struct {
	Summary       string
	Input, Output string
	Links         []ActivityLink
}

// RecordProposals writes the activity row of proposals the box sent to response from a stored plan (actor ai:response). No model is
// called for it: the row only links the plan's AI call to the proposals and requests it led to, since the row of that call is sealed
// before response stores the plan.
func (s *Service) RecordProposals(ctx context.Context, p ProposalRecord) error {
	var links []ActivityLink
	for _, l := range p.Links {
		if (l.Kind == "proposal" || l.Kind == "action") && idRE.MatchString(l.ID) {
			links = append(links, l)
		}
	}
	return s.record(ctx, ActivityEntry{Job: string(JobResponsePlan), Trigger: "system:ai:response", Hooks: []string{}, Tools: []ActivityTool{},
		InputHash: HashContent(p.Input), OutputHash: HashContent(p.Output), Summary: cleanLine(p.Summary, 600), Result: ResultOK, Links: links})
}
