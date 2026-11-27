package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// querier is what both *sql.DB (reads) and *sql.Tx (inside a write) offer.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

// evidenceDoc is the JSON of fnd_finding.evidence (display only) and of the evidence field of the API.
type evidenceDoc struct {
	Summary   string    `json:"summary"`
	Template  string    `json:"template,omitempty"`
	Request   string    `json:"request,omitempty"`
	Response  string    `json:"response,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Agent     bool      `json:"agent,omitempty"`     // The version compared is the one the device's agent reports
	AgentRow  bool      `json:"agent_row,omitempty"` // A product-only match on a row the agent reported with its version
	Source    string    `json:"source,omitempty"`    // snmp or agent: the device itself stated the version (Evidence.Source)
	Read      *readDoc  `json:"read,omitempty"`      // Stored only (Evidence.Read); apiEvidence leaves it out
}

// readDoc is the JSON of Evidence.Read.
type readDoc struct {
	Software string    `json:"software,omitempty"`
	Source   string    `json:"source,omitempty"`
	Version  string    `json:"version,omitempty"`
	Pkg      string    `json:"pkg,omitempty"`
	At       time.Time `json:"at,omitzero"`
}

func newEvidenceDoc(e *Evidence) *evidenceDoc {
	if e == nil {
		return nil
	}
	d := &evidenceDoc{Summary: e.Summary, Template: e.Template, Request: e.Request, Response: e.Response, CheckedAt: e.CheckedAt.UTC(), Agent: e.Agent, AgentRow: e.AgentRow, Source: e.Source}
	if r := e.Read; r != nil {
		d.Read = &readDoc{Software: r.Software, Source: r.Source, Version: r.Version, Pkg: r.Pkg, At: r.At.UTC()}
		if r.At.IsZero() {
			d.Read.At = time.Time{}
		}
	}
	return d
}

// apiEvidence is the evidence as the API shows it: without what is only stored.
func apiEvidence(e *Evidence) *evidenceDoc {
	d := newEvidenceDoc(e)
	if d != nil {
		d.Read = nil
	}
	return d
}

func (d *evidenceDoc) evidence() *Evidence {
	if d == nil {
		return nil
	}
	e := &Evidence{Summary: d.Summary, Template: d.Template, Request: d.Request, Response: d.Response, CheckedAt: d.CheckedAt, Agent: d.Agent, AgentRow: d.AgentRow, Source: d.Source}
	if r := d.Read; r != nil {
		e.Read = &Reading{Software: r.Software, Source: r.Source, Version: r.Version, Pkg: r.Pkg, At: r.At}
	}
	return e
}

func encodeEvidence(e *Evidence) (any, error) {
	if e == nil {
		return nil, nil
	}
	b, err := json.Marshal(newEvidenceDoc(e))
	if err != nil {
		return nil, fmt.Errorf("findings: encoding evidence: %w", err)
	}
	return string(b), nil
}

const findingColumns = `id, asset_id, cve, software_id, detected, basis, verified, range_origin, matched_version, fix_kind, fix_version, fix_ref,
	fix_key, evidence, state, resolution, via, resolved_by, resolved_at, note, accepted_until, from_version, to_version, urgency, urgency_at,
	first_seen, last_seen, updated_at, fix_channel`

// findingSelect is findingColumns as read, with Finding.byEntry from the history: a finding confirmed by a person whose newest
// confirmed event is Vedette's (only the version a person entered makes Vedette confirm one at that level).
const findingSelect = findingColumns + `, (verified = 'person' AND ifnull((SELECT e.actor FROM fnd_finding_event e
	WHERE e.finding_id = fnd_finding.id AND e.kind = 'confirmed' ORDER BY e.id DESC LIMIT 1), '') = '` + SystemUser + `')`

func scanFinding(s scanner) (Finding, error) {
	var (
		f                                           Finding
		basis, verified, fixKind, state, channel    string
		softwareID, matched, fixVersion, fixRef     sql.NullString
		evidence, resolution, via, resolvedBy, note sql.NullString
		resolvedAt, until, from, to                 sql.NullString
		urgencyAt, first, last, updated             string
	)
	if err := s.Scan(&f.ID, &f.AssetID, &f.CVE, &softwareID, &f.Detected, &basis, &verified, &f.RangeOrigin, &matched, &fixKind, &fixVersion, &fixRef,
		&f.FixKey, &evidence, &state, &resolution, &via, &resolvedBy, &resolvedAt, &note, &until, &from, &to, &f.Urgency, &urgencyAt,
		&first, &last, &updated, &channel, &f.byEntry); err != nil {
		return Finding{}, err
	}
	f.SoftwareID, f.MatchedVersion = softwareID.String, matched.String
	f.Basis, f.Verified, f.State = DetectionBasis(basis), Verified(verified), State(state)
	f.Fix = Fix{Kind: FixKind(fixKind), Version: fixVersion.String, Ref: fixRef.String}
	if FixChannel(channel) != ChannelPublic {
		f.Fix.Channel = FixChannel(channel)
	}
	f.Resolution, f.Via, f.ResolvedBy, f.Note = Resolution(resolution.String), Via(via.String), resolvedBy.String, note.String
	f.FromVersion, f.ToVersion = from.String, to.String
	if evidence.Valid {
		var d evidenceDoc
		if err := json.Unmarshal([]byte(evidence.String), &d); err != nil {
			return Finding{}, fmt.Errorf("evidence: %w", err)
		}
		f.Evidence = d.evidence()
	}
	var err error
	for _, p := range []struct {
		dst *time.Time
		src string
	}{{&f.UrgencyAt, urgencyAt}, {&f.FirstSeen, first}, {&f.LastSeen, last}, {&f.UpdatedAt, updated}, {&f.ResolvedAt, resolvedAt.String}} {
		if p.src == "" {
			continue
		}
		if *p.dst, err = parseTS(p.src); err != nil {
			return Finding{}, err
		}
	}
	if until.Valid {
		if f.AcceptedUntil, err = time.Parse(time.DateOnly, until.String); err != nil {
			return Finding{}, fmt.Errorf("accepted_until: %w", err)
		}
	}
	return f, nil
}

func findingArgs(f Finding) ([]any, error) {
	ev, err := encodeEvidence(f.Evidence)
	if err != nil {
		return nil, err
	}
	return []any{f.ID, f.AssetID, f.CVE, nullString(f.SoftwareID), f.Detected, string(f.Basis), string(f.Verified), f.RangeOrigin, nullString(f.MatchedVersion),
		string(f.Fix.Kind), nullString(f.Fix.Version), nullString(f.Fix.Ref), f.FixKey, ev, string(f.State), nullString(string(f.Resolution)),
		nullString(string(f.Via)), nullString(f.ResolvedBy), nullTS(f.ResolvedAt), nullString(f.Note), nullDay(f.AcceptedUntil),
		nullString(f.FromVersion), nullString(f.ToVersion), f.Urgency, store.FormatTS(f.UrgencyAt), store.FormatTS(f.FirstSeen),
		store.FormatTS(f.LastSeen), store.FormatTS(f.UpdatedAt), string(f.Fix.Chan())}, nil
}

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	return t, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullDay(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.DateOnly)
}

func nullTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FormatTS(t)
}

// loadFinding returns one finding, or an error wrapping ErrNotFound.
func loadFinding(ctx context.Context, q querier, id string) (Finding, error) {
	f, err := scanFinding(q.QueryRowContext(ctx, `SELECT `+findingSelect+` FROM fnd_finding WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, fmt.Errorf("findings: loading finding: %w", ErrNotFound)
	}
	if err != nil {
		return Finding{}, fmt.Errorf("findings: loading finding: %w", err)
	}
	return f, nil
}

// queryFindings returns the findings a WHERE clause selects, newest first (findings of one match keep their order).
func queryFindings(ctx context.Context, q querier, where string, args ...any) ([]Finding, error) {
	return selectFindings(ctx, q, where+` ORDER BY first_seen DESC, rowid ASC`, args...)
}

// selectFindings returns the findings of a WHERE clause with its own order (and limit).
func selectFindings(ctx context.Context, q querier, whereOrder string, args ...any) ([]Finding, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+findingSelect+` FROM fnd_finding WHERE `+whereOrder, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading findings: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: reading findings: %w", err)
	}
	return out, nil
}

// findingsOf returns the findings of one device, or of every device when assetID is "".
func findingsOf(ctx context.Context, q querier, assetID string) ([]Finding, error) {
	return queryFindings(ctx, q, `(?1 = '' OR asset_id = ?1)`, assetID)
}

// writeFinding inserts a new finding or updates the row, and appends its events.
func writeFinding(ctx context.Context, tx *sql.Tx, f Finding, isNew bool, evs []Event) error {
	args, err := findingArgs(f)
	if err != nil {
		return err
	}
	if isNew {
		_, err = tx.ExecContext(ctx, `INSERT INTO fnd_finding (`+findingColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE fnd_finding SET software_id = ?4, detected = ?5, basis = ?6, verified = ?7, range_origin = ?8,
			matched_version = ?9, fix_kind = ?10, fix_version = ?11, fix_ref = ?12, fix_key = ?13, evidence = ?14, state = ?15, resolution = ?16,
			via = ?17, resolved_by = ?18, resolved_at = ?19, note = ?20, accepted_until = ?21, from_version = ?22, to_version = ?23, urgency = ?24,
			urgency_at = ?25, first_seen = ?26, last_seen = ?27, updated_at = ?28, fix_channel = ?29 WHERE id = ?1`, args...)
	}
	if err != nil {
		return fmt.Errorf("findings: writing finding: %w", err)
	}
	return insertEvents(ctx, tx, evs)
}

func insertEvents(ctx context.Context, tx *sql.Tx, evs []Event) error {
	for _, e := range evs {
		d, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("findings: encoding an event: %w", err)
		}
		var detail any
		if string(d) != "{}" {
			detail = string(d)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_finding_event (finding_id, ts, actor, kind, detail) VALUES (?, ?, ?, ?, ?)`,
			e.FindingID, store.FormatTS(e.TS), e.Actor, string(e.Kind), detail); err != nil {
			return fmt.Errorf("findings: inserting an event: %w", err)
		}
	}
	return nil
}

// apply runs Transition on f and writes the result; isNew says f has no row yet. It returns the finding after the trigger and its
// events (none when nothing changed: then nothing is written).
func apply(ctx context.Context, tx *sql.Tx, f Finding, isNew bool, t Trigger) (Finding, []Event, error) {
	g, evs, err := Transition(f, t)
	if err != nil {
		return f, nil, err
	}
	if g.State == "" || sameFinding(f, g) && len(evs) == 0 {
		return g, nil, nil
	}
	if err := writeFinding(ctx, tx, g, isNew, evs); err != nil {
		return f, nil, err
	}
	return g, evs, nil
}

// eventsOf returns the events of the findings a WHERE clause on fnd_finding selects (alias f), by finding, oldest first.
func eventsOf(ctx context.Context, q querier, where string, args ...any) (map[string][]Event, error) {
	rows, err := q.QueryContext(ctx, `SELECT e.id, e.finding_id, e.ts, e.actor, e.kind, e.detail FROM fnd_finding_event e
		JOIN fnd_finding f ON f.id = e.finding_id WHERE `+where+` ORDER BY e.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]Event{}
	for rows.Next() {
		var (
			e      Event
			ts     string
			kind   string
			detail sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.FindingID, &ts, &e.Actor, &kind, &detail); err != nil {
			return nil, fmt.Errorf("findings: reading events: %w", err)
		}
		if e.TS, err = parseTS(ts); err != nil {
			return nil, err
		}
		e.Kind = EventKind(kind)
		if detail.Valid {
			if err := json.Unmarshal([]byte(detail.String), &e.Detail); err != nil {
				return nil, fmt.Errorf("findings: reading an event: %w", err)
			}
		}
		out[e.FindingID] = append(out[e.FindingID], e)
	}
	return out, rows.Err()
}

const questionColumns = `id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at, check_key`

func scanQuestion(s scanner) (Question, error) {
	var (
		q                                       Question
		kind, asked                             string
		softwareID, cve, detail, answer, by, at sql.NullString
	)
	if err := s.Scan(&q.ID, &q.AssetID, &softwareID, &cve, &kind, &detail, &q.Cves, &asked, &answer, &by, &at, &q.CheckKey); err != nil {
		return Question{}, err
	}
	q.SoftwareID, q.CVE, q.Kind, q.Answer, q.AnsweredBy = softwareID.String, cve.String, QuestionKind(kind), answer.String, by.String
	var err error
	if q.AskedAt, err = parseTS(asked); err != nil {
		return Question{}, err
	}
	if at.Valid {
		if q.AnsweredAt, err = parseTS(at.String); err != nil {
			return Question{}, err
		}
	}
	if detail.Valid {
		if err := json.Unmarshal([]byte(detail.String), &q.Detail); err != nil {
			return Question{}, fmt.Errorf("findings: reading a question: %w", err)
		}
	}
	return q, nil
}

// questionsOf returns the questions of one device, or of every device when assetID is "", the most CVEs first.
func questionsOf(ctx context.Context, q querier, assetID string) ([]Question, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+questionColumns+` FROM fnd_question WHERE (?1 = '' OR asset_id = ?1)
		ORDER BY asset_id, cves DESC, kind, ifnull(cve, ''), rowid`, assetID)
	if err != nil {
		return nil, fmt.Errorf("findings: reading questions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Question
	for rows.Next() {
		x, err := scanQuestion(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading questions: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// replaceQuestions makes qs the questions of the device: a question that still holds keeps its row (its id, when it was asked and
// its answer), one that no longer holds goes, a new one is added. A person's answer to one CVE holds whatever kind of question it
// answered, while it applies (answeredFor): a CVE asked again under another kind keeps the answered question instead, and a CVE whose
// own question a person answered leaves a question of several CVEs (older_line; a group that keeps no CVE is not asked). An answered
// group asks again when a CVE joins it that the person did not answer for.
func replaceQuestions(ctx context.Context, tx *sql.Tx, assetID string, qs []Question, now time.Time) error {
	old, err := questionsOf(ctx, tx, assetID)
	if err != nil {
		return err
	}
	have := make(map[string]Question, len(old))
	for _, q := range old {
		have[q.key()] = q
	}
	keep := map[string]bool{}
	qs = slices.Clone(qs)
	for i, q := range qs {
		if q.Kind != QuestionOlderLine || q.CVE != "" { // a group of a whole line (as earlier builds asked): its answered CVEs leave it
			continue
		}
		var left []string
		for _, c := range q.Detail.CVEList {
			if was, ok := answeredFor(old, q.SoftwareID, c, q.Detail.Version); ok {
				keep[was.key()] = true // the person's answer to this CVE's own question holds
				continue
			}
			left = append(left, c)
		}
		qs[i].Detail.CVEList, qs[i].Cves = left, len(left)
	}
	for _, q := range qs {
		if q.Kind == QuestionOlderLine && q.CVE == "" && len(q.Detail.CVEList) == 0 {
			continue
		}
		q.AssetID = assetID
		k := q.key()
		if keep[k] {
			continue
		}
		if _, asked := have[k]; !asked && q.CVE != "" {
			if was, ok := answeredFor(old, q.SoftwareID, q.CVE, q.Detail.Version); ok {
				keep[was.key()] = true // the CVE is asked under another kind now; the person's answer to it holds
				continue
			}
		}
		keep[k] = true
		detail, err := json.Marshal(q.Detail)
		if err != nil {
			return fmt.Errorf("findings: encoding a question: %w", err)
		}
		if q.Cves < 1 {
			q.Cves = 1
		}
		if was, ok := have[k]; ok {
			if was.Answer != "" && slices.ContainsFunc(q.Detail.CVEList, func(c string) bool { return !slices.Contains(was.Detail.CVEList, c) }) {
				// a CVE the person did not answer for joined a group they answered: asked again, never decided by that answer
				if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET detail = ?, cves = ?, check_key = ?, answer = NULL, answered_by = NULL, answered_at = NULL, asked_at = ?
					WHERE id = ?`, string(detail), q.Cves, q.CheckKey, store.FormatTS(now), was.ID); err != nil {
					return fmt.Errorf("findings: asking a question again: %w", err)
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET detail = ?, cves = ?, check_key = ? WHERE id = ?`, string(detail), q.Cves, q.CheckKey, was.ID); err != nil {
				return fmt.Errorf("findings: updating a question: %w", err)
			}
			continue
		}
		q.ID, q.AskedAt = store.NewID("q"), now
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, check_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			q.ID, assetID, nullString(q.SoftwareID), nullString(q.CVE), string(q.Kind), string(detail), q.Cves, store.FormatTS(now), q.CheckKey); err != nil {
			return fmt.Errorf("findings: adding a question: %w", err)
		}
	}
	for k, q := range have {
		if keep[k] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_question WHERE id = ?`, q.ID); err != nil {
			return fmt.Errorf("findings: removing a question: %w", err)
		}
	}
	return nil
}

// answeredFor is the person's answer to CVE cve on software line sw that still applies to the line at version: the latest answered
// question of that CVE on that line, whatever its kind, asked about that version (a question stored without its version applies to
// any). An answer given for another version is not the person's word on this one.
func answeredFor(old []Question, sw, cve, version string) (Question, bool) {
	var best Question
	found := false
	for _, q := range old {
		// an answer to an older_line question of a whole line (stored before each CVE was its own question) holds for each CVE it listed
		of := q.CVE == cve || q.CVE == "" && q.Kind == QuestionOlderLine && slices.Contains(q.Detail.CVEList, cve)
		if q.Answer == "" || !of || q.SoftwareID != sw || (q.Detail.Version != "" && q.Detail.Version != version) {
			continue
		}
		if !found || q.AnsweredAt.After(best.AnsweredAt) {
			best, found = q, true
		}
	}
	return best, found
}
