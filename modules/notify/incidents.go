package notify

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

const (
	maxNote         = 500
	maxIncidentText = 1000
	maxDevices      = 20
	maxKeyPart      = 200
	systemUser      = "system"
)

func (in IncidentInput) validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidNotice, why) }
	switch {
	case !in.Kind.Valid():
		return bad("kind must be lower case words, digits and underscores, at most 40 characters")
	case !in.Severity.Valid():
		return bad("unknown severity")
	case strings.TrimSpace(in.Title) == "" || utf8.RuneCountInString(in.Title) > 200:
		return bad("title must be 1 to 200 characters")
	case utf8.RuneCountInString(in.What) > maxIncidentText || utf8.RuneCountInString(in.Action) > maxIncidentText:
		return bad("what and action are at most 1000 characters")
	case utf8.RuneCountInString(in.Source) > maxKeyPart || utf8.RuneCountInString(in.Target) > maxKeyPart:
		return bad("source and target are at most 200 characters")
	case !strings.HasPrefix(in.Link, "/") || strings.HasPrefix(in.Link, "//") || len(in.Link) > 300 || strings.IndexFunc(in.Link, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return bad("link must be a path inside Vedette, such as /logs")
	case len(in.Devices) > maxDevices:
		return bad("too many devices")
	case in.Attempt && in.Kind != IncidentBadAddress:
		return bad("only a bad_address incident can be an attempt")
	}
	for _, d := range in.Devices {
		if d.ID == "" || len(d.ID) > 96 || strings.TrimSpace(d.Name) == "" || utf8.RuneCountInString(d.Name) > 253 {
			return bad("a device needs an id and a name")
		}
	}
	return nil
}

func dedupeKey(in IncidentInput) string {
	k := string(in.Kind) + "\x00" + in.Source + "\x00" + in.Target
	if in.Attempt {
		k += "\x00attempt"
	}
	h := sha256.Sum256([]byte(k))
	return hex.EncodeToString(h[:])
}

// mergeKeys are the dedupe keys a repeat of in counts on, in order: first is the key whose open incident it joins before one of its own
// (for an attempt, the open connection of the same source and target), key is its own.
func mergeKeys(in IncidentInput) (first, key string) {
	key = dedupeKey(in)
	if !in.Attempt {
		return key, key
	}
	conn := in
	conn.Attempt = false
	return dedupeKey(conn), key
}

// OpenIncident records an incident (PRE-2, POST-2, INV-10). The same kind, source and target while
// the incident is not resolved only raises its count and last_seen; a new incident is queued for the
// channels and announced as notify.incident.created. Repeats are not sent again. In the first-run window a
// low or medium bad-connection or log incident is not queued: the hourly first-run summary tells it (INV-23). It returns the
// incident id and whether it was created.
func (s *Service) OpenIncident(ctx context.Context, in IncidentInput) (id string, created bool, err error) {
	if !s.on() {
		return "", false, ErrModuleOff // nothing is recorded or queued while the module is off
	}
	if err := in.validate(); err != nil {
		return "", false, err
	}
	now := s.now()
	at := in.At
	if at.IsZero() {
		at = now
	}
	ts := store.FormatTS(at)
	first, key := mergeKeys(in)
	held := false // INV-23: a low or medium bad-connection or log incident of the first-run window waits for the hourly summary
	if heldKind(in.Kind) && in.Severity.rank() <= Medium.rank() {
		if held, err = s.firstDiscovery(ctx); err != nil {
			return "", false, err
		}
	}
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		ob = &events.Outbox{}
		var wasHeld bool
		var cur string
		switch err := tx.QueryRowContext(ctx, `SELECT id, first_run, severity FROM notify_incident WHERE dedupe_key IN (?, ?) AND status <> 'resolved' ORDER BY dedupe_key = ? DESC LIMIT 1`,
			first, key, first).Scan(&id, &wasHeld, &cur); {
		case err == nil:
			created = false
			_, err = tx.ExecContext(ctx, `UPDATE notify_incident SET count = count + 1, last_seen = CASE WHEN ? > last_seen THEN ? ELSE last_seen END, active_at = ? WHERE id = ?`,
				ts, ts, store.FormatTS(now), id)
			if err != nil {
				return fmt.Errorf("notify: count repeated incident: %w", err)
			}
			if wasHeld && in.Severity.rank() > Severity(cur).rank() {
				return s.raiseHeld(ctx, tx, id, in.Severity, at) // INV-23: a held incident that turns high or critical is sent as usual
			}
			if in.Kind == IncidentIntrusion && in.Severity.rank() > Severity(cur).rank() {
				return s.raiseIntrusion(ctx, tx, id, in, at) // INV-26: an attack at an affected device raises the incident and says so
			}
			return nil
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("notify: find incident: %w", err)
		}
		created, id = true, store.NewID("in")
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_incident (id, kind, attempt, title, link, severity, what, action, first_seen, last_seen, dedupe_key, first_run, active_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, string(in.Kind), in.Attempt, strings.TrimSpace(in.Title), in.Link, string(in.Severity), in.What, in.Action, ts, ts, key, boolInt(held), store.FormatTS(now)); err != nil {
			return fmt.Errorf("notify: save incident: %w", err)
		}
		names, ids := make([]string, 0, len(in.Devices)), make([]string, 0, len(in.Devices))
		for _, d := range in.Devices {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, id, d.ID, d.Name); err != nil {
				return fmt.Errorf("notify: save incident device: %w", err)
			}
			names, ids = append(names, d.Name), append(ids, d.ID)
		}
		if err := s.record(ctx, tx, systemUser, "notify.incident_open", clip(strings.TrimSpace(in.Title), 400), string(in.Kind)); err != nil {
			return err
		}
		if !held {
			if err := s.enqueue(ctx, tx, Notice{ID: id, Kind: KindIncident, Severity: in.Severity, Title: strings.TrimSpace(in.Title), What: in.What, Action: in.Action,
				Devices: names, DeviceIDs: ids, IncidentKind: string(in.Kind), Link: s.link("/incidents/" + id), At: at}); err != nil {
				return err
			}
		}
		ob.Add(events.Event{Name: "notify.incident.created", Data: map[string]string{"id": id, "kind": string(in.Kind), "severity": string(in.Severity)}})
		return nil
	})
	if err != nil {
		return "", false, err
	}
	s.flush(ctx, ob)
	return id, created, nil
}

func notFound(what string) *apierr.Error {
	return apierr.New(http.StatusNotFound, apierr.CodeNotFound, what)
}

func scanSends(rows *sql.Rows) ([]SendView, error) {
	defer func() { _ = rows.Close() }()
	out := []SendView{}
	for rows.Next() {
		var v SendView
		var ch string
		var e sql.NullString
		if err := rows.Scan(&v.ID, &ch, &v.To, &v.At, &v.OK, &e, &v.Delayed); err != nil {
			return nil, fmt.Errorf("notify: read sends: %w", err)
		}
		v.Channel, v.Error = channel.Type(ch), e.String
		out = append(out, v)
	}
	return out, rows.Err()
}

const incidentCols = `id, kind, attempt, title, link, severity, what, action, first_seen, last_seen, count, status, handled_by, handled_at, note, resolved_reason, first_run = 1`

func scanIncident(r scanner) (Incident, error) {
	var i Incident
	var kind, sev, status string
	var by, at, note, reason sql.NullString
	var firstRun bool
	if err := r.Scan(&i.ID, &kind, &i.Attempt, &i.Title, &i.Link, &sev, &i.What, &i.Action, &i.FirstSeen, &i.LastSeen, &i.Count, &status, &by, &at, &note, &reason, &firstRun); err != nil {
		return i, err
	}
	i.Kind, i.Severity, i.Status = IncidentKind(kind), Severity(sev), IncidentStatus(status)
	i.HandledBy, i.HandledAt, i.Note, i.ResolvedReason = ptr(by.String), ptr(at.String), ptr(note.String), ptr(reason.String)
	i.FirstRunSummary = firstRun
	i.Devices, i.Sends = []Device{}, []SendView{}
	return i, nil
}

// fillIncident adds the devices and the delivery log.
func fillIncident(ctx context.Context, q dbtx, i *Incident) error {
	if err := fillDevices(ctx, q, i); err != nil {
		return err
	}
	srows, err := q.QueryContext(ctx, `SELECT id, channel, "to", at, ok, error, delayed FROM notify_send WHERE kind = 'incident' AND ref_id = ? ORDER BY at, rowid`, i.ID)
	if err != nil {
		return fmt.Errorf("notify: read incident sends: %w", err)
	}
	i.Sends, err = scanSends(srows)
	return err
}

// fillDevices adds the devices of the incident, in the order it stored them.
func fillDevices(ctx context.Context, q dbtx, i *Incident) error {
	i.Devices = []Device{}
	rows, err := q.QueryContext(ctx, `SELECT asset_id, name FROM notify_incident_device WHERE incident_id = ? ORDER BY rowid`, i.ID)
	if err != nil {
		return fmt.Errorf("notify: read incident devices: %w", err)
	}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: read incident devices: %w", err)
		}
		i.Devices = append(i.Devices, d)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: read incident devices: %w", err)
	}
	return nil
}

// IncidentTop is one incident of an IncidentPeriod: its kind, severity, title, the newest activity and its first device ("" = none).
type IncidentTop struct {
	Kind       IncidentKind
	Severity   Severity
	Title      string
	LastSeen   time.Time
	DeviceID   string
	DeviceName string
	Devices    int // how many devices the incident names (DeviceID is the first by name)
}

// IncidentPeriod is the incidents with activity in a period: how many of each kind (all of them, however many there are, with the
// newest activity) and the first few that matter most, by severity then recency.
type IncidentPeriod struct {
	Kinds []KindCount
	Top   []IncidentTop
}

// IncidentsIn reads the incidents with activity in the period (from, to]: first seen before its end and last seen after its start,
// for the periodic report; top is how many incidents to name.
func (s *Service) IncidentsIn(ctx context.Context, from, to time.Time, top int) (IncidentPeriod, error) {
	db := s.cfg.DB.Reader()
	var p IncidentPeriod
	f, t := store.FormatTS(from), store.FormatTS(to)
	rows, err := db.QueryContext(ctx, `SELECT kind, count(*), sum(status = 'new'), max(last_seen) FROM notify_incident WHERE last_seen > ? AND first_seen <= ?
		GROUP BY kind ORDER BY kind`, f, t)
	if err != nil {
		return p, fmt.Errorf("notify: count incidents: %w", err)
	}
	for rows.Next() {
		var c KindCount
		var k, last string
		if err := rows.Scan(&k, &c.Incidents, &c.New, &last); err != nil {
			_ = rows.Close()
			return p, fmt.Errorf("notify: count incidents: %w", err)
		}
		c.Kind = IncidentKind(k)
		c.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		p.Kinds = append(p.Kinds, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return p, fmt.Errorf("notify: count incidents: %w", err)
	}
	rows, err = db.QueryContext(ctx, `SELECT i.id, i.kind, i.severity, i.title, i.last_seen,
			ifnull((SELECT d.asset_id FROM notify_incident_device d WHERE d.incident_id = i.id ORDER BY d.name, d.asset_id LIMIT 1), ''),
			ifnull((SELECT d.name FROM notify_incident_device d WHERE d.incident_id = i.id ORDER BY d.name, d.asset_id LIMIT 1), ''),
			(SELECT count(*) FROM notify_incident_device d WHERE d.incident_id = i.id)
		FROM notify_incident i WHERE i.last_seen > ? AND i.first_seen <= ?
		ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, i.last_seen DESC, i.id LIMIT ?`, f, t, top)
	if err != nil {
		return p, fmt.Errorf("notify: top incidents: %w", err)
	}
	var ids []string
	for rows.Next() {
		var x IncidentTop
		var id, k, sev, at string
		if err := rows.Scan(&id, &k, &sev, &x.Title, &at, &x.DeviceID, &x.DeviceName, &x.Devices); err != nil {
			_ = rows.Close()
			return p, fmt.Errorf("notify: top incidents: %w", err)
		}
		x.Kind, x.Severity = IncidentKind(k), Severity(sev)
		if x.LastSeen, err = time.Parse(time.RFC3339Nano, at); err != nil {
			_ = rows.Close()
			return p, fmt.Errorf("notify: top incidents: %w", err)
		}
		p.Top = append(p.Top, x)
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return p, fmt.Errorf("notify: top incidents: %w", err)
	}
	return p, s.topNames(ctx, db, p.Top, ids)
}

// topNames gives the incidents of a report (top, their ids) the current names of their devices, as the incidents page shows them.
func (s *Service) topNames(ctx context.Context, db dbtx, top []IncidentTop, ids []string) error {
	if s.cfg.Devices == nil || len(top) == 0 {
		return nil
	}
	list := make([]Incident, len(top))
	for k, x := range top {
		list[k] = Incident{ID: ids[k], Title: x.Title}
		if err := fillDevices(ctx, db, &list[k]); err != nil {
			return err
		}
	}
	s.currentNames(ctx, list)
	for k := range top {
		top[k].Title = list[k].Title
		for _, d := range list[k].Devices {
			if d.ID == top[k].DeviceID {
				top[k].DeviceName = d.Name
			}
		}
	}
	return nil
}

// Incidents lists the incidents for GET /notify/incidents: every open one (new or acknowledged) first, then the resolved ones, each
// most recently seen first, at most incidentsLimit. An open incident is never cut by the limit (the page once counted its "open" from
// the 500 seen last, while Home and the nav badge count every open one with OpenIncidents).
func (s *Service) Incidents(ctx context.Context) ([]Incident, error) {
	db := s.cfg.DB.Reader()
	rows, err := db.QueryContext(ctx, `SELECT `+incidentCols+` FROM notify_incident ORDER BY `+incidentsOrder+` LIMIT ?`, incidentsLimit)
	if err != nil {
		return nil, fmt.Errorf("notify: list incidents: %w", err)
	}
	out := []Incident{}
	at := map[string]int{}
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: list incidents: %w", err)
		}
		at[i.ID] = len(out)
		out = append(out, i)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: list incidents: %w", err)
	}
	if len(out) == 0 {
		return out, nil
	}
	// Two queries for all the incidents of the page, not two per incident.
	const page = `(SELECT id FROM notify_incident ORDER BY ` + incidentsOrder + ` LIMIT ?)` // the same rows as the list (#931 r1 H)
	drows, err := db.QueryContext(ctx, `SELECT incident_id, asset_id, name FROM notify_incident_device WHERE incident_id IN `+page+` ORDER BY rowid`, incidentsLimit)
	if err != nil {
		return nil, fmt.Errorf("notify: read incident devices: %w", err)
	}
	for drows.Next() {
		var inc string
		var d Device
		if err := drows.Scan(&inc, &d.ID, &d.Name); err != nil {
			_ = drows.Close()
			return nil, fmt.Errorf("notify: read incident devices: %w", err)
		}
		if k, ok := at[inc]; ok {
			out[k].Devices = append(out[k].Devices, d)
		}
	}
	if err := errors.Join(drows.Err(), drows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read incident devices: %w", err)
	}
	srows, err := db.QueryContext(ctx, `SELECT ref_id, id, channel, "to", at, ok, error, delayed FROM notify_send WHERE kind = 'incident' AND ref_id IN `+page+` ORDER BY at, rowid`, incidentsLimit)
	if err != nil {
		return nil, fmt.Errorf("notify: read incident sends: %w", err)
	}
	for srows.Next() {
		var ref, ch string
		var v SendView
		var e sql.NullString
		if err := srows.Scan(&ref, &v.ID, &ch, &v.To, &v.At, &v.OK, &e, &v.Delayed); err != nil {
			_ = srows.Close()
			return nil, fmt.Errorf("notify: read incident sends: %w", err)
		}
		v.Channel, v.Error = channel.Type(ch), e.String
		if k, ok := at[ref]; ok {
			out[k].Sends = append(out[k].Sends, v)
		}
	}
	if err := errors.Join(srows.Err(), srows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read incident sends: %w", err)
	}
	if err := s.withNotSent(ctx, db, out); err != nil {
		return nil, err
	}
	s.withConnections(ctx, out)
	s.currentNames(ctx, out)
	return out, nil
}

const hitLinkPrefix = "/honeypot/hits/"

// withConnections raises the count of each trap incident to the connections its hit saw: notify counts one per event, and a
// repeat connection folds into the hit without an event. The hit is counted once, so a later hit of the same incident
// stays one. Without the port, or when it fails, the count stays notify's own (one log line, no error to the page).
func (s *Service) withConnections(ctx context.Context, list []Incident) {
	if s.cfg.Hits == nil || len(list) == 0 || (s.cfg.Modules != nil && !s.cfg.Modules.Enabled("honeypot")) {
		return
	}
	var refs []HitRef
	for _, i := range list {
		id, ok := strings.CutPrefix(i.Link, hitLinkPrefix)
		at, err := time.Parse(time.RFC3339, i.FirstSeen)
		if i.Kind != IncidentTrap || !ok || id == "" || err != nil {
			continue
		}
		refs = append(refs, HitRef{ID: id, At: at})
	}
	if len(refs) == 0 {
		return
	}
	conns, err := s.cfg.Hits.HitConnections(ctx, refs)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: trap hit connections are not available, showing notify's own count", "error", err)
		return
	}
	for k := range list {
		if id, ok := strings.CutPrefix(list[k].Link, hitLinkPrefix); ok && list[k].Kind == IncidentTrap {
			if n := conns[id]; n > 1 {
				list[k].Count += n - 1
			}
		}
	}
}

// incidentsLimit is the most incidents GET /notify/incidents returns, open ones first, then newest seen first (the page of an
// unbounded list would grow with every trap hit).
const incidentsLimit = 500

// incidentsOrder is the order of GET /notify/incidents and of the page its devices and sends are read for: open first.
const incidentsOrder = `status = 'resolved', last_seen DESC, rowid DESC`

// IncidentDetail returns one incident with what each channel received (GET /notify/incidents/{id}).
func (s *Service) IncidentDetail(ctx context.Context, id string) (IncidentDetail, error) {
	d, err := s.incidentDetail(ctx, s.cfg.DB.Reader(), id)
	s.detailConnections(ctx, &d)
	return d, err
}

// detailConnections is withConnections and currentNames for one incident, called outside any write transaction. The previews keep the
// stored words: they are what each channel received.
func (s *Service) detailConnections(ctx context.Context, d *IncidentDetail) {
	one := []Incident{d.Incident}
	s.withConnections(ctx, one)
	s.currentNames(ctx, one)
	d.Incident = one[0]
}

func (s *Service) incidentDetail(ctx context.Context, q dbtx, id string) (IncidentDetail, error) {
	i, err := scanIncident(q.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM notify_incident WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return IncidentDetail{}, notFound("No such incident. It may have been removed.")
	}
	if err != nil {
		return IncidentDetail{}, fmt.Errorf("notify: read incident: %w", err)
	}
	if err := fillIncident(ctx, q, &i); err != nil {
		return IncidentDetail{}, err
	}
	one := []Incident{i}
	if err := s.withNotSent(ctx, q, one); err != nil {
		return IncidentDetail{}, err
	}
	i = one[0]
	names := make([]string, 0, len(i.Devices))
	for _, d := range i.Devices {
		names = append(names, d.Name)
	}
	ids := make([]string, 0, len(i.Devices))
	for _, d := range i.Devices {
		ids = append(ids, d.ID)
	}
	msg := channel.Message{ID: i.ID, Kind: "incident", IncidentKind: string(i.Kind), Severity: string(i.Severity), Title: i.Title, Device: joinDevices(names),
		Devices: deviceRefs(names, ids), What: i.What, Action: i.Action, Link: s.link("/incidents/" + i.ID)}
	d := IncidentDetail{Incident: i, Previews: []Preview{}}
	seen := map[channel.Type]bool{}
	for _, sd := range i.Sends {
		if seen[sd.Channel] {
			continue
		}
		seen[sd.Channel] = true
		subject, text, err := channel.Preview(sd.Channel, msg)
		if err != nil {
			continue // a message the adapters would refuse has no preview
		}
		d.Previews = append(d.Previews, Preview{Channel: sd.Channel, Subject: subject, Text: text})
	}
	return d, nil
}

// HandleIncident acknowledges, resolves or reopens an incident (PATCH /notify/incidents/{id}, INV-10).
// Reopening (status new) clears who handled it and the note; acknowledging or resolving without a note keeps the note already there.
func (s *Service) HandleIncident(ctx context.Context, actor, id string, status IncidentStatus, note string) (IncidentDetail, error) {
	if status != StatusNew && status != StatusAcknowledged && status != StatusResolved {
		return IncidentDetail{}, badRequest("bad_status", "Status must be new, acknowledged or resolved.")
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > maxNote {
		return IncidentDetail{}, badRequest("note_too_long", "A note can be at most 500 characters.")
	}
	var d IncidentDetail
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var title, cur, key string
		if err := tx.QueryRowContext(ctx, `SELECT title, status, dedupe_key FROM notify_incident WHERE id = ?`, id).Scan(&title, &cur, &key); errors.Is(err, sql.ErrNoRows) {
			return notFound("No such incident.")
		} else if err != nil {
			return fmt.Errorf("notify: read incident: %w", err)
		}
		if cur == string(StatusResolved) && status != StatusResolved {
			// Reopening: only one incident per kind, source and target may be open (INV-10). A newer one has
			// taken its place, so the person is told which one to handle instead.
			var open string
			switch err := tx.QueryRowContext(ctx, `SELECT id FROM notify_incident WHERE dedupe_key = ? AND status <> 'resolved' AND id <> ?`, key, id).Scan(&open); {
			case err == nil:
				return apierr.New(http.StatusConflict, "already_open", "A newer incident with the same source and target is already open. Handle that one instead.").With("open_id", open)
			case !errors.Is(err, sql.ErrNoRows):
				return fmt.Errorf("notify: look for an open incident: %w", err)
			}
		}
		now := store.FormatTS(s.now())
		var by, at, nt any
		if status != StatusNew {
			by, at, nt = actor, now, nullable(note)
		}
		// A person's action replaces Vedette's reason (INV-22): the incident is theirs now. Reopening makes it active again, so the
		// quiet window of autoclose starts over from now, and clears the note; acknowledging or resolving with no note keeps the one
		// already there, as the bulk change does (INV-25).
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = ?, handled_by = ?, handled_at = ?, note = CASE WHEN ? = 'new' THEN NULL ELSE COALESCE(?, note) END,
			resolved_reason = NULL, active_at = CASE WHEN ? = 'new' THEN ? ELSE active_at END WHERE id = ?`, string(status), by, at, string(status), nt, string(status), now, id); err != nil {
			return fmt.Errorf("notify: update incident: %w", err)
		}
		detail := string(status)
		if note != "" {
			detail += ": " + note
		}
		if err := s.record(ctx, tx, actor, "notify.incident_status", clip(title, 400), detail); err != nil {
			return err
		}
		var err error
		d, err = s.incidentDetail(ctx, tx, id)
		return err
	})
	if err == nil {
		s.detailConnections(ctx, &d) // after the write closed: the honeypot is asked outside the transaction
	}
	return d, err
}

// ---- history ----

// History lists every message sent, newest first, the vulnerability notices of the last historyDays days that no channel delivered with
// why, and how many new vulnerabilities matched no device recently (GET /notify/history). Each list has at most historyLimit rows.
func (s *Service) History(ctx context.Context) (HistoryView, error) {
	db := s.cfg.DB.Reader()
	v := HistoryView{Items: []HistoryItem{}, NotSent: []UnsentNotice{}}
	rows, err := db.QueryContext(ctx, `SELECT id, channel, "to", at, ok, error, delayed, kind, what, link, resend_of IS NOT NULL FROM notify_send ORDER BY at DESC, rowid DESC LIMIT ?`, historyLimit)
	if err != nil {
		return v, fmt.Errorf("notify: read history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var h HistoryItem
		var ch string
		var e sql.NullString
		if err := rows.Scan(&h.ID, &ch, &h.To, &h.At, &h.OK, &e, &h.Delayed, &h.Kind, &h.What, &h.Link, &h.Resent); err != nil {
			return v, fmt.Errorf("notify: read history: %w", err)
		}
		h.Channel, h.Error = channel.Type(ch), e.String
		v.Items = append(v.Items, h)
	}
	if err := rows.Err(); err != nil {
		return v, fmt.Errorf("notify: read history: %w", err)
	}
	if v.NotSent, err = s.notSentNotices(ctx, db, s.now().AddDate(0, 0, -historyDays)); err != nil {
		return v, err
	}
	if s.cfg.Signals != nil {
		n, err := s.cfg.Signals.UnmatchedExploited(ctx, s.now().AddDate(0, 0, -historyDays))
		if err != nil {
			return v, fmt.Errorf("notify: read suppressed count: %w", err)
		}
		v.Suppressed.Count = n
	}
	v.Suppressed.Days = historyDays
	return v, nil
}

// SentSince counts the alert messages (kinds incident and vuln: an approval request is not an alert) sent since a time (Home's "alerts
// sent", #825): sent = attempts that arrived; failed = attempts that did not arrive, are not waiting to be sent again (a "Delayed" row
// resends by itself), and were not resent with success later to the same channel for the same item (kind, ref_id). One range on
// notify_send_at_ix; the resend check is a lookup on notify_send_ref_ix.
func (s *Service) SentSince(ctx context.Context, since time.Time) (sent, failed int, err error) {
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT ifnull(sum(s.ok = 1), 0),
  ifnull(sum(s.ok = 0 AND s.delayed = 0 AND NOT EXISTS (SELECT 1 FROM notify_send r
    WHERE r.kind = s.kind AND r.ref_id = s.ref_id AND r.channel = s.channel AND r.ok = 1 AND r.at >= s.at)), 0)
FROM notify_send s WHERE s.at >= ? AND s.kind IN ('incident', 'vuln')`, store.FormatTS(since)).Scan(&sent, &failed)
	if err != nil {
		return 0, 0, fmt.Errorf("notify: count sent messages: %w", err)
	}
	return sent, failed, nil
}

// OpenIncidents counts the open incidents (new or acknowledged, the Incidents page's Open tab) and, of them, the urgent ones (high or
// critical, its "?severity=urgent" filter): the shell's nav badge and Home (#825). One read on notify_incident_status_ix.
func (s *Service) OpenIncidents(ctx context.Context) (open, urgent int, err error) {
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*), ifnull(sum(severity IN ('high', 'critical')), 0) FROM notify_incident WHERE status IN ('new', 'acknowledged')`).
		Scan(&open, &urgent)
	if err != nil {
		return 0, 0, fmt.Errorf("notify: count open incidents: %w", err)
	}
	return open, urgent, nil
}

// historyLimit is the most rows History returns (API_CONVENTIONS 6: /notify/history max 500).
const historyLimit = 500

// Resend sends a message of the history again through the same channel (POST /notify/history/{id}/resend, INV-11).
// A failed attempt is still a 200 with ok=false: it is a new row in the history.
func (s *Service) Resend(ctx context.Context, actor, id string) (HistoryItem, error) {
	var old struct {
		ch              channel.Type
		kind, ref, what string
		link, raw       string
		recipient       sql.NullString
	}
	var ch string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT channel, kind, ref_id, what, link, message, recipient FROM notify_send WHERE id = ?`, id).Scan(&ch, &old.kind, &old.ref, &old.what, &old.link, &old.raw, &old.recipient)
	if errors.Is(err, sql.ErrNoRows) {
		return HistoryItem{}, notFound("No such message in the history.")
	}
	if err != nil {
		return HistoryItem{}, fmt.Errorf("notify: read message: %w", err)
	}
	old.ch = channel.Type(ch)
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), old.ch)
	if err != nil {
		return HistoryItem{}, err
	}
	if !c.Configured || !c.Enabled {
		return HistoryItem{}, apierr.New(http.StatusConflict, "channel_not_ready", "This channel is not set up or is turned off. An administrator can turn it on in Settings, Alert channels.")
	}
	var msg channel.Message
	if err := unmarshalMessage(old.raw, &msg); err != nil {
		return HistoryItem{}, err
	}
	var rec SendRecord
	var to []string // a message that went to one person (an approver) goes to that person again, not to the alert list
	if old.recipient.Valid {
		// The approver is checked again, as at the first send (approverProblem): a demoted, disabled or removed approver, or an address
		// that is no longer theirs, gets nothing, and no row is written because nothing was attempted.
		if why, err := s.resendApproverProblem(ctx, old.ch, old.recipient.String); err != nil {
			return HistoryItem{}, err
		} else if why != "" {
			s.cfg.Log.WarnContext(ctx, "resend refused: the approver no longer qualifies", "channel", string(old.ch), "reason", why)
			return HistoryItem{}, apierr.New(http.StatusConflict, "approver_not_ready", "This message went to one approver, who can no longer approve ("+why+"). It was not sent again.")
		}
		to = []string{old.recipient.String}
	}
	var snd channel.Sender
	if old.ch == channel.ZaloPersonal && old.recipient.Valid {
		// An approver's own message: to that approver again, through the session of the channel (never a second sign-in, never the
		// alert recipient). The reply codes are not kept, so the copy has none.
		if snd, err = s.savedSender(ctx, c, nil); err == nil {
			snd, err = s.zaloTo(snd, old.recipient.String)
		}
	} else {
		snd, err = s.savedSender(ctx, c, to)
	}
	if err != nil {
		rec = SendRecord{ID: store.NewID("sd"), Channel: old.ch, To: string(old.ch), At: s.now(), Error: "The channel settings cannot be used: " + userText(err)}
	} else {
		rec = Deliver(ctx, store.NewID("sd"), snd, msg, s.now)
	}
	ctx, stop := detached(ctx) // the message may have gone out: its record is written even if the request ended
	defer stop()
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := insertSend(ctx, tx, rec, old.kind, old.ref, old.what, old.link, old.recipient.String, msg); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_send SET resend_of = ? WHERE id = ?`, id, rec.ID); err != nil {
			return fmt.Errorf("notify: mark resend: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_send_notice (send_id, notice_id) SELECT ?, notice_id FROM notify_send_notice WHERE send_id = ?`, rec.ID, id); err != nil {
			return fmt.Errorf("notify: link resend to notices: %w", err)
		}
		name := "notify.message.sent"
		if !rec.OK {
			name = "notify.message.failed"
		}
		ob.Add(events.Event{Name: name, Data: map[string]string{"id": rec.ID, "channel": string(rec.Channel)}})
		return s.record(ctx, tx, actor, "notify.resend", clip(old.what, 400), string(old.ch))
	})
	if err != nil {
		return HistoryItem{}, err
	}
	s.flush(ctx, ob)
	return HistoryItem{SendView: SendView{ID: rec.ID, Channel: rec.Channel, To: rec.To, At: store.FormatTS(rec.At), OK: rec.OK, Error: clip(rec.Error, 1000)},
		Kind: old.kind, What: old.what, Link: old.link, Resent: true}, nil
}

// FindingNotices lists who was told about a finding, oldest first (GET /notify/findings/{id}/notices).
func (s *Service) FindingNotices(ctx context.Context, findingID string) ([]SendView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT s.id, s.channel, s."to", s.at, s.ok, s.error, s.delayed FROM notify_send s
		WHERE s.id IN (SELECT sn.send_id FROM notify_send_notice sn JOIN notify_notice_finding nf ON nf.notice_id = sn.notice_id WHERE nf.finding_id = ?)
		ORDER BY s.at, s.rowid`, findingID)
	if err != nil {
		return nil, fmt.Errorf("notify: read finding notices: %w", err)
	}
	return scanSends(rows)
}

// AlertTarget says where an old alert id leads now: the finding or the incident it became.
func (s *Service) AlertTarget(ctx context.Context, id string) (string, error) {
	db := s.cfg.DB.Reader()
	var first sql.NullString
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(finding_id) FROM notify_notice_finding WHERE notice_id = ?`, id).Scan(&n, &first); err != nil {
		return "", fmt.Errorf("notify: read alert: %w", err)
	}
	if n > 0 {
		return "/findings/" + first.String, nil
	}
	var one int
	switch err := db.QueryRowContext(ctx, `SELECT 1 FROM notify_incident WHERE id = ?`, id).Scan(&one); {
	case err == nil:
		return "/incidents/" + id, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("notify: read alert: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT 1 FROM notify_notice WHERE id = ?`, id).Scan(&one); err == nil {
		return findingsList, nil // a notice that names no finding
	}
	return "", notFound("No such alert. It may have been removed from the log.")
}

// resendApproverProblem finds the approver the saved address belongs to on the channel (the list is the one saved now) and asks
// approverProblem about them. No longer on the list is a problem too. It returns why not, or "" when the approver is fine.
func (s *Service) resendApproverProblem(ctx context.Context, ch channel.Type, address string) (string, error) {
	var userID string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT user_id FROM notify_approver WHERE channel_type = ? AND lower(address) = lower(?)`, string(ch), address).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "the address is no longer on the approver list of this channel", nil
	}
	if err != nil {
		return "", fmt.Errorf("notify: find approver of a message: %w", err)
	}
	why, err := s.approverCheck(ctx, ch, Approver{UserID: userID, Address: address})
	if err != nil { // the directory or the link store did not answer: retry later, not "this approver does not qualify"
		return "", apierr.New(http.StatusServiceUnavailable, "approver_check_unavailable", "Vedette could not check the approver just now. Try again in a moment.").With("retry_after", 5)
	}
	return why, nil
}

// IncidentRef is the id and handling state of one incident.
type IncidentRef struct {
	ID     string
	Status IncidentStatus
}

// IncidentOf finds the incident a producer's event counted on: the newest incident of the kind, source and target (OpenIncident's
// dedupe key) opened at or before at, whatever its status now. The ids module links an alert to its intrusion incident with it.
// ok is false when there is none.
func (s *Service) IncidentOf(ctx context.Context, kind IncidentKind, source, target string, at time.Time) (IncidentRef, bool, error) {
	var r IncidentRef
	var status string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT id, status FROM notify_incident WHERE dedupe_key = ? AND first_seen <= ? ORDER BY first_seen DESC, id DESC LIMIT 1`,
		dedupeKey(IncidentInput{Kind: kind, Source: source, Target: target}), store.FormatTS(at)).Scan(&r.ID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return IncidentRef{}, false, nil
	}
	if err != nil {
		return IncidentRef{}, false, fmt.Errorf("notify: find incident: %w", err)
	}
	r.Status = IncidentStatus(status)
	return r, true, nil
}

// ResolvedSince says whether a producer must let a repeat through although it already announced the event's key at since: no
// incident the event would count on is open (OpenIncident would open a new one) and one of them was resolved, by a person or by
// Vedette, at or after since. A producer that holds back repeats of a key (the ids hourly announcement dedupe, the logs dedupe time
// of a bad connection or of failed logins, the honeypot hit window) asks it before holding one back: a repeat after the incident was
// resolved is a new incident and must reach notify (the producer's hourly budget still applies). False while an incident of the key is
// open (notify only counts the repeat), when none was resolved since the producer's announcement (the producer's budget held it, or
// notify was off), for an event that opens no incident, and while the module is off.
func (s *Service) ResolvedSince(ctx context.Context, event string, data any, since time.Time) (bool, error) {
	if !s.on() {
		return false, nil
	}
	in, ok, err := incidentOf(event, data)
	if err != nil || !ok {
		return false, err
	}
	first, key := mergeKeys(in)
	var n int
	// The open incident of a key is unique (notify_incident_open_uq): this reads the index.
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM notify_incident WHERE dedupe_key IN (?, ?) AND status <> 'resolved'`, first, key).Scan(&n); err != nil {
		return false, fmt.Errorf("notify: find an open incident: %w", err)
	}
	if n > 0 {
		return false, nil
	}
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT 1 FROM notify_incident WHERE status = 'resolved' AND dedupe_key IN (?, ?) AND handled_at >= ? LIMIT 1`,
		first, key, store.FormatTS(since)).Scan(&n)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("notify: find a resolved incident: %w", err)
	}
	return true, nil
}

// KindCount is how many incidents of a kind had activity in a window, and how many of them nobody acknowledged or resolved yet.
type KindCount struct {
	Kind       IncidentKind
	Incidents  int
	New        int
	LastSeenAt time.Time // the newest activity of the kind in the window; zero when none
}

// KindCounts counts the incidents of every kind with activity (last_seen) at or after since: the kinds of IncidentKinds in their order,
// then any other kind that has incidents. The kind is an open vocabulary.
func (s *Service) KindCounts(ctx context.Context, since time.Time) ([]KindCount, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT kind, count(*), sum(status = 'new'), max(last_seen) FROM notify_incident WHERE last_seen >= ? GROUP BY kind`, store.FormatTS(since))
	if err != nil {
		return nil, fmt.Errorf("notify: count incidents by kind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[IncidentKind]KindCount{}
	for rows.Next() {
		var k string
		var c KindCount
		var last string
		if err := rows.Scan(&k, &c.Incidents, &c.New, &last); err != nil {
			return nil, fmt.Errorf("notify: count incidents by kind: %w", err)
		}
		c.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		got[IncidentKind(k)] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: count incidents by kind: %w", err)
	}
	out := make([]KindCount, 0, len(IncidentKinds)+len(got))
	for _, k := range IncidentKinds {
		c := got[k]
		c.Kind = k
		out = append(out, c)
		delete(got, k)
	}
	for _, k := range slices.Sorted(maps.Keys(got)) { // a kind a producer added: after the documented ones
		c := got[k]
		c.Kind = k
		out = append(out, c)
	}
	return out, nil
}

// raiseIntrusion raises an open intrusion incident to the severity of a repeat (the attacker hit a device affected by the CVE: critical):
// the incident takes the repeat's title, description and devices, and one notice of the raise is queued (its own id, so a raise to each
// level is sent once and never mistaken for the first notice).
func (s *Service) raiseIntrusion(ctx context.Context, tx *sql.Tx, id string, in IncidentInput, at time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET severity = ?, title = ?, what = ?, action = ? WHERE id = ?`,
		string(in.Severity), strings.TrimSpace(in.Title), in.What, in.Action, id); err != nil {
		return fmt.Errorf("notify: raise an intrusion incident: %w", err)
	}
	names, ids := make([]string, 0, len(in.Devices)), make([]string, 0, len(in.Devices))
	for _, d := range in.Devices {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, id, d.ID, d.Name); err != nil {
			return fmt.Errorf("notify: save incident device: %w", err)
		}
		names, ids = append(names, d.Name), append(ids, d.ID)
	}
	return s.enqueue(ctx, tx, Notice{ID: raisedNoticeID(id, in.Severity), Kind: KindIncident, Severity: in.Severity, Title: strings.TrimSpace(in.Title),
		What: in.What, Action: in.Action, Devices: names, DeviceIDs: ids, IncidentKind: string(in.Kind), Link: s.link("/incidents/" + id), At: at})
}

// raisedNoticeID is the id of the notice of an incident raised to sev (raiseIntrusion). Incident ids are store ids (prefix-base32), so
// none contains "-raised-".
func raisedNoticeID(incidentID string, sev Severity) string {
	return incidentID + "-raised-" + string(sev)
}

// incidentOfNotice is the incident an incident notice belongs to: its own id, or the incident of a raise's notice.
func incidentOfNotice(noticeID string) string {
	id, _, _ := strings.Cut(noticeID, "-raised-")
	return id
}
