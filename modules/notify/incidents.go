package notify

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
		return bad("kind must be trap, bad_address, log_anomaly or unknown_device")
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
	}
	for _, d := range in.Devices {
		if d.ID == "" || len(d.ID) > 96 || strings.TrimSpace(d.Name) == "" || utf8.RuneCountInString(d.Name) > 253 {
			return bad("a device needs an id and a name")
		}
	}
	return nil
}

func dedupeKey(in IncidentInput) string {
	h := sha256.Sum256([]byte(string(in.Kind) + "\x00" + in.Source + "\x00" + in.Target))
	return hex.EncodeToString(h[:])
}

// OpenIncident records an incident (PRE-2, POST-2, INV-10). The same kind, source and target while
// the incident is not resolved only raises its count and last_seen; a new incident is queued for the
// channels and announced as notify.incident.created. Repeats are not sent again. It returns the
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
	key := dedupeKey(in)
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		ob = &events.Outbox{}
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM notify_incident WHERE dedupe_key = ? AND status <> 'resolved'`, key).Scan(&id); {
		case err == nil:
			created = false
			_, err = tx.ExecContext(ctx, `UPDATE notify_incident SET count = count + 1, last_seen = CASE WHEN ? > last_seen THEN ? ELSE last_seen END WHERE id = ?`, ts, ts, id)
			if err != nil {
				return fmt.Errorf("notify: count repeated incident: %w", err)
			}
			return nil
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("notify: find incident: %w", err)
		}
		created, id = true, store.NewID("in")
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_incident (id, kind, title, link, severity, what, action, first_seen, last_seen, dedupe_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, string(in.Kind), strings.TrimSpace(in.Title), in.Link, string(in.Severity), in.What, in.Action, ts, ts, key); err != nil {
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
		if err := s.enqueue(ctx, tx, Notice{ID: id, Kind: KindIncident, Severity: in.Severity, Title: strings.TrimSpace(in.Title), What: in.What, Action: in.Action,
			Devices: names, DeviceIDs: ids, IncidentKind: string(in.Kind), Link: s.link("/incidents/" + id), At: at}); err != nil {
			return err
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
		if err := rows.Scan(&v.ID, &ch, &v.To, &v.At, &v.OK, &e); err != nil {
			return nil, fmt.Errorf("notify: read sends: %w", err)
		}
		v.Channel, v.Error = channel.Type(ch), e.String
		out = append(out, v)
	}
	return out, rows.Err()
}

const incidentCols = `id, kind, title, link, severity, what, action, first_seen, last_seen, count, status, handled_by, handled_at, note`

func scanIncident(r scanner) (Incident, error) {
	var i Incident
	var kind, sev, status string
	var by, at, note sql.NullString
	if err := r.Scan(&i.ID, &kind, &i.Title, &i.Link, &sev, &i.What, &i.Action, &i.FirstSeen, &i.LastSeen, &i.Count, &status, &by, &at, &note); err != nil {
		return i, err
	}
	i.Kind, i.Severity, i.Status = IncidentKind(kind), Severity(sev), IncidentStatus(status)
	i.HandledBy, i.HandledAt, i.Note = ptr(by.String), ptr(at.String), ptr(note.String)
	i.Devices, i.Sends = []Device{}, []SendView{}
	return i, nil
}

// fillIncident adds the devices and the delivery log.
func fillIncident(ctx context.Context, q dbtx, i *Incident) error {
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
	srows, err := q.QueryContext(ctx, `SELECT id, channel, "to", at, ok, error FROM notify_send WHERE kind = 'incident' AND ref_id = ? ORDER BY at, rowid`, i.ID)
	if err != nil {
		return fmt.Errorf("notify: read incident sends: %w", err)
	}
	i.Sends, err = scanSends(srows)
	return err
}

// Incidents lists every incident, most recently seen first (GET /notify/incidents).
func (s *Service) Incidents(ctx context.Context) ([]Incident, error) {
	db := s.cfg.DB.Reader()
	rows, err := db.QueryContext(ctx, `SELECT `+incidentCols+` FROM notify_incident ORDER BY last_seen DESC, rowid DESC LIMIT ?`, incidentsLimit)
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
	const page = `(SELECT id FROM notify_incident ORDER BY last_seen DESC, rowid DESC LIMIT ?)`
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
	srows, err := db.QueryContext(ctx, `SELECT ref_id, id, channel, "to", at, ok, error FROM notify_send WHERE kind = 'incident' AND ref_id IN `+page+` ORDER BY at, rowid`, incidentsLimit)
	if err != nil {
		return nil, fmt.Errorf("notify: read incident sends: %w", err)
	}
	for srows.Next() {
		var ref, ch string
		var v SendView
		var e sql.NullString
		if err := srows.Scan(&ref, &v.ID, &ch, &v.To, &v.At, &v.OK, &e); err != nil {
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
	return out, nil
}

// incidentsLimit is the most incidents GET /notify/incidents returns, newest seen first (the page of an
// unbounded list would grow with every trap hit).
const incidentsLimit = 500

// IncidentDetail returns one incident with what each channel received (GET /notify/incidents/{id}).
func (s *Service) IncidentDetail(ctx context.Context, id string) (IncidentDetail, error) {
	return s.incidentDetail(ctx, s.cfg.DB.Reader(), id)
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
// Reopening (status new) clears who handled it and the note.
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
		var by, at, nt any
		if status != StatusNew {
			by, at, nt = actor, store.FormatTS(s.now()), nullable(note)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = ?, handled_by = ?, handled_at = ?, note = ? WHERE id = ?`, string(status), by, at, nt, id); err != nil {
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
	return d, err
}

// ---- history ----

// History lists every message sent, newest first, and how many new vulnerabilities matched no device
// recently (GET /notify/history). It returns at most historyLimit rows.
func (s *Service) History(ctx context.Context) (HistoryView, error) {
	db := s.cfg.DB.Reader()
	v := HistoryView{Items: []HistoryItem{}}
	rows, err := db.QueryContext(ctx, `SELECT id, channel, "to", at, ok, error, kind, what, link FROM notify_send ORDER BY at DESC, rowid DESC LIMIT ?`, historyLimit)
	if err != nil {
		return v, fmt.Errorf("notify: read history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var h HistoryItem
		var ch string
		var e sql.NullString
		if err := rows.Scan(&h.ID, &ch, &h.To, &h.At, &h.OK, &e, &h.Kind, &h.What, &h.Link); err != nil {
			return v, fmt.Errorf("notify: read history: %w", err)
		}
		h.Channel, h.Error = channel.Type(ch), e.String
		v.Items = append(v.Items, h)
	}
	if err := rows.Err(); err != nil {
		return v, fmt.Errorf("notify: read history: %w", err)
	}
	from := store.FormatTS(s.now().AddDate(0, 0, -historyDays))
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_kev WHERE matched = 0 AND seen_at >= ?`, from).Scan(&v.Suppressed.Count); err != nil {
		return v, fmt.Errorf("notify: read suppressed count: %w", err)
	}
	v.Suppressed.Days = historyDays
	return v, nil
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
		Kind: old.kind, What: old.what, Link: old.link}, nil
}

// FindingNotices lists who was told about a finding, oldest first (GET /notify/findings/{id}/notices).
func (s *Service) FindingNotices(ctx context.Context, findingID string) ([]SendView, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT s.id, s.channel, s."to", s.at, s.ok, s.error FROM notify_send s
		WHERE s.id IN (SELECT sn.send_id FROM notify_send_notice sn JOIN notify_notice_finding nf ON nf.notice_id = sn.notice_id WHERE nf.finding_id = ?)
		ORDER BY s.at, s.rowid`, findingID)
	if err != nil {
		return nil, fmt.Errorf("notify: read finding notices: %w", err)
	}
	return scanSends(rows)
}

// AlertTarget says where an old alert id leads now: the finding or the incident it became (D-52).
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
		return "/findings", nil // a notice that names no finding
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
	return s.approverProblem(ctx, ch, Approver{UserID: userID, Address: address}), nil
}
