package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// A trap session is every hit of one source address, on any trap service or honey token of the box, with no quiet longer than
// trapSession between two hits. It is one incident: a person or malware that reaches the decoy scans it, tries a login and opens
// the files within a minute or two, and the owner needs one alert for that, not one per touch. Ten minutes of quiet ends it (a
// later visit is told again); a resolved incident ends it too (INV-10: a hit after it opens a new incident).
const (
	trapSession       = 10 * time.Minute
	trapSessionTarget = "session"
	// maxSessionHits is the most hits of a session read to tell it; the timeline names the first ones and counts the rest.
	maxSessionHits = 500
)

// tellSession makes the incident a hit joined say what the whole session did: the title sums it up ("192.0.2.7 touched the decoy:
// opened 3 decoy files, tried the bait account Old admin, touched SSH and SMB") and `what` lists every hit in time order. A hit
// that raised the incident (a touch after a scan) sends one more alert with those words. The hit's device joins the incident.
// Without the honeypot's hits (no port, an error, an empty answer) the incident keeps its words, or takes the raising hit's.
func (s *Service) tellSession(ctx context.Context, r opened, in IncidentInput) error {
	title, what := "", ""
	if s.cfg.Sessions != nil {
		from, _ := time.Parse(time.RFC3339Nano, r.firstSeen)
		to := s.now()
		if in.At.After(to) { // a hit stamped by a clock ahead of the box's
			to = in.At
		}
		hits, err := s.cfg.Sessions.SourceHits(ctx, in.Source, from, to)
		switch {
		case err != nil:
			s.cfg.Log.WarnContext(ctx, "notify: the hits of a trap session are not available, the incident keeps its words", "error", err)
		case len(hits) > 1:
			title, what = sessionWords(in.Source, hits, s.loc(ctx))
		}
	}
	if title == "" && r.raisedFrom != "" {
		title, what = strings.TrimSpace(in.Title), in.What
	}
	if title == "" && len(in.Devices) == 0 {
		return nil
	}
	at := in.At
	if at.IsZero() {
		at = s.now()
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var status string
		switch err := tx.QueryRowContext(ctx, `SELECT status FROM notify_incident WHERE id = ?`, r.id).Scan(&status); {
		case errors.Is(err, sql.ErrNoRows):
			return nil // removed since (retention)
		case err != nil:
			return fmt.Errorf("notify: read a trap session: %w", err)
		}
		if status == string(StatusResolved) {
			return nil // closed in the meantime: it keeps the words it was closed with
		}
		if title != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ?, what = ? WHERE id = ?`, title, what, r.id); err != nil {
				return fmt.Errorf("notify: tell a trap session: %w", err)
			}
		}
		for _, d := range in.Devices {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, r.id, d.ID, d.Name); err != nil {
				return fmt.Errorf("notify: save incident device: %w", err)
			}
		}
		if r.raisedFrom == "" {
			return nil
		}
		var names, ids []string
		rows, err := tx.QueryContext(ctx, `SELECT asset_id, name FROM notify_incident_device WHERE incident_id = ? ORDER BY rowid`, r.id)
		if err != nil {
			return fmt.Errorf("notify: read incident devices: %w", err)
		}
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: read incident devices: %w", err)
			}
			names, ids = append(names, name), append(ids, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: read incident devices: %w", err)
		}
		return s.enqueue(ctx, tx, Notice{ID: raisedNoticeID(r.id, in.Severity), Kind: KindIncident, Severity: in.Severity, Title: title, What: what,
			Action: in.Action, Devices: names, DeviceIDs: ids, IncidentKind: string(IncidentTrap), Link: s.link("/incidents/" + r.id), At: at})
	})
}

// sessionWords is the title and the description of a trap session of src: what it did, grouped (files, links, bait accounts, other
// tokens, trap services, a scan), then each hit with its box time. Labels are the honeypot's ("File token Payroll", "SSH").
func sessionWords(src string, hits []SessionHit, loc *time.Location) (title, what string) {
	var files, links, accounts, tokens, services []string
	scanned := false
	add := func(list *[]string, name string) {
		for _, x := range *list {
			if x == name {
				return
			}
		}
		*list = append(*list, name)
	}
	lines := make([]string, 0, len(hits))
	for _, h := range hits {
		label := strings.TrimSpace(h.Label)
		switch {
		case h.Kind == "scan":
			scanned = true
		case h.Kind == "token" && strings.HasPrefix(label, "File token "):
			add(&files, strings.TrimPrefix(label, "File token "))
		case h.Kind == "token" && strings.HasPrefix(label, "URL token "):
			add(&links, strings.TrimPrefix(label, "URL token "))
		case h.Kind == "token" && strings.HasPrefix(label, "Credential token "):
			add(&accounts, strings.TrimPrefix(label, "Credential token "))
		case h.Kind == "token":
			add(&tokens, label)
		default:
			add(&services, label)
		}
		lines = append(lines, h.At.In(loc).Format("15:04:05")+" "+hitWords(h.Kind, label))
	}
	var parts []string
	some := func(list []string, one, many string) {
		switch len(list) {
		case 0:
		case 1:
			parts = append(parts, one+" "+list[0])
		default:
			parts = append(parts, fmt.Sprintf(many, len(list)))
		}
	}
	some(files, "opened the decoy file", "opened %d decoy files")
	some(links, "opened the decoy link", "opened %d decoy links")
	some(accounts, "tried the bait account", "tried %d bait accounts")
	some(tokens, "used the", "used %d honey tokens")
	if len(services) > 0 {
		parts = append(parts, "touched "+andList(services))
	}
	if scanned {
		parts = append(parts, "scanned the Trap IPs")
	}
	title = clip(src+" touched the decoy: "+strings.Join(parts, ", "), 200)
	first, last := hits[0].At.In(loc), hits[len(hits)-1].At.In(loc)
	head := fmt.Sprintf("%s touched the decoy %s between %s and %s (box time). Nobody has a reason to touch it, so a machine there is infected or someone is exploring the network.",
		src, plural(len(hits), "time", "times"), first.Format("15:04:05"), last.Format("15:04:05"))
	if len(hits) == maxSessionHits {
		head = fmt.Sprintf("%s touched the decoy at least %d times from %s (box time). Nobody has a reason to touch it, so a machine there is infected or someone is exploring the network.",
			src, len(hits), first.Format("15:04:05"))
	}
	what = head + "\n"
	budget := maxIncidentText - utf8.RuneCountInString("\n… and 500 more")
	for k, l := range lines {
		if utf8.RuneCountInString(what)+1+utf8.RuneCountInString(l) > budget {
			what += fmt.Sprintf("\n… and %d more", len(lines)-k)
			break
		}
		what += "\n" + l
	}
	return title, what
}

// hitWords is one hit of a session timeline: "opened the File token Payroll", "touched the SSH trap", "scanned the Trap IPs".
func hitWords(kind, label string) string {
	switch {
	case kind == "scan":
		return "scanned the Trap IPs"
	case kind == "token" && (strings.HasPrefix(label, "URL token ") || strings.HasPrefix(label, "File token ")):
		return "opened the " + label
	case kind == "token":
		return "used the " + label
	}
	return "touched the " + label + " trap"
}

// andList is "a", "a and b", "a, b and c".
func andList(xs []string) string {
	if len(xs) < 2 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
