package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Delivery works through a queue (table notify_pending): Publish decides, per channel, whether a notice
// goes out now, waits for the grouping window or waits for quiet hours to end, and only queues it.
// Flush (the "deliver" job, every flushEvery) claims what is due in one transaction, sends it, and
// writes the SendRecord and removes the queue row in a second one. Nothing is sent from inside a
// request or an event handler, and a row is claimed before it is sent, so it is never sent twice.

const (
	flushEvery = 15 * time.Second
	// staleClaim is how long a claimed row may wait for its send to finish before Flush records it as interrupted.
	staleClaim   = 15 * time.Minute
	pruneEvery   = time.Hour
	suppressDays = 30 // notify_suppressed_day keeps this many days (DATA_MODEL 4.4)
	historyDays  = 7  // HistoryView.Suppressed counts this many days

	maxNoticeText  = 4000
	maxNoticeItems = 100
)

// validate checks PRE-1 and the size limits of a notice.
func (n Notice) validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidNotice, why) }
	if n.Kind != KindVuln && n.Kind != KindIncident {
		return bad("kind must be vuln or incident")
	}
	if !n.Severity.Valid() {
		return bad("unknown severity")
	}
	if n.Link == "" {
		return bad("link is required")
	}
	if len(n.CVEs) > maxNoticeItems || len(n.Devices) > maxNoticeItems || len(n.FindingIDs) > maxNoticeItems {
		return bad("too many CVEs, devices or findings")
	}
	for _, s := range append(append([]string{n.Title, n.What, n.Action, n.Product, n.Link}, n.CVEs...), append(n.Devices, n.FindingIDs...)...) {
		if utf8.RuneCountInString(s) > maxNoticeText {
			return bad("a text field is too long")
		}
	}
	return nil
}

// Publish queues a notice for every enabled channel that should receive it (PRE-1, POST-1). A
// vulnerability notice that matched no device is never sent: it only adds to the suppressed count
// (INV-2, FORBID-1). Delivery happens in Flush; each attempt there writes a SendRecord (INV-6).
func (s *Service) Publish(ctx context.Context, n Notice) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.enqueue(ctx, tx, n) })
}

func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, n Notice) error {
	if err := n.validate(); err != nil {
		return err
	}
	now := s.now()
	if n.ID == "" {
		n.ID = store.NewID("nt")
	}
	if n.At.IsZero() {
		n.At = now
	}
	if !n.Sendable() {
		return s.countSuppressed(ctx, tx, now)
	}
	if n.Kind == KindVuln {
		cves, err := json.Marshal(n.CVEs)
		if err != nil {
			return fmt.Errorf("notify: encode CVEs: %w", err)
		}
		r, err := tx.ExecContext(ctx, `INSERT INTO notify_notice (id, created_at, product, cves) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
			n.ID, store.FormatTS(n.At), n.Product, string(cves))
		if err != nil {
			return fmt.Errorf("notify: save notice: %w", err)
		}
		if c, _ := r.RowsAffected(); c == 0 {
			return nil // the same notice again (an event delivered twice): already queued or sent
		}
		for _, f := range n.FindingIDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notify_notice_finding (notice_id, finding_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, n.ID, f); err != nil {
				return fmt.Errorf("notify: save notice findings: %w", err)
			}
		}
	}
	rules, err := loadRules(ctx, tx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("notify: encode notice: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT type, min_severity FROM notify_channel WHERE configured = 1 AND enabled = 1`)
	if err != nil {
		return fmt.Errorf("notify: list channels: %w", err)
	}
	type target struct {
		t     channel.Type
		floor Severity
	}
	var targets []target
	for rows.Next() {
		var t, f string
		if err := rows.Scan(&t, &f); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: list channels: %w", err)
		}
		targets = append(targets, target{channel.Type(t), Severity(f)})
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: list channels: %w", err)
	}
	local := now.In(s.cfg.Location)
	for _, tg := range targets {
		verdict, release := Decide(local, tg.floor, rules.Quiet, n.Severity)
		reason, due := "now", now
		switch {
		case verdict == Skip:
			continue
		case verdict == Hold:
			reason, due = "quiet", release
		case rules.Grouping.Enabled && rules.Grouping.Validate() == nil && n.Kind == KindVuln && n.Severity != Critical && strings.TrimSpace(n.Product) != "":
			reason, due = "group", n.At.Add(time.Duration(rules.Grouping.WindowMin)*time.Minute)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_pending (id, channel, notice_id, notice, reason, due_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (channel, notice_id) DO NOTHING`, store.NewID("pq"), string(tg.t), n.ID, string(raw), reason, store.FormatTS(due), store.FormatTS(now)); err != nil {
			return fmt.Errorf("notify: queue notice: %w", err)
		}
	}
	return nil
}

func (s *Service) countSuppressed(ctx context.Context, tx *sql.Tx, now time.Time) error {
	day := now.In(s.cfg.Location).Format(time.DateOnly)
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_suppressed_day (day, count) VALUES (?, 1) ON CONFLICT (day) DO UPDATE SET count = count + 1`, day); err != nil {
		return fmt.Errorf("notify: count suppressed notice: %w", err)
	}
	return nil
}

// claim is one batch taken from the queue, ready to send.
type claim struct {
	channel channel.Type
	batch   Batch
	rows    []string // notify_pending ids
}

type pendingRow struct {
	id     string
	notice Notice
	reason string
}

// Flush delivers what is due: held notices when quiet hours have ended, grouped batches at their
// DueAt, everything else at once. It is the body of the "deliver" job. It never sends a row twice:
// rows are claimed in one transaction before they are sent.
func (s *Service) Flush(ctx context.Context) error {
	now := s.now()
	if err := s.sweepStale(ctx, now); err != nil {
		return err
	}
	claims, err := s.claim(ctx, now)
	if err != nil {
		return err
	}
	var errs []error
	for _, cl := range claims {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...) // the rest stays claimed: sweepStale records it as interrupted
		}
		if err := s.deliver(ctx, cl); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.prune(ctx, now); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *Service) claim(ctx context.Context, now time.Time) ([]claim, error) {
	var out []claim
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		out = nil
		rules, err := loadRules(ctx, tx)
		if err != nil {
			return err
		}
		quiet := rules.Quiet.Active(now.In(s.cfg.Location))
		rows, err := tx.QueryContext(ctx, `SELECT id, channel, notice, reason FROM notify_pending WHERE state = 'pending' ORDER BY channel, created_at, rowid`)
		if err != nil {
			return fmt.Errorf("notify: read queue: %w", err)
		}
		byChannel := map[channel.Type][]pendingRow{}
		var order []channel.Type
		var broken []string
		for rows.Next() {
			var id, ch, raw, reason string
			if err := rows.Scan(&id, &ch, &raw, &reason); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: read queue: %w", err)
			}
			var n Notice
			if json.Unmarshal([]byte(raw), &n) != nil {
				broken = append(broken, id) // cannot be rebuilt: drop it
				continue
			}
			t := channel.Type(ch)
			if _, ok := byChannel[t]; !ok {
				order = append(order, t)
			}
			byChannel[t] = append(byChannel[t], pendingRow{id, n, reason})
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: read queue: %w", err)
		}
		drop := broken
		for _, t := range order {
			list := byChannel[t]
			c, err := loadChannel(ctx, tx, t)
			if err != nil {
				return err
			}
			if !c.Configured || !c.Enabled { // turned off or removed since the notice was queued
				for _, r := range list {
					drop = append(drop, r.id)
				}
				continue
			}
			rowOf := map[string]string{}
			var nowN, heldN, grpN []Notice
			for _, r := range list {
				rowOf[r.notice.ID] = r.id
				switch r.reason {
				case "quiet":
					heldN = append(heldN, r.notice)
				case "group":
					grpN = append(grpN, r.notice)
				default:
					nowN = append(nowN, r.notice)
				}
			}
			seen := map[string]bool{}
			var release []Batch
			take := func(bs []Batch, due func(Batch) bool) {
				for _, b := range bs {
					for _, n := range b.Notices {
						seen[n.ID] = true
					}
					if due(b) {
						release = append(release, b)
					}
				}
			}
			always := func(Batch) bool { return true }
			take(Group(nowN, Grouping{}, c.MinSeverity), always)
			if quiet { // only what Decide let through (critical with allow_critical) goes during quiet hours
				take(GroupHeld(heldN, c.MinSeverity), func(Batch) bool { return false })
				take(Group(grpN, rules.Grouping, c.MinSeverity), func(Batch) bool { return false })
			} else {
				take(GroupHeld(heldN, c.MinSeverity), always)
				take(Group(grpN, rules.Grouping, c.MinSeverity), func(b Batch) bool { return !b.DueAt(rules.Grouping).After(now) })
			}
			for _, r := range list {
				if !seen[r.notice.ID] {
					drop = append(drop, r.id) // below the channel's minimum now: INV-4
				}
			}
			for _, b := range release {
				cl := claim{channel: t, batch: b}
				for _, n := range b.Notices {
					cl.rows = append(cl.rows, rowOf[n.ID])
				}
				for _, id := range cl.rows {
					if _, err := tx.ExecContext(ctx, `UPDATE notify_pending SET state = 'claimed', claimed_at = ? WHERE id = ? AND state = 'pending'`, store.FormatTS(now), id); err != nil {
						return fmt.Errorf("notify: claim: %w", err)
					}
				}
				out = append(out, cl)
			}
		}
		for _, id := range drop {
			if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE id = ?`, id); err != nil {
				return fmt.Errorf("notify: drop queued notice: %w", err)
			}
		}
		return nil
	})
	return out, err
}

// refOf is the (kind, ref_id, history link) of the first notice of a send.
func refOf(n Notice) (kind, ref, link string) {
	if n.Kind == KindIncident {
		return "incident", n.ID, "/incidents/" + n.ID
	}
	link = "/findings"
	if len(n.FindingIDs) > 0 {
		link += "/" + n.FindingIDs[0]
	}
	return "vuln", n.ID, link
}

// fallbackMessage is a single-notice message for a record of an attempt that never rendered one.
func fallbackMessage(n Notice) channel.Message {
	return channel.Message{ID: n.ID, Kind: n.Kind, Severity: string(n.Severity), Title: n.Title, Device: joinDevices(n.Devices), What: n.What, Action: n.Action, Link: n.Link}
}

func (s *Service) deliver(ctx context.Context, cl claim) error {
	first := cl.batch.Notices[0]
	msg, merr := cl.batch.Message()
	var rec SendRecord
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), cl.channel)
	var snd channel.Sender
	if err == nil {
		snd, err = s.savedSender(ctx, c, nil)
	}
	switch {
	case merr != nil:
		msg = fallbackMessage(first)
		rec = SendRecord{ID: store.NewID("sd"), Channel: cl.channel, To: string(cl.channel), At: s.now(), Error: "The message could not be built."}
	case err != nil:
		rec = SendRecord{ID: store.NewID("sd"), Channel: cl.channel, To: string(cl.channel), At: s.now(), Error: "The channel settings cannot be used: " + userText(err)}
	default:
		rec = Deliver(ctx, store.NewID("sd"), snd, msg, s.now)
	}
	kind, ref, link := refOf(first)
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := insertSend(ctx, tx, rec, kind, ref, msg.Title, link, msg); err != nil {
			return err
		}
		if kind == "vuln" {
			for _, n := range cl.batch.Notices {
				if _, err := tx.ExecContext(ctx, `INSERT INTO notify_send_notice (send_id, notice_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, rec.ID, n.ID); err != nil {
					return fmt.Errorf("notify: link send to notice: %w", err)
				}
			}
		}
		for _, id := range cl.rows {
			if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE id = ?`, id); err != nil {
				return fmt.Errorf("notify: finish queued notice: %w", err)
			}
		}
		name := "notify.message.sent"
		if !rec.OK {
			name = "notify.message.failed"
		}
		ob.Add(events.Event{Name: name, Data: map[string]string{"id": rec.ID, "channel": string(rec.Channel)}})
		return nil
	})
	if err != nil {
		return err
	}
	s.flush(ctx, ob)
	return nil
}

// insertSend writes one notify_send row. msg must not carry a secret or an approval token.
func insertSend(ctx context.Context, tx *sql.Tx, rec SendRecord, kind, ref, what, link string, msg channel.Message) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("notify: encode message: %w", err)
	}
	if len(raw) > 16000 {
		return fmt.Errorf("notify: message of %s is too large to keep", rec.ID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, error, what, link, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, kind, ref, string(rec.Channel), clip(rec.To, 600), store.FormatTS(rec.At), boolInt(rec.OK), nullable(clip(rec.Error, 1000)), clip(what, 400), clip(link, 400), string(raw)); err != nil {
		return fmt.Errorf("notify: save send record: %w", err)
	}
	return nil
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// sweepStale records rows that were claimed but never finished (the box stopped while sending) as failed
// attempts and removes them: a message may or may not have gone out, so it is not sent again; the person
// sees the failure in the history and can resend.
func (s *Service) sweepStale(ctx context.Context, now time.Time) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, channel, notice FROM notify_pending WHERE state = 'claimed' AND claimed_at < ?`, store.FormatTS(now.Add(-staleClaim)))
		if err != nil {
			return fmt.Errorf("notify: find interrupted sends: %w", err)
		}
		type stale struct {
			id, ch string
			n      Notice
		}
		var list []stale
		for rows.Next() {
			var st stale
			var raw string
			if err := rows.Scan(&st.id, &st.ch, &raw); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: find interrupted sends: %w", err)
			}
			if json.Unmarshal([]byte(raw), &st.n) == nil {
				list = append(list, st)
			} else {
				list = append(list, stale{id: st.id})
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: find interrupted sends: %w", err)
		}
		for _, st := range list {
			if st.n.ID != "" {
				kind, ref, link := refOf(st.n)
				rec := SendRecord{ID: store.NewID("sd"), Channel: channel.Type(st.ch), To: st.ch, At: now,
					Error: "The box stopped before this message was sent, so it was not sent again. Use Resend if it is still needed."}
				if err := insertSend(ctx, tx, rec, kind, ref, st.n.Title, link, fallbackMessage(st.n)); err != nil {
					return err
				}
				if kind == "vuln" {
					if _, err := tx.ExecContext(ctx, `INSERT INTO notify_send_notice (send_id, notice_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, rec.ID, st.n.ID); err != nil {
						return fmt.Errorf("notify: link send to notice: %w", err)
					}
				}
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE id = ?`, st.id); err != nil {
				return fmt.Errorf("notify: drop interrupted send: %w", err)
			}
		}
		return nil
	})
}

// prune forgets suppressed-count days older than suppressDays, at most once an hour.
func (s *Service) prune(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	due := now.Sub(s.lastPrune) >= pruneEvery
	if due {
		s.lastPrune = now
	}
	s.mu.Unlock()
	if !due {
		return nil
	}
	cut := now.In(s.cfg.Location).AddDate(0, 0, -suppressDays).Format(time.DateOnly)
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_suppressed_day WHERE day < ?`, cut); err != nil {
			return fmt.Errorf("notify: prune suppressed days: %w", err)
		}
		return nil
	})
}
