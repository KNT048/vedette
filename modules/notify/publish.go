package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
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
// request or an event handler.
//
// Semantics of a send that is interrupted (the run is cancelled, the box stops):
//   - a row that was claimed but never attempted goes back to pending and is sent later: alerts are
//     at-least-once;
//   - a row whose send had started but was not recorded is not sent again: it is recorded as "may or may
//     not have been sent" so the person can resend it;
//   - the record of an attempt that finished is written even when the run was cancelled meanwhile (the
//     write ignores the cancellation, with a short deadline of its own), so every attempt has a record (INV-6).
//
// Approval messages with a link are sent straight from SendApprovalRequest and are at-most-once.

const (
	flushEvery = 15 * time.Second
	// staleClaim is how long a claimed or sending row may wait for its run before Flush treats the run as dead.
	staleClaim  = 15 * time.Minute
	pruneEvery  = time.Hour
	kevKeepDays = 30 // notify_kev keeps this many days
	historyDays = 7  // HistoryView.Suppressed counts this many days
	// maxBatchesPerRun is the most messages one channel sends in one run: a flood on one channel cannot hold
	// a run for ever, and what is left waits for the next run (critical first, so a critical notice is never
	// behind a long backlog).
	maxBatchesPerRun = 20

	maxNoticeText  = 4000
	maxNoticeItems = 100

	interruptedText = "The box was interrupted while this message was being sent, so it may or may not have been sent. It was not sent again. Use Resend if it is still needed."

	// A provider that answers "too many requests" (HTTP 429, Zalo -32) is waited for, not given up on (D-483): the message goes back to
	// the queue, due when the provider said, and the channel sends nothing else until then. defaultRateWait is the wait when the provider
	// named none; after maxRateTries refusals in a row the message is recorded as failed, so a provider that never lets go cannot hold
	// the queue for ever.
	defaultRateWait = time.Minute
	maxRateTries    = 5
)

// errRateLimited stops a channel's run after its provider asked to slow down; the rest of the run's messages go back to the queue.
var errRateLimited = errors.New("notify: the channel is rate limited")

// validate checks PRE-1 and the size limits of a notice. A notice may have no link: that is how it is when the
// box address is not configured, and the adapters then say to open Vedette.
func (n Notice) validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidNotice, why) }
	if n.Kind != KindVuln && n.Kind != KindIncident {
		return bad("kind must be vuln or incident")
	}
	if !n.Severity.Valid() {
		return bad("unknown severity")
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
// vulnerability notice that matched no device is never sent: its CVEs only add to the suppressed count
// (INV-2, FORBID-1). Delivery happens in Flush; each attempt there writes a SendRecord (INV-6). While the
// module is off nothing is queued and ErrModuleOff is returned.
func (s *Service) Publish(ctx context.Context, n Notice) error {
	if !s.on() {
		return ErrModuleOff
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.enqueue(ctx, tx, n) })
}

// kevKey is the key of a CVE in notify_kev: upper case, so the same CVE spelled two ways is one row.
func kevKey(cve string) string {
	return clip(strings.ToUpper(strings.TrimSpace(cve)), 128)
}

// markKEV records exploited vulnerabilities in notify_kev. matched=false only adds a CVE that is not known yet;
// matched=true also marks a known one as matched by a device, which takes it out of the suppressed count.
func markKEV(ctx context.Context, tx *sql.Tx, keys []string, at time.Time, matched bool) error {
	for _, k := range keys {
		if k = kevKey(k); k == "" {
			continue
		}
		q := `INSERT INTO notify_kev (cve, seen_at, matched) VALUES (?, ?, ?) ON CONFLICT (cve) DO NOTHING`
		if matched {
			q = `INSERT INTO notify_kev (cve, seen_at, matched) VALUES (?, ?, ?) ON CONFLICT (cve) DO UPDATE SET matched = 1`
		}
		if _, err := tx.ExecContext(ctx, q, k, store.FormatTS(at), boolInt(matched)); err != nil {
			return fmt.Errorf("notify: record exploited vulnerability: %w", err)
		}
	}
	return nil
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
		keys := slices.Clone(n.CVEs)
		if len(keys) == 0 {
			keys = []string{"notice:" + n.ID} // a notice that names no CVE still counts once
		}
		return markKEV(ctx, tx, keys, now, false)
	}
	if n.Kind == KindVuln {
		if err := markKEV(ctx, tx, n.CVEs, now, true); err != nil {
			return err
		}
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
	rows, err := tx.QueryContext(ctx, `SELECT type, min_severity, enabled FROM notify_channel WHERE configured = 1`)
	if err != nil {
		return fmt.Errorf("notify: list channels: %w", err)
	}
	type target struct {
		t     channel.Type
		floor Severity
	}
	var targets []target
	configured := 0
	for rows.Next() {
		var t, f string
		var on bool
		if err := rows.Scan(&t, &f, &on); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: list channels: %w", err)
		}
		if configured++; on {
			targets = append(targets, target{channel.Type(t), Severity(f)})
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: list channels: %w", err)
	}
	// The decision for an incident is kept on it (INV-24): the Incidents page says why it went nowhere from the same verdicts.
	unsent, floor, lowest := UnsentNoChannel, Severity(""), channel.Type("")
	if configured > 0 {
		unsent = UnsentChannelsOff
	}
	local := now.In(s.loc(ctx))
	for _, tg := range targets {
		verdict, release := Decide(local, tg.floor, rules.Quiet, n.Severity)
		reason, due := "now", now
		switch {
		case verdict == Skip:
			if unsent == UnsentNoChannel || unsent == UnsentChannelsOff || (unsent == UnsentBelowMin && tg.floor.rank() < floor.rank()) {
				unsent, floor, lowest = UnsentBelowMin, tg.floor, tg.t
			}
			continue
		case verdict == Hold:
			reason, due = "quiet", release
			if unsent != UnsentQueued {
				unsent, floor, lowest = UnsentQuietHours, "", ""
			}
		case rules.Grouping.Enabled && rules.Grouping.Validate() == nil && n.Kind == KindVuln && n.Severity != Critical && strings.TrimSpace(n.Product) != "":
			reason, due = "group", n.At.Add(time.Duration(rules.Grouping.WindowMin)*time.Minute)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_pending (id, channel, notice_id, notice, reason, due_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (channel, notice_id) DO NOTHING`, store.NewID("pq"), string(tg.t), n.ID, string(raw), reason, store.FormatTS(due), store.FormatTS(now)); err != nil {
			return fmt.Errorf("notify: queue notice: %w", err)
		}
		if reason == "now" {
			unsent, floor, lowest = UnsentQueued, "", ""
		}
	}
	if n.Kind == KindIncident {
		return markUnsent(ctx, tx, n.ID, unsent, floor, lowest)
	}
	return nil
}

// markUnsent keeps why an incident went to no channel, or that one took it (INV-24); ch is the channel to fix, if one. An id that is no
// incident (a test notice) changes nothing.
func markUnsent(ctx context.Context, tx *sql.Tx, id string, why NotSentReason, floor Severity, ch channel.Type) error {
	if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET unsent = ?, unsent_floor = ?, unsent_channel = ? WHERE id = ?`,
		string(why), nullable(string(floor)), nullable(string(ch)), id); err != nil {
		return fmt.Errorf("notify: keep why an incident was not sent: %w", err)
	}
	return nil
}

// claim is one batch taken from the queue, ready to send.
type claim struct {
	channel  channel.Type
	batch    Batch
	rows     []string // notify_pending ids
	attempts int      // the most rate-limit refusals any of its rows had (D-483)
}

type pendingRow struct {
	id       string
	notice   Notice
	reason   string
	due      string
	attempts int
}

// Flush delivers what is due: held notices when quiet hours have ended, grouped batches at their
// DueAt, everything else at once. It is the body of the "deliver" job. Rows are claimed in one transaction
// before anything is sent, so a notice is never sent twice by two runs. Each channel is served by its own
// goroutine that Flush waits for, so a slow or dead channel does not hold up the others; within a channel
// critical notices go first and at most maxBatchesPerRun messages are sent per run.
func (s *Service) Flush(ctx context.Context) error {
	now := s.now()
	s.sealLegacyURL(ctx)
	if s.reenabled.CompareAndSwap(true, false) {
		if err := s.dropStale(ctx, now); err != nil {
			s.reenabled.Store(true) // try again at the next run
			return err
		}
	}
	if err := s.sweepStale(ctx, now); err != nil {
		return err
	}
	claims, err := s.claim(ctx, now)
	if err != nil {
		return err
	}
	byChannel := map[channel.Type][]claim{}
	var order []channel.Type
	for _, cl := range claims {
		if _, ok := byChannel[cl.channel]; !ok {
			order = append(order, cl.channel)
		}
		byChannel[cl.channel] = append(byChannel[cl.channel], cl)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	fail := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	for _, t := range order {
		list := byChannel[t]
		wg.Add(1)
		go func() { // one per channel type: at most six, all finished before Flush returns
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					fail(fmt.Errorf("notify: delivery on %s stopped: %v", t, p)) // its claimed rows come back through sweepStale
				}
			}()
			for i, cl := range list {
				if ctx.Err() != nil {
					s.release(ctx, list[i:]) // never attempted: the next run sends them
					return
				}
				if err := s.deliver(ctx, cl); errors.Is(err, errRateLimited) {
					s.release(ctx, list[i+1:]) // not attempted: they wait for the provider like the one it refused
					return
				} else if err != nil {
					fail(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return errors.Join(append(errs, err)...)
	}
	if err := s.clearButtons(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := s.clearSlackButtons(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := s.prune(ctx, now); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// staleAfter is how old a queued notice may be when the module is turned on again (D-86 (7)): a notice that waited
// days in the queue is noise, the finding is still in the interface.
const staleAfter = 24 * time.Hour

// dropStale deletes the waiting rows queued more than staleAfter ago, measured from created_at, and audits the
// count in the same transaction. Rows being sent are left to their run. Nothing is audited when nothing is old.
func (s *Service) dropStale(ctx context.Context, now time.Time) error {
	cut := store.FormatTS(now.Add(-staleAfter))
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET unsent = ?, unsent_floor = NULL, unsent_channel = NULL WHERE id IN (SELECT notice_id FROM notify_pending WHERE state = 'pending' AND created_at < ?)`,
			string(UnsentDroppedStale), cut); err != nil {
			return fmt.Errorf("notify: keep why incidents were not sent: %w", err)
		}
		r, err := tx.ExecContext(ctx, `DELETE FROM notify_pending WHERE state = 'pending' AND created_at < ?`, cut)
		if err != nil {
			return fmt.Errorf("notify: drop stale queued notices: %w", err)
		}
		n, _ := r.RowsAffected()
		if n == 0 {
			return nil
		}
		return s.record(ctx, tx, systemUser, "notify.stale_dropped", "notify_pending", fmt.Sprintf("%d queued notice(s) older than 24 h dropped when the module was turned on", n))
	})
}

// release puts claimed rows that were never attempted back to pending.
func (s *Service) release(ctx context.Context, list []claim) {
	wctx, stop := detached(ctx)
	defer stop()
	err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		for _, cl := range list {
			for _, id := range cl.rows {
				if _, err := tx.ExecContext(wctx, `UPDATE notify_pending SET state = 'pending', claimed_at = NULL WHERE id = ? AND state = 'claimed'`, id); err != nil {
					return fmt.Errorf("notify: return unsent notice to the queue: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "notify: could not return claimed notices to the queue; they return after the stale-claim wait", "error", err.Error())
	}
}

// markSending marks the rows of a claim as being sent, just before the network call. After this a crash is
// recorded as "may or may not have been sent" instead of being retried.
func (s *Service) markSending(ctx context.Context, cl claim, now time.Time) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, id := range cl.rows {
			r, err := tx.ExecContext(ctx, `UPDATE notify_pending SET state = 'sending', claimed_at = ? WHERE id = ? AND state = 'claimed'`, store.FormatTS(now), id)
			if err != nil {
				return fmt.Errorf("notify: mark notice as sending: %w", err)
			}
			if n, _ := r.RowsAffected(); n != 1 {
				return errors.New("notify: a claimed notice was taken away")
			}
		}
		return nil
	})
}

func (s *Service) claim(ctx context.Context, now time.Time) ([]claim, error) {
	var out []claim
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		out = nil
		rules, err := loadRules(ctx, tx)
		if err != nil {
			return err
		}
		quiet := rules.Quiet.Active(now.In(s.loc(ctx)))
		rows, err := tx.QueryContext(ctx, `SELECT id, channel, notice, reason, due_at, attempts FROM notify_pending WHERE state = 'pending' ORDER BY channel, created_at, rowid`)
		if err != nil {
			return fmt.Errorf("notify: read queue: %w", err)
		}
		byChannel := map[channel.Type][]pendingRow{}
		var order []channel.Type
		var broken []string
		for rows.Next() {
			var id, ch, raw, reason, due string
			var attempts int
			if err := rows.Scan(&id, &ch, &raw, &reason, &due, &attempts); err != nil {
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
			byChannel[t] = append(byChannel[t], pendingRow{id, n, reason, due, attempts})
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
				why := UnsentChannelOff // this channel only: the others were judged when the incident was queued
				if !c.Configured {
					why = UnsentChannelGone
				}
				for _, r := range list {
					drop = append(drop, r.id)
					if r.notice.Kind == KindIncident {
						if err := markUnsent(ctx, tx, r.notice.ID, why, "", t); err != nil {
							return err
						}
					}
				}
				continue
			}
			nowTS := store.FormatTS(now)
			held := false // a message the provider refused waits until its due_at, and the whole channel with it (D-483; lasts a restart)
			for _, r := range list {
				held = held || (r.attempts > 0 && r.due > nowTS)
			}
			if held {
				continue
			}
			rowOf, triesOf := map[string]string{}, map[string]int{}
			seen := map[string]bool{}
			var nowN, heldN, grpN []Notice
			for _, r := range list {
				rowOf[r.notice.ID], triesOf[r.notice.ID] = r.id, r.attempts
				switch {
				case r.reason == "quiet":
					heldN = append(heldN, r.notice)
				case r.reason == "group":
					grpN = append(grpN, r.notice)
				case r.due > nowTS: // put back after a rate limit, due when the provider said
					seen[r.notice.ID] = true
				default:
					nowN = append(nowN, r.notice)
				}
			}
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
					if r.notice.Kind == KindIncident {
						if err := markUnsent(ctx, tx, r.notice.ID, UnsentBelowMin, c.MinSeverity, t); err != nil {
							return err
						}
					}
				}
			}
			// A message the provider already refused stays its own digest with its own refusal count; new notices do not join it.
			var fresh, retried []Batch
			for _, b := range release {
				if slices.ContainsFunc(b.Notices, func(n Notice) bool { return triesOf[n.ID] > 0 }) {
					retried = append(retried, b)
				} else {
					fresh = append(fresh, b)
				}
			}
			release = append(digest(retried, s.link("/findings")), digest(fresh, s.link("/findings"))...)
			// Critical first, then the order they were queued in; what does not fit in this run stays pending.
			sort.SliceStable(release, func(i, j int) bool {
				return release[i].Severity() == Critical && release[j].Severity() != Critical
			})
			if len(release) > maxBatchesPerRun {
				release = release[:maxBatchesPerRun]
			}
			for _, b := range release {
				cl := claim{channel: t, batch: b}
				for _, n := range b.Notices {
					cl.rows = append(cl.rows, rowOf[n.ID])
					cl.attempts = max(cl.attempts, triesOf[n.ID])
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
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), cl.channel)
	var snd channel.Sender
	if err == nil && merr == nil {
		snd, err = s.savedSender(ctx, c, nil)
	}
	if err != nil && ctx.Err() != nil { // not attempted because the run ended, not because the settings are bad
		s.release(ctx, []claim{cl})
		return ctx.Err()
	}
	var rec SendRecord
	switch {
	case merr != nil:
		msg = fallbackMessage(first)
		rec = SendRecord{ID: store.NewID("sd"), Channel: cl.channel, To: string(cl.channel), At: s.now(), Error: "The message could not be built."}
	case err != nil:
		rec = SendRecord{ID: store.NewID("sd"), Channel: cl.channel, To: string(cl.channel), At: s.now(), Error: "The channel settings cannot be used: " + userText(err)}
	default:
		if err := s.markSending(ctx, cl, s.now()); err != nil {
			s.release(ctx, []claim{cl})
			return err
		}
		rec = Deliver(ctx, store.NewID("sd"), snd, msg, s.now)
		if !rec.OK && ctx.Err() != nil {
			rec.Error = interruptedText // the answer was cut off: the message may have gone out
		}
		if rec.Limited && ctx.Err() == nil {
			if cl.attempts+1 < maxRateTries {
				return s.delay(ctx, cl, rec, msg)
			}
			rec.Error = fmt.Sprintf("%s kept asking Vedette to send more slowly, so this message was not sent after %d tries. Use Resend.", channelName[cl.channel], maxRateTries)
		}
	}
	kind, ref, link := refOf(first)
	wctx, stop := detached(ctx) // the attempt is over: its record is written even if the run was cancelled
	defer stop()
	ob := &events.Outbox{}
	err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		ob = &events.Outbox{}
		if err := insertSend(wctx, tx, rec, kind, ref, msg.Title, link, "", msg); err != nil {
			return err
		}
		if kind == "vuln" {
			told := cl.batch.Listed() // a failure: the findings it would have named, so their page says "Not delivered"
			if rec.OK {
				told = cl.batch.Told(cl.channel, msg) // only the lines the channel sent whole: "Notified" must be true (W1-11)
			}
			for _, n := range told {
				if _, err := tx.ExecContext(wctx, `INSERT INTO notify_send_notice (send_id, notice_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, rec.ID, n.ID); err != nil {
					return fmt.Errorf("notify: link send to notice: %w", err)
				}
			}
		}
		for _, id := range cl.rows {
			if _, err := tx.ExecContext(wctx, `DELETE FROM notify_pending WHERE id = ?`, id); err != nil {
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
	s.flush(wctx, ob)
	return nil
}

// delay handles a send the provider refused with "too many requests" (D-483): the rows go back to the queue due when the provider
// said (defaultRateWait when it did not), which holds the whole channel until then (claim), and the first time a message is held back the
// history gets one "Delayed (rate limited)" row, not linked to the findings (nothing reached anyone yet). It returns errRateLimited.
func (s *Service) delay(ctx context.Context, cl claim, rec SendRecord, msg channel.Message) error {
	wait := rec.RetryAfter
	if wait <= 0 {
		wait = defaultRateWait
	}
	until := s.now().Add(wait) // the refused rows are due then, and they hold the channel's queue until then (claim): it lasts a restart
	kind, ref, link := refOf(cl.batch.Notices[0])
	rec.Delayed, rec.Error = true, fmt.Sprintf("Delayed (rate limited): %s asked Vedette to wait %s. It is sent again by itself after %s.",
		channelName[cl.channel], wait.Round(time.Second), until.In(s.loc(ctx)).Format("15:04"))
	wctx, stop := detached(ctx)
	defer stop()
	err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		if cl.attempts == 0 {
			if err := insertSend(wctx, tx, rec, kind, ref, msg.Title, link, "", msg); err != nil {
				return err
			}
		}
		for _, id := range cl.rows { // reason "now": due_at is kept to, whatever window it waited for before
			if _, err := tx.ExecContext(wctx, `UPDATE notify_pending SET state = 'pending', claimed_at = NULL, reason = 'now', due_at = ?, attempts = attempts + 1 WHERE id = ?`,
				store.FormatTS(until), id); err != nil {
				return fmt.Errorf("notify: put a rate-limited notice back: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return errRateLimited
}

// insertSend writes one notify_send row. msg must not carry a secret or an approval token. recipient is the one
// person the message went to (an approver's address), or "" when it went to the channel's own destination.
func insertSend(ctx context.Context, tx *sql.Tx, rec SendRecord, kind, ref, what, link, recipient string, msg channel.Message) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("notify: encode message: %w", err)
	}
	if len(raw) > 16000 {
		return fmt.Errorf("notify: message of %s is too large to keep", rec.ID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, error, what, link, message, recipient, delayed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, kind, ref, string(rec.Channel), clip(rec.To, 600), store.FormatTS(rec.At), boolInt(rec.OK), nullable(clip(rec.Error, 1000)), clip(what, 400), clip(link, 400), string(raw), nullable(recipient), boolInt(rec.Delayed)); err != nil {
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

// sweepStale deals with runs that died (the box stopped): a claimed row that was never attempted goes back to
// pending; a sending row may or may not have been sent, so it is recorded as such and removed: it is not sent
// again, and the person sees it in the history and can resend.
func (s *Service) sweepStale(ctx context.Context, now time.Time) error {
	cut := store.FormatTS(now.Add(-staleClaim))
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_pending SET state = 'pending', claimed_at = NULL WHERE state = 'claimed' AND claimed_at < ?`, cut); err != nil {
			return fmt.Errorf("notify: return unsent notices to the queue: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT id, channel, notice FROM notify_pending WHERE state = 'sending' AND claimed_at < ?`, cut)
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
			if json.Unmarshal([]byte(raw), &st.n) != nil {
				st.n = Notice{}
			}
			list = append(list, st)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: find interrupted sends: %w", err)
		}
		for _, st := range list {
			if st.n.ID != "" {
				kind, ref, link := refOf(st.n)
				rec := SendRecord{ID: store.NewID("sd"), Channel: channel.Type(st.ch), To: st.ch, At: now, Error: interruptedText}
				if err := insertSend(ctx, tx, rec, kind, ref, st.n.Title, link, "", fallbackMessage(st.n)); err != nil {
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

// prune forgets exploited vulnerabilities older than kevKeepDays, at most once an hour.
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
	cut := store.FormatTS(now.AddDate(0, 0, -kevKeepDays))
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_kev WHERE seen_at < ?`, cut); err != nil {
			return fmt.Errorf("notify: prune exploited vulnerabilities: %w", err)
		}
		if err := pruneSlackButtons(ctx, tx, now); err != nil {
			return err
		}
		return pruneButtons(ctx, tx, now)
	})
}
