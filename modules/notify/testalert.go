package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// TestDelivery is what one channel did with a test alert: delivered (OK, Detail the provider's receipt), failed (Detail why), or
// skipped because the real alert would not go through it (Skipped, Detail why).
type TestDelivery struct {
	Channel channel.Type `json:"channel"`
	OK      bool         `json:"ok"`
	Skipped bool         `json:"skipped"`
	Detail  string       `json:"detail"`
}

// testAlertNote ends the text of every test alert: the reader knows nobody touched anything, and what a real touch does.
const testAlertNote = "This is a test a person started in Vedette: nobody touched the trap. A real touch sends this alert without the word Test, " +
	"and opens an incident."

// SendTrapTest sends the alert a real hit on a trap would send, marked Test, to every channel that is on, now, and says what each did
// (honeypot "Test trap", "Test scan", "Test token"): the person sees the whole path from the trap to their phone work. It follows the
// channels' choice of what to send (a channel that would not take the real alert is skipped and says why; every channel is, when the
// trap's alert trigger holds the real one back) and says when quiet hours would hold the real one; it opens no incident, writes no
// history row and counts nowhere. The source address is the box's own.
// No channel on: an empty list.
func (s *Service) SendTrapTest(ctx context.Context, hit TrapHit) ([]TestDelivery, error) {
	if strings.TrimSpace(hit.SrcIP) == "" {
		hit.SrcIP = "the Vedette box"
	}
	in := trapIncident(hit)
	db := s.cfg.DB.Reader()
	rows, err := db.QueryContext(ctx, `SELECT type FROM notify_channel WHERE configured = 1 AND enabled = 1 ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("notify: list channels: %w", err)
	}
	var types []channel.Type
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: list channels: %w", err)
		}
		types = append(types, channel.Type(t))
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: list channels: %w", err)
	}
	rules, err := loadRules(ctx, db)
	if err != nil {
		return nil, err
	}
	triggers, err := loadTriggers(ctx, db)
	if err != nil {
		return nil, err
	}
	// The trap trigger decides whether the real alert goes to any channel (INV-31): when it holds the real one, no channel takes the test.
	held := ""
	if hold, floor := triggers.holds(Notice{Kind: KindIncident, IncidentKind: string(in.Kind), Severity: in.Severity}); hold {
		held = "Not sent: alerts of this kind are turned off in the alert settings, so a real one would not be sent either."
		if floor != "" {
			held = fmt.Sprintf("Not sent: this alert is %s, and the alert settings send this kind only from %s, so a real one would not be sent either.", in.Severity, floor)
		}
	}
	what := in.What
	now := s.now().In(s.loc(ctx))
	if rules.Quiet.Active(now) && (in.Severity != Critical || !rules.Quiet.AllowCritical) {
		what += fmt.Sprintf(" Quiet hours are on now: a real alert would wait until %s.", orgtime.Clock(rules.Quiet.EndsAt(now), s.loc(ctx)))
	}
	msg := channel.Message{ID: store.NewID("test"), Kind: "test", IncidentKind: string(in.Kind), Severity: string(in.Severity),
		Title: "Test: " + in.Title, What: what + " " + testAlertNote, Action: in.Action, Link: s.link(in.Link)}
	out := make([]TestDelivery, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		out[i].Channel = t
		if held != "" {
			out[i].Skipped, out[i].Detail = true, held
			continue
		}
		c, err := loadChannel(ctx, db, t)
		if err != nil {
			out[i].Detail = "The channel could not be read."
			continue
		}
		if !MeetsMin(in.Severity, c.MinSeverity) {
			out[i].Skipped = true
			out[i].Detail = fmt.Sprintf("Not sent: this alert is %s, and this channel only sends %s and above, so a real one would not go through it either.", in.Severity, c.MinSeverity)
			continue
		}
		snd, err := s.savedSender(ctx, c, nil)
		if err != nil {
			out[i].Detail = "The saved settings cannot be used: " + userText(err) + " Save the channel again."
			continue
		}
		wg.Add(1)
		go func(d *TestDelivery, snd channel.Sender) {
			defer wg.Done()
			tctx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()
			rcpt, err := snd.Send(tctx, msg)
			if err != nil {
				d.Detail = userText(err)
				return
			}
			d.OK, d.Detail = true, rcpt.Detail
		}(&out[i], snd)
	}
	wg.Wait()
	return out, nil
}
