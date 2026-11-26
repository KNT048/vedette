package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/store"
)

// A trigger is a kind of event that can send an alert: every incident kind and the vulnerability notices. An administrator turns each one
// on or off and sets the lowest severity it sends (INV-31). What a trigger does not send is still recorded (the Incidents page, the
// finding's notices) with why it was not sent; only the message is left out. The rule is read when a notice is queued, so a change holds
// from the next event.
//
// The defaults keep the alerts a person must act on and leave out the ones that flood an inbox: a decoy touch, an exploited or urgent
// vulnerability on a device and a high or critical intrusion alert, known-bad connection or log anomaly send; a new device does not (on a
// network where phones use private, random MAC addresses a busy office sees many a day), and the medium and low ones of the other kinds
// do not.

// TriggerVuln is the trigger of the vulnerability notices (an exploited or urgent vulnerability on a device).
const TriggerVuln = "vulnerability"

// Trigger is the rule of one trigger (contract.ts AlertTrigger).
type Trigger struct {
	ID  string   `json:"id"`
	On  bool     `json:"on"`
	Min Severity `json:"min"` // the lowest severity that sends: critical, high, medium or low
}

// TriggerView is a trigger as GET /notify/channels shows it: the rule and its default.
type TriggerView struct {
	Trigger
	DefaultOn  bool     `json:"default_on"`
	DefaultMin Severity `json:"default_min"`
}

// defaultTriggers lists every trigger in the order the settings show them, with its default rule.
var defaultTriggers = []Trigger{
	{ID: string(IncidentTrap), On: true, Min: Low},
	{ID: TriggerVuln, On: true, Min: Low},
	{ID: string(IncidentIntrusion), On: true, Min: High},
	{ID: string(IncidentBadAddress), On: true, Min: High},
	{ID: string(IncidentLogAnomaly), On: true, Min: High},
	{ID: string(IncidentUnknownDevice), On: false, Min: Medium},
}

// triggerNames are the words the not-sent reasons and the audit use for each trigger.
var triggerNames = map[string]string{
	string(IncidentTrap):          "decoy touched",
	TriggerVuln:                   "exploited or urgent vulnerability",
	string(IncidentIntrusion):     "intrusion alert",
	string(IncidentBadAddress):    "connection to a known-bad address",
	string(IncidentLogAnomaly):    "log anomaly",
	string(IncidentUnknownDevice): "new device seen",
}

// Triggers is the stored rule of every trigger: the defaults with the administrator's changes over them.
type Triggers []Trigger

// find returns the rule of a trigger; a trigger the box does not know (a kind added by a newer producer) sends, so a new kind of alert is
// never lost silently.
func (ts Triggers) find(id string) Trigger {
	if i := slices.IndexFunc(ts, func(t Trigger) bool { return t.ID == id }); i >= 0 {
		return ts[i]
	}
	return Trigger{ID: id, On: true, Min: Low}
}

// triggerOf is the trigger a notice belongs to; "" for a notice no trigger holds back (a first-run summary: it already tells many
// incidents in one message, once an hour at most, in the first hours of a new box).
func triggerOf(n Notice) string {
	switch {
	case n.Kind == KindVuln:
		return TriggerVuln
	case n.Kind == KindIncident && strings.HasPrefix(n.ID, "fr-"):
		return ""
	case n.Kind == KindIncident:
		return n.IncidentKind
	}
	return ""
}

// holds says whether the trigger rule keeps a notice from every channel, and the reason to keep: trigger_off, with the trigger's
// minimum as the floor when the trigger is on but the notice is below it. A notice a person asked to send (Forced) is not held.
func (ts Triggers) holds(n Notice) (bool, Severity) {
	id := triggerOf(n)
	if id == "" || n.Forced {
		return false, ""
	}
	t := ts.find(id)
	if !t.On {
		return true, ""
	}
	if !MeetsMin(n.Severity, t.Min) {
		return true, t.Min
	}
	return false, ""
}

func defaultsCopy() Triggers { return slices.Clone(defaultTriggers) }

// loadTriggers reads the stored rules over the defaults; a stored trigger the box no longer knows is dropped.
func loadTriggers(ctx context.Context, q dbtx) (Triggers, error) {
	out := defaultsCopy()
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM notify_setting WHERE key = 'triggers'`).Scan(&v)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("notify: load alert triggers: %w", err)
	}
	var stored []Trigger
	if err := json.Unmarshal([]byte(v), &stored); err != nil {
		return out, fmt.Errorf("notify: stored alert triggers: %w", err)
	}
	for _, st := range stored {
		if i := slices.IndexFunc(out, func(t Trigger) bool { return t.ID == st.ID }); i >= 0 && validMin(st.Min) {
			out[i] = st
		}
	}
	return out, nil
}

func validMin(s Severity) bool { return s.Valid() && s != Info }

// triggerViews is the API's list: every trigger with its default.
func triggerViews(ts Triggers) []TriggerView {
	out := make([]TriggerView, 0, len(defaultTriggers))
	for _, d := range defaultTriggers {
		t := ts.find(d.ID)
		out = append(out, TriggerView{Trigger: t, DefaultOn: d.On, DefaultMin: d.Min})
	}
	return out
}

// triggerWords is how the audit says one trigger's rule: "off" or "on from high".
func triggerWords(t Trigger) string {
	if !t.On {
		return "off"
	}
	if t.Min == Low {
		return "on"
	}
	return "on from " + string(t.Min)
}

// SaveTriggers stores the alert triggers (PUT /notify/triggers, INV-31). Every trigger in the request must be known and have a minimum of
// critical, high, medium or low; a trigger left out keeps its rule. The audit entry names each change, old and new.
func (s *Service) SaveTriggers(ctx context.Context, actor string, in []Trigger) ([]TriggerView, error) {
	seen := map[string]bool{}
	for _, t := range in {
		if _, ok := triggerNames[t.ID]; !ok {
			return nil, badRequest("unknown_trigger", fmt.Sprintf("There is no alert trigger %q.", t.ID))
		}
		if seen[t.ID] {
			return nil, badRequest("duplicate_trigger", fmt.Sprintf("The alert trigger %q is listed twice.", t.ID))
		}
		seen[t.ID] = true
		if !validMin(t.Min) {
			return nil, badRequest("bad_min", "The lowest severity must be critical, high, medium or low.")
		}
	}
	var out Triggers
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := loadTriggers(ctx, tx)
		if err != nil {
			return err
		}
		out = slices.Clone(cur)
		var changes []string
		for _, t := range in {
			i := slices.IndexFunc(out, func(x Trigger) bool { return x.ID == t.ID })
			if out[i] == t {
				continue
			}
			from, to := triggerWords(out[i]), triggerWords(t)
			if from == to { // only the minimum of a trigger that is off changed
				from, to = from+" (from "+string(out[i].Min)+")", to+" (from "+string(t.Min)+")"
			}
			changes = append(changes, fmt.Sprintf("%s: %s -> %s", triggerNames[t.ID], from, to))
			out[i] = t
		}
		if len(changes) == 0 {
			return nil
		}
		// only the rules that differ from their default are stored: a default a later release changes reaches every trigger the
		// administrator left as it was
		var stored []Trigger
		for _, t := range out {
			if d := Triggers(defaultTriggers).find(t.ID); d != t {
				stored = append(stored, t)
			}
		}
		if stored == nil {
			stored = []Trigger{}
		}
		j, err := json.Marshal(stored)
		if err != nil {
			return fmt.Errorf("notify: encode alert triggers: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_setting (key, value, updated_at, updated_by) VALUES ('triggers', ?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			string(j), store.FormatTS(s.now()), actor); err != nil {
			return fmt.Errorf("notify: save alert triggers: %w", err)
		}
		return s.record(ctx, tx, actor, "notify.triggers_save", "alert triggers", strings.Join(changes, "; "))
	})
	if err != nil {
		return nil, err
	}
	return triggerViews(out), nil
}
