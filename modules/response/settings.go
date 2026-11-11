package response

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"slices"
	"time"
)

// Settings, the execution switch and the breaker (INV-7, INV-8, INV-12).

// RiskPhrase is what an admin types to turn execution on (INV-7).
const RiskPhrase = "I ACCEPT THE RISK"

var (
	approvalTypes = []string{"slack", "telegram", "email", "zalo", "zalo-personal"}
	linkTypes     = []string{"email", "zalo"}
	windowIDRE    = regexp.MustCompile(`^[\w.-]{1,96}$`)
)

func chanReady(c NotifyChannel) bool {
	return c.Configured && c.Enabled && c.Approvals && slices.Contains(approvalTypes, c.Type) && c.Approvers > 0
}

func (s *Service) channels(ctx context.Context) ([]NotifyChannel, error) {
	if s.cfg.Notifier == nil {
		return nil, nil
	}
	return s.cfg.Notifier.Channels(ctx)
}

func (s *Service) view(ctx context.Context, st Settings) (SettingsView, error) {
	chans, err := s.channels(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	v := SettingsView{Settings: st, Channels: []ChannelView{}}
	for _, t := range approvalTypes {
		for _, c := range chans {
			if c.Type == t && c.Configured {
				cv := ChannelView{Type: t, Label: c.Label, Ready: chanReady(c), Approvers: c.Approvers, Link: slices.Contains(linkTypes, t), Unlinked: []string{}}
				if err := s.linkedCounts(ctx, &cv); err != nil {
					return SettingsView{}, err
				}
				v.Channels = append(v.Channels, cv)
				break
			}
		}
	}
	return v, nil
}

// linkedCounts fills how many approvers of the channel linked their address and who has not (D-191). Notify lists approvers of a ready
// channel only; for another channel both stay empty.
func (s *Service) linkedCounts(ctx context.Context, cv *ChannelView) error {
	if s.cfg.Notifier == nil || s.cfg.Users == nil {
		return nil
	}
	list, err := s.cfg.Notifier.Approvers(ctx, cv.Type)
	if err != nil {
		return err
	}
	for _, a := range list {
		u, ok, err := s.cfg.Users.Lookup(ctx, a.UserID)
		if err != nil {
			return err
		}
		linked := false
		if ok {
			if linked, err = s.isLinked(ctx, u, cv.Type, a.Address); err != nil {
				return err
			}
		}
		if linked {
			cv.Linked++
			continue
		}
		name := u.Name
		if name == "" {
			name = u.Email
		}
		if name == "" {
			name = a.UserID
		}
		cv.Unlinked = append(cv.Unlinked, truncRunes(cleanLine(name), 80))
	}
	return nil
}

// Settings is GET /response/settings.
func (s *Service) Settings(ctx context.Context) (SettingsView, error) {
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return SettingsView{}, err
	}
	return s.view(ctx, st)
}

func inRange(v, lo, hi int) bool { return v >= lo && v <= hi }

// SaveSettings is PUT /response/settings. It never touches the execution switch (INV-7), the breaker or the AI pause.
func (s *Service) SaveSettings(ctx context.Context, who Actor, in SettingsInput) (SettingsView, error) {
	bad := func(msg string) (SettingsView, error) {
		return SettingsView{}, s.refuse(ctx, invalid(msg), "response.settings", who.Email)
	}
	chans, err := s.channels(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	switch {
	case !inRange(in.MaxPerHour, 1, 20):
		return bad("Actions per hour must be a whole number from 1 to 20.")
	case !inRange(in.ExpiryMin, 15, 30):
		return bad("Approval expiry must be 15 to 30 minutes.")
	case !inRange(in.BreakerMaxPerHour, 1, 200):
		return bad("The circuit breaker limit must be 1 to 200 actions per hour.")
	case !inRange(in.MultiTargetMax, 1, 1000):
		return bad("The multi-target limit must be 1 to 1000.")
	}
	for _, t := range in.ApprovalChannels {
		if !slices.ContainsFunc(chans, func(c NotifyChannel) bool { return c.Type == t && chanReady(c) }) {
			return bad("Approval channels must have approvals turned on and at least one approver (Settings, Alert channels).")
		}
	}
	if len(in.Maintenance) > 20 {
		return bad("Maintenance windows need a name, a start and a later end (up to 20).")
	}
	wins := make([]Window, 0, len(in.Maintenance))
	for _, w := range in.Maintenance {
		st, e1 := time.Parse(time.RFC3339, w.Start)
		en, e2 := time.Parse(time.RFC3339, w.End)
		if !windowIDRE.MatchString(w.ID) || !catTextRE.MatchString(w.Name) || e1 != nil || e2 != nil || !en.After(st) {
			return bad("Maintenance windows need a name, a start and a later end (up to 20).")
		}
		wins = append(wins, Window{ID: w.ID, Name: w.Name, Start: store2(st), End: store2(en)})
	}
	for _, t := range in.AI.Triggers {
		if s.trigger(t) == nil {
			return bad("AI gates: choose triggers, an hourly budget of 1 to 20 and a daily budget of 1 to 100 (not lower than the hourly one).")
		}
	}
	if !inRange(in.AI.BudgetHour, 1, 20) || !inRange(in.AI.BudgetDay, 1, 100) || in.AI.BudgetDay < in.AI.BudgetHour {
		return bad("AI gates: choose triggers, an hourly budget of 1 to 20 and a daily budget of 1 to 100 (not lower than the hourly one).")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Settings
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		st.MaxPerHour, st.ExpiryMin, st.BreakerMaxPerHour, st.MultiTargetMax = in.MaxPerHour, in.ExpiryMin, in.BreakerMaxPerHour, in.MultiTargetMax
		st.ApprovalChannels, st.Maintenance = nonNilS(in.ApprovalChannels), wins
		st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay = nonNilS(in.AI.Triggers), in.AI.BudgetHour, in.AI.BudgetDay
		if err := s.saveSettings(ctx, tx, st); err != nil {
			return err
		}
		out = st
		return s.step(ctx, tx, "response.settings", "response", LogSettings,
			itoa(st.MaxPerHour)+"/hour; expiry "+itoa(st.ExpiryMin)+" min; breaker "+itoa(st.BreakerMaxPerHour)+"/hour; more than "+itoa(st.MultiTargetMax)+" targets needs 2 approvers; "+
				itoa(len(wins))+" maintenance window(s); AI triggers: "+joinNonEmpty(st.AI.Triggers...)+onEmpty(len(st.AI.Triggers), "none")+", budget "+itoa(st.AI.BudgetHour)+"/hour "+itoa(st.AI.BudgetDay)+
				"/day; channels: "+joinNonEmpty(st.ApprovalChannels...)+onEmpty(len(st.ApprovalChannels), "app only"), who.Email)
	})
	if err != nil {
		return SettingsView{}, err
	}
	return s.view(ctx, out)
}

// SetExecution is POST /response/execution. Turning it on needs an admin (the route), two-step sign-in on and the exact
// phrase; it records who accepted the risk and when (INV-7). Turning it off needs an admin too.
func (s *Service) SetExecution(ctx context.Context, who Actor, enabled bool, phrase string) (SettingsView, error) {
	if enabled {
		u, ok, err := s.cfg.Users.Lookup(ctx, who.ID)
		if err != nil {
			return SettingsView{}, err
		}
		if !ok || u.Disabled || u.Role != "admin" {
			return SettingsView{}, s.refuse(ctx, fail(http.StatusForbidden, "forbidden", "Your account is not allowed to do this."), "response.execution", who.Email)
		}
		if !u.TwoStep {
			return SettingsView{}, s.refuse(ctx, fail(http.StatusConflict, "twofa_required", "Turn on two-step sign-in for your account first (My account), then try again."), "response.execution", who.Email)
		}
		if phrase != RiskPhrase {
			return SettingsView{}, s.refuse(ctx, fail(http.StatusBadRequest, "phrase_mismatch", "Type "+RiskPhrase+" exactly, in capital letters."), "response.execution", who.Email)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Settings
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case enabled && !st.Execution:
			st.Execution, st.AcceptedBy, st.AcceptedAt = true, strp(who.Email), strp(s.ts())
			if err := s.saveSettings(ctx, tx, st); err != nil {
				return err
			}
			err = s.step(ctx, tx, "response.execution.enable", "response", LogSettings, who.Email+" accepted the risk and turned on execution", who.Email)
		case !enabled && st.Execution:
			st.Execution = false
			if err := s.saveSettings(ctx, tx, st); err != nil {
				return err
			}
			err = s.step(ctx, tx, "response.execution.disable", "response", LogSettings, who.Email+" turned off execution", who.Email)
		}
		out = st
		return err
	})
	if err != nil {
		return SettingsView{}, err
	}
	return s.view(ctx, out)
}

// ResetBreaker is POST /response/breaker/reset: only an admin resumes response after the global circuit breaker (INV-12).
func (s *Service) ResetBreaker(ctx context.Context, who Actor) (SettingsView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Settings
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		st.BreakerTrippedAt, st.BreakerNotified, st.StoppedAt = nil, []string{}, nil
		if err := s.saveSettings(ctx, tx, st); err != nil {
			return err
		}
		out = st
		return s.step(ctx, tx, "response.breaker_reset", "response", LogSettings, who.Email+" resumed response after the circuit breaker", who.Email)
	})
	if err != nil {
		return SettingsView{}, err
	}
	return s.view(ctx, out)
}
