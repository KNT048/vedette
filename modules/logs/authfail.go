package logs

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
)

// Repeated failed logins (S-LOG-1, D-487). N failed logins from one remote address in M minutes are one incident from the first
// day: no baseline, no 7-day learning (the signature path cannot see it: one signature per account name, so a guesser never repeats
// one). The lines are the ones the counters already read: the remote address is the one the signature reader found (D-210, never the log
// sender or the box), the kind of login line comes from the text (sshd, PAM) or from the Windows event id. The state is in memory and
// bounded; a restart forgets at most the last ten minutes of counting.
// ponytail: a per-process sliding window, MaxAuthTracked keys, new keys ignored while it is full; upgrade path: a table in logs.db.
const (
	// AuthFailThreshold failed attempts within AuthFailWindow open the incident (fail2ban's default is 5 in 10 minutes; Wazuh 8 in 120 s).
	AuthFailThreshold = 5
	AuthFailWindow    = 10 * time.Minute
	// AuthDedupe is how long one (source, address) is one incident after it opened: more failures inside it are not announced again; a
	// login that is accepted from the address is, once, as a second incident of higher severity.
	AuthDedupe = time.Hour
	// MaxAuthTracked is how many (source, address) pairs are followed; maxAuthStamps the times kept for one class of line of one pair;
	// maxAuthUsers the account names kept; AuthEventsPerHour the most incidents announced in a clock hour.
	MaxAuthTracked    = 2048
	maxAuthStamps     = 32
	maxAuthUsers      = 5
	AuthEventsPerHour = 20
	// AuthTarget starts the target of every event of this rule: its own namespace in notify's dedupe key.
	AuthTarget = "auth:"
)

// Classes of a failed login line. sshd writes up to three lines for one attempt ("Invalid user", "authentication failure", "Failed password"):
// they are counted apart and an attempt is the largest of the three, so that one attempt is not three.
const (
	authPassword = iota // "Failed password for ...", Windows 4625
	authInvalid         // "Invalid user ..."
	authPAM             // "authentication failure"
	authClasses
)

// authObs is one login line of a batch: a failure of a class, or an accepted login (class -1), from one remote address.
type authObs struct {
	source string
	addr   netip.Addr
	at     time.Time
	class  int // -1: accepted
	user   string
}

type authKey struct {
	source string
	addr   netip.Addr
}

type authState struct {
	stamps    [authClasses][]time.Time
	users     []string
	success   time.Time // the last accepted login seen from the address
	firedAt   time.Time // when the incident opened; zero before
	escalated bool
	last      time.Time
}

// authAlert is what noteAuth decides to announce.
type authAlert struct {
	source    string
	addr      netip.Addr
	at        time.Time
	attempts  int
	users     []string
	accepted  bool // a login from the address was accepted: high severity
	escalated bool // this alert is the second one: the acceptance came after the first
}

// authLine reads the kind of login a line is: sig is its signature (a Windows event id is a known signature), text the stored line.
// class is -1 for an accepted login and the class constant for a failure; ok is false for any other line.
func authLine(sig, text string) (class int, user string, ok bool) {
	switch sig {
	case "4625: Failed logon":
		return authPassword, "", true
	case "4624: Successful logon":
		return -1, "", true
	}
	low := asciiLower(text)
	switch {
	case strings.Contains(low, "failed password for"):
		return authPassword, userAfter(text, low, "failed password for"), true
	case strings.Contains(low, "invalid user "):
		return authInvalid, userAfter(text, low, "invalid user"), true
	case strings.Contains(low, "authentication failure"):
		return authPAM, "", true
	case strings.Contains(low, "accepted password for"), strings.Contains(low, "accepted publickey for"), strings.Contains(low, "accepted keyboard-interactive"):
		return -1, "", true
	}
	return 0, "", false
}

// userAfter is the account name after marker ("for invalid user admin from": "admin"): one word, plain text, at most 32 characters.
func userAfter(text, low, marker string) string {
	i := strings.Index(low, marker)
	if i < 0 {
		return ""
	}
	w := strings.Fields(text[i+len(marker):])
	if len(w) >= 2 && strings.EqualFold(w[0], "invalid") && strings.EqualFold(w[1], "user") {
		w = w[2:]
	}
	if len(w) == 0 || strings.EqualFold(w[0], "from") {
		return ""
	}
	return clipRunes(plainText(w[0]), 32)
}

// noteAuth follows the login lines of a batch (in receive order) and returns the incidents to announce.
func (s *Service) noteAuth(obs []authObs) []authAlert {
	if len(obs) == 0 {
		return nil
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.auth == nil {
		s.auth = map[authKey]*authState{}
	}
	now := s.now()
	for k, st := range s.auth { // expired pairs go once per batch
		if now.Sub(st.last) > AuthDedupe {
			delete(s.auth, k)
		}
	}
	var out []authAlert
	for _, o := range obs {
		k := authKey{o.source, o.addr}
		st := s.auth[k]
		if o.class < 0 { // an accepted login counts only for an address that has failed lately
			if st == nil || authAttempts(st, o.at) == 0 {
				continue
			}
			st.success, st.last = o.at, o.at
			if !st.firedAt.IsZero() && !st.escalated {
				st.escalated = true
				out = append(out, authAlert{o.source, o.addr, o.at, authAttempts(st, o.at), slices.Clone(st.users), true, true})
			}
			continue
		}
		if st == nil {
			if len(s.auth) >= MaxAuthTracked {
				continue
			}
			st = &authState{}
			s.auth[k] = st
		}
		st.last = o.at
		cut := o.at.Add(-AuthFailWindow)
		st.stamps[o.class] = append(slices.DeleteFunc(st.stamps[o.class], func(t time.Time) bool { return t.Before(cut) }), o.at)
		if n := len(st.stamps[o.class]); n > maxAuthStamps {
			st.stamps[o.class] = st.stamps[o.class][n-maxAuthStamps:]
		}
		if o.user != "" && len(st.users) < maxAuthUsers && !slices.Contains(st.users, o.user) {
			st.users = append(st.users, o.user)
		}
		if n := authAttempts(st, o.at); n >= AuthFailThreshold && (st.firedAt.IsZero() || o.at.Sub(st.firedAt) >= AuthDedupe) {
			acc := !st.success.IsZero() && o.at.Sub(st.success) <= AuthFailWindow
			st.firedAt, st.escalated = o.at, acc
			out = append(out, authAlert{o.source, o.addr, o.at, n, slices.Clone(st.users), acc, false})
		}
	}
	return out
}

// authAttempts is the failed attempts inside the window that ends at at: the largest class (see the classes).
func authAttempts(st *authState, at time.Time) int {
	best, cut := 0, at.Add(-AuthFailWindow)
	for _, c := range st.stamps {
		n := 0
		for _, t := range c {
			if !t.Before(cut) {
				n++
			}
		}
		best = max(best, n)
	}
	return best
}

// authBudget says how many of n alerts may go out now (AuthEventsPerHour in a clock hour) and whether this call is the first to run over.
func (s *Service) authBudget(n int) (allowed int, first bool) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	h := s.now().Unix() / 3600
	if h != s.authHour {
		s.authHour, s.authSent = h, 0
	}
	allowed = max(0, min(n, AuthEventsPerHour-s.authSent))
	s.authSent += allowed
	if allowed < n && s.authCapLogged != h {
		s.authCapLogged, first = h, true
	}
	return allowed, first
}

// announceAuth publishes the incidents of a committed batch as logs.anomaly.detected (notify opens a log_anomaly incident; never inside the
// transaction). Without a bus nothing is sent.
func (s *Service) announceAuth(ctx context.Context, obs []authObs, names map[string]string, senders map[string]netip.Addr) {
	alerts := s.noteAuth(obs)
	if s.cfg.Events == nil || len(alerts) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), iocAnnounceTimeout)
	defer cancel()
	allowed, first := s.authBudget(len(alerts))
	if first {
		s.cfg.Log.WarnContext(ctx, "logs: more failed-login incidents than the hourly limit; the rest are not announced", "limit", AuthEventsPerHour)
	}
	for _, a := range alerts[:allowed] {
		devices := []DeviceInfo{}
		if sender, ok := senders[a.source]; ok {
			devices = s.devicesOf(ctx, sourceRow{SenderIP: sender.String()})
		}
		if a.addr.IsPrivate() {
			devices = append(devices, s.devicesAt(ctx, a.addr.String(), devices)...)
		}
		if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: authEvent(a, names[a.source], devices)}); err != nil {
			s.cfg.Log.WarnContext(ctx, "logs: announcing failed logins failed", "err", err)
		}
	}
}

// authEvent words an incident. name is the log source's name and the users are account names from the log (untrusted): every text is plain
// and cut, and notify shows it as text.
func authEvent(a authAlert, name string, devices []DeviceInfo) AnomalyEvent {
	name, addr := clipRunes(plainText(name), 100), a.addr.String()
	where := "the log of " + name
	inside := ""
	if a.addr.IsPrivate() {
		inside = " This address is on your own network: a device inside it is guessing passwords."
	}
	tried := ""
	if len(a.users) > 0 {
		tried = " Accounts tried: " + strings.Join(a.users, ", ") + "."
	}
	ev := AnomalyEvent{Source: clipRunes(plainText(name), MaxEventKey), Target: clipRunes(AuthTarget+addr, MaxEventKey), Devices: devices}
	switch {
	case a.escalated:
		ev.Target = clipRunes(AuthTarget+addr+" accepted", MaxEventKey)
		ev.Title = fmt.Sprintf("A login from %s was ACCEPTED after failed attempts on %s", addr, name)
		ev.What = fmt.Sprintf("%d failed login attempts from %s were followed by a login that succeeded (%s).%s%s", a.attempts, addr, where, tried, inside)
		ev.Action = "Treat the account as taken over: change its password, end its sessions, and look at what it did after the login. Then block the address at the firewall and turn off password login (use keys)."
		ev.Severity = "high"
	default:
		ev.Title = fmt.Sprintf("%d failed logins from %s on %s in %d minutes", a.attempts, addr, name, int(AuthFailWindow/time.Minute))
		ev.What = fmt.Sprintf("%d failed login attempts from %s within %d minutes (%s).%s%s", a.attempts, addr, int(AuthFailWindow/time.Minute), where, tried, inside)
		ev.Action = "Open Logs and search for the address: check whether any login from it succeeded. Block the address at the firewall and turn off password login for SSH (use keys)."
		ev.Severity = "medium"
		if a.accepted {
			ev.What += " A login from the same address was ACCEPTED in that time."
			ev.Action = "A login from this address succeeded: treat that account as taken over (change its password, end its sessions). " + ev.Action
			ev.Severity = "high"
		}
	}
	ev.Title, ev.What, ev.Action = clipRunes(ev.Title, MaxEventTitle), clipRunes(ev.What, MaxEventText), clipRunes(ev.Action, MaxEventText)
	return ev
}
