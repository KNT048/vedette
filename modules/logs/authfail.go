package logs

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/logs/listen"
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
	addr   netip.Addr // authNet of the remote address
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

// authLine reads the kind of login a line is: sig is its signature, bounded says the signature comes from shipped data (a Windows event id:
// a mined signature is made from whatever a visitor wrote), text the stored line. A text rule applies only when the program of the syslog
// header is sshd (or a PAM service for "authentication failure") and the phrase starts the message: the words anywhere else in a line
// (a web server's User-Agent, an account name) are the sender's, and anyone on the Internet could write them. class is -1 for an accepted
// login and the class constant for a failure; ok is false for any other line.
func authLine(sig string, bounded bool, text string) (class int, user string, ok bool) {
	if bounded {
		switch sig {
		case "4625: Failed logon":
			return authPassword, "", true
		case "4624: Successful logon":
			return -1, "", true
		}
	}
	env := listen.ParseSyslog(text)
	if env.Format == listen.FormatRaw { // no <PRI>: a header may still be there
		env = listen.ParseSyslog("<13>" + text)
	}
	app := asciiLower(env.App)
	msg := env.Msg
	switch app {
	case "sshd", "sshd-session":
		switch {
		case strings.HasPrefix(msg, "Failed password for "):
			return authPassword, userAfter(msg, "Failed password for "), true
		case strings.HasPrefix(msg, "Invalid user "):
			return authInvalid, userAfter(msg, "Invalid user "), true
		case strings.HasPrefix(msg, "Accepted password for "), strings.HasPrefix(msg, "Accepted publickey for "), strings.HasPrefix(msg, "Accepted keyboard-interactive/pam for "):
			return -1, "", true
		}
		fallthrough
	case "login", "su", "sudo":
		if strings.HasPrefix(msg, "pam_unix(") && strings.Contains(msg, ":auth): authentication failure") {
			return authPAM, "", true
		}
	}
	return 0, "", false
}

// userAfter is the account name after marker ("for invalid user admin from": "admin"): one word, plain text, at most 32 characters.
func userAfter(msg, marker string) string {
	w := strings.Fields(strings.TrimPrefix(msg, marker))
	if len(w) >= 2 && strings.EqualFold(w[0], "invalid") && strings.EqualFold(w[1], "user") {
		w = w[2:]
	}
	if len(w) == 0 || strings.EqualFold(w[0], "from") {
		return ""
	}
	return clipRunes(plainText(w[0]), 32)
}

// authNet is the address a pair is followed under: an IPv6 address by its /64 (one host gets a whole /64, so one address per guess would
// never add up; sshguard counts the same way), an IPv4 address as it is.
func authNet(a netip.Addr) netip.Addr {
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().Addr()
	}
	return a
}

// authLabel is how an incident names the address: the /64 for IPv6.
func authLabel(a netip.Addr) string {
	if a.Is6() {
		return netip.PrefixFrom(a, 64).String()
	}
	return a.String()
}

// noteAuth follows the login lines of a batch (in receive order) and returns the incidents to announce. A pair counts as announced from now
// on; announceAuth takes that back (authUnmark) for an incident that the hourly budget did not let out.
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
	for k, st := range s.auth { // expired pairs go once per batch: one that never opened an incident after the window, the others after the dedupe time
		if age := now.Sub(st.last); age > AuthDedupe || st.firedAt.IsZero() && age > AuthFailWindow {
			delete(s.auth, k)
		}
	}
	var out []authAlert
	for _, o := range obs {
		net := authNet(o.addr)
		k := authKey{o.source, net}
		st := s.auth[k]
		if o.class < 0 { // an accepted login counts only for an address that has failed lately
			if st == nil || authAttempts(st, o.at) == 0 {
				continue
			}
			st.success, st.last = o.at, o.at
			if !st.firedAt.IsZero() && !st.escalated && o.at.Sub(st.firedAt) < AuthDedupe { // the incident of an hour ago is over
				st.escalated = true
				out = append(out, authAlert{o.source, net, o.at, authAttempts(st, o.at), slices.Clone(st.users), true, true})
			}
			continue
		}
		if st == nil {
			if len(s.auth) >= MaxAuthTracked && !s.evictOldestQuiet() {
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
			out = append(out, authAlert{o.source, net, o.at, n, slices.Clone(st.users), acc, false})
		}
	}
	return out
}

// evictOldestQuiet drops the pair that has not opened an incident and was seen longest ago, to make room for a new one; false when every
// pair has opened one (none is a half-counted attacker). ponytail: a scan of at most MaxAuthTracked pairs, only while the table is full.
func (s *Service) evictOldestQuiet() bool {
	var oldest authKey
	var at time.Time
	found := false
	for k, st := range s.auth {
		if st.firedAt.IsZero() && (!found || st.last.Before(at)) {
			oldest, at, found = k, st.last, true
		}
	}
	if found {
		delete(s.auth, oldest)
	}
	return found
}

// authUnmark takes back "announced" for an incident the budget cut: the pair opens it again at its next failed line.
func (s *Service) authUnmark(a authAlert) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if st := s.auth[authKey{a.source, a.addr}]; st != nil && st.firedAt.Equal(a.at) {
		st.firedAt, st.escalated = time.Time{}, false
	}
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

// authBudget says how many of n medium alerts may go out now (AuthEventsPerHour in a clock hour) and whether this call is the first to run
// over. An alert that says a login was accepted is never counted or cut: it is the one a person must not miss.
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
	if len(alerts) == 0 {
		return
	}
	if s.cfg.Events == nil {
		for _, a := range alerts {
			s.authUnmark(a)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), iocAnnounceTimeout)
	defer cancel()
	slices.SortStableFunc(alerts, func(a, b authAlert) int { return flag(b.accepted) - flag(a.accepted) }) // accepted logins first
	medium := 0
	for _, a := range alerts {
		if !a.accepted {
			medium++
		}
	}
	allowed, first := s.authBudget(medium)
	if first {
		s.cfg.Log.WarnContext(ctx, "logs: more failed-login incidents than the hourly limit; the rest wait for the next hour", "limit", AuthEventsPerHour)
	}
	for _, a := range alerts {
		if !a.accepted {
			if allowed == 0 {
				s.authUnmark(a)
				continue
			}
			allowed--
		}
		devices := []DeviceInfo{}
		if sender, ok := senders[a.source]; ok {
			devices = s.devicesOf(ctx, sourceRow{SenderIP: sender.String()})
		}
		if a.addr.Is4() && a.addr.IsPrivate() {
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
	name, addr := clipRunes(plainText(name), 100), authLabel(a.addr)
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
	if a.accepted { // its own incident: the one of the failures may be open already, and a count in it would hide this
		ev.Target = clipRunes(AuthTarget+addr+" accepted", MaxEventKey)
	}
	ev.Title, ev.What, ev.Action = clipRunes(ev.Title, MaxEventTitle), clipRunes(ev.What, MaxEventText), clipRunes(ev.Action, MaxEventText)
	return ev
}
