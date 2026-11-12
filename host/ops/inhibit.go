package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// binBusctl is systemd's busctl (D-453): one fixed call, logind's ListInhibitors, answered as JSON. The host
// speaks no D-Bus itself; busctl comes with the systemd package the .deb already depends on (>= 254), and
// --json exists since systemd 240 (Ubuntu 24.04 has 255, Debian 13 257, Ubuntu 26.04 259).
const binBusctl = "busctl"

// argsListInhibitors is the only busctl argv: read-only, no polkit (logind answers any caller).
var argsListInhibitors = []string{
	"--system", "--json=short", "call",
	"org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListInhibitors",
}

const (
	maxInhibitOutput = 1 << 20 // logind keeps at most InhibitorsMax (8192 by default) locks; a longer answer is unknown
	maxInhibitors    = 8192
	inhibitWhoMax    = 64 // bytes of the cleaned who and why that a message or an audit line carries
	inhibitWhyMax    = 120
)

// inhibitor is one logind lock that refuses a reboot: mode "block" and "shutdown" among its what. Who and why
// are logind's text from whoever took the lock, cleaned by cleanInhibitText.
type inhibitor struct {
	Who, Why string
}

var errInhibitorsUnknown = errors.New("the inhibitor list could not be read")

// parseInhibitors reads busctl's JSON answer of ListInhibitors, {"type":"a(ssssuu)","data":[[[what, who, why,
// mode, uid, pid], ...]]}, and returns the locks that block a reboot. It is fail-closed: any other shape, an
// unknown field, a wrong type, trailing data or more than maxInhibitors entries is errInhibitorsUnknown, never
// a partial list. "block-weak" (systemd 257) is not counted: logind ignores it for root, which the host is;
// "delay" only holds a shutdown for InhibitDelayMaxSec and never refuses it.
func parseInhibitors(out []byte) ([]inhibitor, error) {
	if len(out) > maxInhibitOutput {
		return nil, errInhibitorsUnknown
	}
	var msg struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&msg); err != nil || msg.Type != "a(ssssuu)" || len(msg.Data) != 1 {
		return nil, errInhibitorsUnknown
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errInhibitorsUnknown
	}
	var rows [][]json.RawMessage
	if v := bytes.TrimSpace(msg.Data[0]); len(v) == 0 || v[0] != '[' || json.Unmarshal(v, &rows) != nil || len(rows) > maxInhibitors {
		return nil, errInhibitorsUnknown
	}
	var block []inhibitor
	for _, r := range rows {
		if len(r) != 6 {
			return nil, errInhibitorsUnknown
		}
		var s [4]string
		for i := range s {
			// The first byte check keeps null out: json.Unmarshal takes null for any type and leaves it zero.
			if v := bytes.TrimSpace(r[i]); len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s[i]) != nil {
				return nil, errInhibitorsUnknown
			}
		}
		for _, n := range r[4:] {
			var u uint32
			if v := bytes.TrimSpace(n); len(v) == 0 || v[0] < '0' || v[0] > '9' || json.Unmarshal(v, &u) != nil {
				return nil, errInhibitorsUnknown
			}
		}
		what, who, why, mode := s[0], s[1], s[2], s[3]
		if mode == "block" && slices.Contains(strings.Split(what, ":"), "shutdown") {
			block = append(block, inhibitor{Who: cleanInhibitText(who, inhibitWhoMax), Why: cleanInhibitText(why, inhibitWhyMax)})
		}
	}
	return block, nil
}

// cleanInhibitText makes logind's who or why (any local program's text) safe to put in a message, a log and
// an audit line: printable ASCII without quotes, angle brackets, ampersand, backquote or backslash (anything
// else becomes "?"), runs of spaces collapsed, at most n bytes; empty is "unknown".
func cleanInhibitText(s string, n int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			space = b.Len() > 0
			continue
		case r < 0x21 || r > 0x7e || strings.ContainsRune("\"'<>&`\\", r):
			r = '?'
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
		if b.Len() >= n {
			break
		}
	}
	out := b.String()
	if len(out) > n {
		out = strings.TrimRight(out[:n], " ") // a space written with the next character can end up last after the cut
	}
	if out == "" {
		return "unknown"
	}
	return out
}

// How long one read of the list may take: inside os.reboot's Check (the server bounds a Check at 5 s), and
// everywhere else (timers and the reboot itself, no request waits on them).
const (
	inhibitReadCheck = 3 * time.Second
	inhibitReadWait  = 10 * time.Second
)

// shutdownBlockers asks logind which locks refuse a reboot right now, within d. An error means the list is
// unknown (busctl failed, timed out, or answered something parseInhibitors does not accept); the first
// unknown after a good read is logged once (WARN), since on systemd 255 the host's own read is the only
// guard against rebooting during apt (D-453).
func (o *Ops) shutdownBlockers(ctx context.Context, d time.Duration) ([]inhibitor, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	res, code, err := o.exec(ctx, binBusctl, argsListInhibitors...)
	var bl []inhibitor
	if err == nil && code == 0 && !res.Truncated {
		bl, err = parseInhibitors(res.Stdout)
	} else {
		err = errInhibitorsUnknown
	}
	if err != nil {
		if o.inhUnknown.CompareAndSwap(false, true) {
			o.log.WarnContext(ctx, "could not read logind's shutdown locks; rebooting without the host's own check (systemd 257 and later still refuse a locked reboot, 255 does not)", "exit_code", code)
		}
		return nil, err
	}
	o.inhUnknown.Store(false)
	return bl, nil
}

// inhibitedMessage names who holds the first blocking lock and why, and how many more there are.
func inhibitedMessage(bl []inhibitor) string {
	more := ""
	if len(bl) > 1 {
		more = fmt.Sprintf(" (and %d more)", len(bl)-1)
	}
	return fmt.Sprintf("The box cannot reboot now: %s holds a shutdown lock%s (%s). Reboot after it finishes.", bl[0].Who, more, bl[0].Why)
}

// inhibitDetail is the audit detail of a reboot that waits for, or gave up on, a blocking lock.
func inhibitDetail(kind string, bl []inhibitor) map[string]any {
	d := map[string]any{"kind": kind}
	if len(bl) > 0 {
		d["who"], d["why"], d["locks"] = bl[0].Who, bl[0].Why, len(bl)
	}
	return d
}
