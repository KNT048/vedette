package notify_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
)

// fakeSessions is the honeypot's store of hits, as notify reads a source's session from it.
type fakeSessions struct {
	mu   sync.Mutex
	hits map[string][]notify.SessionHit
}

func (f *fakeSessions) SourceHits(_ context.Context, src string, from, to time.Time) ([]notify.SessionHit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []notify.SessionHit
	for _, h := range f.hits[src] {
		if !h.At.Before(from) && !h.At.After(to) {
			out = append(out, h)
		}
	}
	return out, nil
}

// trapBench publishes honeypot hits the way the honeypot does: stored first, then announced.
type trapBench struct {
	e  *env
	hp *fakeSessions // nil = notify has no reader of the honeypot's hits
	n  int
}

func newTrapBench(t *testing.T, withSessions bool) *trapBench {
	b := &trapBench{}
	var opts []func(*notify.Config)
	if withSessions {
		b.hp = &fakeSessions{hits: map[string][]notify.SessionHit{}}
		opts = append(opts, func(c *notify.Config) { c.Sessions = b.hp })
	}
	b.e = newEnv(t, opts...)
	b.e.telegram(notify.Low)
	b.e.plain()
	t.Cleanup(b.e.svc.Subscribe(b.e.bus))
	return b
}

// hit stores and announces one hit of src after the clock moved on by after.
func (b *trapBench) hit(after time.Duration, src, kind, label string) string {
	b.e.t.Helper()
	b.e.clock.Add(after)
	b.n++
	id := fmt.Sprintf("hit-%d", b.n)
	at := b.e.clock.Now()
	svc := ""
	if kind == "service" {
		svc = strings.ToLower(label)
	}
	if b.hp != nil {
		b.hp.mu.Lock()
		b.hp.hits[src] = append(b.hp.hits[src], notify.SessionHit{ID: id, At: at, Kind: kind, Service: svc, Label: label})
		b.hp.mu.Unlock()
	}
	data := map[string]any{"id": id, "ts": at.Format(time.RFC3339Nano), "kind": kind, "service": svc, "src_ip": src, "label": label,
		"decoy": "BUILD-SRV-02, NAS-ARCHIVE", "src_asset_id": "a-laptop", "src_name": "LAPTOP-ANNA"}
	if err := b.e.bus.Publish(b.e.ctx(), events.Event{Name: notify.EventHoneypotHit, Data: data}); err != nil {
		b.e.t.Fatal(err)
	}
	b.e.flush()
	return id
}

func (b *trapBench) traps(src string) []notify.Incident {
	b.e.t.Helper()
	l, err := b.e.svc.Incidents(b.e.ctx())
	if err != nil {
		b.e.t.Fatal(err)
	}
	var out []notify.Incident
	for _, i := range l {
		if i.Kind == notify.IncidentTrap && strings.HasPrefix(i.Title, src+" ") {
			out = append(out, i)
		}
	}
	return out
}

func (b *trapBench) sends(id string) int {
	return b.e.count(`SELECT count(*) FROM notify_send WHERE kind = 'incident' AND ref_id = ? AND ok = 1`, id)
}

// One source touching the decoy in one session (a scan, a trap service, decoy files, a bait account; no quiet longer than ten
// minutes) is ONE incident: it says everything the source did, lists every hit, names the source device, and is told twice at
// most: when it opens (the scan, High) and once when a touch makes it Critical. Another source is its own incident.
func TestTrapSessionIsOneIncidentToldAtMostTwice(t *testing.T) {
	b := newTrapBench(t, true)
	src := "192.168.10.145"
	first := b.hit(0, src, "scan", "Scan across the Trap IPs")
	b.hit(5*time.Second, src, "service", "SSH")
	b.hit(10*time.Second, src, "token", "Credential token Old admin")
	b.hit(10*time.Second, src, "token", "File token Payroll")
	b.hit(0, src, "token", "File token Passwords")
	b.hit(3*time.Minute, src, "token", "File token Payroll") // the same file again: one file
	b.hit(0, src, "service", "SMB")
	b.hit(20*time.Second, "192.168.10.99", "service", "FTP")

	l := b.traps(src)
	if len(l) != 1 {
		t.Fatalf("%d incidents for one session, want 1: %+v", len(l), l)
	}
	i := l[0]
	want := src + " touched the decoy: opened 2 decoy files, tried the bait account Old admin, touched SSH and SMB, scanned the Trap IPs"
	if i.Title != want || i.Severity != notify.Critical || i.Count != 7 || i.Link != "/honeypot/hits/"+first {
		t.Fatalf("incident %q %s count %d link %s, want %q critical 7", i.Title, i.Severity, i.Count, i.Link, want)
	}
	for _, line := range []string{"touched the decoy 7 times between 10:00:00 and 10:03:25 (box time)", "\n10:00:00 scanned the Trap IPs",
		"\n10:00:05 touched the SSH trap", "\n10:00:15 used the Credential token Old admin", "\n10:00:25 opened the File token Passwords", "\n10:03:25 touched the SMB trap"} {
		if !strings.Contains(i.What, line) {
			t.Fatalf("what lacks %q:\n%s", line, i.What)
		}
	}
	if len(i.Devices) != 1 || i.Devices[0].ID != "a-laptop" {
		t.Fatalf("devices %+v", i.Devices)
	}
	if n := b.sends(i.ID); n != 2 {
		t.Fatalf("%d alerts for one session, want 2 (opened by the scan, raised once by the first touch)", n)
	}
	if n := b.e.count(`SELECT count(*) FROM notify_send WHERE ref_id = ? AND message LIKE ?`, i.ID, "%"+src+" touched the decoy: touched SSH, scanned the Trap IPs%"); n != 1 {
		t.Fatalf("the raise does not tell the session so far (%d)", n)
	}
	if o := b.traps("192.168.10.99"); len(o) != 1 || o[0].Title != "192.168.10.99 touched the FTP trap" {
		t.Fatalf("other source %+v", o)
	}
}

// Ten minutes of quiet end a session: the next hit opens a new incident and the old one stays as it was. A hit after the incident
// was resolved opens a new one too, also within the ten minutes.
func TestTrapSessionEndsAfterQuietOrWhenResolved(t *testing.T) {
	b := newTrapBench(t, true)
	src := "192.168.10.145"
	b.hit(0, src, "service", "SSH")
	b.hit(9*time.Minute, src, "service", "SMB") // within the session
	if l := b.traps(src); len(l) != 1 || l[0].Count != 2 {
		t.Fatalf("after 9 minutes: %+v", l)
	}
	b.hit(10*time.Minute+time.Second, src, "token", "File token Payroll") // a new session
	l := b.traps(src)
	if len(l) != 2 {
		t.Fatalf("%d incidents after the quiet, want 2", len(l))
	}
	newer, older := l[0], l[1]
	if newer.Title != src+" opened the File token Payroll" || newer.Count != 1 || older.Count != 2 || older.Status != notify.StatusNew ||
		older.Title != src+" touched the decoy: touched SSH and SMB" {
		t.Fatalf("sessions %q (%d) and %q (%d %s)", newer.Title, newer.Count, older.Title, older.Count, older.Status)
	}
	if b.sends(newer.ID) != 1 || b.sends(older.ID) != 1 {
		t.Fatal("each session is told once")
	}
	if _, err := b.e.svc.HandleIncident(b.e.ctx(), "u-op", newer.ID, notify.StatusResolved, ""); err != nil {
		t.Fatal(err)
	}
	b.hit(time.Minute, src, "service", "FTP")
	if l := b.traps(src); len(l) != 3 || l[0].Title != src+" touched the FTP trap" || l[0].Status != notify.StatusNew {
		t.Fatalf("after resolve: %+v", l)
	}
	b.hit(time.Minute, src, "service", "SSH") // and it joins that new one, not the session that ended
	if l := b.traps(src); len(l) != 3 || l[0].Count != 2 || l[1].Count != 2 || l[2].Status != notify.StatusResolved {
		t.Fatalf("a hit after the new incident: %+v", l)
	}
}

// Without the honeypot's hits the session is still one incident: it keeps the words of the hit that opened it, and a raise takes
// the words of the raising hit.
func TestTrapSessionWithoutTheHitsKeepsItsWords(t *testing.T) {
	b := newTrapBench(t, false)
	src := "192.168.10.145"
	b.hit(0, src, "scan", "Scan across the Trap IPs")
	b.hit(time.Second, src, "service", "SSH")
	b.hit(time.Second, src, "service", "SMB")
	l := b.traps(src)
	if len(l) != 1 || l[0].Title != src+" touched the SSH trap" || l[0].Severity != notify.Critical || l[0].Count != 3 || b.sends(l[0].ID) != 2 {
		t.Fatalf("%+v", l)
	}
}

// A long session fits the 1000 characters of an incident's description: the first hits by time, then how many more.
func TestTrapSessionDescriptionFitsAndCountsTheRest(t *testing.T) {
	at := time.Date(2026, 11, 25, 9, 28, 0, 0, time.UTC)
	var hits []notify.SessionHit
	for k := range 80 {
		hits = append(hits, notify.SessionHit{ID: fmt.Sprint(k), At: at.Add(time.Duration(k) * time.Second), Kind: "token", Label: fmt.Sprintf("File token Report-%02d", k)})
	}
	title, what := notify.SessionWordsForTest("192.0.2.118", hits, time.UTC)
	if title != "192.0.2.118 touched the decoy: opened 80 decoy files" {
		t.Fatalf("title %q", title)
	}
	if n := utf8.RuneCountInString(what); n > 1000 || !strings.Contains(what, "\n09:28:00 opened the File token Report-00") || !strings.Contains(what, " more") {
		t.Fatalf("what (%d):\n%s", n, what)
	}
	var shown int
	for _, l := range strings.Split(what, "\n") {
		if strings.HasPrefix(l, "09:") {
			shown++
		}
	}
	if !strings.HasSuffix(what, fmt.Sprintf("… and %d more", 80-shown)) {
		t.Fatalf("shown %d, end %q", shown, what[len(what)-30:])
	}
}
