package logs

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The 20 log ids and 26 actions of the FortiGate profile (data/profiles/fortigate.json): every bounded signature it can make.
var (
	allFgIDs     = []string{"0000000013", "0000000020", "0001000014", "0100032001", "0100032002", "0100032003", "0100040704", "0100044546", "0100044547", "0101037138", "0101039426", "0101039947", "0102043008", "0102043009", "0211008192", "0316013056", "0317013312", "0419016384", "1059028704", "1059028705"}
	allFgActions = []string{"", "accept", "deny", "close", "timeout", "start", "ip-conn", "client-rst", "server-rst", "dropped", "blocked", "passthrough", "monitored", "reset", "detected", "login", "logout", "ssl-login-fail", "tunnel-up", "tunnel-down", "perf-stats", "pass", "block", "Add", "Edit", "Delete", "Move"}
)

// allBoundedFortiLines is one line for every bounded FortiGate signature: 20 ids x (26 actions + none) = 540.
func allBoundedFortiLines() []string {
	var out []string
	for _, id := range allFgIDs {
		for _, a := range allFgActions {
			if a == "" {
				out = append(out, fmt.Sprintf(`logid="%s" type="event"`, id))
			} else {
				out = append(out, fmt.Sprintf(`logid="%s" type="event" action="%s"`, id, a))
			}
		}
	}
	return out
}

// The largest bounded vocabulary is 540 signatures, and the bucket quota for bounded rows is at least that (so each has its own row).
func TestBoundedVocabularyFitsTheQuotas(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	seen := map[string]bool{}
	for _, l := range allBoundedFortiLines() {
		r := e.svc.sigs.Of("fortigate", l)
		if !r.Bounded {
			t.Fatalf("not bounded: %s -> %+v", l, r)
		}
		seen[r.Signature] = true
	}
	if len(seen) != 540 || MaxBoundedPerBucket < len(seen) || MaxBoundedPerDay < len(seen) {
		t.Fatalf("%d bounded FortiGate signatures, bucket quota %d, day quota %d", len(seen), MaxBoundedPerBucket, MaxBoundedPerDay)
	}
}

// H-1: a spoof of every bounded FortiGate signature (540; the room is 20 an hour, 480 a day) never ages out unannounced: each one is announced
// on its own or named in a backlog summary before it stops being new; and a real bounded event that arrives an hour after the flood is
// announced in the first pass with room, not a day later.
func TestContract_Events_BoundedOverflowIsNeverSilent(t *testing.T) {
	t.Parallel()
	for _, reps := range []int{1, 2, 50} { // a real event of one, two or fifty lines: the count does not put it behind a flood of 1-line items
		t.Run(fmt.Sprintf("real event of %d lines", reps), func(t *testing.T) { t.Parallel(); boundedOverflow(t, reps) })
	}
}

func boundedOverflow(t *testing.T, reps int) {
	t.Helper()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.warmSource("fortigate", "192.168.10.1")
	hist := sigFor(22) // the history of the source: not new
	realLine := `logid="0101039947" type="event" action="tunnel-up" dstip=203.0.113.9`
	realSig := e.svc.sigs.Of("fortigate", realLine).Signature
	var spoof []string
	want := map[string]bool{}
	for _, l := range allBoundedFortiLines() {
		if sig := e.svc.sigs.Of("fortigate", l).Signature; sig != hist && sig != realSig {
			spoof = append(spoof, l)
			want[sig] = true
		}
	}
	ingestAll(e, src, len(spoof), func(i int) string { return spoof[i] }, 1)
	start := e.svc.now()
	realAt := time.Duration(-1)
	for step := 0; step < 24*12; step++ {
		if step == 12 {
			e.feed(src, realLine, reps)
		}
		before := len(p.events())
		e.detect()
		for _, ev := range p.events()[before:] {
			notifyAccepts(t, ev)
			if ev.Target == BoundedPrefix+realSig && realAt < 0 {
				realAt = e.svc.now().Sub(start) - time.Hour
			}
		}
		e.advance(5 * time.Minute)
	}
	announced := map[string]bool{}
	backlogs := 0
	for _, ev := range p.events() {
		if sig, ok := strings.CutPrefix(ev.Target, BoundedPrefix); ok && !strings.HasPrefix(sig, BacklogTarget) {
			announced[sig] = true
			continue
		}
		backlogs++
		if !strings.HasPrefix(ev.Target, BoundedPrefix+BacklogTarget+" ") {
			t.Fatalf("an event of neither kind: %+v", ev)
		}
		for _, line := range strings.Split(ev.What, "\n") {
			if rest, ok := strings.CutPrefix(line, "New: "); ok {
				if i := strings.LastIndex(rest, " ("); i > 0 {
					announced[rest[:i]] = true // named in the summary
				}
			}
		}
	}
	missing := 0
	for sig := range want {
		if !announced[sig] {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("%d of %d bounded signatures aged out without being announced or named (%d backlog summaries)", missing, len(want), backlogs)
	}
	if backlogs == 0 {
		t.Fatal("no backlog summary")
	}
	if realAt < 0 || realAt > 5*time.Minute {
		t.Fatalf("the real bounded event was announced %v after it happened", realAt)
	}
	// the hourly limit holds, summaries included
	if n := count(t, e.vol, `SELECT max(c) FROM (SELECT count(*) c FROM (SELECT DISTINCT target, sent_at FROM logs_anomaly_sent WHERE kind <> 'covered' AND bounded = 1) GROUP BY substr(sent_at, 1, 13))`); n > EventsPerHour {
		t.Fatalf("%d events in an hour", n)
	}
}

// M-3: the room of the hour is per class: 20 mined events do not use up the room of a bounded one.
func TestContract_Events_MinedRoomIsNotTheBoundedRoom(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.warmSource("fortigate", "192.168.10.1")
	minedFlood(e, src, EventsPerHour) // exactly the room: 20 mined events, one each
	e.detect()
	n := len(p.events())
	if n != EventsPerHour || len(summaries(p)) != 0 {
		t.Fatalf("%d events", n)
	}
	e.advance(5 * time.Minute)
	e.feed(src, realNew, 1)
	e.detect()
	if got := p.events()[n:]; len(got) != 1 || !strings.Contains(got[0].Title, "0100044547") {
		t.Fatalf("the bounded new after a full mined room: %+v", got)
	}
}

// H-2: notify groups incidents by (kind, source, target). A mined incident and a bounded event about the same destination must not
// have the same target, or the bounded event only counts up the mined incident (and its title stays the old one).
func TestContract_Events_BoundedTargetIsNotTheMinedTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.warmSource("fortigate", "192.168.10.1")
	// an unlisted log id: the miner reads it, the event is about the destination
	e.feed(src, `logid="0000000015" type="traffic" subtype="forward" srcip=192.168.1.5 dstip=10.0.0.5 dstport=443 action="start"`, 3)
	e.detect()
	e.advance(2 * time.Hour)
	e.feed(src, `logid="0100044547" type="event" subtype="system" action="Edit" dstip=10.0.0.5 msg="Edit system.admin"`, 1)
	e.detect()
	got := p.events()
	if len(got) != 2 {
		t.Fatalf("%d events: %+v", len(got), got)
	}
	// notify's dedupe key (modules/notify/incidents.go dedupeKey): sha256(kind \x00 source \x00 target); logs does not import notify.
	key := func(ev AnomalyEvent) [32]byte {
		return sha256.Sum256([]byte("log_anomaly\x00" + ev.Source + "\x00" + ev.Target))
	}
	if got[0].Target != "10.0.0.5" || got[1].Target != BoundedPrefix+"logid=0100044547 action=Edit" || key(got[0]) == key(got[1]) {
		t.Fatalf("one incident would absorb the other: %q and %q", got[0].Target, got[1].Target)
	}
	if !strings.Contains(got[1].What, "Destination: 10.0.0.5") {
		t.Fatalf("the destination is in the text: %q", got[1].What)
	}
	open := map[[32]byte]bool{}
	for _, ev := range got {
		open[key(ev)] = true
	}
	if len(open) != 2 {
		t.Fatalf("%d incidents for 2 events", len(open))
	}
}

// M-4: the digest takes items round-robin across the sources: one source's flood of bounded signatures does not hide another source's
// realLine event.
func TestContract_INV6_DigestIsRoundRobinAcrossSources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.warmSource("fortigate", "192.168.10.1")
	b, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "FW-B", SenderIP: "192.168.10.2", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	*e.clock = t0
	e.history(b, 3)
	*e.clock = t0.Add(3*24*time.Hour + 2*time.Hour)
	all := allBoundedFortiLines()
	ingestAll(e, a, 60, func(i int) string { return all[i+30] }, 1) // 60 bounded new of A (rarest first: same count, ties by newest)
	e.feed(b, realNew, 1)
	d := e.digest()
	if len(d.New) != DigestMax {
		t.Fatalf("%d items", len(d.New))
	}
	pos := -1
	for i, n := range d.New {
		if n.SourceID == b.ID {
			pos = i
		}
	}
	if pos < 0 || pos > 1 {
		t.Fatalf("the realLine event of source B is at position %d of the digest", pos)
	}
}

// A steady trickle of fresh bounded kinds (21 or 25 an hour, more than a backlog summary leaves room for) keeps a real event from being
// only named in backlogs: when a summary goes out, one individual place of the hour is for the item that has been named longest and
// still waits (first in, first out), so the real event has its own event within a couple of hours. And every item of the trickle is
// announced or named before it ages out.
func TestContract_Events_TrickleDoesNotKeepARealEventInTheBacklog(t *testing.T) {
	t.Parallel()
	for _, perHour := range []int{21, 25} {
		t.Run(fmt.Sprintf("%d an hour", perHour), func(t *testing.T) {
			t.Parallel()
			trickle(t, perHour)
		})
	}
}

func trickle(t *testing.T, perHour int) {
	t.Helper()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.warmSource("fortigate", "192.168.10.1")
	realLine := `logid="0101039947" type="event" action="tunnel-up" dstip=203.0.113.9`
	realSig := e.svc.sigs.Of("fortigate", realLine).Signature
	var spoof []string
	for _, l := range allBoundedFortiLines() {
		if sig := e.svc.sigs.Of("fortigate", l).Signature; sig != sigFor(22) && sig != realSig {
			spoof = append(spoof, l)
		}
	}
	e.feed(src, realLine, 1)
	start := e.svc.now()
	realAt := time.Duration(-1)
	used := 0
	seen := map[string]bool{}
	for step := 0; step < 40*12; step++ { // 16 hours of trickle, then time for the first ones to age out
		if step%12 == 0 && step < 16*12 && used < len(spoof) {
			e.advance(time.Second)
			k := min(perHour, len(spoof)-used)
			ingestAll(e, src, k, func(i int) string { return spoof[used+i] }, 1)
			used += k
		}
		before := len(p.events())
		e.detect()
		for _, ev := range p.events()[before:] {
			if ev.Target == BoundedPrefix+realSig && realAt < 0 {
				realAt = e.svc.now().Sub(start)
			}
			if sig, ok := strings.CutPrefix(ev.Target, BoundedPrefix); ok && !strings.HasPrefix(sig, BacklogTarget) {
				seen[sig] = true
			}
			for _, line := range strings.Split(ev.What, "\n") {
				if rest, ok := strings.CutPrefix(line, "New: "); ok && strings.Contains(rest, " (") {
					seen[rest[:strings.LastIndex(rest, " (")]] = true
				}
			}
		}
		e.advance(5 * time.Minute)
	}
	if realAt < 0 || realAt > 2*time.Hour+10*time.Minute {
		t.Fatalf("%d an hour: the real event had its own event after %v", perHour, realAt)
	}
	for _, l := range spoof[:used] {
		if sig := e.svc.sigs.Of("fortigate", l).Signature; !seen[sig] {
			t.Fatalf("%d an hour: %s was neither announced nor named", perHour, sig)
		}
	}
}

// detailsOf answers as one lookup per signature did: over more than one chunk of signatures, the newest non-empty destination and
// sample of each win, a signature with no row is the zero detail, and a day older than the counters kept is not read.
func TestDetailsOfIsOneLookupPerSignature(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.svc.now()
	dayOf := func(back int) string { return now.UTC().Add(-time.Duration(back) * day).Format("2006-01-02") }
	first := now.UTC().Format("2006-01-02T15:04:05.000Z")
	var sigs []string
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		for i := range 2*detailChunk + 5 {
			sig := fmt.Sprintf("sig%04d", i)
			sigs = append(sigs, sig)
			for back, row := range [][2]string{{"", "today"}, {"203.0.113.1", ""}, {"203.0.113.2", "older"}, {"", ""}} { // back 0..3
				if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?, 'ls-1', ?, ?, 1, ?, ?, 1)`,
					dayOf(back), sig, row[0], first, row[1]); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?, 'ls-1', 'sig-old', '198.51.100.9', 1, ?, 'gone', 1)`,
			dayOf(BaselineDays+3), first)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.detailsOf(t.Context(), "ls-1", append(sigs, "sig-none", "sig-old", sigs[0]), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range sigs {
		if d := got[sig]; d.dest != "203.0.113.1" || d.sample != "today" {
			t.Fatalf("%s: %+v, want the newest non-empty destination and sample", sig, d)
		}
		if one, err := e.svc.detailOf(t.Context(), "ls-1", sig, now); err != nil || one != got[sig] {
			t.Fatalf("%s: detailOf %+v %v, detailsOf %+v", sig, one, err, got[sig])
		}
	}
	if got["sig-none"] != (detail{}) || got["sig-old"] != (detail{}) {
		t.Fatalf("no row in the counters kept: %+v %+v", got["sig-none"], got["sig-old"])
	}
}
