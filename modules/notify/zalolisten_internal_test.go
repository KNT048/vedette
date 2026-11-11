package notify

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// The waits of the listener: 30 s doubling to 30 minutes, 10 minutes after a takeover, never before a sign-in pause ends, cleared by a
// connection that lived 10 minutes, given up after 8 failures until the channel is saved again (a new revision starts afresh).
func TestZaloRetrySchedule(t *testing.T) {
	var r zaloRetry
	t0 := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	fail := errors.New("could not connect")
	if !r.due(1, t0) {
		t.Fatal("not due at first")
	}
	wants := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute}
	now := t0
	for i, w := range wants {
		if r.after(fail, time.Second, now) {
			t.Fatalf("gave up after %d failures", i+1)
		}
		if r.due(1, now.Add(w-time.Second)) || !r.due(1, now.Add(w)) {
			t.Fatalf("failure %d: want a wait of %v (next %v)", i+1, w, r.next.Sub(now))
		}
		now = now.Add(w)
	}
	if !r.after(fail, time.Second, now) || r.due(1, now.Add(24*time.Hour)) {
		t.Fatal("did not give up after 8 failures")
	}
	if !r.due(2, now) || r.fails != 0 {
		t.Fatal("a new revision of the channel did not start afresh")
	}
	r.after(fail, 61*time.Second, now) // ended with an error after a minute: still a failure
	if r.fails != 1 {
		t.Fatalf("fails = %d", r.fails)
	}
	r.after(fail, 10*time.Minute, now)
	if r.fails != 0 || !r.due(2, now) {
		t.Fatal("a healthy connection did not clear the failures")
	}
	r.after(channel.ErrZaloReplaced, time.Second, now)
	if r.due(2, now.Add(10*time.Minute-time.Second)) || !r.due(2, now.Add(10*time.Minute)) {
		t.Fatal("a takeover does not wait 10 minutes")
	}
	pause := now.Add(45 * time.Minute)
	r.after(&channel.BackoffError{Channel: channel.ZaloPersonal, Until: pause}, time.Second, now)
	if r.due(2, pause.Add(-time.Second)) || !r.due(2, pause) {
		t.Fatal("the sign-in pause is not honoured")
	}
}

func TestZaloNotesAreCapped(t *testing.T) {
	var n zaloNotes
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	if !n.due("1111111", now) || n.due("1111111", now.Add(time.Hour)) || !n.due("1111111", now.Add(25*time.Hour)) {
		t.Fatal("not once a day per sender")
	}
	var m zaloNotes
	ok := 0
	for i := range 30 {
		if m.due(string(rune('a'+i)), now) {
			ok++
		}
	}
	if ok != zaloNotesPerHour || !m.due("late", now.Add(time.Hour)) {
		t.Fatalf("%d notes in an hour", ok)
	}
}

func TestLinkCodeNormalisation(t *testing.T) {
	for in, want := range map[string]string{"123456": "123456", " 012345\n": "012345", "12345": "", "1234567": "", "12345a": "", "１２３４５６": ""} {
		got, ok := normLinkCode(in)
		if got != want || ok != (want != "") {
			t.Errorf("normLinkCode(%q) = %q %v", in, got, ok)
		}
	}
}
