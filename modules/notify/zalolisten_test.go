package notify_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

const zaloStranger = "4756102938475610293"

// fakeInbox hands the listener the texts, then ends with end.
type fakeInbox struct {
	texts []channel.ZaloText
	end   error
}

func (f *fakeInbox) Run(_ context.Context, take func(channel.ZaloText)) error {
	for _, m := range f.texts {
		take(m)
	}
	return f.end
}

func (*fakeInbox) Close() {}

type zaloListenEnv struct {
	*env
	dec    *recDecisions
	z      *zaloRecorder
	mu     sync.Mutex
	opens  int
	inbox  *fakeInbox
	openEr error
	events []map[string]string
}

func newZaloListenEnv(t *testing.T, res notify.DecisionResult, decideErr error) *zaloListenEnv {
	dec := &recDecisions{res: res, err: decideErr}
	l := &zaloListenEnv{dec: dec, inbox: &fakeInbox{end: channel.ErrZaloReplaced}}
	l.env = newEnv(t, func(c *notify.Config) { c.Decisions = dec })
	l.z = l.zaloApprovals()
	l.svc.SetZaloListenForTest(func(context.Context, channel.Sender) (notify.ZaloInboxForTest, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.opens++
		if l.openEr != nil {
			return nil, l.openEr
		}
		return l.inbox, nil
	})
	l.bus.Subscribe(notify.EventApprovalDecided, func(_ context.Context, ev events.Event) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		d, _ := ev.Data.(map[string]string)
		l.events = append(l.events, d)
		return nil
	})
	return l
}

// A reply code from a listed approver goes to Decisions with the sender's user ID and the normalised code (spec 7.1), and the approver
// gets the answer privately; a code from a stranger is decided too (response refuses and logs it) but answered to nobody; texts that are
// not codes decide nothing.
func TestContract_PRE8_ZaloReplyCodeIsDecidedAndAnsweredPrivately(t *testing.T) {
	l := newZaloListenEnv(t, notify.DecisionResult{Status: "approved", Message: "Approved. The action is being run; see Vedette for the result.", RequestID: "req-z1"}, nil)
	l.inbox.texts = []channel.ZaloText{
		{From: zaloAdmin, Text: " a-7kq2mx \n"},
		{From: zaloAdmin, Text: "thanks"},
		{From: zaloOp, Text: "A-7KQ2M0"}, // 0 is not in the alphabet
		{From: zaloStranger, Name: "Stranger", Text: "R-7KQ2MX"},
	}
	err := l.svc.ListenZaloForTest(l.ctx())
	if !errors.Is(err, channel.ErrZaloReplaced) {
		t.Fatalf("listen = %v", err)
	}
	got := l.dec.got()
	want := []notify.Decision{
		{Channel: channel.ZaloPersonal, ExternalID: zaloAdmin, Approve: true, Code: "A-7KQ2MX"},
		{Channel: channel.ZaloPersonal, ExternalID: zaloStranger, Approve: false, Code: "R-7KQ2MX"},
	}
	if len(got) != 2 || !sameDecisions(got, want) {
		t.Fatalf("decisions = %+v", got)
	}
	l.z.mu.Lock()
	sent := append([]sentZalo(nil), l.z.sent...)
	l.z.mu.Unlock()
	if len(sent) != 1 || sent[0].to != zaloAdmin || sent[0].msg.Kind != channel.KindReply || sent[0].msg.Title != "Approved. The action is being run; see Vedette for the result." {
		t.Fatalf("answers = %+v", sent)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) != 2 { // both were "recorded" by the fake: each publishes the decision with the request the code named
		t.Fatalf("events = %+v", l.events)
	}
	for _, ev := range l.events {
		if ev["request_id"] != "req-z1" || ev["channel"] != "zalo-personal" || ev["decision"] != "approved" {
			t.Errorf("event %+v", ev)
		}
	}
}

// decisions are made on workers: compare without order.
func sameDecisions(got, want []notify.Decision) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			return false
		}
	}
	return true
}

// A refusal is relayed with response's own words and publishes nothing; a failure of Decisions gets the fixed answer.
func TestContract_POST8_ZaloRefusalIsRelayedWithoutEvent(t *testing.T) {
	for name, c := range map[string]struct {
		res  notify.DecisionResult
		err  error
		want string
	}{
		"refused": {notify.DecisionResult{Status: "used", Message: "This code was already used."}, nil, "This code was already used."},
		"failed":  {notify.DecisionResult{}, errors.New("db down"), "Vedette could not record your decision. Try again, or open Vedette to decide."},
		"silent":  {notify.DecisionResult{Status: "expired"}, nil, "Vedette did not take this decision. Open Vedette to see why."},
	} {
		t.Run(name, func(t *testing.T) {
			l := newZaloListenEnv(t, c.res, c.err)
			l.inbox.texts = []channel.ZaloText{{From: zaloOp, Text: "R-7KQ2MX"}}
			_ = l.svc.ListenZaloForTest(l.ctx())
			if len(l.z.sent) != 1 || l.z.sent[0].to != zaloOp || l.z.sent[0].msg.Title != c.want {
				t.Fatalf("answers = %+v", l.z.sent)
			}
			if len(l.events) != 0 {
				t.Fatalf("events = %+v", l.events)
			}
		})
	}
}

// A message from someone who is not an approver is noted with their user ID (how an admin finds the ID of a new approver), once a day
// per sender; an approver's chatter is not noted.
func TestZaloMessageFromAStrangerIsNotedOnce(t *testing.T) {
	l := newZaloListenEnv(t, notify.DecisionResult{}, nil)
	l.inbox.texts = []channel.ZaloText{
		{From: zaloStranger, Name: "Lan Nguyen", Text: "hello, what is my id?"},
		{From: zaloStranger, Name: "Lan Nguyen", Text: "again"},
		{From: zaloAdmin, Text: "hi"},
	}
	_ = l.svc.ListenZaloForTest(l.ctx())
	if n := l.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.zalo_message'`); n != 1 {
		t.Fatalf("notes = %d", n)
	}
	if n := l.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.zalo_message' AND target = ? AND detail LIKE '%Lan Nguyen%' AND detail LIKE '%' || ? || '%'`, zaloStranger, zaloStranger); n != 1 {
		t.Fatal("the note does not name the sender's user ID")
	}
	if len(l.dec.got()) != 0 || len(l.z.sent) != 0 {
		t.Fatalf("decisions %v answers %v", l.dec.got(), l.z.sent)
	}
}

// The listener runs only when replies can decide something: Decisions and the recorder wired, the channel takes approvals. After a
// failed or taken-over connection it waits instead of reconnecting at once.
func TestZaloListenerRunsOnlyWhenReady(t *testing.T) {
	l := newZaloListenEnv(t, notify.DecisionResult{}, nil)
	l.openEr = errors.New("notify: zalo-personal: could not connect to Zalo")
	if err := l.svc.ListenZaloForTest(l.ctx()); err == nil || l.opens != 1 {
		t.Fatalf("first run = %v, opens %d", err, l.opens)
	}
	if err := l.svc.ListenZaloForTest(l.ctx()); err != nil || l.opens != 1 {
		t.Fatalf("a run during the wait = %v, opens %d", err, l.opens)
	}

	off := newZaloListenEnv(t, notify.DecisionResult{}, nil)
	off.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789", "group": "true"}, Secret: zaloSession, MinSeverity: notify.Low})
	if err := off.svc.ListenZaloForTest(off.ctx()); err != nil || off.opens != 0 {
		t.Fatalf("approvals off: %v, opens %d", err, off.opens)
	}

	none := newEnv(t)
	opened := false
	none.svc.SetZaloListenForTest(func(context.Context, channel.Sender) (notify.ZaloInboxForTest, error) { opened = true; return &fakeInbox{}, nil })
	none.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-admin", Address: zaloAdmin}}})
	if err := none.svc.ListenZaloForTest(none.ctx()); err != nil || opened {
		t.Fatalf("no Decisions port: %v, opened %v", err, opened)
	}
}

func TestReplyCodeNormalisation(t *testing.T) {
	for in, want := range map[string]string{
		" a-7kq2mx ": "A-7KQ2MX", "R-ABCDEF": "R-ABCDEF", "\tr-zzzzzz\r\n": "R-ZZZZZZ",
		"A-7KQ2M0": "", "A-7KQ2MXX": "", "A 7KQ2MX": "", "B-7KQ2MX": "", "A-7KQ2MI": "", "Ａ-7KQ2MX": "", " A-7KQ2MX ": "", "": "",
	} {
		code, approve, ok := notify.NormReplyCodeForTest(in)
		if code != want || ok != (want != "") || (ok && approve != (want[0] == 'A')) {
			t.Errorf("norm(%q) = %q %v %v", in, code, approve, ok)
		}
	}
}
