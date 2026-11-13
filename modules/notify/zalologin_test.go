package notify_test

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// fakeQR is a QR sign-in the test drives: it waits on scan, then on confirm, then Finish answers finish.
type fakeQR struct {
	scan    chan string
	confirm chan error
	finish  channel.ZaloSignedIn
	fail    error
}

func newFakeQR() *fakeQR { return &fakeQR{scan: make(chan string, 1), confirm: make(chan error, 1)} }

func (*fakeQR) QR() channel.ZaloQRImage { return channel.ZaloQRImage{Size: 29, Path: "M4 4h7v1h-7z"} }
func (f *fakeQR) WaitScan(ctx context.Context) (string, error) {
	select {
	case n := <-f.scan:
		return n, nil
	case <-ctx.Done():
		return "", channel.ErrZaloQRExpired
	}
}
func (f *fakeQR) WaitConfirm(ctx context.Context) error {
	select {
	case err := <-f.confirm:
		return err
	case <-ctx.Done():
		return channel.ErrZaloQRExpired
	}
}
func (f *fakeQR) Finish(context.Context) (channel.ZaloSignedIn, error) { return f.finish, f.fail }

func useQR(e *env, f *fakeQR, startErr error) {
	e.svc.SetZaloStartQRForTest(func(context.Context, *http.Client) (notify.ZaloQRFlowForTest, error) {
		if startErr != nil {
			return nil, startErr
		}
		return f, nil
	})
	e.t.Cleanup(func() {
		e.svc.CancelZaloLogin("admin@acme.example")
		e.svc.CancelZaloLogin("it@acme.example")
		e.svc.WaitZaloForTest()
	})
}

// waitLogin waits (by state, at most 30 s) until the sign-in of who reaches state.
func waitLogin(t *testing.T, e *env, who, state string) notify.ZaloLogin {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		v := e.svc.ZaloLoginState(who)
		if v.State == state {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("sign-in state %+v, want %s", v, state)
		}
		runtime.Gosched()
	}
}

func zaloErr(err error) string {
	if ae, ok := apierr.As(err); ok {
		return ae.Code
	}
	return ""
}

// D-447: the QR sign-in walks waiting → scanned → signed in; only then does Save take its session, and only for the administrator who
// signed in. One sign-in at a time per box; starts are rationed.
func TestContract_D447_ZaloQRSignInThenSave(t *testing.T) {
	e := newEnv(t)
	f := newFakeQR()
	f.finish = channel.ZaloSignedIn{Session: secrets.NewValue(zaloSession), Name: "Vedette Box"}
	useQR(e, f, nil)
	const admin = "admin@acme.example"
	v, err := e.svc.StartZaloLogin(e.ctx(), admin)
	if err != nil || v.State != "waiting" || v.QR == nil || v.QR.Path == "" || v.ExpiresAt == nil {
		t.Fatalf("start = %+v, %v", v, err)
	}
	if _, err := e.svc.StartZaloLogin(e.ctx(), "it@acme.example"); zaloErr(err) != "login_busy" {
		t.Errorf("a second administrator during a sign-in: %v", err)
	}
	if _, err := e.svc.StartZaloLogin(e.ctx(), admin); zaloErr(err) != "login_too_soon" {
		t.Errorf("a new QR code at once: %v", err)
	}
	if got := e.svc.ZaloLoginState("it@acme.example"); got.State != "none" {
		t.Errorf("another administrator sees %+v", got)
	}
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "8000000001", "group": "true", "name": "IT team", "account": "typed by the client"}, MinSeverity: notify.Low, ZaloLogin: true}
	if _, err := e.svc.SaveChannel(e.ctx(), admin, channel.ZaloPersonal, in); zaloErr(err) != "login_required" {
		t.Errorf("save before the sign-in finished: %v", err)
	}
	f.scan <- "Phone owner"
	if v := waitLogin(t, e, admin, "scanned"); v.Name != "Phone owner" || v.QR == nil {
		t.Errorf("scanned = %+v", v)
	}
	f.confirm <- nil
	if v := waitLogin(t, e, admin, "signed_in"); v.Name != "Vedette Box" || v.QR != nil {
		t.Errorf("signed in = %+v", v)
	}
	if _, err := e.svc.SaveChannel(e.ctx(), "it@acme.example", channel.ZaloPersonal, in); zaloErr(err) != "login_required" {
		t.Errorf("another administrator saved the sign-in: %v", err)
	}
	c := e.save(channel.ZaloPersonal, in)
	if c.Fields["account"] != "Vedette Box" || c.Fields["name"] != "IT team" || c.SecretLast4 == nil {
		t.Errorf("saved %+v", c)
	}
	if got := e.svc.ZaloLoginState(admin); got.State != "none" {
		t.Errorf("after the save the sign-in is %+v", got)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.zalo_login' AND detail = 'QR sign-in: signed in as Vedette Box'`) != 1 {
		t.Error("the sign-in is not in the audit log")
	}
	// Saving again without a new sign-in keeps the session and the account name.
	in.ZaloLogin = false
	if c := e.save(channel.ZaloPersonal, in); c.Fields["account"] != "Vedette Box" {
		t.Errorf("account after a plain save: %+v", c.Fields)
	}
	in.Secret = zaloSession // a pasted session (API only): the signed-in account's name no longer applies
	if c := e.save(channel.ZaloPersonal, in); c.Fields["account"] != "" {
		t.Errorf("account after a pasted session: %+v", c.Fields)
	}
}

// Five QR sign-ins an hour per box, whatever became of them (review L6).
func TestZaloQRSignInsAreFiveAnHour(t *testing.T) {
	e := newEnv(t)
	useQR(e, nil, &channel.ProviderError{Channel: channel.ZaloPersonal, Code: -1, Reason: "x"})
	for i := range 5 {
		if _, err := e.svc.StartZaloLogin(e.ctx(), "admin@acme.example"); zaloErr(err) != "zalo_unreachable" {
			t.Fatalf("start %d: %v", i+1, err)
		}
		e.clock.Add(31 * time.Second)
	}
	if _, err := e.svc.StartZaloLogin(e.ctx(), "admin@acme.example"); zaloErr(err) != "too_many_logins" {
		t.Fatalf("sixth start in the hour: %v", err)
	}
	e.clock.Add(time.Hour)
	if _, err := e.svc.StartZaloLogin(e.ctx(), "admin@acme.example"); zaloErr(err) != "zalo_unreachable" {
		t.Fatalf("an hour later: %v", err)
	}
}

func TestZaloQRSignInDeclinedOrFailed(t *testing.T) {
	e := newEnv(t)
	f := newFakeQR()
	useQR(e, f, nil)
	if _, err := e.svc.StartZaloLogin(e.ctx(), "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	f.scan <- ""
	f.confirm <- channel.ErrZaloQRDeclined
	waitLogin(t, e, "admin@acme.example", "declined")

	e2 := newEnv(t)
	useQR(e2, nil, &channel.ProviderError{Channel: channel.ZaloPersonal, Code: -1, Reason: "x"})
	if _, err := e2.svc.StartZaloLogin(e2.ctx(), "admin@acme.example"); zaloErr(err) != "zalo_unreachable" {
		t.Errorf("no QR code: %v", err)
	}
	if v := e2.svc.ZaloLoginState("admin@acme.example"); v.State != "failed" || v.Error == "" {
		t.Errorf("state after a failed start %+v", v)
	}
}

func TestZaloResolveRefusesAtTheEdge(t *testing.T) {
	e := newEnv(t)
	for _, q := range []string{"", "hello", "https://evil.example/g/abcdef1", strings.Repeat("1", 300)} {
		if _, err := e.svc.ResolveZalo(e.ctx(), "admin@acme.example", q); zaloErr(err) != "bad_query" {
			t.Errorf("%q: %v", q, err)
		}
	}
	if got, err := e.svc.ResolveZalo(e.ctx(), "admin@acme.example", " 2938475610293847561 "); err != nil || got.ID != "2938475610293847561" || got.Group {
		t.Errorf("a typed ID: %+v, %v", got, err)
	}
	if _, err := e.svc.ResolveZalo(e.ctx(), "admin@acme.example", "https://zalo.me/g/rowukgvsyq24kacrh4ii"); zaloErr(err) != "no_session" {
		t.Errorf("a link without a session: %v", err)
	}
	if _, err := e.svc.ListZaloContacts(e.ctx(), "admin@acme.example"); zaloErr(err) != "no_session" {
		t.Errorf("contacts without a session: %v", err)
	}
	if e.net.total() != 0 {
		t.Errorf("%d requests left the box", e.net.total())
	}
}

// fakeLinkCodes is the LinkCodes port (module response in production).
type fakeLinkCodes struct {
	mu      sync.Mutex
	asked   []string
	dropped []string
	err     error
}

func (f *fakeLinkCodes) DropChatLink(_ context.Context, actor, userID string, _ channel.Type, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, actor+"|"+userID+"|"+address)
	return nil
}

func (f *fakeLinkCodes) ChatLinkToken(_ context.Context, userID string, _ channel.Type, address string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, userID+"|"+address)
	return "0a1b2c3d-tokenTOKENtoken0123456", "IT Operator", f.err
}

// D-447: saving a Zalo approver sends a confirm link to that Zalo from the box's account; the dialog shows the approver waiting until
// they confirm it signed in (response's proof); Send again makes a new link; a refusal of response reaches the administrator; removing a
// linked approver is audited. The token is never in the audit log.
func TestContract_D447_ZaloApproverLinkCodes(t *testing.T) {
	links := &fakeLinks{}
	codes := &fakeLinkCodes{}
	e := newZaloEnv(t, func(c *notify.Config) { c.ApproverLinks, c.LinkCodes = links, codes })
	z := &zaloRecorder{codes: func() int { return 0 }}
	e.svc.SetZaloToForTest(z.direct)
	e.svc.SetZaloSelfForTest(func(context.Context, channel.Sender) (string, error) { return "", nil }) // the box's account is none of these
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-op", Address: zaloOp, Name: "Op on Zalo"}}}
	c := e.save(channel.ZaloPersonal, in)
	e.svc.WaitZaloForTest()
	if len(c.Approvers) != 1 || c.Approvers[0].Name != "Op on Zalo" {
		t.Errorf("approvers %+v", c.Approvers)
	}
	if len(z.sent) != 1 || z.sent[0].to != zaloOp || !strings.Contains(z.sent[0].msg.Title, "open this link and sign in to Vedette as IT Operator to link this Zalo account to IT Operator: https://box.example:8443/link/zalo?c=0a1b2c3d-tokenTOKENtoken0123456 ") {
		t.Fatalf("sent %+v", z.sent)
	}
	st, err := e.svc.ZaloApprovers(e.ctx(), "admin@acme.example")
	if err != nil || len(st) != 1 || st[0].State != "waiting" || st[0].SentAt == nil || st[0].Name != "Op on Zalo" {
		t.Fatalf("approvers = %+v, %v", st, err)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.zalo_link_code' AND detail LIKE '%it@acme.example%' AND detail NOT LIKE '%tokenTOKEN%'`) != 1 {
		t.Error("the code send is not audited (or the code is in it)")
	}
	e.save(channel.ZaloPersonal, in) // nothing changed for the approver: no second code
	e.svc.WaitZaloForTest()
	if len(z.sent) != 1 {
		t.Errorf("a plain save sent %d codes", len(z.sent))
	}
	codes.mu.Lock()
	codes.err = apierr.New(http.StatusTooManyRequests, "resend_too_soon", "Wait 40 seconds before asking for a new code.")
	codes.mu.Unlock()
	if _, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-op"); zaloErr(err) != "resend_too_soon" {
		t.Errorf("send again too soon: %v", err)
	}
	if _, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-admin"); zaloErr(err) != "not_listed" {
		t.Errorf("send to someone not listed: %v", err)
	}
	links.mu.Lock()
	links.linked = true
	links.mu.Unlock()
	if st, _ := e.svc.ZaloApprovers(e.ctx(), "admin@acme.example"); st[0].State != "linked" {
		t.Errorf("after the reply: %+v", st)
	}
	in.Approvers = []notify.Approver{{UserID: "u-admin", Address: zaloAdmin}}
	e.save(channel.ZaloPersonal, in)
	e.svc.WaitZaloForTest()
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.zalo_unlink' AND detail LIKE 'it@acme.example: Zalo `+zaloOp+`%'`) != 1 {
		t.Error("removing a linked approver is not audited")
	}
	if len(codes.dropped) != 1 || codes.dropped[0] != "admin@acme.example|u-op|"+zaloOp {
		t.Errorf("the old proof was not dropped: %v", codes.dropped)
	}
}

// One box sends at most 10 confirm-link messages in 10 minutes, however many approvers a save adds (review L3, D-46).
func TestZaloLinkCodeMessagesAreRationed(t *testing.T) {
	codes := &fakeLinkCodes{}
	e := newZaloEnv(t, func(c *notify.Config) { c.ApproverLinks, c.LinkCodes = &fakeLinks{}, codes })
	z := &zaloRecorder{codes: func() int { return 0 }}
	e.svc.SetZaloToForTest(z.direct)
	e.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-op", Address: zaloOp}}})
	e.svc.WaitZaloForTest()
	for i := 2; i <= 10; i++ {
		if _, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-op"); err != nil {
			t.Fatalf("code %d: %v", i, err)
		}
	}
	if _, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-op"); zaloErr(err) != "too_many_codes" {
		t.Fatalf("eleventh code: %v", err)
	}
	if len(z.sent) != 10 {
		t.Errorf("%d messages sent", len(z.sent))
	}
	if st, _ := e.svc.ZaloApprovers(e.ctx(), "admin@acme.example"); st[0].State != "not_sent" || !strings.Contains(st[0].Error, "Too many links") {
		t.Errorf("state after the ration %+v", st)
	}
	e.clock.Add(10 * time.Minute)
	if _, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-op"); err != nil {
		t.Errorf("after 10 minutes: %v", err)
	}
}

// D-447 (review round 2): an administrator's own row skips the message only when the address is the box's own signed-in Zalo account,
// which the QR sign-in proved. Any other Zalo of theirs (a friend picked by mistake, say) gets the confirm link like everyone, and
// nothing links it until that link is confirmed.
func TestContract_D447_AdminOwnZaloIsProvedUnlessItIsTheBoxAccount(t *testing.T) {
	const box = "9990009990"
	codes := &fakeLinkCodes{}
	links := &fakeLinks{}
	e := newZaloEnv(t, func(c *notify.Config) { c.ApproverLinks, c.LinkCodes = links, codes })
	z := &zaloRecorder{codes: func() int { return 0 }}
	e.svc.SetZaloToForTest(z.direct)
	e.svc.SetZaloSelfForTest(func(context.Context, channel.Sender) (string, error) { return box, nil })
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-admin", Address: zaloAdmin}, {UserID: "u-op", Address: zaloOp}}}
	e.save(channel.ZaloPersonal, in)
	e.svc.WaitZaloForTest()
	if len(z.sent) != 2 || z.sent[0].to != zaloAdmin || z.sent[1].to != zaloOp {
		t.Fatalf("messages %+v: my own other Zalo gets the link too", z.sent)
	}
	e.clock.Add(time.Minute)
	mine, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-admin")
	if err != nil || mine.Link != "" || !mine.Self || mine.BoxAccount || len(z.sent) != 3 || z.sent[2].to != zaloAdmin {
		t.Fatalf("send again for my own other Zalo: %+v, %v; messages %d", mine, err, len(z.sent))
	}
	if st, _ := e.svc.ZaloApprovers(e.ctx(), "admin@acme.example"); st[0].State != "waiting" {
		t.Fatalf("linked without the confirm from the link: %+v", st[0])
	}
	// The box's own account: no message, the confirm page comes back for this session.
	in.Approvers = []notify.Approver{{UserID: "u-admin", Address: box}}
	e.save(channel.ZaloPersonal, in)
	e.svc.WaitZaloForTest()
	if len(z.sent) != 3 {
		t.Fatalf("a message went to the box's own account: %+v", z.sent[3:])
	}
	e.clock.Add(time.Minute)
	own, err := e.svc.SendZaloCode(e.ctx(), "admin@acme.example", "u-admin")
	if err != nil || own.Link != "/link/zalo?c=0a1b2c3d-tokenTOKENtoken0123456" || !own.BoxAccount || len(z.sent) != 3 {
		t.Fatalf("own box account: %+v, %v; messages %d", own, err, len(z.sent))
	}
}

// D-447 (review round 2): deleting the channel ends the approvers' proofs, so a recreated channel does not show them linked.
func TestZaloDeleteChannelDropsTheApproversProofs(t *testing.T) {
	codes := &fakeLinkCodes{}
	e := newZaloEnv(t, func(c *notify.Config) { c.ApproverLinks, c.LinkCodes = &fakeLinks{}, codes })
	e.svc.SetZaloToForTest((&zaloRecorder{codes: func() int { return 0 }}).direct)
	e.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-op", Address: zaloOp}}})
	e.svc.WaitZaloForTest()
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.ZaloPersonal); err != nil {
		t.Fatal(err)
	}
	if len(codes.dropped) != 1 || codes.dropped[0] != "admin@acme.example|u-op|"+zaloOp {
		t.Fatalf("dropped %v", codes.dropped)
	}
}
