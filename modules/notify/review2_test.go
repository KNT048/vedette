package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// A client in Config.HTTPClient is for Slack, Telegram and Zalo. It must never reach a webhook: it would skip the
// address check at connect time. The name below cannot resolve, so the guarded client fails; the shared client
// would have answered 200.
func TestWebhookNeverUsesTheSharedHTTPClient(t *testing.T) {
	e := newEnv(t) // Config.HTTPClient is the fake network of the other channels
	e.save(channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": "https://hooks.example.invalid/vedette"}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
	res, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook)
	if err != nil || res.OK {
		t.Fatalf("test result = %+v, %v: the shared client answered a webhook", res, err)
	}
	if c := e.net.to("hooks.example.invalid"); len(c) != 0 {
		t.Fatalf("the shared client carried %d webhook calls", len(c))
	}
}

// ---- approvers are checked again when the link is minted ----

func TestApprovalSkipsApproversWhoNoLongerQualify(t *testing.T) {
	cases := []struct {
		name   string
		change func(u *notify.User)
	}{
		{"disabled", func(u *notify.User) { u.Active = false }},
		{"demoted", func(u *notify.User) { u.Role = "viewer" }},
		{"email changed", func(u *notify.User) { u.Email = "new.address@acme.example" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			s := newFakeSMTP(t)
			e.email(s, func(in *notify.ChannelInput) {
				in.Approvals = true
				in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-admin", Address: "admin@acme.example"}}
			})
			e.users.mu.Lock()
			u := e.users.users["u-op"]
			c.change(&u)
			e.users.users["u-op"] = u
			e.users.mu.Unlock()
			sv, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: "req-1", Title: "Block x", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)})
			if err != nil || len(sv) != 1 {
				t.Fatalf("sends = %+v, %v", sv, err)
			}
			if rc := strings.Join(s.recipients(), " "); strings.Contains(rc, "it@acme.example") || !strings.Contains(rc, "admin@acme.example") {
				t.Fatalf("recipients = %s", rc)
			}
			if len(e.tokens.recs) != 1 || e.tokens.recs[0].UserID != "u-admin" {
				t.Fatalf("a token was minted for %+v", e.tokens.recs)
			}
			if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.approval_skipped' AND target = 'u-op'`); n != 1 {
				t.Fatalf("%d audit entries for the skipped approver, want 1", n)
			}
		})
	}
}
