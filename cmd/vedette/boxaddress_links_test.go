package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// saveBoxAddressSQL writes core's Box address setting the way PUT /core/network/box-address does (the stack has no host, so the route is 409).
const saveBoxAddressSQL = `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('core_box_address', ?, '2026-11-13T09:00:00.000Z', 'admin@acme.example')
ON CONFLICT (key) DO UPDATE SET value = excluded.value`

// fixedNameRE is a link to the fixed name "vedette" (any port or path): what every link of an appliance read before D-465.
var fixedNameRE = regexp.MustCompile(`https?://vedette([:/"'\s]|$)`)

// TestEveryLinkCarriesTheBoxAddress pins D-465 on the binary's real wiring (wireBoxAddr, as serve does it, over core's saved setting):
// every path that makes a link of the box renders it with the Box address and never with the fixed name vedette: the notify test
// message, the sign-in code mail, an approval request, the block list URL, a URL honey token and the agent install address. A new
// Box address applies to the next link without a restart.
func TestEveryLinkCarriesTheBoxAddress(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { wireBoxAddr(d, true, nil, "0.0.0.0:8443") })
	for _, m := range []string{"notify", "inventory", "response", "honeypot", "agent-intake"} {
		if !s.d.Reg.Enabled(m) {
			s.setModule(m, true)
		}
	}
	ctx := t.Context()
	setBox := func(addr string) {
		t.Helper()
		s.exec(saveBoxAddressSQL, `{"address":"`+addr+`"}`) //nolint:contextcheck // the stack's own helper
		s.d.BoxAddr.Invalidate()                            //nolint:contextcheck // what core's AddressesChanged does after a save (no context there)
		if got := s.d.BoxAddr.Host(ctx); got != addr {
			t.Fatalf("Box address %q, want %q", got, addr)
		}
	}
	setBox("192.168.18.141")

	op := s.addUser("op@acme.example", routes.Operator)
	sink := newSMTPSink(t)
	s.email(sink, notify.Approver{UserID: op.ID, Address: "op@acme.example"})
	s.exec(`INSERT INTO resp_identity (user_id, channel, address, linked_at) VALUES (?, 'email', 'op@acme.example', '2026-11-10T09:00:00.000Z')`, op.ID) // proved in My account (D-191)
	n := newNotify(s.d)
	if r, err := n.TestChannel(ctx, "admin@acme.example", channel.Email); err != nil || !r.OK {
		t.Fatalf("test message: %+v %v", r, err)
	}
	if err := n.CodeMailer().SendCode(ctx, "it@acme.example", "123456"); err != nil {
		t.Fatalf("sign-in code mail: %v", err)
	}
	if _, err := n.SendApprovalRequest(ctx, notify.ApprovalRequest{ID: "req-1", Title: "Block 203.0.113.9", What: "w", Action: "a",
		Severity: notify.High, Expires: time.Now().Add(time.Hour), Channels: []channel.Type{channel.Email}}); err != nil {
		t.Fatalf("approval request: %v", err)
	}
	var links []string
	for i, m := range sink.messages() {
		body := mailBody(t, m)
		u := regexp.MustCompile(`https?://[^\s"'<>)]+`).FindString(body)
		if u == "" {
			t.Fatalf("mail %d has no link:\n%s", i, body)
		}
		links = append(links, u)
	}
	if len(links) != 3 {
		t.Fatalf("%d mails, want the test message, the code mail and the approval request", len(links))
	}
	code, out := s.do("GET", "/response/blocklist", "admin", "")
	if code != 200 {
		t.Fatalf("block list: %d %v", code, out)
	}
	links = append(links, str(out["url"]))
	tok, err := s.d.Honeypot.AddToken(ctx, "admin@acme.example", honeypot.TokenInput{Type: honeypot.TokenURL, Name: "Wiki", PlantAt: "Intranet wiki"})
	if err != nil {
		t.Fatalf("URL token: %v", err)
	}
	links = append(links, tok.Value)
	code, out = s.do("GET", "/inventory/agents", "admin", "")
	if code != 200 {
		t.Fatalf("agents: %d %v", code, out)
	}
	links = append(links, str(out["server_url"]))
	for i, u := range links {
		if !strings.HasPrefix(u, "https://192.168.18.141:8443") || fixedNameRE.MatchString(u) {
			t.Errorf("link %d = %q, want https://192.168.18.141:8443…", i, u)
		}
	}

	setBox("vedette.office.lan") // a save applies to the next link
	if _, out = s.do("GET", "/response/blocklist", "admin", ""); !strings.HasPrefix(str(out["url"]), "https://vedette.office.lan:8443/api/v1/response/blocklist/") {
		t.Errorf("after a new Box address the block list URL is %v", out["url"])
	}
	if _, out = s.do("GET", "/inventory/agents", "admin", ""); str(out["server_url"]) != "https://vedette.office.lan:8443" {
		t.Errorf("after a new Box address the install address is %v", out["server_url"])
	}
	if !s.d.BoxAddr.Allows("vedette.office.lan:8443") || s.d.BoxAddr.Allows("vedette:8443") {
		t.Error("the Host allowlist does not follow the Box address")
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
