package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// saveBoxAddressSQL writes core's Box address setting the way PUT /core/network/box-address does (the stack has no host, so the route is 409).
const saveBoxAddressSQL = `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('core_box_address', ?, '2026-11-13T09:00:00.000Z', 'admin@acme.example')
ON CONFLICT (key) DO UPDATE SET value = excluded.value`

// fixedNameRE is a link to the fixed name "vedette" (any port or path): what every link of an appliance read before D-465.
var fixedNameRE = regexp.MustCompile(`https?://vedette([:/"'\s]|$)`)

var linkRE = regexp.MustCompile(`https?://[^\s"'<>)]+`)

// linkStack is the binary's real wiring with wireBoxAddr as serve does it (host: whether the install has vedette-host; flags: -hosts),
// with every module that makes a link on and an email channel whose sink receives the mails.
func linkStack(t *testing.T, host bool, flags []string, listen string) (*stack, *smtpSink) {
	t.Helper()
	s := newStackWith(t, func(d *deps) { wireBoxAddr(d, host, flags, listen) })
	for _, m := range []string{"notify", "inventory", "response", "honeypot", "agent-intake"} {
		if !s.d.Reg.Enabled(m) {
			s.setModule(m, true)
		}
	}
	op := s.addUser("op@acme.example", routes.Operator)
	sink := newSMTPSink(t)
	s.email(sink, notify.Approver{UserID: op.ID, Address: "op@acme.example"})
	s.exec(`INSERT INTO resp_identity (user_id, channel, address, linked_at) VALUES (?, 'email', 'op@acme.example', '2026-11-10T09:00:00.000Z')`, op.ID) // proved in My account (D-191)
	return s, sink
}

// boxLinks makes every link of the box once and returns them by name: the notify test message, the sign-in code mail and an approval
// request (mails), a finding and an incident notice (queued, the link is made when they are queued), the block list URL, a URL honey
// token and the agent install address. notices false leaves out the finding and incident notices (a second round on one stack).
func boxLinks(t *testing.T, s *stack, sink *smtpSink, notices bool) map[string]string {
	t.Helper()
	ctx := t.Context()
	n := newNotify(s.d)
	out := map[string]string{}
	mails := len(sink.messages())
	if r, err := n.TestChannel(ctx, "admin@acme.example", channel.Email); err != nil || !r.OK {
		t.Fatalf("test message: %+v %v", r, err)
	}
	if err := n.CodeMailer().SendCode(ctx, "it@acme.example", "123456"); err != nil {
		t.Fatalf("sign-in code mail: %v", err)
	}
	if _, err := n.SendApprovalRequest(ctx, notify.ApprovalRequest{ID: "req-" + time.Now().Format("150405.000000000"), Title: "Block 203.0.113.9", What: "w", Action: "a",
		Severity: notify.High, Expires: time.Now().Add(time.Hour), Channels: []channel.Type{channel.Email}}); err != nil {
		t.Fatalf("approval request: %v", err)
	}
	msgs := sink.messages()[mails:]
	if len(msgs) != 3 {
		t.Fatalf("%d mails, want the test message, the code mail and the approval request", len(msgs))
	}
	for i, name := range []string{"test message", "sign-in mail", "approval link"} {
		out[name] = linkRE.FindString(mailBody(t, msgs[i]))
	}
	if notices {
		if _, _, err := n.OpenIncident(ctx, notify.IncidentInput{Kind: notify.IncidentTrap, Source: "203.0.113.9", Target: "Decoy SMB", Title: "203.0.113.9 touched a trap",
			Severity: notify.High, What: "w", Action: "a", Link: "/honeypot"}); err != nil {
			t.Fatalf("incident: %v", err)
		}
		s.kev("CVE-2026-4001", "Fortinet", "FortiOS")
		s.addFortiGate()
		for _, q := range s.queuedNotices() {
			switch {
			case strings.Contains(q.Link, "/incidents/"):
				out["incident notice"] = q.Link
			case strings.Contains(q.Link, "/findings/"):
				out["finding notice"] = q.Link
			}
		}
	}
	code, body := s.do("GET", "/response/blocklist", "admin", "")
	if code != 200 {
		t.Fatalf("block list: %d %v", code, body)
	}
	out["block list URL"] = str(body["url"])
	tok, err := s.d.Honeypot.AddToken(ctx, "admin@acme.example", honeypot.TokenInput{Type: honeypot.TokenURL, Name: fmt.Sprintf("Wiki %d", len(sink.messages())), PlantAt: "Intranet wiki"}) // one name per round
	if err != nil {
		t.Fatalf("URL token: %v", err)
	}
	out["URL token"] = tok.Value
	code, body = s.do("GET", "/inventory/agents", "admin", "")
	if code != 200 {
		t.Fatalf("agents: %d %v", code, body)
	}
	out["install address"] = str(body["server_url"])
	return out
}

// wantLinks checks that every link starts with base followed by "/" or nothing, and none names the fixed name vedette.
func wantLinks(t *testing.T, links map[string]string, base string, want ...string) {
	t.Helper()
	for _, name := range want {
		u, ok := links[name]
		if !ok || (u != base && !strings.HasPrefix(u, base+"/")) || fixedNameRE.MatchString(u) {
			t.Errorf("%s = %q, want %s…", name, u, base)
		}
	}
}

var allLinks = []string{"test message", "sign-in mail", "approval link", "incident notice", "finding notice", "block list URL", "URL token", "install address"}

// TestEveryLinkCarriesTheBoxAddress pins D-465 on the binary's real wiring (wireBoxAddr, as serve does it, over core's saved setting):
// every path that makes a link of the box renders it with the Box address and never with the fixed name vedette: the notify test
// message, the sign-in code mail, an approval request, a finding and an incident notice, the block list URL, a URL honey token and the
// agent install address. A new Box address applies to the next link without a restart; the earlier one is still answered to (review M1).
// The Zalo confirm link (notify sendLinkCode) is made by the same link() and is pinned in modules/notify (zalologin_test.go): the stack
// has no Zalo account to send it from.
func TestEveryLinkCarriesTheBoxAddress(t *testing.T) {
	t.Parallel()
	s, sink := linkStack(t, true, nil, "0.0.0.0:8443")
	ctx := t.Context()
	setBox := func(addr string, prev ...string) {
		t.Helper()
		v := `{"address":"` + addr + `"`
		if len(prev) > 0 {
			v += `,"previous":["` + strings.Join(prev, `","`) + `"]`
		}
		s.exec(saveBoxAddressSQL, v+`}`) //nolint:contextcheck // the stack's own helper
		s.d.BoxAddr.Invalidate()         //nolint:contextcheck // what core's AddressesChanged does after a save (no context there)
		if got := s.d.BoxAddr.Host(ctx); got != addr {
			t.Fatalf("Box address %q, want %q", got, addr)
		}
	}
	setBox("192.168.18.141")
	wantLinks(t, boxLinks(t, s, sink, true), "https://192.168.18.141:8443", allLinks...)

	setBox("vedette.office.lan", "192.168.18.141") // a save applies to the next link; the earlier address stays answered to
	links := boxLinks(t, s, sink, false)
	wantLinks(t, links, "https://vedette.office.lan:8443", "test message", "approval link", "block list URL", "URL token", "install address")
	if !s.d.BoxAddr.Allows("vedette.office.lan:8443") || !s.d.BoxAddr.Allows("192.168.18.141") || s.d.BoxAddr.Allows("vedette:8443") {
		t.Error("the Host allowlist does not follow the Box address and the earlier one")
	}
}

// The default end to end (D-465): nothing saved, the management IPv4 vedette-host reports in state/net is every link's address; the
// container-only path: no host, the first usable -hosts entry; port 443 leaves the port out; an IPv6 address is bracketed.
func TestEveryLinkCarriesTheDefaultOrTheHostsAddress(t *testing.T) {
	t.Parallel()
	t.Run("management IPv4", func(t *testing.T) {
		t.Parallel()
		s, sink := linkStack(t, true, nil, "0.0.0.0:8443")
		nh, err := core.NewNetworkHandlers(core.NetworkConfig{DB: s.d.DB, Auth: s.d.Auth, Audit: s.d.Audit, Log: s.d.Log, Host: mgmtHost{"192.168.18.141/24"}})
		if err != nil {
			t.Fatal(err)
		}
		s.d.Network = nh
		s.d.BoxAddr.Invalidate()
		wantLinks(t, boxLinks(t, s, sink, true), "https://192.168.18.141:8443", allLinks...)
	})
	t.Run("-hosts, port 443", func(t *testing.T) {
		t.Parallel()
		s, sink := linkStack(t, false, []string{"*.corp.example", "localhost", "box.corp.example", "10.0.0.5"}, "0.0.0.0:443")
		links := boxLinks(t, s, sink, true)
		wantLinks(t, links, "https://box.corp.example", allLinks...)
		for name, u := range links {
			if strings.Contains(u, ":443") {
				t.Errorf("%s = %q carries :443", name, u)
			}
		}
	})
	t.Run("-hosts IPv6", func(t *testing.T) {
		t.Parallel()
		s, sink := linkStack(t, false, []string{"fd00::5"}, "[::]:8443")
		wantLinks(t, boxLinks(t, s, sink, false), "https://[fd00::5]:8443", "test message", "approval link", "block list URL", "install address")
	})
}

// mgmtHost is a vedette-host whose state/net has one management card with the given address; nothing else is asked of it here.
type mgmtHost struct{ addr string }

func (m mgmtHost) StateNet(context.Context) (api.NetState, error) {
	return api.NetState{Interfaces: []api.NetInterface{{Name: "eth0", Role: api.NetRoleManagement, Addresses: []string{m.addr}}}}, nil
}

func (mgmtHost) NetApply(context.Context, api.NetApplyArgs, string, string) (api.Run, error) {
	return api.Run{}, nil
}

func (mgmtHost) NetConfirm(context.Context, string, string, string) (api.Run, error) {
	return api.Run{}, nil
}

func (mgmtHost) NetRevert(context.Context, string, string, string) (api.Run, error) {
	return api.Run{}, nil
}

func (mgmtHost) GetRun(context.Context, string) (api.Run, error) { return api.Run{}, nil }

func (mgmtHost) Events(context.Context, string, uint64) *hostclient.Stream { return nil }

func str(v any) string {
	s, _ := v.(string)
	return s
}
