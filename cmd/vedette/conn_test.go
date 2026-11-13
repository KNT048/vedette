package main

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/secrets"
)

func (s *stack) connCreate(in conn.Input) conn.Connection {
	s.t.Helper()
	var c conn.Connection
	err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) (err error) {
		c, err = s.d.Conn.Create(s.t.Context(), tx, "admin@acme.example", in)
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

func connInput(name, secret string) conn.Input {
	return conn.Input{Name: name, Kind: "http", Target: "https://192.168.10.1", AuthType: "token", Secret: secrets.NewValue(secret), Allow: []string{"https://192.168.10.1/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
}

func flow12(s *stack) string {
	s.t.Helper()
	code, v := s.do("GET", "/core/privacy", "viewer", "")
	if code != 200 {
		s.t.Fatalf("privacy = %d %v", code, v)
	}
	for _, f := range v["flows"].([]any) {
		if m := f.(map[string]any); m["id"] == float64(12) {
			return m["state"].(string)
		}
	}
	s.t.Fatal("no flow 12")
	return ""
}

// The connection store in the real wiring (D-93): the Privacy page follows the enabled connections (flow 12), the response
// catalog lists them with the write tools that are on, and response's fingerprint is core/conn's.
func TestWiringConnections(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.setModule("notify", true)
	s.setModule("inventory", true)
	s.setModule("response", true)

	if got := flow12(s); got != "off" {
		t.Fatalf("flow 12 with no connection = %s", got)
	}
	c := s.connCreate(connInput("Office firewall", "tok-0123456789-abcdef"))
	if got := flow12(s); got != "on" {
		t.Errorf("flow 12 with an enabled connection = %s", got)
	}
	_, cat := s.do("GET", "/response/catalog", "admin", "")
	list, _ := cat["connections"].([]any)
	if len(list) != 1 {
		t.Fatalf("catalog connections = %v", cat["connections"])
	}
	got := list[0].(map[string]any)
	if got["id"] != c.ID || got["name"] != "Office firewall" || got["enabled"] != true || got["kind"] != "http" || got["read_only"] != false {
		t.Errorf("catalog connection = %v", got)
	}
	if w, _ := got["write_tools"].([]any); len(w) != 1 || w[0] != "send_request" {
		t.Errorf("write tools = %v", got["write_tools"])
	}
	// What the response module fingerprints is what core/conn says.
	infos, err := responseConnections{s.d.Conn}.List(t.Context())
	if err != nil || len(infos) != 1 || infos[0].Target != c.Target || infos[0].UpdatedAt != c.UpdatedAt {
		t.Fatalf("adapter = %+v %v", infos, err)
	}

	// Turning it off ends flow 12; the catalog still lists it, off.
	off := connInput("Office firewall", "")
	off.Secret, off.Enabled = secrets.Value{}, false
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := s.d.Conn.Update(t.Context(), tx, "admin@acme.example", c.ID, off)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := flow12(s); got != "off" {
		t.Errorf("flow 12 with every connection off = %s", got)
	}

	// Delete is refused while response has a change in force on it (409 in_use), and goes through when it is rolled back.
	items := `[{"id":"it-1","connector_id":"` + c.ID + `","status":"executed"}]`
	err = s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES ('act-1', 'rule', 'p-1', 'FW', 'Block', 'low', 'executed', '2026-11-09T10:00:00.000Z', '2026-11-10T10:00:00.000Z', 1, ?)`, items)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	del := func() error {
		return s.d.DB.Write(t.Context(), func(tx *sql.Tx) error { return s.d.Conn.Delete(t.Context(), tx, "admin@acme.example", c.ID) })
	}
	err = del()
	if ae, ok := apierr.As(err); !ok || ae.Status != 409 || ae.Code != "in_use" || !strings.Contains(ae.Message, "Office firewall") {
		t.Fatalf("delete with a change in force = %v", err)
	}
	s.exec(`UPDATE resp_actions SET items = REPLACE(items, '"executed"', '"rolled_back"'), status = 'rolled_back'`)
	if err := del(); err != nil {
		t.Fatalf("delete after the rollback: %v", err)
	}
	if n := s.count(`SELECT count(*) FROM core_connection`) + s.count(`SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'`); n != 0 {
		t.Errorf("%d rows left", n)
	}
}

func (s *stack) exec(q string, args ...any) {
	s.t.Helper()
	if err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(s.t.Context(), q, args...); return err }); err != nil {
		s.t.Fatal(err)
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func contains(l []netip.Prefix, a string) bool {
	ad := netip.MustParseAddr(a)
	for _, p := range l {
		if p.Contains(ad) {
			return true
		}
	}
	return false
}

// H1: the box's own addresses are the union of the container's interfaces (whole subnets), the default gateway, the IP literals of
// -hosts, what the host says, and the decoy addresses. Each source on its own, with fakes.
func TestBoxAddrsSources(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	t.Run("nothing", func(t *testing.T) {
		if got := (&boxSources{}).BoxAddrs(ctx); len(got) != 0 {
			t.Errorf("no source gave %v", got)
		}
	})
	t.Run("the container's interfaces, with their whole subnet", func(t *testing.T) {
		b := &boxSources{ifaces: func() []netip.Prefix { return []netip.Prefix{pfx("10.88.0.5/16"), pfx("fd00:1::5/64")} }}
		got := b.BoxAddrs(ctx)
		for _, a := range []string{"10.88.0.5", "10.88.200.9", "fd00:1::99"} {
			if !contains(got, a) {
				t.Errorf("%s is not the box: %v", a, got)
			}
		}
		if contains(got, "10.89.0.1") || contains(got, "192.168.10.1") {
			t.Errorf("another network counted as the box: %v", got)
		}
	})
	t.Run("the default gateway is the host", func(t *testing.T) {
		b := &boxSources{gateways: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.88.0.1")} }}
		if got := b.BoxAddrs(ctx); !contains(got, "10.88.0.1") || contains(got, "10.88.0.2") {
			t.Errorf("gateway: %v", got)
		}
		none := &boxSources{gateways: func() []netip.Addr { return nil }}
		if got := none.BoxAddrs(ctx); len(got) != 0 {
			t.Errorf("no gateway gave %v", got)
		}
	})
	t.Run("IP literals of -hosts, not names", func(t *testing.T) {
		b := &boxSources{hosts: []string{"192.168.10.250", "[2001:db8::7]", "vedette.lan", "*.corp.example", "localhost"}}
		got := b.BoxAddrs(ctx)
		if !contains(got, "192.168.10.250") || !contains(got, "2001:db8::7") || contains(got, "192.168.10.251") {
			t.Errorf("hosts: %v", got)
		}
		if len(got) != 2 {
			t.Errorf("names were taken for addresses: %v", got)
		}
	})
	t.Run("decoys", func(t *testing.T) {
		b := &boxSources{decoys: func(context.Context) []netip.Addr {
			return []netip.Addr{netip.MustParseAddr("192.168.10.201"), netip.MustParseAddr("::ffff:192.168.10.202")}
		}}
		got := b.BoxAddrs(ctx)
		if !contains(got, "192.168.10.201") || !contains(got, "192.168.10.202") || contains(got, "192.168.10.203") {
			t.Errorf("decoys: %v", got)
		}
	})
	t.Run("a host answer is cached for 30 seconds and survives a failure", func(t *testing.T) {
		now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
		calls, fail := 0, false
		b := &boxSources{now: func() time.Time { return now }, hostNet: func(context.Context) ([]netip.Prefix, error) {
			calls++
			if fail {
				return nil, errors.New("host busy")
			}
			return []netip.Prefix{pfx("192.168.10.250/32"), pfx("fe80::1/128")}, nil
		}}
		if got := b.BoxAddrs(ctx); !contains(got, "192.168.10.250") || !contains(got, "fe80::1") {
			t.Fatalf("host: %v", got)
		}
		b.BoxAddrs(ctx)
		now = now.Add(29 * time.Second)
		b.BoxAddrs(ctx)
		if calls != 1 {
			t.Errorf("the host was asked %d times inside 30 s", calls)
		}
		now = now.Add(2 * time.Second)
		fail = true
		if got := b.BoxAddrs(ctx); calls != 2 || !contains(got, "192.168.10.250") {
			t.Errorf("after the cache expired and the host failed: %d calls, %v", calls, got)
		}
	})
	t.Run("no host is nil-safe and the union holds every source", func(t *testing.T) {
		b := &boxSources{
			ifaces: func() []netip.Prefix { return []netip.Prefix{pfx("10.88.0.5/16")} }, gateways: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.88.0.1")} },
			hosts: []string{"192.168.10.250"}, decoys: func(context.Context) []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.10.201")} },
		}
		got := b.BoxAddrs(ctx)
		for _, a := range []string{"10.88.7.7", "10.88.0.1", "192.168.10.250", "192.168.10.201"} {
			if !contains(got, a) {
				t.Errorf("%s is not the box", a)
			}
		}
	})
}

func TestDefaultGatewayFromProcNetRoute(t *testing.T) {
	t.Parallel()
	const route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100580A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000580A\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n"
	g, ok := defaultGateway(strings.NewReader(route))
	if !ok || g != netip.MustParseAddr("10.88.0.1") {
		t.Fatalf("gateway = %v %v, want 10.88.0.1", g, ok)
	}
	if _, ok := defaultGateway(strings.NewReader("Iface\tDestination\tGateway\neth0\t0000580A\t00000000\n")); ok {
		t.Error("a route table without a default route gave a gateway")
	}
	if _, ok := defaultGateway(strings.NewReader("")); ok {
		t.Error("an empty table gave a gateway")
	}
}

// D-446 deferred line: the IPv6 default gateway of the container is the machine too.
func TestDefaultGatewayFromProcNetIPv6Route(t *testing.T) {
	t.Parallel()
	const zero = "00000000000000000000000000000000"
	route := "fd000000000000000000000000000000 40 " + zero + " 00 " + zero + " 00000100 00000001 00000000 00000001 eth0\n" + // the subnet, no next hop
		zero + " 00 " + zero + " 00 fd000000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" + // ::/0 via fd00::1
		zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00200200 lo\n" // ::/0 unreachable, no next hop
	if got := defaultGateway6(strings.NewReader(route)); len(got) != 1 || got[0] != netip.MustParseAddr("fd00::1") {
		t.Fatalf("gateways = %v, want fd00::1", got)
	}
	if got := defaultGateway6(strings.NewReader("")); len(got) != 0 {
		t.Errorf("an empty table gave %v", got)
	}
}

// The binary's own list reaches core/conn: a connection to a decoy address of the honeypot or to the container's subnet is refused.
func TestWiringRefusesTheBoxItself(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.Hosts = []string{"192.168.77.9", "vedette.lan"} })
	in := connInput("Self", "tok-0123456789-abcdef")
	in.Target, in.Allow = "https://192.168.77.9", []string{"https://192.168.77.9/"}
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := s.d.Conn.Create(t.Context(), tx, "admin@acme.example", in)
		return err
	})
	if ae, ok := apierr.As(err); !ok || ae.Code != "invalid_target" || !strings.Contains(ae.Message, "the box itself") {
		t.Fatalf("a connection to an address of -hosts = %v", err)
	}
}

// INV-23: the same boxSources.BoxAddrs that refuses the box at save time is asked at dial time, about the address the name resolves to
// then: a name that was fine when it was saved and now points at the box (a -hosts address here) is not dialled.
func TestWiringTestRefusesTheBoxAtDialTime(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.Hosts = []string{"192.168.77.9"} })
	host := conntest.ResolveTo(t, "192.168.77.9")
	in := connInput("Rebound", "tok-0123456789-abcdef")
	in.Target, in.Allow = "https://"+host, []string{"https://" + host + "/"}
	var id string
	err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		c, err := s.d.Conn.Create(t.Context(), tx, "admin@acme.example", in)
		id = c.ID
		return err
	})
	if err != nil {
		t.Fatalf("a public name is fine when it is saved: %v", err)
	}
	_, err = s.d.Conn.Test(t.Context(), "admin@acme.example", id, func(context.Context, *sql.Tx) error { return nil })
	if ae, ok := apierr.As(err); !ok || ae.Code != "address_refused" || !strings.Contains(ae.Message, "the box itself") {
		t.Fatalf("a name that points at the box = %v, want 502 address_refused", err)
	}
}

// Low 6: when the store cannot be read the Privacy page says flow 12 is on: it must not claim that nothing leaves the box.
func TestPrivacyFlow12IsOnWhenTheStoreCannotBeRead(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if (privacyFacts{conns: s.d.Conn}).ConnectionsConfigured(t.Context()) {
		t.Fatal("flow 12 is on with no connection")
	}
	if err := s.d.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if !(privacyFacts{conns: s.d.Conn}).ConnectionsConfigured(t.Context()) {
		t.Error("flow 12 is off when the store cannot be read")
	}
}

// The reader the ai module is given (D-93 (3)): built with the store, it lists the read tools of a ready connection and calls one
// through the same dialer, with the box's own addresses refused at dial time.
func TestWiringConnReader(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	if s.d.ConnReader == nil {
		t.Fatal("no reader")
	}
	f := conntest.NewHTTPS(t, nil)
	in := connInput("Reader", "tok-0123456789-abcdef")
	in.Target, in.Allow = f.URL, []string{f.URL + "/api/x"}
	in.Tools = append(in.Tools, conn.ToolInput{Name: "fetch_url", Enabled: true}) // a read tool of an HTTP kind starts off (D-127)
	c := s.connCreate(in)
	if tools, err := s.d.ConnReader.ListReadTools(t.Context()); err != nil || len(tools) != 0 {
		t.Fatalf("an untested connection lists %v, %v", tools, err)
	}
	if _, err := s.d.Conn.Test(t.Context(), "admin@acme.example", c.ID, func(context.Context, *sql.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tools, err := s.d.ConnReader.ListReadTools(t.Context())
	if err != nil || len(tools) != 1 || tools[0].Name != "fetch_url" || tools[0].ConnectionID != c.ID {
		t.Fatalf("tools %v, %v", tools, err)
	}
	out, err := s.d.ConnReader.CallRead(read.WithActor(t.Context(), "ai:job-1"), c.ID, "fetch_url", map[string]any{"path": "/api/x"})
	if err != nil || out != `{"ok":true}` {
		t.Fatalf("call = %q, %v", out, err)
	}
	if _, err := s.d.ConnReader.CallRead(t.Context(), c.ID, "send_request", nil); !errors.Is(err, read.ErrUnavailable) {
		t.Errorf("a write tool = %v", err)
	}
}
