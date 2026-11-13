package exposure

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakeGateway struct {
	g     GatewayDevice
	err   error
	calls int
}

func (f *fakeGateway) Gateway(context.Context) (GatewayDevice, error) {
	f.calls++
	return f.g, f.err
}

func withPorts(kind Kind, n int) TargetView {
	v := TargetView{Kind: kind}
	for range n {
		v.OpenPorts = append(v.OpenPorts, PortRow{IP: ipA, Port: 10443, Service: "https"})
	}
	return v
}

// D-492: what the gateway note says in each case, and that it is asked only when the box's own IP has an open port.
func TestGatewayNote(t *testing.T) {
	t.Parallel()
	gw := netip.MustParseAddr("192.168.18.1")
	cases := []struct {
		name  string
		g     *fakeGateway
		items []TargetView
		want  *GatewayView // nil: no note
		asked bool
	}{
		{"known with findings", &fakeGateway{g: GatewayDevice{IP: gw, DeviceID: "d1", Name: "fortigate-hq", OpenExploited: 3}}, []TargetView{withPorts(KindIP, 2)},
			&GatewayView{IP: new("192.168.18.1"), DeviceID: new("d1"), Name: new("fortigate-hq"), OpenExploited: 3}, true},
		{"known without findings", &fakeGateway{g: GatewayDevice{IP: gw, DeviceID: "d1", Name: "fortigate-hq"}}, []TargetView{withPorts(KindIP, 1)},
			&GatewayView{IP: new("192.168.18.1"), DeviceID: new("d1"), Name: new("fortigate-hq")}, true},
		{"not in inventory", &fakeGateway{g: GatewayDevice{IP: gw, OpenExploited: 5}}, []TargetView{withPorts(KindIP, 1)},
			&GatewayView{IP: new("192.168.18.1")}, true},
		{"gateway unknown", &fakeGateway{}, []TargetView{withPorts(KindIP, 1)}, &GatewayView{}, true},
		{"lookup fails", &fakeGateway{err: errors.New("host down")}, []TargetView{withPorts(KindIP, 1)}, &GatewayView{}, true},
		{"no open ports", &fakeGateway{g: GatewayDevice{IP: gw}}, []TargetView{withPorts(KindIP, 0)}, nil, false},
		{"only a domain has open ports", &fakeGateway{g: GatewayDevice{IP: gw}}, []TargetView{withPorts(KindDomain, 2), withPorts(KindIP, 0)}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.svc.cfg.Gateway = c.g
			got := e.svc.GatewayNote(e.ctx(), c.items)
			if (c.g.calls == 1) != c.asked {
				t.Fatalf("asked %d times, want asked=%v", c.g.calls, c.asked)
			}
			if c.want == nil {
				if got != nil {
					t.Fatalf("got %+v, want no note", got)
				}
				return
			}
			if got == nil || ptrText(got.IP) != ptrText(c.want.IP) || ptrText(got.DeviceID) != ptrText(c.want.DeviceID) || ptrText(got.Name) != ptrText(c.want.Name) || got.OpenExploited != c.want.OpenExploited {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
	// no Gateway wired: never a note
	e := newEnv(t)
	if got := e.svc.GatewayNote(e.ctx(), []TargetView{withPorts(KindIP, 1)}); got != nil {
		t.Fatalf("no gateway wired: %+v", got)
	}
}

func ptrText(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// A name a device announced is an untrusted label: control characters go, the length is bounded.
func TestGatewayNote_NameIsCleaned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("192.168.18.1"), DeviceID: "d1", Name: "fw\x00\x1b[31m\n" + strings.Repeat("é", 200)}}
	got := e.svc.GatewayNote(e.ctx(), []TargetView{withPorts(KindIP, 1)})
	if got == nil || got.Name == nil {
		t.Fatalf("got %+v", got)
	}
	if strings.ContainsAny(*got.Name, "\x00\x1b\n") || len([]rune(*got.Name)) != maxGatewayName || !strings.HasPrefix(*got.Name, "fw[31m") {
		t.Fatalf("name = %q", *got.Name)
	}
}

// The API carries the note: it decodes against the OpenAPI schema (a drift fails loudly) and is null while no IP has an open port.
func TestHandlers_GatewayInTargetList(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("192.168.18.1"), DeviceID: "d1", Name: "fortigate-hq", OpenExploited: 2}}
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	if code, b := e.call("GET", "/exposure/targets", "viewer", ""); code != 200 || b["gateway"] != nil {
		t.Fatalf("before any scan: %d %v", code, b)
	}
	ips := e.detect(ipA)
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", ips[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err != nil {
		t.Fatal(err)
	}
	code, b := e.call("GET", "/exposure/targets", "viewer", "")
	g, _ := b["gateway"].(map[string]any)
	if code != 200 || g["ip"] != "192.168.18.1" || g["device_id"] != "d1" || g["name"] != "fortigate-hq" || g["open_exploited"] != float64(2) {
		t.Fatalf("after a scan: %d %v", code, b)
	}
}
