package sensoractive

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"
)

var ownIP = netip.MustParseAddr("8.8.8.8")

// readExternal is the parse of an external run as ScanExternal does it: the XML limits (INV-7), then externalOf's own bounds over
// every host nmap reported (D-514).
func readExternal(data []byte) (External, error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return External{}, err
	}
	return externalOf(all, ownIP)
}

// D-514: what -sV read on each open port of the box's own IP: the application CPE only, the extra info, a service with no
// version (nginx), a tcpwrapped port; Ports is the probed list, not the open ports.
func TestExternalServicesFromTheXML(t *testing.T) {
	t.Parallel()
	got, err := readExternal(fixture(t, "external.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []ExternalService{
		{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "7.4p1 Debian 10+deb9u7", CPE: "cpe:/a:openbsd:openssh:7.4p1", Extra: "protocol 2.0"},
		{Port: 443, Name: "http", Product: "nginx", CPE: "cpe:/a:igor_sysoev:nginx"},
		{Port: 8443, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)"},
		{Port: 10443, Name: "tcpwrapped"},
	}
	if got.Ports != 98 || !slices.Equal(got.Services, want) {
		t.Fatalf("got %d ports %+v", got.Ports, got.Services)
	}
}

// The output is untrusted (INV-7, D-514): an answer outside what was asked fails the whole run, never a part of it; a DOCTYPE with
// an internal subset (an entity) is refused before anything is read; nmap giving up on the host is said, not read as "no service".
func TestExternalOutputFailsClosed(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	host := base[strings.Index(base, "<host ") : strings.Index(base, "</host>")+len("</host>")]
	port := `<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="ssh" method="table" conf="3"/></port>`
	deep := strings.Repeat("<a>", 12) + strings.Repeat("</a>", 12)
	for name, c := range map[string]struct {
		data []byte
		want error
	}{
		"a port that was not probed": {fixture(t, "external_unprobed.xml"), errXMLInvalid},
		"a UDP port":                 {fixture(t, "external_udp.xml"), errXMLInvalid},
		"an entity in the DOCTYPE":   {fixture(t, "external_entity.xml"), errXMLInvalid},
		"nmap gave up on the host":   {fixture(t, "external_timedout.xml"), ErrHostTimedOut},
		"the host twice":             {[]byte(strings.Replace(base, host, host+host, 1)), errXMLInvalid},
		"a port twice":               {[]byte(strings.Replace(base, "</ports>", port+"</ports>", 1)), errXMLInvalid},
		"too deep":                   {[]byte(strings.Replace(base, "<hostnames/>", "<hostnames>"+deep+"</hostnames>", 1)), errXMLInvalid},
		"over the size limit":        {append([]byte(base), bytes.Repeat([]byte(" "), maxOutput)...), errXMLTooBig},
		"cut off":                    {[]byte(base[:len(base)/2]), errXMLInvalid},
		"another charset":            {[]byte(strings.Replace(base, `encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1)), errXMLInvalid},
		"an external DTD":            {[]byte(strings.Replace(base, "<!DOCTYPE nmaprun>", `<!DOCTYPE nmaprun SYSTEM "http://203.0.113.9/x.dtd">`, 1)), errXMLInvalid},
	} {
		if _, err := readExternal(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	// #723 review L3: a host of another address fails the run, with or without the target's; no usable host is not "0 open ports"
	other := strings.Replace(host, `addr="8.8.8.8"`, `addr="1.1.1.1"`, 1)
	down := strings.Replace(host, `state="up"`, `state="down"`, 1)
	for name, data := range map[string]string{
		"another host as well": strings.Replace(base, host, host+other, 1),
		"only another host":    strings.Replace(base, host, other, 1),
		"no host":              strings.Replace(base, host, "", 1),
		"the host down":        strings.Replace(base, host, down, 1),
	} {
		if got, err := readExternal([]byte(data)); !errors.Is(err, errXMLInvalid) {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
}

// FuzzExternalOf: whatever the XML, what reaches exposure is at most one row per probed TCP port, printable text of at most 200
// runes, and an application CPE or nothing.
func FuzzExternalOf(f *testing.F) {
	for _, n := range []string{"external.xml", "external_unprobed.xml", "external_udp.xml", "external_timedout.xml", "external_entity.xml", "device.xml"} {
		f.Add(fixture(f, n))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ext, err := readExternal(data)
		if err != nil {
			return
		}
		if ext.Ports != len(externalPorts) || len(ext.Services) > len(externalPorts) {
			t.Fatalf("%d services of %d ports", len(ext.Services), ext.Ports)
		}
		seen := map[int]bool{}
		for _, s := range ext.Services {
			if !slices.Contains(externalPorts, s.Port) || seen[s.Port] {
				t.Fatalf("port %d", s.Port)
			}
			seen[s.Port] = true
			for _, v := range []string{s.Name, s.Product, s.Version, s.Extra} {
				if v != "" && (text(v) != v || utf8.RuneCountInString(v) > maxText) {
					t.Fatalf("unchecked text %q", v)
				}
			}
			if s.CPE != "" && (!strings.HasPrefix(s.CPE, "cpe:/a:") || cpeText(s.CPE) != s.CPE) {
				t.Fatalf("cpe %q", s.CPE)
			}
		}
	})
}

type yesFence struct{}

func (yesFence) OwnEgress(context.Context, netip.Addr) (bool, error) { return true, nil }

// #723 review L4: the module turned off (Stop) while a run waited for the nmap slot ends it once it has the slot, before it asks or
// sends anything: an external run and a picked identification alike.
func TestStopDuringTheSlotWaitIsHonoured(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now}
		s.runMu.Lock() // another nmap run holds the slot
		ext, ident := make(chan error, 1), make(chan error, 1)
		go func() { _, err := s.ScanExternal(t.Context(), ownIP, yesFence{}); ext <- err }()
		go func() { _, err := s.IdentifyDevice(t.Context(), "a-web"); ident <- err }()
		synctest.Wait() // both wait for the slot
		s.Stop()
		s.runMu.Unlock()
		for name, ch := range map[string]chan error{"external": ext, "identify": ident} {
			if err := <-ch; !errors.Is(err, ErrStopped) {
				t.Errorf("%s: err = %v, want ErrStopped", name, err)
			}
		}
	})
}

// #723 review L5: with less of the caller's time left than the run needs (the worker's fence, nmap's 3-minute host timeout, the
// pickup and the result), the run is skipped before it waits, asks or sends anything.
func TestExternalSkippedWhenTooLittleTimeIsLeft(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now}
		ctx, cancel := context.WithTimeout(t.Context(), externalNeed+coreFenceTime-time.Second)
		defer cancel()
		if _, err := s.ScanExternal(ctx, ownIP, yesFence{}); !errors.Is(err, ErrNoTime) {
			t.Fatalf("err = %v, want ErrNoTime", err)
		}
	})
}
