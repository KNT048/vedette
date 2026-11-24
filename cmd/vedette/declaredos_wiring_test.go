package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The OS a device page shows is the OS its findings are decided on (inventory INV-45): for every way a person's declared OS row
// meets what the sources read, the page's OS and the matcher's agree. The page asks the matcher (findings.DeclaredOSRow); this test
// reads both sides through the real wiring and compares them.
func TestWiringDeclaredOSPageIsTheMatchersOS(t *testing.T) {
	const ip = "100.66.254.1"
	snmp := func(s *stack, id, os string) {
		t.Helper()
		if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{Device: id}, Field: observe.OS, Value: os, Source: observe.SNMP, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	agent := func(s *stack, os string, rows ...observe.Software) {
		t.Helper()
		h := observe.AssetHint{IP: netip.MustParseAddr(ip), Agent: "osquery:node-1"}
		if err := s.d.Inventory.Record(t.Context(), []observe.Observation{{AssetHint: h, Field: observe.OS, Value: os, Source: observe.Agent, Confidence: 0.95}}); err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			if err := s.d.Inventory.ReplaceSoftware(t.Context(), observe.AssetHint{IP: h.IP, Agent: h.Agent}, observe.Osquery, nil, rows); err != nil {
				t.Fatal(err)
			}
		}
	}
	add := func(s *stack, in inventory.AddInput) string {
		t.Helper()
		in.IP = ip
		r, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", in)
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	manualRow := func(s *stack, id string) string {
		t.Helper()
		d, err := s.d.Inventory.Device(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, sw := range d.Software {
			if sw.Source == "manual" {
				return sw.ID
			}
		}
		t.Fatal("no declared row")
		return ""
	}
	winRelease := observe.Software{Display: "Windows 11 24H2", Vendor: "microsoft", Product: "Windows 11 24H2", Version: "10.0.26100.1742",
		CPE: "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.1742:*:*:*:*:*:*:*", KevKeys: []string{"microsoft|windows"}, Confidence: 0.95}

	for _, c := range []struct {
		name  string
		setup func(s *stack) string
		want  string // the page's OS
	}{
		{"a row with v7.2.13 alone", func(s *stack) string {
			return add(s, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"})
		}, "FortiOS 7.2.13"},
		{"SNMP's version over a row without one", func(s *stack) string {
			id := add(s, inventory.AddInput{CatalogID: "fortigate"})
			snmp(s, id, "FortiOS 7.2.12")
			return id
		}, "FortiOS 7.2.12"},
		{"a row with v7.2.13 over SNMP's 7.2.12", func(s *stack) string {
			id := add(s, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"})
			snmp(s, id, "FortiOS 7.2.12")
			return id
		}, "FortiOS 7.2.13"},
		{"the agent's Windows build over a row without one", func(s *stack) string {
			id := add(s, inventory.AddInput{CatalogID: "windows-11"})
			agent(s, "Microsoft Windows 11 Pro 10.0.26100.1742", winRelease)
			return id
		}, "Microsoft Windows 11 Pro 10.0.26100.1742"},
		{"a kernel row never names the OS", func(s *stack) string {
			id := add(s, inventory.AddInput{Vendor: "Linux", Product: "Kernel", Version: "6.8.0-45"})
			agent(s, "Ubuntu 24.04.1 LTS")
			return id
		}, "Ubuntu 24.04.1 LTS"},
		{"the OS a person typed", func(s *stack) string {
			id := add(s, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"})
			snmp(s, id, "FortiOS 7.2.12")
			if err := s.d.Inventory.PatchDevice(t.Context(), "op@example.com", id, inventory.Patch{OS: ptrTo("FortiOS 7.4.1")}); err != nil {
				t.Fatal(err)
			}
			return id
		}, "FortiOS 7.4.1"},
		{"the row removed", func(s *stack) string {
			id := add(s, inventory.AddInput{CatalogID: "fortigate", Version: "v7.2.13"})
			snmp(s, id, "FortiOS 7.2.12")
			if err := s.d.Inventory.RemoveSoftware(t.Context(), "it@acme.example", id, manualRow(s, id)); err != nil {
				t.Fatal(err)
			}
			return id
		}, "FortiOS 7.2.12"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStack(t)
			id := c.setup(s)
			d, err := s.d.Inventory.Detail(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			page := d.Asset.OS
			if page == nil || page.Value != c.want {
				t.Fatalf("page OS %+v, want %q", page, c.want)
			}
			a, ok, err := findingsInventory{s.d.Inventory}.MatchInput(t.Context(), id)
			if err != nil || !ok {
				t.Fatalf("match input: %v %v", ok, err)
			}
			if matched := matchedOS(a); matched != page.Value {
				t.Errorf("the matcher decides on %q, the page shows %q", matched, page.Value)
			}
		})
	}
}

// osProducts are the products of the scenarios that are a whole OS (a kernel is not: it is a package of one).
var osProducts = []string{"fortinet|fortios", "microsoft|windows 11"}

// matchedOS is the OS the matcher decides a device's findings on, read from what it matches, not from the page's rule: the OS a person
// typed; else the OS the device states when the matcher keeps it as a row (deviceOS); else a declared OS row the matcher keeps, as it
// reads its version (one without a version only when no source reads an OS); else the agent's reading; else SNMP's.
func matchedOS(a findings.Asset) string {
	if a.ManualOS != "" {
		return a.ManualOS
	}
	rows := findings.MatchedSoftware(a)
	for _, r := range rows {
		if r.ID == "os:"+a.ID {
			if r.Source == "snmp" {
				return a.SNMPOS
			}
			return a.StatedOS
		}
	}
	for _, r := range rows {
		if r.Source != "manual" || !slices.Contains(osProducts, productid.Key(r.Vendor, r.Product)) {
			continue
		}
		if v := findings.OSVersion(r.Version); v != "" || a.AgentOS == "" && a.SNMPOS == "" {
			return strings.TrimSpace(r.Product + " " + v)
		}
	}
	if a.AgentOS != "" {
		return a.AgentOS
	}
	return a.SNMPOS
}

func ptrTo[T any](v T) *T { return &v }
