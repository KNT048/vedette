package ops

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The netplan side of the network commands (D-99). The host owns exactly one netplan file,
// 90-vedette.yaml, and renders it from the typed structs below with yaml.v3: no string is ever
// pasted into YAML, and every value is validated first. This file only renders and reads back
// what the host itself rendered; writing and applying belong to net.apply (slice 3-4).
//
// The host never parses a netplan file it did not write: parseNetplan accepts a file only when
// rendering what it understood gives back the very same bytes.

const (
	netplanName   = "90-vedette.yaml"
	netplanHeader = "# Written by vedette-host. Do not edit: the host rewrites this file.\n"
	maxNetplan    = 64 << 10

	maxDNS    = 3 // spec 6.5: mgmt.dns holds at most three
	maxSearch = 6
)

var (
	// ifaceNameRE narrows the kernel's interface-name rule (1 to 15 bytes, no '/', ':' or space, not
	// "." or "..") to a safe alphabet with an alphanumeric first character: a name can never look
	// like an option, a YAML indicator or a path.
	ifaceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,14}$`)
	// dnsNameRE is the repository name regex (host-api section 6.5, security rules).
	dnsNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
)

// validIfaceName reports whether s is an interface name the host will put in a file or an argv.
func validIfaceName(s string) bool { return ifaceNameRE.MatchString(s) }

// NetplanMgmt is the management card: DHCP or a static IPv4 address.
type NetplanMgmt struct {
	Iface   string
	Mode    string // api.NetModeDHCP or api.NetModeStatic
	Address netip.Prefix
	Gateway netip.Addr
	DNS     []netip.Addr
	Search  []string
}

// NetplanConfig is everything the host writes: the management card and, optionally, the SPAN card.
type NetplanConfig struct {
	Mgmt NetplanMgmt
	SPAN string // "" for none
}

// fieldError says which argument of net.apply is wrong; the command turns it into args details.
type fieldError struct{ Field, Reason string }

func (e *fieldError) Error() string { return "netplan: " + e.Field + ": " + e.Reason }

func bad(field, reason string) error { return &fieldError{Field: field, Reason: reason} }

// ipv4Parts returns the address as a number, for the network and broadcast tests.
func ipv4Num(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// unicast4 is a usable IPv4 host address: not 0.x, not multicast or class E, not loopback or link-local.
func unicast4(a netip.Addr) bool {
	return a.IsValid() && a.Is4() && a.IsGlobalUnicast() && a.As4()[0] != 0 && a.As4()[0] < 224
}

// hostInSubnet reports whether a lies in p and is neither its network nor its broadcast address.
func hostInSubnet(p netip.Prefix, a netip.Addr) bool {
	if !p.Contains(a) {
		return false
	}
	mask := ^uint32(0) << (32 - p.Bits())
	n := ipv4Num(a)
	return n&^mask != 0 && n&^mask != ^mask
}

func (c NetplanConfig) validate() error {
	m := c.Mgmt
	if !validIfaceName(m.Iface) {
		return bad("mgmt.iface", "is not a valid interface name")
	}
	switch m.Mode {
	case api.NetModeDHCP:
		if m.Address.IsValid() || m.Gateway.IsValid() {
			return bad("mgmt.address", "must be empty with dhcp")
		}
	case api.NetModeStatic:
		a := m.Address
		switch {
		case !a.IsValid() || !a.Addr().Is4() || a.Bits() < 8 || a.Bits() > 30:
			return bad("mgmt.address", "must be an IPv4 address with a prefix between 8 and 30")
		case !unicast4(a.Addr()) || !hostInSubnet(a.Masked(), a.Addr()):
			return bad("mgmt.address", "must be a unicast host address, not a network or broadcast address")
		}
		if g := m.Gateway; g.IsValid() {
			switch {
			case !unicast4(g) || !hostInSubnet(a.Masked(), g):
				return bad("mgmt.gateway", "must be a host address inside the subnet of mgmt.address")
			case g == a.Addr():
				return bad("mgmt.gateway", "must not be the address of the box")
			}
		}
	default:
		return bad("mgmt.mode", "must be dhcp or static")
	}
	if len(m.DNS) > maxDNS {
		return bad("mgmt.dns", "holds at most 3 servers")
	}
	for _, d := range m.DNS {
		if !d.IsValid() || d.Zone() != "" || d.Is4In6() || !d.IsGlobalUnicast() {
			return bad("mgmt.dns", "must be unicast addresses that are not loopback or link-local")
		}
	}
	if len(m.Search) > maxSearch {
		return bad("mgmt.search", "holds at most 6 domains")
	}
	for _, s := range m.Search {
		if !dnsNameRE.MatchString(s) {
			return bad("mgmt.search", "must be names made of letters, digits, '.', '_' and '-'")
		}
	}
	if c.SPAN != "" {
		if !validIfaceName(c.SPAN) {
			return bad("span.iface", "is not a valid interface name")
		}
		if c.SPAN == m.Iface {
			return bad("span.iface", "must differ from mgmt.iface")
		}
	}
	return nil
}

// The typed shape of the file. Field order is the output order.
type netplanDoc struct {
	Network netplanNetwork `yaml:"network"`
}

type netplanNetwork struct {
	Version   int                   `yaml:"version"`
	Renderer  string                `yaml:"renderer"`
	Ethernets map[string]netplanEth `yaml:"ethernets"`
}

type netplanEth struct {
	DHCP4       bool           `yaml:"dhcp4"`
	DHCP6       *bool          `yaml:"dhcp6,omitempty"`
	AcceptRA    *bool          `yaml:"accept-ra,omitempty"`
	LinkLocal   *[]string      `yaml:"link-local,omitempty"` // a non-nil pointer to an empty list renders "[]": no link-local address
	Addresses   []string       `yaml:"addresses,omitempty"`
	Routes      []netplanRoute `yaml:"routes,omitempty"`
	Nameservers *netplanNS     `yaml:"nameservers,omitempty"`
	Optional    bool           `yaml:"optional,omitempty"` // the SPAN card: boot does not wait for it
}

type netplanRoute struct {
	To  string `yaml:"to"`
	Via string `yaml:"via"`
}

type netplanNS struct {
	Addresses []string `yaml:"addresses,omitempty"`
	Search    []string `yaml:"search,omitempty"`
}

// renderNetplan validates c and returns the text of 90-vedette.yaml. The management card takes
// its address (or DHCP), default route and name servers. The SPAN card is brought up with no
// address of any kind (no DHCP, no router advertisements, no link-local) and is optional at boot;
// promiscuous mode is not a netplan key: the sensor sets it on its own socket.
func renderNetplan(c NetplanConfig) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	m := c.Mgmt
	mg := netplanEth{}
	if m.Mode == api.NetModeDHCP {
		mg.DHCP4 = true
	} else {
		mg.Addresses = []string{m.Address.String()}
		if m.Gateway.IsValid() {
			mg.Routes = []netplanRoute{{To: "default", Via: m.Gateway.String()}}
		}
	}
	if len(m.DNS) > 0 || len(m.Search) > 0 {
		ns := &netplanNS{Search: slices.Clone(m.Search)}
		for _, d := range m.DNS {
			ns.Addresses = append(ns.Addresses, d.String())
		}
		mg.Nameservers = ns
	}
	doc := netplanDoc{Network: netplanNetwork{Version: 2, Renderer: "networkd", Ethernets: map[string]netplanEth{m.Iface: mg}}}
	if c.SPAN != "" {
		off, none := false, []string{}
		doc.Network.Ethernets[c.SPAN] = netplanEth{DHCP6: &off, AcceptRA: &off, LinkLocal: &none, Optional: true}
	}
	var buf bytes.Buffer
	buf.WriteString(netplanHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("ops: render netplan: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("ops: render netplan: %w", err)
	}
	return buf.Bytes(), nil
}

var errNotOurs = errors.New("netplan: not a file the host rendered")

// parseNetplan reads back a file the host wrote. It decodes strictly into the typed shape,
// rebuilds the configuration, validates it and renders it again: anything but the exact bytes the
// host would have written is refused, so a hand-edited or foreign file never yields a configuration.
func parseNetplan(data []byte) (NetplanConfig, error) {
	if len(data) > maxNetplan {
		return NetplanConfig{}, errNotOurs
	}
	var doc netplanDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return NetplanConfig{}, errNotOurs
	}
	var cfg NetplanConfig
	haveMgmt := false
	for name, e := range doc.Network.Ethernets {
		if e.Optional {
			if cfg.SPAN != "" {
				return NetplanConfig{}, errNotOurs
			}
			cfg.SPAN = name
			continue
		}
		if haveMgmt {
			return NetplanConfig{}, errNotOurs
		}
		haveMgmt = true
		m, err := mgmtFromEth(name, e)
		if err != nil {
			return NetplanConfig{}, err
		}
		cfg.Mgmt = m
	}
	if !haveMgmt {
		return NetplanConfig{}, errNotOurs
	}
	again, err := renderNetplan(cfg)
	if err != nil || !bytes.Equal(again, data) {
		return NetplanConfig{}, errNotOurs
	}
	return cfg, nil
}

func mgmtFromEth(name string, e netplanEth) (NetplanMgmt, error) {
	m := NetplanMgmt{Iface: name, Mode: api.NetModeDHCP}
	if !e.DHCP4 {
		m.Mode = api.NetModeStatic
		if len(e.Addresses) != 1 {
			return m, errNotOurs
		}
		p, err := netip.ParsePrefix(e.Addresses[0])
		if err != nil {
			return m, errNotOurs
		}
		m.Address = p
		switch len(e.Routes) {
		case 0:
		case 1:
			g, err := netip.ParseAddr(e.Routes[0].Via)
			if err != nil || e.Routes[0].To != "default" {
				return m, errNotOurs
			}
			m.Gateway = g
		default:
			return m, errNotOurs
		}
	}
	if e.Nameservers != nil {
		for _, s := range e.Nameservers.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return m, errNotOurs
			}
			m.DNS = append(m.DNS, a)
		}
		m.Search = e.Nameservers.Search
	}
	return m, nil
}

// netplanDirs are the directories netplan reads (spec 6.5). The host writes only the first two,
// and only the file 90-vedette.yaml in them.
var netplanDirs = []string{"etc/netplan", "run/netplan", "lib/netplan"}

// CheckBackend is the backend half of the Check of net.apply (D-99): 412 net_backend_unsupported
// when netplan is missing or when any netplan file other than the host's own exists. The host
// never reads the other files; it only lists the directories. Its own file must be a regular
// file: a symlink at that name is refused too. It only reads.
func (o *Ops) CheckBackend() *server.Refusal {
	unsupported := func(msg string) *server.Refusal { return refuse412("net_backend_unsupported", msg) }
	if st, err := os.Stat(o.path("usr/sbin/netplan")); err != nil || !st.Mode().IsRegular() {
		return unsupported("netplan is not installed on this machine, so the host cannot manage its network.")
	}
	for _, dir := range netplanDirs {
		p := o.path(dir)
		st, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !st.IsDir() { // Lstat: a symlink is not a directory here
			return unsupported("The netplan directory /" + dir + " cannot be read as a plain directory.")
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return unsupported("The netplan directory /" + dir + " cannot be read.")
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".yaml") {
				continue
			}
			if n != netplanName || dir == "lib/netplan" {
				return unsupported("Another netplan file exists in /" + dir + ". The host needs netplan to itself.")
			}
			if !e.Type().IsRegular() {
				return unsupported("The host's netplan file in /" + dir + " is not a plain file.")
			}
		}
	}
	return nil
}
