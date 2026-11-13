package core

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/host/api"
)

// The checks of the Box network inputs (S-CORE-8). The mock (web/src/features/core/networkMock.ts and
// networkRules.ts) is the contract: the codes and sentences below are its, word for word. vedette-host checks
// everything again before it touches the system (D-55); these exist so a person gets the sentence of the form
// and not a refusal of the host.

// Error codes of the Box network screen. The host's own refusals and run endings come through mapNetCode.
const (
	CodeAddressConflict       = "address_conflict"
	CodeGatewayOutsideSubnet  = "gateway_outside_subnet"
	CodeGatewayNotHost        = "gateway_not_host"
	CodeSpanOnManagement      = "span_on_management"
	CodeBadInterface          = "bad_interface"
	CodeSpanHasAddress        = "span_has_address"
	CodeSpanNotPhysical       = "span_not_physical"
	CodeNetBackendUnsupported = "net_backend_unsupported"
	CodeNothingPending        = "nothing_pending"
	CodeChangePending         = "change_pending"
	CodeConnectivityCheck     = "connectivity_check_failed"
	CodeRevertedByReboot      = "reverted_by_reboot"
	CodeRevertFailed          = "revert_failed"
	CodeNetplanApplyFailed    = "netplan_apply_failed"
	CodeNTPNotApplied         = "ntp_not_applied"
	CodeARPProbeFailed        = "arp_probe_failed"
	CodePendingInvalid        = "pending_invalid"
	CodeConfirmFailed         = "confirm_failed"
	CodeConfirmRequired       = "confirm_required"
	CodeDHCPNoStatic          = "dhcp_no_static"
	CodeInvalidStatic         = "invalid_static"
	CodeIPInUse               = "ip_in_use"
	CodeManagementFixed       = "management_fixed"
	CodeManagementCount       = "management_count"
	CodeManagementNotSet      = "management_not_set"
	CodeSpanCount             = "span_count"
	CodeInvalidRoles          = "invalid_roles"
	CodeNoInterface           = "no_interface"
	CodeNothingSelected       = "nothing_selected"
	CodeBadFilter             = "bad_filter"
	CodeDefaultNoServers      = "default_no_servers"
	CodeBadNTP                = "bad_ntp"
	CodeBadBoxAddress         = "bad_box_address"
)

// msgNothingPending is what a confirm or a cancel says when no change waits.
const msgNothingPending = "No management change is waiting for confirmation."

// msgRanOut is what it says when the box already went back because nobody confirmed in time.
const msgRanOut = "The time to confirm ran out and the box went back to the old settings. Make the change again."

// mapNetCode is the part of the host-code table (INV-21, INV-25) that belongs to the network commands; nil for
// a code that is not one of theirs. The refusals of a call and the ending of a run both come here.
func mapNetCode(code string) *apierr.Error {
	switch code {
	case api.CodeAddressConflict:
		return apierr.New(409, CodeAddressConflict, "Another device already uses this address.")
	case api.CodeGatewayOutsideSubnet:
		return apierr.New(400, CodeGatewayOutsideSubnet, "The gateway must be inside the address range you entered.")
	case api.CodeSameIface:
		return apierr.New(409, CodeSpanOnManagement, "The management interface cannot be the SPAN port. SPAN needs its own port: it listens with no IP address, and mirrored packets would reach your management network.")
	case api.CodeInvalidArgs: // core checks first; this is what the host's stricter check adds (host-api 6.5)
		return apierr.New(400, apierr.CodeInvalid, "The box did not accept these network settings. Check the address, gateway, DNS and NTP servers, then try again.")
	case api.CodeIfaceUnknown:
		return apierr.New(400, CodeBadInterface, "That network interface is not on this box. Reload the page and choose one from the list.")
	case api.CodeSPANHasAddress:
		return apierr.New(409, CodeSpanHasAddress, "That port has an IP address, and a SPAN port must have none. Remove the address from that port first, or choose another port.")
	case api.CodeSPANNotPhysical:
		return apierr.New(409, CodeSpanNotPhysical, "Only a physical network card can be the SPAN port, not a VLAN, bridge, bond or virtual interface.")
	case api.CodeNetBackendUnsupported:
		return apierr.New(409, CodeNetBackendUnsupported, "This box's network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself.")
	case api.CodeNotAwaitingConfirm:
		return apierr.New(409, CodeNothingPending, msgNothingPending)
	case api.CodeNotConfirmed:
		return apierr.New(409, CodeNothingPending, msgRanOut)
	case api.CodeConnectivityCheckFail:
		return apierr.New(409, CodeConnectivityCheck, "The box could not reach the network with the new settings, so it went back to the old ones. Check the address, prefix length and gateway, then try again.")
	case api.CodeRevertedByReboot:
		return apierr.New(409, CodeRevertedByReboot, "The box restarted before the change was confirmed, so it came back on the old address.")
	case api.CodeRevertFailed:
		return apierr.New(502, CodeRevertFailed, "The box could not go back to the old network settings by itself. The settings saved on the box are the old ones, so it comes back on the old address when it restarts, and it restarts by itself in about a minute.")
	case api.CodeNetplanApplyFailed:
		return apierr.New(502, CodeNetplanApplyFailed, "The operating system could not apply the network settings. If anything was changed it was put back; the details are in the box log.")
	case api.CodeNTPNotApplied:
		return apierr.New(502, CodeNTPNotApplied, "The time service did not take the new NTP servers. The old list was kept.")
	case api.CodeARPProbeFailed:
		return apierr.New(502, CodeARPProbeFailed, "The box could not check whether the new address is free, so nothing was changed. Try again.")
	case api.CodePendingInvalid:
		return apierr.New(502, CodePendingInvalid, "The box could not trust its record of the waiting change, so it went back to the old settings. Make the change again.")
	case api.CodeConfirmFailed:
		return apierr.New(502, CodeConfirmFailed, "The box could not save the new settings, so it went back to the old ones. Make the change again.")
	}
	return nil
}

// ---- inputs ----

var (
	nameRE   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`) // the host's name alphabet (host-api 6.5)
	labelRE  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	numLabel = regexp.MustCompile(`^(\d+|0[xX][0-9a-fA-F]*)$`)
)

func invalid(code, msg string) *apierr.Error { return apierr.New(400, code, msg) }

// bareIPv4 reports whether s is a plain dotted IPv4 address (no zone, no leading zeros, no port, no prefix).
func bareIPv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return netip.Addr{}, false
	}
	return a, true
}

// unicast4 is the host's rule for an IPv4 address of the box, a gateway or an NTP server (host/ops unicast4): a
// global unicast address, so not 0/8, loopback, link-local (169.254/16), multicast and above, or 255.255.255.255.
func unicast4(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && a.As4()[0] != 0 && a.As4()[0] < 224
}

// hostIn is the host's rule hostInSubnet: a lies in p and is neither its network nor its broadcast address.
func hostIn(p netip.Prefix, a netip.Addr) bool {
	if !p.Contains(a) {
		return false
	}
	b := a.As4()
	m := ^uint32(0) << (32 - p.Bits())
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return n&^m != 0 && n&^m != ^m
}

// staticSettings is a checked static management configuration.
type staticSettings struct {
	Addr    netip.Addr
	Prefix  int
	Gateway netip.Addr
	DNS     []string
}

// CIDR is the address with its prefix length, "10.0.0.5/24".
func (s staticSettings) CIDR() string { return netip.PrefixFrom(s.Addr, s.Prefix).String() }

// checkStatic is staticProblem of networkRules.ts: the sentences of the form for a static configuration. The
// gateway outside the range is its own code (D-100).
func checkStatic(address string, prefix *int, gateway string, dns []string) (staticSettings, *apierr.Error) {
	var out staticSettings
	a, ok := bareIPv4(address)
	if !ok {
		return out, invalid(CodeInvalidStatic, "The IP address must be an IPv4 address like 192.168.10.250.")
	}
	if prefix == nil || *prefix < 8 || *prefix > 30 {
		return out, invalid(CodeInvalidStatic, "The prefix length must be a whole number from 8 to 30 (24 means 255.255.255.0).")
	}
	if !unicast4(a) || !hostIn(netip.PrefixFrom(a, *prefix).Masked(), a) {
		return out, invalid(CodeInvalidStatic, "That address is the network or broadcast address of its range, or a reserved address. Pick a host address.")
	}
	g, ok := bareIPv4(gateway)
	if !ok {
		return out, invalid(CodeInvalidStatic, "The gateway must be an IPv4 address like 192.168.10.1.")
	}
	if g == a {
		return out, invalid(CodeInvalidStatic, "The gateway cannot be the same as the box address.")
	}
	rng := netip.PrefixFrom(a, *prefix).Masked()
	if !rng.Contains(g) {
		return out, invalid(CodeGatewayOutsideSubnet, "The gateway must be inside the address range you entered.")
	}
	if !hostIn(rng, g) { // the network or broadcast address of the range
		return out, invalid(CodeGatewayNotHost, "The gateway cannot be the network or broadcast address of the range. Use the address of your router.")
	}
	if len(dns) < 1 || len(dns) > 3 {
		return out, invalid(CodeInvalidStatic, "Give 1 to 3 DNS servers.")
	}
	seen := map[string]bool{}
	for _, d := range dns {
		x, ok := bareIPv4(d)
		if !ok {
			return out, invalid(CodeInvalidStatic, "Each DNS server must be an IPv4 address.")
		}
		if !x.IsGlobalUnicast() { // not loopback, link-local, multicast, 0.0.0.0 or 255.255.255.255 (host/ops)
			return out, invalid(CodeInvalidStatic, "A DNS server cannot be a loopback, link-local (169.254.x.x) or multicast address.")
		}
		if seen[d] {
			return out, invalid(CodeInvalidStatic, "A DNS server is listed twice.")
		}
		seen[d] = true
	}
	return staticSettings{Addr: a, Prefix: *prefix, Gateway: g, DNS: dns}, nil
}

// hostName is HOST_RE of networkRules.ts plus the host's own limits: letters, digits and hyphens in dot-separated
// parts of at most 63 characters, 64 in all, and not a name made only of numbers (1.2.3, 0x7f): the resolver
// reads those as addresses and the host refuses them.
func hostName(s string) bool {
	if len(s) < 1 || len(s) > 64 || !nameRE.MatchString(s) {
		return false
	}
	numeric := true
	for _, l := range strings.Split(s, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
		if !numLabel.MatchString(l) {
			numeric = false
		}
	}
	return !numeric
}

// checkNTP is ntpProblem of networkRules.ts for the servers of a custom list (already trimmed and lower-cased).
func checkNTP(servers []string) *apierr.Error {
	if len(servers) < 1 || len(servers) > api.MaxNTPServers {
		return invalid(CodeBadNTP, "Give 1 to 4 NTP servers.")
	}
	seen := map[string]bool{}
	for _, s := range servers {
		if a, ok := bareIPv4(s); ok && !unicast4(a) || !ok && !hostName(s) {
			return invalid(CodeBadNTP, "\""+cutAtRune(s, 40)+"\" is not a server name or IPv4 address.")
		}
		if seen[s] {
			return invalid(CodeBadNTP, "An NTP server is listed twice.")
		}
		seen[s] = true
	}
	return nil
}

// msgBadBoxAddress is boxAddressProblem's sentence in networkRules.ts.
const msgBadBoxAddress = "Enter a host name like vedette.office.lan or an IPv4 address like 192.168.1.10, without https:// and without a port."

// checkBoxAddress is boxAddressProblem of networkRules.ts (D-465): the Box address in its normal form (trimmed, lower case, no trailing
// dot), "" for "use the default". It is a host name (hostName: the NTP rule) or a unicast IPv4 address (unicast4); a URL, a port, a
// path, a space or an IPv6 address is refused, so what is saved can go into a link, a certificate and an install command as is.
func checkBoxAddress(s string) (string, *apierr.Error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" {
		return "", nil
	}
	if a, ok := bareIPv4(s); ok {
		if !unicast4(a) {
			return "", invalid(CodeBadBoxAddress, msgBadBoxAddress)
		}
		return s, nil
	}
	if !hostName(s) {
		return "", invalid(CodeBadBoxAddress, msgBadBoxAddress)
	}
	return s, nil
}

// SpanFilter is one exclusion filter as stored.
type SpanFilter struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// checkFilter is filterProblem and normaliseFilter of networkRules.ts: the filter in its normal form, or the sentence.
func checkFilter(typ, value string) (SpanFilter, *apierr.Error) {
	v := strings.TrimSpace(value)
	switch typ {
	case "cidr", "host", "port":
	default:
		return SpanFilter{}, invalid(CodeBadFilter, "The filter type must be a network range, a host or a port.")
	}
	if v == "" {
		return SpanFilter{}, invalid(CodeBadFilter, "Enter a value to exclude.")
	}
	q := "\"" + cutAtRune(v, 40) + "\""
	switch typ {
	case "cidr":
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			return SpanFilter{}, invalid(CodeBadFilter, q+" is not a network range. Write it like 10.0.5.0/24, with the prefix length.")
		}
		if p.Bits() < 8 {
			return SpanFilter{}, invalid(CodeBadFilter, "Ranges larger than a /8 cannot be excluded: that would hide almost everything.")
		}
		return SpanFilter{Type: typ, Value: p.Masked().String()}, nil
	case "host":
		if _, ok := bareIPv4(v); ok {
			return SpanFilter{Type: typ, Value: v}, nil
		}
		if !hostName(strings.ToLower(v)) {
			return SpanFilter{}, invalid(CodeBadFilter, q+" is not a host. Use an IPv4 address like 10.0.5.20 or a name like backup.lan.")
		}
		return SpanFilter{Type: typ, Value: strings.ToLower(v)}, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || len(v) > 5 || n < 1 || n > 65535 || strings.TrimLeft(v, "0123456789") != "" {
		return SpanFilter{}, invalid(CodeBadFilter, q+" is not a port. Use a number from 1 to 65535.")
	}
	return SpanFilter{Type: typ, Value: strconv.Itoa(n)}, nil
}
