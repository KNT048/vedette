package api

import "time"

// The body of GET /v1/state/net (docs/specs/host-api.md section 5, D-101). It reports what the host can
// read without looking at traffic: interface counters from /sys/class/net, addresses, the default
// routes from /proc/net/route and /proc/net/ipv6_route with their gateways' MACs from the kernel's
// neighbour table, the resolvers of resolv.conf and what the host itself wrote to netplan. The number of foreign MACs
// and the time of the last packet on the SPAN card are not here: the sensor measures them (D-101).

// Interface roles.
const (
	NetRoleManagement = "management"
	NetRoleSPAN       = "span"
)

// Management modes.
const (
	NetModeDHCP   = "dhcp"
	NetModeStatic = "static"
)

// NetCounters are the kernel's counters of one interface (/sys/class/net/<if>/statistics).
type NetCounters struct {
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// NetInterface is one network card (a device with a hardware parent; bridges, veth and macvlan
// links are not cards).
type NetInterface struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	// State is the kernel's operstate: "up", "down", "dormant" or "unknown".
	State     string `json:"state"`
	SpeedMbps *int   `json:"speed_mbps"` // null when the link is down or the card does not say
	// Role is "management" for the management card, "span" for the SPAN card, "" for any other.
	Role string `json:"role"`
	// Promisc is the kernel's IFF_PROMISC flag. On the SPAN card it is on while the sensor listens
	// (the sensor sets it on its own socket); netplan has no such key.
	Promisc bool `json:"promisc"`
	// Addresses are the IPv4 and IPv6 addresses of the card as CIDR text, "10.0.0.5/24".
	Addresses []string    `json:"addresses"`
	Counters  NetCounters `json:"counters"`
}

// NetMgmt is the management part of the running configuration, as the host wrote it.
type NetMgmt struct {
	Iface   string   `json:"iface"`
	Mode    string   `json:"mode"`    // "dhcp" or "static"
	Address string   `json:"address"` // CIDR; "" with dhcp
	Gateway string   `json:"gateway"` // "" with dhcp
	DNS     []string `json:"dns"`
	Search  []string `json:"search"`
}

// NetConfig is what the host wrote to its netplan file. Mgmt is null when the host has not written
// one (the box still has the network the installer gave it).
type NetConfig struct {
	Mgmt *NetMgmt `json:"mgmt"`
	SPAN *string  `json:"span"` // name of the SPAN card, or null
	NTP  []string `json:"ntp"`  // the servers of vedette.sources; empty when the file is absent or holds the default pool.ntp.org line (the distribution's own sources stay either way, D-166)
}

// NetRoute is a default route the kernel has: IPv4 from /proc/net/route, IPv6 from /proc/net/ipv6_route.
type NetRoute struct {
	Iface string `json:"iface"`
	// Gateway is the next hop as plain address text, never with a zone: an IPv6 link-local next hop ("fe80::1") is on Iface.
	Gateway string `json:"gateway"`
	// MAC is the gateway's link-layer address from the kernel's neighbour table (D-390); absent when the table has no usable entry for it
	// on Iface (no traffic yet, or a resolution that failed). Absent from a host older than D-390.
	MAC string `json:"mac,omitempty"`
}

// NetPending is a network change that waits for confirmation (D-100). Null when none waits.
type NetPending struct {
	RunID    string    `json:"run_id"`
	RevertAt time.Time `json:"revert_at"`
	// RebootAt is set when a revert could not be applied: the host has scheduled a reboot at this
	// time, because the saved configuration on disk is the old one (D-100 (8)). Not set otherwise.
	RebootAt *time.Time `json:"reboot_at,omitempty"`
}

// NetDecoy is a secondary address the honeypot answers on (D-102): what hp/decoys.json holds.
type NetDecoy struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// NetState is the body of GET /v1/state/net.
type NetState struct {
	Interfaces   []NetInterface `json:"interfaces"`
	Config       NetConfig      `json:"config"`
	DefaultRoute *NetRoute      `json:"default_route"`
	// DefaultRoutes6 are the IPv6 default routes of every routing table, each next hop of an equal-cost route on its own, lowest metric
	// first; [] when there is none (D-390; absent from an older host).
	DefaultRoutes6 []NetRoute  `json:"default_routes6"`
	Pending        *NetPending `json:"pending"`
	Decoys         []NetDecoy  `json:"decoys"`
	// Resolvers are the DNS servers the box's resolver uses now, whoever set them (a DHCP lease, netplan, an administrator): the
	// nameserver lines of /run/systemd/resolve/resolv.conf and /etc/resolv.conf, without loopback stubs (D-390). An older host does not
	// send the field.
	Resolvers []string `json:"resolvers"`
}

// Commands of the network part (spec 6.5).
const (
	CmdNetApply   = "net.apply"
	CmdNetConfirm = "net.confirm"
	CmdNetRevert  = "net.revert"
)

// Refusal codes (HTTP 412) and run-ending codes of the network commands (spec 11).
const (
	CodeAddressConflict       = "address_conflict"
	CodeGatewayOutsideSubnet  = "gateway_outside_subnet"
	CodeSameIface             = "same_iface"
	CodeIfaceUnknown          = "iface_unknown"
	CodeNetBackendUnsupported = "net_backend_unsupported"
	CodeConnectivityCheckFail = "connectivity_check_failed"
	CodeSPANHasAddress        = "span_has_address"
	CodeSPANNotPhysical       = "span_not_physical"
	CodeNotConfirmed          = "not_confirmed"
	CodeCancelled             = "cancelled"
	CodeRevertedByReboot      = "reverted_by_reboot"
	CodeRevertFailed          = "revert_failed"
	CodeNetplanApplyFailed    = "netplan_apply_failed"
	CodeNTPNotApplied         = "ntp_not_applied"
	CodePendingInvalid        = "pending_invalid"
	CodeConfirmFailed         = "confirm_failed"
	CodeARPProbeFailed        = "arp_probe_failed"
	CodeBootIDUnreadable      = "boot_id_unreadable"
	DefaultConfirmTimeoutS    = 120
	MinConfirmTimeoutS        = 30
	MaxConfirmTimeoutS        = 600
	MaxNTPServers             = 4
)

// NetApplyMgmt is the management card of net.apply.
type NetApplyMgmt struct {
	Iface   string   `json:"iface"`
	Mode    string   `json:"mode"`    // "dhcp" | "static"
	Address string   `json:"address"` // CIDR; required with static
	Gateway string   `json:"gateway"` // optional with static
	DNS     []string `json:"dns"`
}

// NetApplySPAN is the SPAN card of net.apply; Iface null (or the whole object absent) means none.
type NetApplySPAN struct {
	Iface *string `json:"iface"`
}

// NetApplyArgs is the desired state of the part Vedette manages (spec 6.5): every call carries the
// whole state, so a field left out means "none", never "keep".
type NetApplyArgs struct {
	Mgmt NetApplyMgmt `json:"mgmt"`
	SPAN NetApplySPAN `json:"span"`
	// NTP holds up to four IPv4 addresses or names, added to the sources of the distribution's own chrony configuration (D-106, D-166); empty writes the default `pool pool.ntp.org` into vedette.sources.
	NTP []string `json:"ntp"`
	// ConfirmTimeoutS is the confirm window of a management change, 30 to 600; 0 means 120.
	ConfirmTimeoutS int `json:"confirm_timeout_s"`
}

// NetRunArgs are the args of net.confirm and net.revert: the run that waits.
type NetRunArgs struct {
	RunID string `json:"run_id"`
}

// NetApplyResult is the result of net.apply. Confirm is true when the run waits for net.confirm.
type NetApplyResult struct {
	Changed bool `json:"changed"`
	Confirm bool `json:"confirm"`
}
