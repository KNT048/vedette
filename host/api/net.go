package api

import "time"

// The body of GET /v1/state/net (docs/specs/host-api.md section 5, D-101). It reports what the host can
// read without looking at traffic: interface counters from /sys/class/net, addresses, the default
// route from /proc/net/route and what the host itself wrote to netplan. The number of foreign MACs
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
	NTP  []string `json:"ntp"`  // empty until the NTP command exists (slice 3-4)
}

// NetRoute is the default route the kernel has, from /proc/net/route.
type NetRoute struct {
	Iface   string `json:"iface"`
	Gateway string `json:"gateway"`
}

// NetPending is a network change that waits for confirmation (D-100). Null until slice 3-4.
type NetPending struct {
	RunID    string    `json:"run_id"`
	RevertAt time.Time `json:"revert_at"`
}

// NetDecoy is a secondary address the honeypot answers on (D-102). Empty until slice 3-5.
type NetDecoy struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// NetState is the body of GET /v1/state/net.
type NetState struct {
	Interfaces   []NetInterface `json:"interfaces"`
	Config       NetConfig      `json:"config"`
	DefaultRoute *NetRoute      `json:"default_route"`
	Pending      *NetPending    `json:"pending"`
	Decoys       []NetDecoy     `json:"decoys"`
}
