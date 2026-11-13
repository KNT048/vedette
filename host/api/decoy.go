package api

// decoy_ip.add, decoy_ip.set_ports and decoy_ip.remove (docs/specs/host-api.md section 6.6, D-102, D-466).

// Commands of the decoy part.
const (
	CmdDecoyAdd    = "decoy_ip.add"
	CmdDecoyRemove = "decoy_ip.remove"
	// CmdDecoySetPorts replaces the ports a decoy address answers on (D-466). Core sends ports (here
	// and in decoy_ip.add) only when GET /v1/info lists this command: an older host refuses the field.
	CmdDecoySetPorts = "decoy_ip.set_ports"
)

// The protocols of a DecoyPort.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// MaxDecoyPorts is the most ports one decoy address may answer on (D-466).
const MaxDecoyPorts = 64

// DecoyPort is one port a decoy address answers on: Proto "tcp" or "udp", Port 1 to 65535.
type DecoyPort struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// Refusal codes (HTTP 412) of the decoy commands, and the codes a decoy run can end failed with.
const (
	CodeIPNotInMgmtSubnet = "ip_not_in_mgmt_subnet"
	CodeIPIsGateway       = "ip_is_gateway"
	CodeIPIsHost          = "ip_is_host"
	CodeIPIsNetwork       = "ip_is_network"
	CodeIPIsBroadcast     = "ip_is_broadcast"
	CodeIPInUse           = "ip_in_use"
	CodeDuplicateDecoy    = "duplicate_decoy"
	CodeLimitReached      = "limit_reached"
	// CodeLinkNameInUse: a link called vdh<8 hex of the IP> already exists outside the honeypot
	// namespace and the host did not create it, so it is never touched (slice 3-5).
	CodeLinkNameInUse = "link_name_in_use"
	// CodeMACInUse: the MAC the key and the IP give is already a decoy's (only possible with an
	// oui: three bytes of HMAC).
	CodeMACInUse = "mac_in_use"
	// CodeNotADecoy: decoy_ip.set_ports for an address that is not a decoy (412).
	CodeNotADecoy = "not_a_decoy"
	// Failure codes.
	CodeHPNamespaceUnavailable = "hp_namespace_unavailable"
	CodeMACKeyInvalid          = "mac_key_invalid"
	CodeDecoysStateInvalid     = "decoys_state_invalid"
	CodeDecoyFailed            = "decoy_failed"
	CodeHPStateUnusable        = "hp_state_unusable"

	// MaxDecoys is the limit of decoy addresses (spec 6.6).
	MaxDecoys = 32
)

// DecoyAddArgs are the args of decoy_ip.add. OUI is six hex digits (unicast, globally
// administered); empty means "no OUI": the MAC is then locally administered. Ports nil means no
// allow-list: the address answers on every port the honeypot listens on (what an older core gets);
// a list, even an empty one, means only those ports (D-466).
type DecoyAddArgs struct {
	IP    string       `json:"ip"`
	OUI   string       `json:"oui,omitempty"`
	Ports *[]DecoyPort `json:"ports,omitempty"`
}

// DecoySetPortsArgs are the args of decoy_ip.set_ports: the whole allow-list of one decoy address
// (required; an empty list closes every TCP and UDP port of it).
type DecoySetPortsArgs struct {
	IP    string      `json:"ip"`
	Ports []DecoyPort `json:"ports"`
}

// DecoySetPortsResult is the result of decoy_ip.set_ports: the allow-list now in force, sorted.
type DecoySetPortsResult struct {
	IP    string      `json:"ip"`
	Ports []DecoyPort `json:"ports"`
}

// DecoyAddResult is the result of decoy_ip.add.
type DecoyAddResult struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// HPTouch is one source that tried a new TCP or UDP connection to a decoy address (allowed port or not): AgeS is the seconds
// since it first did within the set's two minutes (D-466, B2 review M2).
type HPTouch struct {
	Src  string `json:"src"`
	Dst  string `json:"dst"`
	AgeS int    `json:"age_s"`
}

// HPTouchesState is the body of GET /v1/state/hp-touches; Touches is [] when none (or while the namespace is not proven).
// Recording is false when the host loaded the ruleset without the set (its print form could not be proven, B2 review H1): no
// attempt is recorded then. Full is true when the set holds close to its 1024 elements: new pairs may be missing.
type HPTouchesState struct {
	Touches   []HPTouch `json:"touches"`
	Recording bool      `json:"recording"`
	Full      bool      `json:"full"`
}

// HPTouchesFull is the number of elements from which the set touched (1024) counts as full.
const HPTouchesFull = 1000

// DecoyRemoveArgs are the args of decoy_ip.remove.
type DecoyRemoveArgs struct {
	IP string `json:"ip"`
}

// DecoyRemoveResult is the result of decoy_ip.remove: Removed is false when the IP was no decoy.
type DecoyRemoveResult struct {
	Removed bool `json:"removed"`
}
