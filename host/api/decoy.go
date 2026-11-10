package api

// decoy_ip.add and decoy_ip.remove (docs/specs/host-api.md section 6.6, D-102).

// Commands of the decoy part.
const (
	CmdDecoyAdd    = "decoy_ip.add"
	CmdDecoyRemove = "decoy_ip.remove"
)

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
	// Failure codes.
	CodeHPNamespaceUnavailable = "hp_namespace_unavailable"
	CodeMACKeyInvalid          = "mac_key_invalid"
	CodeDecoysStateInvalid     = "decoys_state_invalid"
	CodeDecoyFailed            = "decoy_failed"

	// MaxDecoys is the limit of decoy addresses (spec 6.6).
	MaxDecoys = 32
)

// DecoyAddArgs are the args of decoy_ip.add. OUI is six hex digits (unicast, globally
// administered); empty means "no OUI": the MAC is then locally administered.
type DecoyAddArgs struct {
	IP  string `json:"ip"`
	OUI string `json:"oui,omitempty"`
}

// DecoyAddResult is the result of decoy_ip.add.
type DecoyAddResult struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// DecoyRemoveArgs are the args of decoy_ip.remove.
type DecoyRemoveArgs struct {
	IP string `json:"ip"`
}

// DecoyRemoveResult is the result of decoy_ip.remove: Removed is false when the IP was no decoy.
type DecoyRemoveResult struct {
	Removed bool `json:"removed"`
}
