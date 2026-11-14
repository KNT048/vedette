package api

// The domain fence commands (docs/specs/host-api.md §6.17, D-591, FULL-5 slice 2): vedette-host holds the box's fence key (core never
// does) and gives core a verified domain's box-bound token, and checks the fence itself for the OpenVAS scan of an address a name under
// the domain resolves to.

// Names of the commands.
const (
	// CmdExposureToken gives the box-bound token of a domain: hex(HMAC-SHA256(fence key, "vedette-verify\x00"+domain)), its first 16
	// hex digits (the length of every domain token, D-591).
	CmdExposureToken = "exposure.token"
	// CmdExposureFenceCheck checks a domain_ip scan with the host's own fence (core/domainfence): the token is this box's, the domain's
	// TXT record carries it, the name resolves to the address now (and, for a disruptive scan, the name stays inside the domain).
	CmdExposureFenceCheck = "exposure.fence_check"
)

// Refusal codes of the domain fence (with CodeTargetNotOwned and CodeOwnershipUnchecked of zap.baseline).
const (
	// CodeTokenForeign: the token is not the one this box's fence key gives for the domain (another box's, or one made before the fence).
	CodeTokenForeign = "token_foreign"
	// CodeNameMoved: the name no longer resolves to the address (that address only).
	CodeNameMoved = "name_moved"
	// CodeCNAMEOutside: a disruptive scan of a name whose CNAME leaves the domain.
	CodeCNAMEOutside = "cname_outside"
	// CodeFenceUnavailable: the host has no usable fence key (it could not make or read <state>/fence.key).
	CodeFenceUnavailable = "fence_unavailable"
)

// ExposureTokenArgs are the args of exposure.token.
type ExposureTokenArgs struct {
	Domain string `json:"domain"`
}

// ExposureTokenResult is its result.
type ExposureTokenResult struct {
	Token string `json:"token"`
}

// ExposureFenceCheckArgs are the args of exposure.fence_check: the domain_ip job fields of plan 2026-11-14 §5.
type ExposureFenceCheckArgs struct {
	Domain     string `json:"domain"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	Token      string `json:"token"`
	Disruptive bool   `json:"disruptive,omitempty"`
}

// ExposureFenceCheckResult is the result of a check that said yes: the CNAME chain of the name ("a -> b"), for the probe log.
type ExposureFenceCheckResult struct {
	Chain string `json:"chain"`
}
