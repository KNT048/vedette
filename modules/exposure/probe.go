package exposure

import (
	"net/http"
	"time"

	"github.com/knt048/vedette/core/egressip"
)

// The public-IP check lives in core/egressip, so the scan container's worker can run the same code for its own-IP fence right
// before nmap -sV (D-514, plan exposure-real-vulns §1.3). These names keep exposure's API as it was.

// DefaultServices are the three independent public "what is my IP" services the box asks (D-81, PRIVACY flow 9).
var DefaultServices = egressip.DefaultServices

// The two ways a round can end without an address.
var (
	// ErrNoAgreement: some services answered, but no two of them gave the same address.
	ErrNoAgreement = egressip.ErrNoAgreement
	// ErrServicesDown: no service gave a usable answer.
	ErrServicesDown = egressip.ErrServicesDown
)

// PublicServiceProber is the EgressProber over HTTPS: one Round asks each service once and accepts an address only when two agree.
type PublicServiceProber = egressip.Prober

// NewPublicServiceProber returns a prober for exactly three https URLs without user info (nil: DefaultServices); see egressip.New.
func NewPublicServiceProber(urls []string, transport *http.Transport, timeout time.Duration) (*PublicServiceProber, error) {
	return egressip.New(urls, transport, timeout)
}
