package exposure

import (
	"context"
	"net/netip"
)

// The shared safety block of Settings › Scanning (#850, INV-30): the speed and the exclusion list a person sets once for every
// engine that sends anything. Inventory stores them (D-627, GET /scanning shows them); cmd/vedette hands them to exposure through
// ScanSafety, so exposure never reads another module's tables. The time window does not apply here: a scan of a public target runs
// only when a person presses Scan now, as the LAN's Scan now does.

// Safety is what exposure takes from the shared block.
type Safety struct {
	// RPS is the most requests a second a person allows (scan config `rate`, 1 to 20). It only lowers the module's own rates
	// (TemplateRPS, FullTemplateRPS), never raises them; 0 means no ceiling of its own.
	RPS int
	// Exclusions are the addresses and networks a person never wants scanned (scan config `exclusions`).
	Exclusions []netip.Prefix
}

// ScanSafety reads the shared block now. An error means it could not be read: the step it was asked for sends nothing.
type ScanSafety interface {
	ScanSafety(ctx context.Context) (Safety, error)
}

// excluded says whether ip is on the exclusion list.
func (s Safety) excluded(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range s.Exclusions {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// rps is the rate of a job that asks for want: the lower of the two when a ceiling is set.
func (s Safety) rps(want int) int {
	if s.RPS > 0 && s.RPS < want {
		return s.RPS
	}
	return want
}

// safety reads the shared block; without a ScanSafety (tests, an older wiring) it is the module's own limits and no exclusion.
func (s *Service) safety(ctx context.Context) (Safety, error) {
	if s.cfg.Safety == nil {
		return Safety{}, nil
	}
	return s.cfg.Safety.ScanSafety(ctx)
}

const (
	// notSafetyRead is the line of a step that did not run because the shared safety settings could not be read.
	notSafetyRead = "Not checked: the shared safety settings (Settings, Scanning, Safety) could not be read, so nothing was sent."
	// notDeepExcluded is the line of a domain's address on the exclusion list (D-571 deep scan, INV-30).
	notDeepExcluded = "%s is on the exclusion list under Settings, Scanning, Safety, so nothing was sent to it."
)

// errExcluded is the refusal of a scan of an IP target on the exclusion list (400 out_of_scope, as the LAN's Scan now).
func errExcluded(ip string) *APIError {
	return apiErr(400, "out_of_scope", "%s is on the exclusion list under Settings, Scanning, Safety, so it is not scanned. Remove it there to scan it.", ip)
}
