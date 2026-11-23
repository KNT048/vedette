package exposure

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/apierr"
)

// APIError maps 1:1 to an error code of the exposure endpoints (web/src/features/exposure/mocks.ts).
// Callers wrap it with %w and the HTTP layer turns it into the response with ToAPIError.
type APIError struct {
	HTTP    int
	Code    string
	Message string // user-facing, English
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func apiErr(status int, code, format string, a ...any) *APIError {
	return &APIError{HTTP: status, Code: code, Message: fmt.Sprintf(format, a...)}
}

// The API errors of the exposure endpoints. Texts are those of the mock, which is the behaviour spec.
var (
	ErrNotFound    = apiErr(404, "not_found", "No such target. It may have been deleted.")
	ErrNoSnapshot  = apiErr(404, "not_found", "No snapshot for this day.")
	ErrNoSnapshots = apiErr(404, "not_found", "There is no snapshot for one of the two selected days.")
	ErrSameDate    = apiErr(400, "same_date", "Pick two different days to compare.")
	ErrEmpty       = apiErr(400, "empty", "Enter a domain, for example example.com.")
	ErrBadValue    = apiErr(400, "bad_value", "Enter only a domain name, without http://, a path, a port or spaces. Example: example.com.")
	ErrBadDomain   = apiErr(400, "bad_value", "Not a valid domain. Example: example.com.")
	// ErrPublicSuffix: a public suffix (co.uk, ddns.net, github.io) is where many owners register their names; no record there can
	// prove one of them.
	ErrPublicSuffix   = apiErr(400, "bad_value", "That is a public suffix, under which many owners register their own names: add your own domain (for example yourcompany.co.uk or yourname.ddns.net).")
	ErrIPNotAllowed   = apiErr(400, "ip_not_allowed", "That is an IP address, not a domain. Choose Public IP to add an address.")
	ErrIPNotPublic    = apiErr(400, "ip_not_allowed", "Enter a public IPv4 address, for example 203.0.113.10. Private, reserved, carrier-grade NAT and IPv6 addresses cannot be scanned from the Internet.")
	ErrNotAnIP        = apiErr(400, "bad_value", "Not an IP address. Example: 203.0.113.10.")
	ErrKind           = apiErr(400, "bad_value", "Choose Domain or Public IP.")
	ErrTooMany        = apiErr(400, "too_many", "At most %d targets. Delete ones you no longer use.", MaxTargets)
	ErrUnreachable    = apiErr(502, "unreachable", "%s", msgOffline)
	ErrDisagree       = apiErr(502, "unreachable", "%s", msgDisagree)
	ErrNotImplemented = apiErr(501, "not_implemented", "This part of the box is not built yet.")
	// ErrFenceDown: on a box with vedette-host, a new domain's box-bound token comes from the host; no answer, no
	// domain (a random token would leave it without the deep scan of its addresses).
	ErrFenceDown = apiErr(502, "unreachable", "The domain was not added: the Vedette host did not answer when asked for the domain's verification token. Try again in a minute.")
	// ErrFenceFull: the host has issued fence tokens for its limit of domains.
	ErrFenceFull = apiErr(400, "too_many", "The domain was not added: this box's host has already issued verification tokens for its limit of 20 domains.")
)

// The answers of a scan that the runner did not do (INV-12). Nothing is stored for them.
var (
	// ErrScanOff: the runner found the External exposure module off when the scan began or was switched off while it ran
	// (the runner is the scan module's code behind exposure's switch, so the Vulnerability scans module may be off).
	ErrScanOff = apiErr(409, "module_off", "The External exposure module is off, so the box cannot scan. An admin can turn it on in Settings, Modules.")
	// ErrCTDown: the certificate-transparency search gave no answer; a snapshot without the subdomains would say they are gone.
	ErrCTDown = apiErr(502, "unreachable", "The certificate-transparency search (crt.sh) did not answer, so the scan stopped and nothing was saved. Try again in a few minutes.")
	// ErrDNSDown: the box's DNS resolver gave no clear answer for the domain itself (INV-27); like ErrCTDown, a snapshot without
	// the names would say they are gone.
	ErrDNSDown = apiErr(502, "unreachable", "The box's DNS resolver gave no answer for this domain, so the scan stopped and nothing was saved. Check the box's DNS settings, then try again in a few minutes.")
	// ErrScanTooLong: the scan hit its time cap.
	ErrScanTooLong = apiErr(502, "unreachable", "The scan did not finish within 5 minutes, so nothing was saved. Try again later.")
	// ErrScanBusy: another scan runs on the box (one at a time).
	ErrScanBusy = apiErr(409, "busy", "Another external scan is running on this box. Wait for it to finish, then try again.")
	// ErrModuleOff: the Exposure module was switched off while the scan's gate was running.
	ErrModuleOff = apiErr(409, "module_off", "The External exposure module is off, so the box cannot scan. An admin can turn it on in Settings, Modules.")
	// ErrNotRunning: Stop was pressed when no scan runs.
	ErrNotRunning = apiErr(409, "not_running", "No scan is running now.")
)

// TooManyNames is the answer when the certificate-transparency logs list more names under domain than one scan reads, counting only
// the names this target scans (not those of its own subdomain targets): nothing is scanned rather than a part that would change from
// day to day.
func TooManyNames(domain string) *APIError {
	return apiErr(400, "too_many", "The certificate-transparency logs list more than 300 names under %s that this target would scan, more than one scan reads, so nothing was scanned. Set its scope to only this name or to the names you choose, or add its largest subdomain (for example shop.%s) as its own target: the names a subdomain target scans do not count here.", domain, domain)
}

// NotNamesCut is the "Not checked" line of a scan whose scope is the names chosen, on a domain with more names than one scan lists.
const NotNamesCut = "Names under the domain: more than 300 in the certificate logs, so only the names you chose were looked up and scanned, and new names were not listed."

// Messages that are shared by a response and the stored result of a check.
const (
	msgOffline  = "The box could not reach the public IP services (checkip.amazonaws.com, icanhazip.com, ifconfig.me/ip). Check that this box can make outgoing HTTPS connections, then try again."
	msgDisagree = "The public IP services did not agree on the box's IP (at least two of the three must return the same address), so nothing was added. Try again in a few minutes."
)

func duplicate(value string) *APIError {
	return apiErr(409, "duplicate", "%s is already in the list.", value)
}

func rateLimited(wait int) *APIError {
	s := "s"
	if wait == 1 {
		s = ""
	}
	return apiErr(429, "rate_limited", "Too many verification attempts (limit %d per hour). Try again in about %d minute%s.", MaxAttemptsPerHour, wait, s)
}

// checkedTooSoon is the 429 of a domain target checked less than DomainCheckEvery ago: it says in seconds when the next check is allowed.
func checkedTooSoon(wait int) *APIError {
	s := "s"
	if wait == 1 {
		s = ""
	}
	return apiErr(429, "rate_limited", "This target was checked a moment ago. The next check is allowed in %d second%s.", wait, s)
}

// checksTooBusy is the 429 of the box-wide bound on ownership checks: it says in seconds when the next one is allowed.
func checksTooBusy(wait int) *APIError {
	s := "s"
	if wait == 1 {
		s = ""
	}
	return apiErr(429, "rate_limited", "Many ownership checks were made on this box just now. The next check is allowed in %d second%s.", wait, s)
}

func notPublic(ips []string) *APIError {
	one := len(ips) == 1
	is, kind, it := "are", "addresses", "them"
	if one {
		is, kind, it = "is a", "address", "it"
	}
	return apiErr(400, "not_public", "The box reaches the Internet via %s, which %s private, reserved or shared carrier (CGNAT) %s. Scanning %s could hit other people's devices, so Vedette will not verify %s. Ask your admin to give the box a public IP that belongs to your company, then try again.",
		strings.Join(ips, ", "), is, kind, it, it)
}

// ToAPIError turns an API error of this package into the *apierr.Error of the response; other errors
// pass through (the server answers them as 500 internal without detail).
func ToAPIError(err error) error {
	var ae *APIError
	if errors.As(err, &ae) {
		return apierr.New(ae.HTTP, ae.Code, ae.Message)
	}
	return err
}

// The API errors of the Ignored list.
var (
	ErrOnlyIPCanBeIgnored = apiErr(400, "bad_value", "Only a public IP can go on the Ignored list.")
	ErrIgnoredFull        = apiErr(400, "too_many", "At most %d ignored IPs. Restore the ones you no longer need to block.", MaxIgnored)
	ErrBadIP              = apiErr(400, "bad_value", "Not a valid IPv4 address.")
	ErrNotIgnored         = apiErr(404, "not_found", "This IP is not on the Ignored list.")
)
