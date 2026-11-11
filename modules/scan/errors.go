package scan

import (
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/apierr"
)

// APIError maps 1:1 to an error code of the scan endpoints (web/src/features/scan/mocks.ts, the behaviour spec).
// Callers wrap it with %w and the HTTP layer turns it into the response with ToAPIError.
type APIError struct {
	HTTP    int
	Code    string
	Message string // user-facing, English (D-28)
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func apiErr(status int, code, format string, a ...any) *APIError {
	return &APIError{HTTP: status, Code: code, Message: fmt.Sprintf(format, a...)}
}

// Messages shared by an error and a block reason. Texts are the mock's; scanner_unavailable is API_CONVENTIONS §3.3 (D-125 (5)).
const (
	msgNoCommitment = "The scan scope commitment is not ticked yet. Do it under Devices, Scope and sensors."
	msgZoneUnknown  = "The schedule is on, but the time zone of the organization cannot be read, so no scan starts on its own (rescans for new KEV entries wait too). Check the time zone under Settings, General."
	msgScannerDown  = "The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again."
)

// The API errors of the scan endpoints.
var (
	ErrDangerousLocked    = apiErr(400, "dangerous_locked", "Vedette has no dangerous checks: no exploitation, no denial of service. It cannot be turned on.")
	ErrScannerUnavailable = apiErr(503, "scanner_unavailable", "%s", msgScannerDown)
)

func invalidConfig(format string, a ...any) *APIError {
	return apiErr(400, "invalid_config", format, a...)
}

// ToAPIError turns an API error of this package into the *apierr.Error of the response; other errors pass through
// (the server answers them as 500 internal without detail).
func ToAPIError(err error) error {
	var ae *APIError
	if errors.As(err, &ae) {
		return apierr.New(ae.HTTP, ae.Code, ae.Message)
	}
	return err
}
