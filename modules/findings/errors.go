package findings

import "errors"

// APIError is a sentinel that maps 1:1 to an API error code of the findings
// endpoints (web/src/features/findings/contract.ts, mocks.ts). Callers wrap it
// with %w and the HTTP layer finds it with errors.As.
type APIError struct {
	Code    string // e.g. "note_required"
	HTTP    int
	Message string // user-facing, English (D-28)
}

func (e *APIError) Error() string { return e.Message }

// API errors of the findings endpoints; Code and HTTP are what the client sees.
var (
	ErrNotFound     = &APIError{"not_found", 404, "No such finding."}
	ErrBadAction    = &APIError{"bad_action", 400, "Choose one of: patched, mitigated, false positive, not relevant, or reopen."}
	ErrNoteTooLong  = &APIError{"note_too_long", 400, "The note can be at most 500 characters. Shorten it."}
	ErrNoteRequired = &APIError{"note_required", 400, "Write why this is a false positive or not relevant (at least 3 characters) so the next person understands."}
	ErrAlreadyOpen  = &APIError{"already_open", 409, "This finding is already open."}
)

// Errors that are not API codes.
var (
	// ErrInvalidCVE: the id does not match ^CVE-\d{4}-\d{4,}$ (PRE-1).
	ErrInvalidCVE = errors.New("invalid CVE id")
	// ErrInvalidEvidence: scan evidence lacks a template or time, or a field is too large (PRE-2).
	ErrInvalidEvidence = errors.New("invalid scan evidence")
)
