package findings

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

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
	ErrBadAction    = &APIError{"bad_action", 400, "Choose one of: patched, mitigated, false positive, not relevant, accept risk, or reopen."}
	ErrNoteTooLong  = &APIError{"note_too_long", 400, "The note can be at most 500 characters. Shorten it."}
	ErrNoteRequired = &APIError{"note_required", 400, "Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands."}
	ErrBadUntil     = &APIError{"bad_until", 400, "Accept the risk until a date from tomorrow up to one year from today."}
	ErrAlreadyOpen  = &APIError{"already_open", 409, "This finding is already open."}
)

// Errors that are not API codes.
var (
	// ErrInvalidCVE: the id does not match ^CVE-\d{4}-\d{4,}$ (PRE-1).
	ErrInvalidCVE = errors.New("invalid CVE id")
	// ErrInvalidEvidence: scan evidence lacks a template or time, or a field is too large (PRE-2).
	ErrInvalidEvidence = errors.New("invalid scan evidence")
)

// ErrUnknownAsset means the device does not exist in the inventory (PRE-1 of UpsertFromMatch).
var ErrUnknownAsset = errors.New("unknown asset")

// ErrInvalidUser means the acting user is not 1 to 320 bytes of valid text (an email address or "system").
var ErrInvalidUser = errors.New("invalid user")

// ValidUser checks a history and audit user: 1 to 320 bytes of UTF-8 without NUL, the limits of
// core_audit and of the history table.
func ValidUser(u string) error {
	if u == "" || len(u) > 320 || !utf8.ValidString(u) || strings.ContainsRune(u, 0) {
		return fmt.Errorf("findings: checking the acting user: %w", ErrInvalidUser)
	}
	return nil
}
