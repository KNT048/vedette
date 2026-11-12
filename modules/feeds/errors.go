package feeds

import (
	"errors"
	"fmt"
)

// Sentinel errors. Callers map them to API codes (invalid_url, too_large, ...).
var (
	ErrInvalidURL       = errors.New("feeds: invalid feed address")
	ErrHTTPSRequired    = fmt.Errorf("%w: use https:// (http:// is only allowed for internal addresses)", ErrInvalidURL)
	ErrInvalidInterval  = errors.New("feeds: invalid interval")
	ErrInvalidFormat    = errors.New("feeds: format does not fit the feed kind")
	ErrInvalidName      = errors.New("feeds: invalid feed name")
	ErrDuplicateName    = errors.New("feeds: duplicate feed name")
	ErrDuplicateURL     = errors.New("feeds: another feed already uses this address")
	ErrBlockedHost      = errors.New("feeds: the address is the box itself, loopback, link-local or cloud metadata")
	ErrInvalidAuth      = errors.New("feeds: invalid authentication settings")
	ErrInvalidSecret    = errors.New("feeds: invalid secret")
	ErrInvalidWhitelist = errors.New("feeds: invalid whitelist entry")

	ErrTooLarge  = errors.New("feeds: data too large")
	ErrBadConfig = errors.New("feeds: bad parser configuration")
	ErrBadSample = errors.New("feeds: data could not be parsed")
)

// Error carries a sentinel plus a sentence that is safe to show to the user.
type Error struct {
	Err    error
	Detail string
}

func (e *Error) Error() string { return e.Err.Error() + ": " + e.Detail }
func (e *Error) Unwrap() error { return e.Err }

func fail(sentinel error, format string, a ...any) error {
	return &Error{Err: sentinel, Detail: fmt.Sprintf(format, a...)}
}
