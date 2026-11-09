// Package apierr is the one way to build an API error (docs/API_CONVENTIONS.md section 3.1).
// The response body is {"error":{"code","message", ...extra}}; client code branches on code,
// so every code is listed in section 3.3 of that document. Message is English, safe to show
// to the user, and never carries internal detail (paths, SQL, stack traces, secrets).
package apierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
)

// Codes used by the HTTP layer itself. Modules add their own codes through New; each must be
// in API_CONVENTIONS section 3.3 (the apierr test checks the ones declared here).
const (
	CodeUnauthenticated = "unauthenticated"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeInvalid         = "invalid"
	CodeTooLarge        = "too_large"
	CodeCoreModule      = "core_module"
	CodeMissingDeps     = "missing_dependencies"

	// New codes (not yet in section 3.3, proposed [DX] in the WP-04a report).
	CodeCSRFInvalid    = "csrf_invalid"
	CodeNotImplemented = "not_implemented"
	CodeInternal       = "internal"
)

var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Error is an API error. It implements error so handlers can return it directly.
type Error struct {
	Status  int
	Code    string
	Message string
	// Extra holds fields that sit next to code and message inside "error" (for example "missing").
	// Keys code and message are reserved.
	Extra map[string]any
}

// New returns an error with the given HTTP status, machine code and user-safe message.
// A status outside 400..599 or a malformed code is a programming error and panics.
func New(status int, code, message string) *Error {
	if status < 400 || status > 599 {
		panic(fmt.Sprintf("apierr: status %d is not an error status", status))
	}
	if !codeRE.MatchString(code) {
		panic("apierr: malformed code " + code)
	}
	return &Error{Status: status, Code: code, Message: message}
}

// With returns a copy of e with one more extra field.
func (e *Error) With(key string, value any) *Error {
	if key == "code" || key == "message" {
		panic("apierr: extra key " + key + " is reserved")
	}
	c := *e
	c.Extra = maps.Clone(e.Extra)
	if c.Extra == nil {
		c.Extra = map[string]any{}
	}
	c.Extra[key] = value
	return &c
}

// Error implements error. The text is for logs; the response body uses Message.
func (e *Error) Error() string {
	return fmt.Sprintf("api error %d %s: %s", e.Status, e.Code, e.Message)
}

// Unauthenticated is 401: no valid session.
func Unauthenticated() *Error {
	return New(http.StatusUnauthorized, CodeUnauthenticated, "Not signed in.")
}

// Forbidden is 403: signed in but the role is too low.
func Forbidden() *Error {
	return New(http.StatusForbidden, CodeForbidden, "Your account is not allowed to do this.")
}

// CSRFInvalid is 403: a state-changing request without a matching CSRF token.
func CSRFInvalid() *Error {
	return New(http.StatusForbidden, CodeCSRFInvalid, "The security token is missing or has expired. Reload the page and try again.")
}

// NotFound is 404. Also used for a disabled module's routes, so it looks like an unknown route (SYS-5).
func NotFound() *Error {
	return New(http.StatusNotFound, CodeNotFound, "This item no longer exists.")
}

// Invalid is 400: input rejected at the boundary. message must say what to fix.
func Invalid(message string) *Error {
	return New(http.StatusBadRequest, CodeInvalid, message)
}

// TooLarge is 413: the request body is over the limit.
func TooLarge() *Error {
	return New(http.StatusRequestEntityTooLarge, CodeTooLarge, "The request is too large.")
}

// NotImplemented is 501: the contract has the operation but no handler is wired yet.
func NotImplemented() *Error {
	return New(http.StatusNotImplemented, CodeNotImplemented, "This feature is not available in this build yet.")
}

// Internal is 500. The cause is logged by the caller, never sent.
func Internal() *Error {
	return New(http.StatusInternalServerError, CodeInternal, "Something went wrong on the box. Try again; if it keeps happening, check the logs.")
}

// As returns the *Error inside err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Body returns the JSON object of the response: {"error": {"code", "message", ...extra}}.
func (e *Error) Body() map[string]any {
	inner := make(map[string]any, len(e.Extra)+2)
	maps.Copy(inner, e.Extra)
	inner["code"] = e.Code
	inner["message"] = e.Message
	return map[string]any{"error": inner}
}

// Write sends e as the response (Content-Type application/json; charset=utf-8).
func Write(w http.ResponseWriter, e *Error) {
	body, err := json.Marshal(e.Body())
	if err != nil { // only possible with an unmarshalable Extra value: a programming error, never leak it
		body = []byte(`{"error":{"code":"internal","message":"Something went wrong on the box."}}`)
		e = Internal()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(e.Status)
	_, _ = w.Write(append(body, '\n'))
}
