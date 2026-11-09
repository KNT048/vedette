package sensorlink

import (
	"fmt"
	"net/http"
	"time"
)

// Error is an error of the wire: what the server answers and what the client reads back. Code is the contract (the table in
// sensor-protocol.md section 7); the message the server sends is fixed per code and never carries an internal detail.
type Error struct {
	Status     int
	Code       string
	RetryAfter time.Duration // 429 and 503
}

func (e *Error) Error() string { return fmt.Sprintf("sensorlink: %d %s", e.Status, e.Code) }

// The closed set of codes and the status each goes with. A handler that returns an *Error outside this table gets a 500.
const (
	CodeInvalidRequest   = "invalid_request"
	CodeForbiddenRoute   = "forbidden_route"
	CodeCertRetired      = "cert_retired"
	CodeUnknownJob       = "unknown_job"
	CodeModuleOff        = "module_off"
	CodePollInProgress   = "poll_in_progress"
	CodePayloadTooLarge  = "payload_too_large"
	CodeProtoUnsupported = "proto_unsupported"
	CodeRateLimited      = "rate_limited"
	CodeStoreBusy        = "store_busy"
	CodeInternal         = "internal"
)

var codes = map[string]struct {
	status  int
	message string
}{
	CodeInvalidRequest:   {http.StatusBadRequest, "The request is not valid."},
	CodeForbiddenRoute:   {http.StatusForbidden, "This role may not call this route."},
	CodeCertRetired:      {http.StatusForbidden, "This certificate is no longer current."},
	CodeUnknownJob:       {http.StatusNotFound, "No such running job."},
	CodeModuleOff:        {http.StatusConflict, "The module for this role is off."},
	CodePollInProgress:   {http.StatusConflict, "A long poll is already open for this role."},
	CodePayloadTooLarge:  {http.StatusRequestEntityTooLarge, "The request body is too large."},
	CodeProtoUnsupported: {http.StatusUpgradeRequired, "Unsupported protocol version."},
	CodeRateLimited:      {http.StatusTooManyRequests, "Too many requests."},
	CodeStoreBusy:        {http.StatusServiceUnavailable, "The store is busy."},
	CodeInternal:         {http.StatusInternalServerError, "Internal error."},
}

// NewError builds the Error for code. It panics on a code outside the table: that is a programming error.
func NewError(code string) *Error {
	c, ok := codes[code]
	if !ok {
		panic("sensorlink: unknown error code " + code)
	}
	return &Error{Status: c.status, Code: code}
}

// StoreBusy is the 503 a handler returns when the store is busy; retry is the Retry-After (at least one second).
func StoreBusy(retry time.Duration) *Error {
	e := NewError(CodeStoreBusy)
	e.RetryAfter = retry
	return e
}

// retrySeconds is the Retry-After value for d: whole seconds, rounded up, at least 1.
func retrySeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	return max(s, 1)
}
