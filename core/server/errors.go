package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-faster/jx"
	ht "github.com/ogen-go/ogen/http"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/validate"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// safeField admits only names that can come from the contract (property and parameter names).
var safeField = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\[\]-]{0,63}$`)

// mapError turns anything that can reach the error paths of the generated server into an API error.
// The returned bool says the cause is the server's own fault and must be logged.
func mapError(err error) (*apierr.Error, bool) {
	var (
		api     *apierr.Error
		maxErr  *http.MaxBytesError
		secErr  *ogenerrors.SecurityError
		reqErr  *ogenerrors.DecodeRequestError
		parErr  *ogenerrors.DecodeParamsError
		valErr  *validate.Error
		ctErr   *validate.InvalidContentTypeError
		paramEr *ogenerrors.DecodeParamError
	)
	switch {
	case errors.As(err, &api):
		return api, false
	case errors.Is(err, store.ErrBusy): // the writer stayed taken past the request's wait limit (D-246); store logged it
		return serverBusy(), false
	case errors.As(err, &maxErr):
		return apierr.TooLarge(), false
	case errors.As(err, &secErr):
		return apierr.Unauthenticated(), false
	case errors.Is(err, ht.ErrNotImplemented):
		return apierr.NotImplemented(), false
	case errors.Is(err, validate.ErrBodyRequired):
		return apierr.Invalid("Send a JSON request body."), false
	case errors.As(err, &ctErr):
		return apierr.Invalid("Send the request body as application/json."), false
	case errors.As(err, &valErr):
		if path := fieldPath(valErr); safeField.MatchString(path) {
			return apierr.Invalid(fmt.Sprintf("The field %q is missing or has a value that is not allowed. Fix it and try again.", path)).With("field", path), false
		}
		return apierr.Invalid("The request has a value that is not allowed. Fix it and try again."), false
	case errors.As(err, &paramEr):
		if safeField.MatchString(paramEr.Name) {
			return apierr.Invalid(fmt.Sprintf("The parameter %q is not valid.", paramEr.Name)), false
		}
		return apierr.Invalid("A parameter is not valid."), false
	case errors.As(err, &parErr):
		return apierr.Invalid("A parameter is not valid."), false
	case errors.As(err, &reqErr):
		if path, unknown := decodeFieldPath(reqErr.Err); safeField.MatchString(path) {
			msg := "The field %q has a value of the wrong type. Fix it and try again."
			if unknown {
				msg = "The field %q is not allowed. Remove it and try again."
			}
			return apierr.Invalid(fmt.Sprintf(msg, path)).With("field", path), false
		}
		return apierr.Invalid("The request body is not valid JSON of the expected shape."), false
	}
	return apierr.Internal(), true
}

// serverBusy is the 503 of a request refused because the database writer stayed busy past store.RequestWriteWait (D-246).
func serverBusy() *apierr.Error {
	return apierr.New(http.StatusServiceUnavailable, "server_busy", "The box is busy saving other changes. Try again in a few seconds.").
		With("retry_after", int(store.RequestWriteWait/time.Second))
}

// fieldPath is the full path of the first failing field of a validation error, for example
// "active.days[0]" or "lan_ranges": ogen nests one validate.Error per object level and names array
// elements "[i]". It is "" when there is no field. The path is made of contract names only (D-73).
func fieldPath(e *validate.Error) string {
	path := ""
	for e != nil && len(e.Fields) > 0 {
		f := e.Fields[0]
		if path != "" && !strings.HasPrefix(f.Name, "[") {
			path += "."
		}
		path += f.Name
		var next *validate.Error
		if !errors.As(f.Error, &next) {
			break
		}
		e = next
	}
	return path
}

// decodeFieldPath recovers the path of the failing field from a body decode error. ogen wraps the error
// of a field as `decode field "name"` once per object level and names an unknown key as
// `unexpected field "key"` (additionalProperties: false); array elements carry no index, so the path
// of an element is "tools.name", not "tools[0].name". Only these exact prefixes of the wrapping layers
// are read, never the leaf message (it can hold a value from the body). unknown says the last step
// is an unexpected key. The caller must still check the path against safeField: an unknown key is
// attacker-controlled.
func decodeFieldPath(err error) (path string, unknown bool) {
	const fieldPrefix, unknownPrefix = `decode field `, `unexpected field `
	for err != nil {
		if j, ok := err.(interface{ Unwrap() []error }); ok {
			// ogen joins the decode error with the result of closing the body (nil): same message
			if errs := j.Unwrap(); len(errs) == 1 {
				err = errs[0]
				continue
			}
			return "", false
		}
		next := errors.Unwrap(err)
		if next == nil {
			// the leaf is the only place a body key can appear, and only in this one form
			if q, ok := strings.CutPrefix(err.Error(), unknownPrefix); ok {
				key, uerr := strconv.Unquote(q)
				if uerr != nil {
					return "", true
				}
				return joinPath(path, key), true
			}
			return path, false
		}
		// the layer's own message is what it adds in front of the inner error
		layer := strings.TrimSuffix(err.Error(), ": "+next.Error())
		if q, ok := strings.CutPrefix(layer, fieldPrefix); ok {
			if name, uerr := strconv.Unquote(q); uerr == nil {
				path = joinPath(path, name)
			}
		}
		err = next
	}
	return path, false
}

func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// toOAS converts an API error to the generated response type, extras included.
func toOAS(e *apierr.Error, log *slog.Logger) *oas.ErrorStatusCode {
	extra := make(oas.ErrorErrorAdditional, len(e.Extra))
	for k, v := range e.Extra {
		b, err := json.Marshal(v)
		if err != nil {
			log.Error("dropping an error field that is not JSON", "field", k, "error", err)
			continue
		}
		extra[k] = jx.Raw(b)
	}
	return &oas.ErrorStatusCode{
		StatusCode: e.Status,
		Response:   oas.Error{Error: oas.ErrorError{Code: e.Code, Message: e.Message, AdditionalProps: extra}},
	}
}

// Fallback is the base of the composite handler: it answers every operation with 501 not_implemented
// (through oas.UnimplementedHandler) and implements NewError, the default error response of the
// generated server. See ExampleFallback for how it sits in the composite handler.
type Fallback struct {
	oas.UnimplementedHandler
	Log *slog.Logger
}

// NewError implements the default error response of oas.Handler: an *apierr.Error keeps its status,
// code, message and extra fields; ogen's own errors become 400/401/413/501; the rest is a 500 whose
// cause is logged with the request id and never sent.
func (f Fallback) NewError(ctx context.Context, err error) *oas.ErrorStatusCode {
	e, own := mapError(err)
	if own {
		f.Log.ErrorContext(ctx, "request failed", "request_id", RequestIDFrom(ctx), "error", err)
	}
	setRetryAfter(ctx, e)
	return toOAS(e, f.Log)
}

// errorHandler is installed with oas.WithErrorHandler: ogen sends decode, validation and
// not-implemented errors there instead of to NewError.
func errorHandler(log *slog.Logger) ogenerrors.ErrorHandler {
	return func(ctx context.Context, w http.ResponseWriter, _ *http.Request, err error) {
		e, own := mapError(err)
		if own {
			log.ErrorContext(ctx, "request failed", "request_id", RequestIDFrom(ctx), "error", err)
		}
		apierr.Write(w, e)
	}
}

// session is the ogen security handler. Authentication already ran outside ogen (the cookie is
// decoded once); here we only confirm that it produced a principal.
type session struct{}

func (session) HandleSession(ctx context.Context, _ oas.OperationName, _ oas.Session) (context.Context, error) {
	if _, ok := PrincipalFrom(ctx); !ok {
		return ctx, apierr.Unauthenticated()
	}
	return ctx, nil
}
