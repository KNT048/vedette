package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/go-faster/jx"
	ht "github.com/ogen-go/ogen/http"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/validate"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
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
		if len(valErr.Fields) > 0 && safeField.MatchString(valErr.Fields[0].Name) {
			return apierr.Invalid(fmt.Sprintf("The field %q is missing or has a value that is not allowed. Fix it and try again.", valErr.Fields[0].Name)), false
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
		return apierr.Invalid("The request body is not valid JSON of the expected shape."), false
	}
	return apierr.Internal(), true
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
