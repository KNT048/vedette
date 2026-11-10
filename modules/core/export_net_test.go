package core

import (
	"context"
	"log/slog"

	"github.com/knt048/vedette/core/apierr"
)

// MapHostCodeForTest lets the external tests read the table of host codes.
func MapHostCodeForTest(code string) *apierr.Error {
	return mapHostCode(context.Background(), slog.New(slog.DiscardHandler), code, "", 0)
}
