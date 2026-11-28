package exposure

import (
	"fmt"
	"regexp"
)

// The marks of migration 0003 are plain columns (no CHECK, so a release that carries them stays safe to roll back): their values are
// checked here, the one place the module makes them, before any write. opened_at is a timestamp as store.FormatTS writes it (the shape
// of first_seen); exploited is 0 (checked, not told) or 1 (told as exploited in the wild).

// tsShape is the shape store.FormatTS writes and every other timestamp column of the module checks in SQL.
var tsShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// openedAt returns at as a value of opened_at, or an error when it is not a timestamp of store.FormatTS.
func openedAt(at string) (string, error) {
	if !tsShape.MatchString(at) {
		return "", fmt.Errorf("exposure: %q is not a timestamp for opened_at", at)
	}
	return at, nil
}

// The values of exp_issue.exploited.
const (
	markChecked = 0 // checked, not exploited (or open again): the exploited-check job alerts it once if its CVE becomes exploited
	markTold    = 1 // told as exploited in the wild
)

// exploitedMark returns v as a value of exp_issue.exploited, or an error for anything but 0 and 1.
func exploitedMark(v int) (int, error) {
	if v != markChecked && v != markTold {
		return 0, fmt.Errorf("exposure: %d is not a value for exploited (0 or 1)", v)
	}
	return v, nil
}
