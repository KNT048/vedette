package pdftext

import "time"

// ValidArgs and SetWallLimit are the two internals the external tests need.
var ValidArgs = validArgs

// SetWallLimit shortens the wall-clock kill and returns the function that restores it.
func SetWallLimit(d time.Duration) (restore func()) {
	old := wallLimit
	wallLimit = d
	return func() { wallLimit = old }
}
