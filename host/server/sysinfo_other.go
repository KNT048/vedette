//go:build !linux

package server

import "time"

// systemInfo has no source off Linux (the binary refuses to run there; this serves tests).
func systemInfo(time.Time) (string, string, time.Time) { return "unknown", "", time.Time{} }
