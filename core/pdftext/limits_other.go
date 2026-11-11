//go:build !linux

package pdftext

// setLimits: only Linux is a supported box (the container image). Elsewhere (a developer's Mac) the child runs with the parent's
// wall-clock kill and the output caps alone.
//
// ponytail: no RLIMIT_AS off Linux (macOS refuses to lower it); the upgrade path is a Setrlimit file per OS if one ever ships.
func setLimits() error { return nil }
