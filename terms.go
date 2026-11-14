// Package vedette holds TERMS.md, the terms of use the first-run setup and the first-run restore ask the operator to
// accept (D-544). TERMS.md is the one source: the web interface imports the same file, and this package gives core its
// text and version.
package vedette

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"sync"
)

//go:embed TERMS.md
var Terms string

var termsDate = regexp.MustCompile(`(?m)^Version: (\d{4}-\d{2}-\d{2})$`)

// TermsVersion is the version of TERMS.md stored with an acceptance: the date of its "Version:" line and the first 8 hex
// digits of the file's SHA-256 (for example 2026-11-14.3f2a9c1b), so a change to the text is a new version even when the
// date line was not bumped.
var TermsVersion = sync.OnceValue(func() string {
	sum := sha256.Sum256([]byte(Terms))
	date := "undated"
	if m := termsDate.FindStringSubmatch(Terms); m != nil {
		date = m[1]
	}
	return date + "." + hex.EncodeToString(sum[:4])
})
