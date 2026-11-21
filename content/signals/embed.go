// Package signaldata embeds the release's seed of exploitation claims (seed.json): the claims Vedette's own decoders read from the
// sources that keep no history (the blogs' feeds hold their last 20 or so posts, Cisco's and Fortinet's advisory feeds about 7 weeks,
// Android's pages are read for two months), so a box installed later is not blind to claims made before it existed. Facts only: CVE
// id, source, date, link; no text. It is written by `go run ./scripts/release signal-seed` at each release, from the previous seed and
// the current feeds, never by hand, and it ships inside the release: no box fetches it from anywhere.
package signaldata

import _ "embed" // seed.json

// Seed is seed.json.
//
//go:embed seed.json
var Seed []byte
