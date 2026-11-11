// Package nucleipack is the index of the safe nuclei template pack baked into the scan-base image (D-146), committed so
// core plans jobs against the same pack: core picks the templates of a device's CVEs from it and names the pack's
// version and sha256 in every job, and the worker refuses a job planned for another pack (D-133 (4)).
//
// index.json and index.source are written by `make scan-pack` (scripts/scanpack, from deploy/containers/pins.env) next
// to the pack it puts in the image, and are never edited by hand: a test holds them to pins.env and to the index's own
// label. If they still drift from the image, the dispatcher's pack check refuses every job with a message naming both
// packs.
package nucleipack

import (
	_ "embed" // index.json

	"github.com/knt048/vedette/modules/scan/pack"
)

//go:embed index.json
var data []byte

// Index parses the embedded index with pack.Parse, the reader of core and the worker.
func Index() (*pack.Index, error) { return pack.Parse(data) }
