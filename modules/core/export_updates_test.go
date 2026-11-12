package core

import (
	"context"

	"github.com/knt048/vedette/internal/release"
)

// SetUpdateOfferForTest stands in for the check side of the software update (updates.go seam) in the run
// side's tests: version is offered with an image for each of services (an empty version: nothing is offered),
// and restores says whether the running release puts the database back on rollback (rollback.safe=false).
func SetUpdateOfferForTest(h *OSHandlers, version string, services []string, restores bool) {
	h.upd.seam.Store(&updateSeam{
		offered: func(context.Context) (*verifiedRelease, error) {
			if version == "" {
				return nil, errNoUpdate
			}
			m := &release.Manifest{Version: version}
			for _, s := range services {
				m.Images = append(m.Images, release.Image{Service: s})
			}
			return &verifiedRelease{Index: []byte("index"), IndexSig: []byte("index sig"), Manifest: []byte("manifest"), ManifestSig: []byte("manifest sig"), M: m}, nil
		},
		restoresData: func(context.Context) (bool, error) { return restores, nil },
	})
}
