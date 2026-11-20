package sensorpassive

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// MirrorMatcher is what core does with the mirror-port metadata of the sensor (POST /metadata): cmd/vedette hands it to the logs
// module, which matches the names and addresses against the threat feeds and stores only the matches. The module never stores
// metadata itself (INV-3, FORBID-2).
type MirrorMatcher func(ctx context.Context, items []sensorlink.MetadataItem) error

// Metadata implements sensorlink.MetadataReceiver: the batch goes to the MirrorMatcher as it is (the server has checked every item's
// shape). With the module turned off since the listener let the request in it is refused (SYS-5); without a matcher it is dropped.
// A matcher that fails makes the sensor send the batch again later.
func (s *Service) Metadata(ctx context.Context, req *sensorlink.MetadataRequest) error {
	if req == nil || len(req.Items) == 0 || len(req.Items) > sensorlink.MaxMetadataItems {
		return sensorlink.NewError(sensorlink.CodeInvalidRequest)
	}
	if s.off() {
		return sensorlink.NewError(sensorlink.CodeModuleOff)
	}
	if s.mirror == nil {
		return nil
	}
	if err := s.mirror(ctx, req.Items); err != nil {
		s.log.WarnContext(ctx, "sensor-passive: mirror-port metadata not matched, the sensor will send it again", "count", len(req.Items), "error", err)
		return sensorlink.StoreBusy(time.Second)
	}
	return nil
}
