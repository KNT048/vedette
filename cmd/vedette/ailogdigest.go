package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/knt048/vedette/modules/ai"
)

// aiLogDigest is ai.Config.LogDigest: the digest of the logs module for the log-digest job (S-AI-4, D-221). It is read when asked,
// not when the services are built (logsService is built once with the finished deps). The answer of logs goes through JSON into
// ai's own type, which names only signatures, counts, devices and connections: the sample line of an item has no field there, so it
// cannot reach the AI. The second result is false while the logs module is off or the box has no logs.db.
func aiLogDigest(d *deps) func(context.Context) (ai.LogDigestData, bool, error) {
	return func(ctx context.Context) (ai.LogDigestData, bool, error) {
		if d.Reg != nil && !d.Reg.Enabled("logs") {
			return ai.LogDigestData{}, false, nil
		}
		svc := logsService(*d)
		if svc == nil {
			return ai.LogDigestData{}, false, nil
		}
		dg, err := svc.Digest(ctx)
		if err != nil {
			return ai.LogDigestData{}, false, fmt.Errorf("logs digest: %w", err)
		}
		raw, err := json.Marshal(dg)
		if err != nil {
			return ai.LogDigestData{}, false, fmt.Errorf("logs digest: %w", err)
		}
		var out ai.LogDigestData
		if err := json.Unmarshal(raw, &out); err != nil {
			return ai.LogDigestData{}, false, fmt.Errorf("logs digest: %w", err)
		}
		return out, true, nil
	}
}
