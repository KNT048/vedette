package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/store"
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

// aiLogAround is ai.Config.LogAround: what the logs counted about one address (kinds of line, counts and connections to listed
// destinations; D-223), for the events_around tool of log investigation. Field by field: logs.Around has no line to drop.
func aiLogAround(d *deps) func(context.Context, netip.Addr, time.Time, time.Time) (ai.LogAroundData, bool, error) {
	return func(ctx context.Context, ip netip.Addr, from, to time.Time) (ai.LogAroundData, bool, error) {
		if d.Reg != nil && !d.Reg.Enabled("logs") {
			return ai.LogAroundData{}, false, nil
		}
		svc := logsService(*d)
		if svc == nil {
			return ai.LogAroundData{}, false, nil
		}
		a, err := svc.EventsAround(ctx, ip, from, to)
		if err != nil {
			return ai.LogAroundData{}, false, fmt.Errorf("logs around an address: %w", err)
		}
		out := ai.LogAroundData{Lines: a.Lines}
		for _, k := range a.Kinds {
			out.Kinds = append(out.Kinds, ai.LogAroundKind{Signature: k.Signature, SourceName: k.SourceName, Count: k.Count})
		}
		for _, h := range a.Connections {
			out.Connections = append(out.Connections, ai.LogDigestBadConn{TS: store.FormatTS(h.TS), AssetName: h.AssetName, SrcIP: h.SrcIP, Dest: h.Dest, DestKind: h.DestKind,
				SeenVia: h.SeenVia, Feeds: h.Feeds, Confidence: h.Confidence})
		}
		return out, true, nil
	}
}
