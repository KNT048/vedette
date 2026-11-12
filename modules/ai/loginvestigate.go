package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Log investigation (S-AI-4 at the maximum level, D-223): the log digest made with read-only tools. Besides the tools of the box that
// "Ask your data" uses (search_assets, lookup_ioc, lookup_cve), the model gets events_around, which reads through Config.LogAround
// what the logs counted about one address: kinds of line and counts, and connections to listed destinations. Never a log line
// (INV-11 of logs), like the digest itself.

// LogAroundData is what the logs counted about one address in a range.
type LogAroundData struct {
	Lines       int // every line counted for the address, also the kinds past the list
	Kinds       []LogAroundKind
	Connections []LogDigestBadConn
}

// LogAroundKind is a kind of line that named the address, with the name of its source and how many lines of it arrived.
type LogAroundKind struct {
	Signature  string
	SourceName string
	Count      int
}

// aroundKept is how far back the logs keep the counts per address (24 hours and one 5-minute bucket).
const aroundKept = 24 * time.Hour

const (
	eventsAroundDesc   = "Count what the logs of the last 24 hours say about one IP address around a time: the kinds of log line (signatures) that named it as the remote side, how many lines of each kind and from which log source, and its connections to addresses on threat feeds (blocked: true means the device that logged it stopped it, an attempt that never reached the address; false means it went through or the log does not say; seen_via span_dns is a DNS lookup, not a connection). at is an ISO 8601 time (default: now) and minutes the half-width of the window around it (default 60). Log lines themselves are never given, only kinds and counts."
	eventsAroundSchema = `{"type":"object","properties":{"ip":{"type":"string","maxLength":45},"at":{"type":"string","maxLength":32},"minutes":{"type":"integer","minimum":5,"maximum":720}},"required":["ip"],"additionalProperties":false}`
)

var eventsAroundArgs = map[string]argSpec{"ip": {kind: "string", max: 45}, "at": {kind: "string", max: 32}, "minutes": {kind: "int", min: 5, max: 720}}

func (s *Service) toolEventsAround(ctx context.Context, raw map[string]any) (toolOut, error) {
	ip, err := netip.ParseAddr(str(raw, "ip"))
	if err != nil || ip.Zone() != "" {
		return toolOut{}, errBadArgs{"ip is not an IP address"}
	}
	ip = ip.Unmap()
	now := s.cfg.Clock()
	at := now
	if v := str(raw, "at"); v != "" {
		if at, err = time.Parse(time.RFC3339, v); err != nil {
			return toolOut{}, errBadArgs{"at must be a time such as 2026-11-12T09:30:00Z"}
		}
	}
	half := 60 * time.Minute
	if m, ok := raw["minutes"].(int); ok {
		half = time.Duration(m) * time.Minute
	}
	from, to := at.Add(-half), at.Add(half)
	if kept := now.Add(-aroundKept); from.Before(kept) {
		from = kept
	}
	if to.After(now) {
		to = now
	}
	m := map[string]any{"ip": ip.String(), "from": FormatTS(from), "to": FormatTS(to), "note": "Kinds of line and counts only; the box does not give log lines."}
	if !from.Before(to) {
		m["note"] = "The box keeps these counts for 24 hours, and that time is outside them."
		b, _ := json.Marshal(m)
		return toolOut{Text: string(b), Summary: "outside the 24 hours kept", Cite: "Logs: counts per address"}, nil
	}
	d, on, err := s.cfg.LogAround(ctx, ip, from, to)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	if !on {
		return toolOut{}, errToolFailed{"the logs module is off"}
	}
	kinds := []map[string]any{}
	for _, k := range d.Kinds {
		// counts as text with thousands separators, as in the digest: a long number must not read as an identity number to the hooks
		kinds = append(kinds, map[string]any{"source": clip(k.SourceName, digestNameChars), "kind": clip(k.Signature, digestSigChars), "lines": number(k.Count)})
	}
	conns := []map[string]any{}
	for _, c := range d.Connections[:min(len(d.Connections), 10)] {
		who := ""
		if c.AssetName != nil {
			who = clip(*c.AssetName, digestNameChars)
		}
		conns = append(conns, map[string]any{"ts": clip(c.TS, 32), "device": who, "src_ip": clip(c.SrcIP, 45), "dest": clip(c.Dest, 253), "seen_via": clip(c.SeenVia, 60),
			"feeds": cleanAll(c.Feeds[:min(len(c.Feeds), digestFeedsMax)], digestNameChars), "confidence": c.Confidence, "blocked": c.Blocked})
	}
	m["lines"] = number(d.Lines)
	// as many connections, then kinds, as fit one result: a cut in the middle would leave no JSON (signatures are full of < and >,
	// written as they are, not escaped)
	for {
		m["kinds"], m["connections_to_listed"] = kinds, conns
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(m); err != nil {
			return toolOut{}, errToolFailed{"the box could not read that data"}
		}
		if b.Len() <= askResultBytes || (len(kinds) == 0 && len(conns) == 0) {
			return toolOut{Text: strings.TrimSuffix(b.String(), "\n"), Summary: fmt.Sprintf("%s lines of %s, %s", number(d.Lines), plural(len(kinds), "kind", "kinds"), plural(len(conns), "bad connection", "bad connections")),
				Cite: "Logs: counts per address"}, nil
		}
		if len(conns) > 0 {
			conns = conns[:len(conns)-1]
		} else {
			kinds = kinds[:len(kinds)-1]
		}
	}
}
