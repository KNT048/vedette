package notify

import "context"

type baselineKey struct{}

// WithBaseline marks ctx as the work that follows the first CISA pull (D-78): the pull publishes one
// feeds.sync.baseline instead of one event per CVE, and inventory re-matches every device, which makes findings in
// bulk. cmd/vedette marks the context of that re-match; the mark travels with the context through inventory, findings
// and the event bus, down to the findings.finding.created handler here, which sends nothing for it.
func WithBaseline(ctx context.Context) context.Context {
	return context.WithValue(ctx, baselineKey{}, true)
}

// IsBaseline reports whether ctx carries the mark of WithBaseline.
func IsBaseline(ctx context.Context) bool {
	v, _ := ctx.Value(baselineKey{}).(bool)
	return v
}
