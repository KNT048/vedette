package server

import (
	"strings"

	"github.com/knt048/vedette/core/api/routes"
)

// moduleOverrides map a path prefix (on segment boundaries) to the module that owns it when that
// differs from the ogen tag. The longest matching prefix wins. The tag is the first path segment of
// the contract (API_CONVENTIONS section 1), so only the exceptions are listed.
var moduleOverrides = []struct{ prefix, module string }{
	{"/findings", "findings"}, // D-57 (6): its own module; the folder arrives with WP-21
	{"/scans", "scan"},
	{"/core/oidc", "auth-oidc"},
	{"/core/sso", "auth-oidc"},
	{"/core/mcp", "mcp-server"},
	{"/install", "agent-intake"},
	{"/intake", "agent-intake"},
	{"/inventory/agents", "agent-intake"},
	{"/inventory/sensors", "sensor-passive"},
	{"/core/network", "host"},
	{"/auth", "core"},
	{"/me", "core"},
	{"/modules", "core"},
	{"/setup", "core"},
}

// ModuleOf returns the id of the module that owns an operation. When that module is off its routes
// answer 404 as if they did not exist (SYS-5).
func ModuleOf(op routes.Operation) string {
	best, bestLen := op.Tag, 0
	for _, o := range moduleOverrides {
		if len(o.prefix) > bestLen && hasSegmentPrefix(op.Path, o.prefix) {
			best, bestLen = o.module, len(o.prefix)
		}
	}
	return best
}

func hasSegmentPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}
