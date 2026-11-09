package ops

import (
	"strconv"
	"strings"
)

// schemaNewer reports whether the backup's schema is ahead of the current one: some module has a
// higher version in the backup, or exists only there. Both strings are core's own report
// ("module=version,..." from snapshot.json, kept in the archive manifest); the host never reads
// them from the database (D-87), so this is an early warning, and core's own check when it starts
// is the authority (a newer schema makes core refuse to start, the health check fails, the host
// puts the previous state back).
func schemaNewer(backup, live string) bool {
	l := parseSchema(live)
	for mod, v := range parseSchema(backup) {
		if v > l[mod] {
			return true
		}
	}
	return false
}

func parseSchema(s string) map[string]int {
	m := map[string]int{}
	for _, p := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil {
			m[k] = n
		}
	}
	return m
}
