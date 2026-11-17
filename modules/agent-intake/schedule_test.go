package agentintake

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The config every node gets is the schedule the approved GUI shows (agentConfig.ts, OSQUERY_SCHEDULE): same queries, intervals,
// platforms. Drift between the two means the user is told something other than what is collected.
func TestScheduleEqualsTheGUIText(t *testing.T) {
	src, err := os.ReadFile("../../web/src/features/inventory/agentConfig.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\s+(\w+): \{ query: ('|")(.*?)('|"), interval: (\d+), snapshot: true(?:, platform: '(\w+)')? \},?$`)
	m := re.FindAllStringSubmatch(string(src), -1)
	if len(m) != len(schedule) {
		t.Fatalf("the GUI has %d queries, the module %d", len(m), len(schedule))
	}
	for i, g := range m {
		interval, _ := strconv.Atoi(g[5])
		q := schedule[i]
		if g[1] != q.name || g[3] != q.query || interval != q.interval || g[6] != q.platform {
			t.Errorf("query %d differs:\nGUI    %s %q %d %q\nmodule %s %q %d %q", i, g[1], g[3], interval, g[6], q.name, q.query, q.interval, q.platform)
		}
		if _, ok := columns[q.name]; !ok {
			t.Errorf("query %s has no allow-listed columns", q.name)
		}
	}
	if len(columns) != len(schedule) {
		t.Errorf("%d allow-listed queries for %d scheduled", len(columns), len(schedule))
	}
}

// What a node must never be asked: no exec-type, file, hash or curl table, no write.
func TestScheduleIsReadOnly(t *testing.T) {
	bad := regexp.MustCompile(`(?i)\b(curl|curl_certificate|file|hash|augeas|yara|carves|osquery_extensions|processes|process_open_sockets|users|shadow|authorized_keys|startup_items|crontab|docker_\w+|command)\b|;.*;|\b(insert|update|delete|drop|create|attach)\b`)
	// INV-22: the only read of processes is the name of the program behind a listening port, joined on its pid (no command line,
	// path, user or environment): that join is taken out before the check, and nothing else of p may be read.
	const join = " LEFT JOIN processes p USING (pid)"
	otherCol := regexp.MustCompile(`\bp\.(\w+)`)
	for _, q := range schedule {
		text := q.query
		if strings.Contains(text, join) {
			text = strings.Replace(text, join, "", 1)
			for _, m := range otherCol.FindAllStringSubmatch(text, -1) {
				if m[1] != "name" {
					t.Errorf("query %s reads processes.%s", q.name, m[1])
				}
			}
		}
		if bad.MatchString(text) {
			t.Errorf("query %s: %s", q.name, q.query)
		}
	}
}
