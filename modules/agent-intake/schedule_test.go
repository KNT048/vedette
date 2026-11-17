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
	// path, user or environment). The two queries that join it are pinned whole (#933 review L7: an unqualified cmdline through USING
	// (pid) would read the column too), and the join is taken out before the check of the rest.
	const join = " LEFT JOIN processes p USING (pid)"
	const listen = "SELECT DISTINCT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p USING (pid) WHERE l.port > 0 AND l.protocol IN (6, 17) AND l.address NOT LIKE '127.%' AND l.address != '::1'"
	pinned := map[string]string{
		"listening_ports":         listen + " AND l.net_namespace = (SELECT net_namespace FROM process_namespaces WHERE pid = 1);",
		"listening_ports_windows": listen + ";",
	}
	for _, q := range schedule {
		text := q.query
		if strings.Contains(text, join) {
			if text != pinned[q.name] {
				t.Errorf("query %s joins processes and is not the reviewed text: %s", q.name, text)
			}
			text = strings.Replace(text, join, "", 1)
		}
		if bad.MatchString(text) {
			t.Errorf("query %s: %s", q.name, q.query)
		}
	}
}
