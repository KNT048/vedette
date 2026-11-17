package orgtime

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// formatCall is a call of time.Time.Format with a literal layout; humanLayout is a layout people read (a month name or a clock),
// not a machine one (ISO 8601 with its "T", a bare YYYY-MM-DD, a file-name stamp).
var (
	formatCall  = regexp.MustCompile(`\.Format\("([^"]*)"\)`)
	labelledUTC = regexp.MustCompile(`\+\s*" UTC"`)
)

func humanLayout(l string) bool {
	return (strings.Contains(l, "Jan") || strings.Contains(l, "15:04")) && !strings.Contains(l, "T15:04")
}

// cause sorts one line that writes a time for people outside this package.
func cause(line string) string {
	switch {
	case labelledUTC.MatchString(line):
		return "labelled UTC"
	case strings.Contains(line, ".UTC().Format("):
		return "UTC"
	case strings.Contains(line, ".In("):
		return "own zone conversion"
	}
	return "zone of the value (often UTC or the server's)"
}

// TestDisplayTimesGoThroughOrgTime is the guard of the whole class: every time written for people (pages, alerts, emails, AI
// facts) is written by this package, in the organization's time zone, or as a calendar day. A Format call with a layout people
// read anywhere else in the server is a date that can differ from the one the web shows for the same moment.
func TestDisplayTimesGoThroughOrgTime(t *testing.T) {
	root := filepath.Join("..", "..")
	byCause := map[string][]string{}
	for _, dir := range []string{"modules", "cmd", "core"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if slices.Contains([]string{"oas", "coredb", "testdata", "node_modules"}, d.Name()) || path == filepath.Join(root, "core", "orgtime") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path) //nolint:gosec // walks the repository's own source tree in a test
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(bytes.NewReader(b))
			sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
			for n := 1; sc.Scan(); n++ {
				line := sc.Text()
				human := labelledUTC.MatchString(line)
				for _, m := range formatCall.FindAllStringSubmatch(line, -1) {
					human = human || humanLayout(m[1])
				}
				if human {
					rel, _ := filepath.Rel(root, path)
					byCause[cause(line)] = append(byCause[cause(line)], rel+":"+itoa(n)+": "+strings.TrimSpace(line))
				}
			}
			return sc.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for c, lines := range byCause {
		total += len(lines)
		t.Errorf("%d time(s) written for people outside orgtime (%s):\n  %s", len(lines), c, strings.Join(lines, "\n  "))
	}
	if total > 0 {
		t.Logf("total: %d; write them with orgtime.Day/Stamp/Clock (an instant, in the organization's zone) or orgtime.CalendarDay (a day without a time)", total)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
