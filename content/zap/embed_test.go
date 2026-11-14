package zapdata

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// D-565: the shipped list is a file zap-baseline.py -c accepts (the format -g writes), every rule line is explained by the comment
// above it, and it holds exactly the plan's statuses.
func TestBaseline_IsZAPConfig(t *testing.T) {
	t.Parallel()
	rules, err := Parse(Baseline)
	if err != nil {
		t.Fatal(err)
	}
	// load_config of zaproxy docker/zap_common.py: skip "#" and blank lines, refuse fewer than two tabs, split("\t", 2), the level
	// must be one of PASS, IGNORE, INFO, WARN, FAIL (OUTOFSCOPE takes a regex instead).
	lines := strings.Split(strings.TrimSuffix(string(Baseline), "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Count(line, "\t") < 2 {
			t.Fatalf("line %d: ZAP needs two tabs: %q", i+1, line)
		}
		f := strings.SplitN(strings.TrimRight(line, " \t\r"), "\t", 3)
		if !slices.Contains([]string{"PASS", "IGNORE", "INFO", "WARN", "FAIL"}, f[1]) {
			t.Fatalf("line %d: ZAP refuses level %q", i+1, f[1])
		}
		if i == 0 || !strings.HasPrefix(lines[i-1], "# ") {
			t.Fatalf("line %d: rule %s has no comment saying why", i+1, f[0])
		}
	}
	want := map[int]string{}
	for _, id := range []int{10096, 10027, 10109, 10049, 10015, 10111, 10112, 10110, 90004, 10063} {
		want[id] = Ignore
	}
	for _, id := range []int{10020, 10021, 10035, 10038, 10055, 10010, 10011, 10054, 10098, 10202, 2} {
		want[id] = Warn
	}
	for _, id := range []int{10003, 10036, 10037, 90022, 10023, 10062, 10040, 10105, 10041, 10042, 10097, 10052, 10056} {
		want[id] = Fail
	}
	if !maps.Equal(rules, want) {
		t.Fatalf("rules = %v", rules)
	}
}

// D-565: a list that ZAP would refuse, or that says one rule twice, is refused.
func TestParse_RefusesWhatZAPWouldNot(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"10020\tWARN\n",                        // one tab: ZAP's load_config fails
		"10020 WARN (x)\n",                     // spaces, not tabs
		"10020\tINFO\t(x)\n",                   // not one of Vedette's three
		"10020\twarn\t(x)\n",                   // case
		"010020\tWARN\t(x)\n",                  // leading zero
		"-1\tWARN\t(x)\n",                      // not an id
		"10020\tWARN\tx\n",                     // name not in parentheses
		"10020\tWARN\t(x)\tmsg\n",              // a third tab
		"10020\tWARN\t(x)\n10020\tFAIL\t(x)\n", // twice
		"10020\tWARN\t(x)",                     // no final newline
		" 10020\tWARN\t(x)\n",                  // leading space
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if r, err := Parse([]byte("# c\n\n10020\tWARN\t(Anti-clickjacking Header)\n")); err != nil || r[10020] != Warn {
		t.Fatalf("%v %v", r, err)
	}
}

// D-565: every header product maps to a CPE part:vendor:product as nmap prints it.
func TestHeaderCPE_IsValid(t *testing.T) {
	t.Parallel()
	var m map[string]string
	if err := json.Unmarshal(HeaderCPE, &m); err != nil {
		t.Fatal(err)
	}
	key, cpe := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`), regexp.MustCompile(`^a:[a-z0-9_.-]+:[a-z0-9_.-]+$`)
	for k, v := range m {
		if k == "_about" {
			continue
		}
		if !key.MatchString(k) || !cpe.MatchString(v) {
			t.Errorf("%q: %q", k, v)
		}
	}
	if len(m) < 5 {
		t.Fatalf("only %d entries", len(m))
	}
}
