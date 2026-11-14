// Package zapdata embeds Vedette's rule list for ZAP's baseline scan (D-565, exposure INV-24): ONE file that the host hands to ZAP
// with -c and that exposure applies itself when it reads a report, so both agree on what is noise, hardening or "fix this".
//
//   - vedette-baseline.conf: zap-baseline.py -c format, rule ids from https://www.zaproxy.org/docs/alerts/.
//   - header-cpe.json: the product a Server or X-Powered-By header names to the CPE nmap prints for it.
package zapdata

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Baseline is vedette-baseline.conf.
//
//go:embed vedette-baseline.conf
var Baseline []byte

// HeaderCPE is header-cpe.json.
//
//go:embed header-cpe.json
var HeaderCPE []byte

// The statuses a rule may have in the file. ZAP also knows PASS, INFO and OUTOFSCOPE; Vedette's list uses these three only.
const (
	Ignore = "IGNORE"
	Warn   = "WARN"
	Fail   = "FAIL"
)

var ruleName = regexp.MustCompile(`^\([^\t]{1,120}\)$`)

// Parse reads a rule list the way zap-baseline.py's load_config does, and stricter: a line that starts with '#' is a comment, an
// empty line is skipped, and every other line is exactly "<id>\t<IGNORE|WARN|FAIL>\t(<name>)" (ZAP refuses a line with fewer than two
// tabs). An id is a ZAP plugin id (digits, no leading zero) listed once. It returns each id's status.
func Parse(data []byte) (map[int]string, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("zap rules: the file does not end with a newline")
	}
	out := map[int]string{}
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("zap rules: line %d: want <id> TAB <status> TAB (<name>)", i+1)
		}
		id, err := strconv.Atoi(f[0])
		if err != nil || id < 0 || id > 999999 || strconv.Itoa(id) != f[0] {
			return nil, fmt.Errorf("zap rules: line %d: %q is not a rule id", i+1, f[0])
		}
		if f[1] != Ignore && f[1] != Warn && f[1] != Fail {
			return nil, fmt.Errorf("zap rules: line %d: status %q is not IGNORE, WARN or FAIL", i+1, f[1])
		}
		if !ruleName.MatchString(f[2]) {
			return nil, fmt.Errorf("zap rules: line %d: the name must be in parentheses", i+1)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("zap rules: line %d: rule %d is listed twice", i+1, id)
		}
		out[id] = f[1]
	}
	return out, nil
}
