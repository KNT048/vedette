package wordlist

import (
	"strings"
	"testing"
)

// The committed list is clean: every line a label, none twice, at most MaxLabels, all of them loaded.
func TestLabelsAreClean(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	n := 0
	for line := range strings.SplitSeq(data, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if !labelRE.MatchString(line) || seen[line] {
			t.Errorf("labels.txt: %q is not a label or is there twice", line)
		}
		seen[line] = true
	}
	if n == 0 || n > MaxLabels || len(Labels()) != n {
		t.Errorf("labels.txt has %d labels (at most %d), %d loaded", n, MaxLabels, len(Labels()))
	}
}
