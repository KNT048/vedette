package nucleiout

import (
	"bytes"
	"strconv"
	"testing"
)

// D-527 (review r1 M4): a full run of 200 templates may print 40 lines a template (matches of tech-detect, payload requests), so
// its limit is 8000 lines; a small run keeps MaxLines.
func TestParse_LinesOfAFullRun(t *testing.T) {
	t.Parallel()
	many := make([]string, 200)
	for i := range many {
		many[i] = "t" + strconv.Itoa(i)
	}
	many[0] = templates[0]
	if _, err := Parse(bytes.Repeat([]byte(ok+"\n"), 200*LinesPerTemplate), many, targets); err != nil {
		t.Fatalf("8000 lines of a 200-template run refused: %v", err)
	}
	if _, err := Parse(bytes.Repeat([]byte(ok+"\n"), 200*LinesPerTemplate+1), many, targets); err == nil {
		t.Fatal("more than 8000 lines accepted")
	}
}
