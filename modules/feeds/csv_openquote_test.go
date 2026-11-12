package feeds

import "testing"

// A quote left open flags the row that opened it and the rest is read with quotes literal; when that row is a comment nothing is flagged.
func TestParseCSVOpenQuote(t *testing.T) {
	t.Parallel()
	rows := parseCSV("a,b\n1,\"x\n2,y\n", ',', true)
	if len(rows) != 3 || rows[1].bad != csvOpenQuote || rows[1].line != 2 || rows[2].bad != "" || rows[2].line != 3 {
		t.Errorf("open quote: %+v", rows)
	}
	rows = parseCSV("#a,\"b\nX,y\n", ',', true)
	if len(rows) != 1 || rows[0].bad != "" || rows[0].line != 2 || rows[0].cells[0] != "X" {
		t.Errorf("comment row that opens a quote: %+v", rows)
	}
}
