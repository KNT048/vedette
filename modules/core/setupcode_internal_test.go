package core

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewSetupCodeShape(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$`) // no 0, 1, I, O: they cannot be mistaken for each other
	seen := map[string]bool{}
	for range 200 {
		c, err := newSetupCode()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(c) {
			t.Fatalf("code %q", c)
		}
		if seen[c] {
			t.Fatalf("code %q made twice", c)
		}
		seen[c] = true
	}
}

func TestSetupCodesEqual(t *testing.T) {
	t.Parallel()
	const want = "ABCDE-FGHJK-LMNPQ-RSTUV"
	for in, eq := range map[string]bool{
		want: true, "abcde-fghjk-lmnpq-rstuv": true, "ABCDEFGHJKLMNPQRSTUV": true, " abcde fghjk lmnpq rstuv ": true, "ABCDE-FGHJK-LMNPQ-RSTUV\n": true,
		"": false, "ABCDE-FGHJK-LMNPQ-RSTUW": false, "ABCDE-FGHJK-LMNPQ": false, want + "A": false, "ABCDE": false,
		"ＡＢＣＤＥ-FGHJK-LMNPQ-RSTUV": false, strings.Repeat("A", 10_000): false,
	} {
		if got := setupCodesEqual(in, want); got != eq {
			t.Errorf("setupCodesEqual(%q) = %v, want %v", clipForTest(in), got, eq)
		}
	}
}

func clipForTest(s string) string {
	if len(s) > 30 {
		return s[:30] + "..."
	}
	return s
}
