package apkver

import "testing"

// The order the feeds module keeps the higher of two fixed releases by, and the shapes it refuses.
func TestCompareAndValid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"29.4.3-r0", "29.4.2-r0", 1}, {"6.11.0-r1", "6.10.2-r13", 1}, {"10.2_p1-r1", "10.2_p1-r1", 0}, {"9.9_p2-r1", "10.0_p1-r11", -1},
		// apk-tools src/version.c: a suffix without a number before the same with 0, and the orders it checked
		{"1.0_p-r5", "1.0_p0-r0", -1}, {"1.0_rc1-r0", "1.0-r0", -1}, {"1.0-r0", "1.0_p1-r0", -1}, {"1.0_p1-r0", "1.0a-r0", -1}, {"1.0a-r0", "1.0.1-r0", -1},
		{"1.0_alpha-r0", "1.0_alpha1-r0", -1}, {"1.0_rc1_alpha-r0", "1.0_rc1-r0", -1}, {"1.0-r1", "1.0-r10", -1}, {"10.0_p1-r0", "10.0_p1-r0", 0},
	} {
		a, okA := Parse(tc.a)
		b, okB := Parse(tc.b)
		if !okA || !okB || Compare(a, b) != tc.want {
			t.Errorf("%s vs %s: %d, want %d", tc.a, tc.b, Compare(a, b), tc.want)
		}
	}
	// a later component with a leading zero is compared as a string by apk-tools: refused (fail closed); the first one is a number there too
	for _, bad := range []string{"1.9.5p2-r0", "0", "10.2_p1", "1:9.6p1-3ubuntu13.14", "", "1.05-r0", "1.010-r0", "2.4.01-r0"} {
		if Valid(bad) {
			t.Errorf("%q read as an apk release", bad)
		}
	}
	if Upstream("10.2_p1-r1") != "10.2_p1" {
		t.Error(Upstream("10.2_p1-r1"))
	}
}

// The first component with a leading zero is still read (apk-tools compares it as a number).
func TestLeadingZeroFirstComponent(t *testing.T) {
	t.Parallel()
	a, okA := Parse("01.2-r0")
	b, okB := Parse("1.2-r0")
	if !okA || !okB || Compare(a, b) != 0 {
		t.Errorf("01.2 vs 1.2: %v %v", okA, okB)
	}
}
