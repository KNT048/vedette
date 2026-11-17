package apkver

import "testing"

// D-605: the order the feeds module keeps the higher of two fixed releases by, and the shapes it refuses.
func TestCompareAndValid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"29.4.3-r0", "29.4.2-r0", 1}, {"6.11.0-r1", "6.10.2-r13", 1}, {"10.2_p1-r1", "10.2_p1-r1", 0}, {"9.9_p2-r1", "10.0_p1-r11", -1},
	} {
		a, okA := Parse(tc.a)
		b, okB := Parse(tc.b)
		if !okA || !okB || Compare(a, b) != tc.want {
			t.Errorf("%s vs %s: %d, want %d", tc.a, tc.b, Compare(a, b), tc.want)
		}
	}
	for _, bad := range []string{"1.9.5p2-r0", "0", "10.2_p1", "1:9.6p1-3ubuntu13.14", ""} {
		if Valid(bad) {
			t.Errorf("%q read as an apk release", bad)
		}
	}
	if Upstream("10.2_p1-r1") != "10.2_p1" {
		t.Error(Upstream("10.2_p1-r1"))
	}
}
