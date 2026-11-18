package pkgrel_test

import (
	"testing"

	"github.com/knt048/vedette/core/pkgrel"
)

func TestSame(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		av, ap, bv, bp string
		want           bool
	}{
		{"10.2", "", "10.2p1", "", true},
		{"10.2", "", "", "10.2_p1-r1", true},
		{"10.2p1", "10.2_p1-r1", "10.2", "", true},
		{"10.2", "10.2_p1-r1", "10.2p1", "", true},
		{"10.2p1 Ubuntu 2ubuntu3.8", "", "10.2p1", "1:10.2p1-2ubuntu3.8", true},
		{"9.2", "", "9.2p1", "1:9.2p1-2+deb12u3", true},
		{"8.7", "", "", "8.7p1-38.el9", true},
		{"", "8.7p1-38.el9_4.4", "", "8.7p1-38.el9", true},
		{"10.2", "", "10.3", "", false},
		{"10.2", "", "9.8", "", false},
		{"10.2", "", "10.20", "", false},
		{"10.2", "", "10.2.1", "", false},
		{"9.2", "", "", "1:9.6p1-3ubuntu13", false},
		{"", "", "10.2", "", false},
		{"2.4.0-rc1", "", "2.4.0", "", false},
		{"1.0-beta", "", "1.0", "", false},
		{"2024-01-15", "", "2024-01-20", "", false},
		{"2:2.3-1", "", "1:2.3-1", "", false},
		{"", "2:2.3-1", "", "2.3-1", true},
	} {
		if got := pkgrel.Same(tc.av, tc.ap, tc.bv, tc.bp); got != tc.want {
			t.Errorf("Same(%q,%q,%q,%q) = %v, want %v", tc.av, tc.ap, tc.bv, tc.bp, got, tc.want)
		}
		if got := pkgrel.Same(tc.bv, tc.bp, tc.av, tc.ap); got != tc.want {
			t.Errorf("reversed Same(%q,%q,%q,%q) = %v, want %v", tc.bv, tc.bp, tc.av, tc.ap, got, tc.want)
		}
	}
}
