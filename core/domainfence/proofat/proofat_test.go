package proofat

import "testing"

// D-632 (review r1 L1 of #960): a record's name is the domain or a parent of it, down to the registered domain, never a public
// suffix of either section of the list, nor a name above one.
func TestWithin(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		domain, at string
		want       bool
	}{
		{"git.beyondnetglobal.com", "beyondnetglobal.com", true},
		{"git.beyondnetglobal.com", "git.beyondnetglobal.com", true},
		{"a.b.beyondnetglobal.com", "b.beyondnetglobal.com", true},
		{"git.beyondnetglobal.com", "com", false},
		{"beyondnetglobal.com", "git.beyondnetglobal.com", false},
		{"git.beyondnetglobal.com", "evil.com", false},
		{"x.beyondhcm.ddns.net", "ddns.net", false},
		{"x.beyondhcm.ddns.net", "beyondhcm.ddns.net", true},
		{"victim.github.io", "github.io", false},
		{"a.b.co.uk", "co.uk", false},
		{"a.b.co.uk", "b.co.uk", true},
		{"bucket.s3.amazonaws.com", "amazonaws.com", false},
		{"bucket.s3.amazonaws.com", "s3.amazonaws.com", false},
		{"x.bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com", true},
		{"git.beyondnetglobal.com", "", false},
	} {
		if got := Within(c.domain, c.at); got != c.want {
			t.Errorf("Within(%s, %s) = %v, want %v", c.domain, c.at, got, c.want)
		}
	}
}
