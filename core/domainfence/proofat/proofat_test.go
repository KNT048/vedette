package proofat

import "testing"

// A record's name is the domain or a parent of it, down to the registered domain, never a public
// suffix of either section of the list, nor a name above one.
func TestWithin(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		domain, at string
		want       bool
	}{
		{"git.example.org", "example.org", true},
		{"git.example.org", "git.example.org", true},
		{"a.b.example.org", "b.example.org", true},
		{"git.example.org", "com", false},
		{"example.org", "git.example.org", false},
		{"git.example.org", "evil.com", false},
		{"x.example.ddns.net", "ddns.net", false},
		{"x.example.ddns.net", "example.ddns.net", true},
		{"victim.github.io", "github.io", false},
		{"a.b.co.uk", "co.uk", false},
		{"a.b.co.uk", "b.co.uk", true},
		{"bucket.s3.amazonaws.com", "amazonaws.com", false},
		{"bucket.s3.amazonaws.com", "s3.amazonaws.com", false},
		{"x.bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com", true},
		{"git.example.org", "", false},
	} {
		if got := Within(c.domain, c.at); got != c.want {
			t.Errorf("Within(%s, %s) = %v, want %v", c.domain, c.at, got, c.want)
		}
	}
}
