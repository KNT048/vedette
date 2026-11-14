package debver

import "testing"

// The vectors are written for this package from Debian Policy §5.6.12 and from the versions the Ubuntu and Debian
// security data name (D-516); each was checked once against "dpkg --compare-versions" on Ubuntu 26.04.
func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0-0", 0},    // no revision is revision ""; "" and "0" are the same number
		{"0:1.0", "1.0", 0},    // no epoch is epoch 0
		{"1.0", "1.1", -1},     // numbers
		{"1.10", "1.9", 1},     // numbers, not text
		{"1.01", "1.1", 0},     // leading zeros
		{"1:1.0", "2.0", 1},    // the epoch first
		{"2:0.1", "1:9.9", 1},  // the epoch first
		{"1.0~rc1", "1.0", -1}, // a tilde sorts before the end
		{"1.0~~", "1.0~", -1},  // and before another tilde's end
		{"1.0", "1.0+b1", -1},  // anything else after the end sorts after it
		{"1.0a", "1.0+", -1},   // letters before other characters
		{"1.0a", "1.0", 1},     // a letter after the end
		{"1.0-1", "1.0-2", -1}, // the revision
		{"1.0-10", "1.0-9", 1}, // the revision is numeric too
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"1:9.6p1-3ubuntu13.14", "1:9.6p1-3ubuntu13.5", 1},
		{"1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.5", 0},
		{"1.9.15p5-3ubuntu5.24.04.1", "1.9.15p5-3ubuntu5.24.04.4", -1},
		{"1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.24.04.1", -1},
		{"2.36-9+deb12u7", "2.36-9+deb12u3", 1},
		{"2.36-9", "2.36-9+deb12u3", -1},
		{"1:2.25.1-1ubuntu3.14+esm6", "1:2.25.1-1ubuntu3.14", 1},
		{"1:7.9p1-10~ubuntu18.04.fips.0.10", "1:7.9p1-10", -1},
		{"1.2-3-4", "1.2-3-5", -1}, // the revision is after the last hyphen
		{"1.2-3-4", "1.2-3", 1},
	} {
		got, err := Compare(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
		if back, _ := Compare(c.b, c.a); back != -c.want {
			t.Errorf("Compare(%q, %q) = %d; want %d", c.b, c.a, back, -c.want)
		}
	}
}

func TestInvalid(t *testing.T) {
	for _, v := range []string{"", "abc", ":1.0", "a:1.0", "1.0-", "1.0 1", "1.0-1:2", "1.0-1_2", "1:", "1234567890:1.0", "1.0;rm", "1.0\n"} {
		if Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
		if _, err := Compare(v, "1.0"); err == nil {
			t.Errorf("Compare(%q, 1.0) accepted", v)
		}
	}
	long := "1." + string(make([]byte, MaxLen))
	if Valid(long) {
		t.Error("a version over MaxLen is valid")
	}
	for _, v := range []string{"0", "1:1.0", "1:1.0-1:2-3", "1.0~rc1+dfsg-1ubuntu0.1~esm1", "2.38-1ubuntu6"} {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false", v)
		}
	}
}

func FuzzCompare(f *testing.F) {
	for _, s := range []string{"1:9.6p1-3ubuntu13.5", "1.0~rc1", "2.36-9+deb12u3", "0"} {
		f.Add(s, "1.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		x, err1 := Compare(a, b)
		y, err2 := Compare(b, a)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("errors differ: %v %v", err1, err2)
		}
		if err1 == nil && x != -y {
			t.Fatalf("Compare(%q,%q)=%d but Compare(%q,%q)=%d", a, b, x, b, a, y)
		}
		if same, err := Compare(a, a); err1 == nil && (err != nil || same != 0) {
			t.Fatalf("Compare(%q,%q)=%d", a, a, same)
		}
	})
}

func TestSameUpstreamAndRevision(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"1:9.6p1-3ubuntu13.14", "1:9.6p1-3ubuntu13.5", true},
		{"7.0.0-43.43", "7.0.0-31.31", true},
		{"2.4.62-1+ubuntu24.04.1+deb.sury.org+1", "2.4.58-1ubuntu8.8", false}, // another upstream release (a PPA)
		{"9.6p1-3ubuntu13.14", "1:9.6p1-3ubuntu13.5", false},                  // the epoch counts
		{"1.01-1", "1.1-1", false},
		{"bad", "1.0-1", false},
	} {
		if got := SameUpstream(c.a, c.b); got != c.same {
			t.Errorf("SameUpstream(%q, %q) = %v", c.a, c.b, got)
		}
	}
	if Revision("1:9.6p1-3ubuntu13.14") != "3ubuntu13.14" || Revision("2.38") != "" || Revision("x") != "" {
		t.Error("Revision")
	}
}
