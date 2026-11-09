package findings

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"7.2.4", "7.2.4", 0},
		{"7.2", "7.2.0", 0},
		{"7.2.0.0", "7.2", 0},
		{"7.2.10", "7.2.9", 1},
		{"7.10", "7.9", 1},
		{"2.4.57", "v2.4.57", 0},
		{"V2.4.57", "2.4.56", 1},
		{"7.0.0 build 1234", "7.0.0", 0},
		{"7.0.0 build 1234", "7.0.1", -1},
		{"7.0.0 build 1234", "7.0.0 build 9999", 0},
		{"1.1.1w", "1.1.1", 1},
		{"1.1.1w", "1.1.1v", 1},
		{"1.1.1a", "1.1.2", -1},
		{"1.0.2p", "1.0.2", 1},
		{"10.0.19045.3693", "10.0.19045.3692", 1},
		{"10.0.19045.3693", "10.0.19044.9999", 1},
		{"DSM 7.1.1-42962", "7.1.1", 0},
		{"DSM 7.1.1-42962", "7.1.2", -1},
		{"1.0-rc1", "1.0", -1},
		{"1.0-rc1", "1.0.0", -1},
		{"1.0-rc2", "1.0-rc1", 1},
		{"1.0-beta", "1.0-rc1", -1},
		{"1.0-alpha", "1.0-beta", -1},
		{"1.0b2", "1.0a9", 1},
		{"1.0rc1", "1.0-RC1", 0},
		{"1.0~rc1", "1.0", -1},
		{"8.9p1", "8.9", 1},
		{"8.9p1", "9.0", -1},
		{"2.0-sp1", "2.0", 1},
		{"1.2.3+dfsg", "1.2.3", 0},
		{"1.2.3-4ubuntu1", "1.2.3", 0},
		{"1.2.3 GA", "1.2.3", 0},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"20230101", "20221231", 1},
		{"115.0esr", "115.0", 0},
		{"1.99999999999999999", "1.2", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"|"+tt.b, func(t *testing.T) {
			t.Parallel()
			got, ok := CompareVersions(tt.a, tt.b)
			if !ok {
				t.Fatalf("CompareVersions(%q,%q) not comparable", tt.a, tt.b)
			}
			if got != tt.want {
				t.Fatalf("CompareVersions(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if back, _ := CompareVersions(tt.b, tt.a); back != -tt.want {
				t.Fatalf("not antisymmetric: reverse = %d", back)
			}
		})
	}
}

func TestCompareVersions_NotComparable(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"", "   ", "unknown", "latest", "n/a", "x86_64", "R2", "(1.2)", "1.2.3-foo", "1.0-ubuntu", "1.0.git2023",
		"1.0~git", "7.2.x", ".", strings.Repeat("1.", 40) + "1", strings.Repeat("9", 40), strings.Repeat("a", 200) + "1",
		"1.99999999999999999999999",
	} {
		if _, ok := CompareVersions(s, "1.0"); ok {
			t.Errorf("CompareVersions(%.30q, 1.0) claimed to be comparable", s)
		}
		if _, ok := CompareVersions("1.0", s); ok {
			t.Errorf("CompareVersions(1.0, %.30q) claimed to be comparable", s)
		}
	}
}

func TestVersionRange_Contains(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    VersionRange
		v    string
		want Tri
	}{
		{"all versions", VersionRange{}, "1.0", Yes},
		{"all versions, unknown version", VersionRange{}, "weird", Yes},
		{"start incl at bound", VersionRange{StartIncl: "7.0"}, "7.0.0", Yes},
		{"start incl below", VersionRange{StartIncl: "7.0"}, "6.9", No},
		{"start excl at bound", VersionRange{StartExcl: "7.0"}, "7.0", No},
		{"start excl above", VersionRange{StartExcl: "7.0"}, "7.0.1", Yes},
		{"end incl at bound", VersionRange{EndIncl: "7.2.4"}, "7.2.4", Yes},
		{"end incl above", VersionRange{EndIncl: "7.2.4"}, "7.2.5", No},
		{"end excl at bound", VersionRange{EndExcl: "7.2.4"}, "7.2.4", No},
		{"end excl below", VersionRange{EndExcl: "7.2.4"}, "7.2.3", Yes},
		{"closed interval inside", VersionRange{StartIncl: "7.0", EndExcl: "7.2.4"}, "7.1.9", Yes},
		{"closed interval outside high", VersionRange{StartIncl: "7.0", EndExcl: "7.2.4"}, "7.2.4", No},
		{"vendor string inside", VersionRange{StartIncl: "7.0", EndExcl: "7.2.4"}, "7.1.1 build 55", Yes},
		{"1.1.1w vs end excl 1.1.1w", VersionRange{EndExcl: "1.1.1w"}, "1.1.1w", No},
		{"unparseable version", VersionRange{StartIncl: "7.0"}, "weird", Unknown},
		{"empty version", VersionRange{EndExcl: "7.0"}, "", Unknown},
		{"unparseable bound", VersionRange{EndExcl: "next"}, "1.0", Unknown},
		{"definite violation beats unknown bound", VersionRange{StartIncl: "9.0", EndExcl: "next"}, "1.0", No},
		{"unknown bound, other satisfied", VersionRange{StartIncl: "1.0", EndExcl: "next"}, "2.0", Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.r.Contains(tt.v); got != tt.want {
				t.Fatalf("Contains(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestVersionRange_String(t *testing.T) {
	t.Parallel()
	for r, want := range map[VersionRange]string{
		{}:                                     "all versions",
		{StartIncl: "7.0", EndExcl: "7.2.1"}:   "7.0 or later, before 7.2.1",
		{StartExcl: "7.0", EndIncl: "7.2.1"}:   "later than 7.0, up to 7.2.1",
		{StartIncl: "7.2.4", EndIncl: "7.2.4"}: "version 7.2.4",
		{EndExcl: "2.4.58"}:                    "before 2.4.58",
	} {
		if got := r.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func FuzzCompareVersions(f *testing.F) {
	for _, s := range []string{"7.2.4", "7.2", "v2.4.57", "1.1.1w", "7.0.0 build 1234", "10.0.19045.3693", "DSM 7.1.1-42962", "1.0-rc1", "8.9p1", "1.0~beta2", "", "x", "1.0+meta"} {
		f.Add(s, s, s)
		f.Add(s, "1.0", "2.0.1")
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, okAB := CompareVersions(a, b)
		ba, okBA := CompareVersions(b, a)
		if okAB != okBA {
			t.Fatalf("comparability not symmetric for %q,%q", a, b)
		}
		if okAB && ab != -ba {
			t.Fatalf("not antisymmetric for %q,%q: %d vs %d", a, b, ab, ba)
		}
		if aa, ok := CompareVersions(a, a); ok && aa != 0 {
			t.Fatalf("not reflexive for %q", a)
		}
		// consistency (transitivity of <=) when all three parse
		bc, okBC := CompareVersions(b, c)
		ac, okAC := CompareVersions(a, c)
		if okAB && okBC && okAC && ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
		// ranges never panic and never claim Yes for an incomparable version
		r := VersionRange{StartIncl: b, EndExcl: c}
		if _, ok := CompareVersions(a, b); !ok && r.Contains(a) == Yes && b != "" {
			t.Fatalf("Contains said Yes for incomparable %q against bound %q", a, b)
		}
	})
}
