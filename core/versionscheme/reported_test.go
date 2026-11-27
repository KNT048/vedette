package versionscheme

import "testing"

// A program's reported version with a word before the release or its build in parentheses after it is the release it states, by the
// conventions of Windows' DisplayVersion and of release tags; anything that does not leave a plain release is kept as given.
func TestReported(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"v2.3.1", "2.3.1", true},               // a release tag
		{"V4.8.120.0", "4.8.120.0", true},       // upper case
		{"v2.4.0-rc.1", "2.4.0-rc.1", true},     // a tag's pre-release stays with the release
		{"zx 5.4.2", "5.4.2", true},             // a vendor's word before the release
		{"Version 4.1.0", "4.1.0", true},        // a word in another case
		{"4.2.9 (31207)", "4.2.9", true},        // the build in parentheses
		{"4.2.9(31207)", "4.2.9(31207)", false}, // a number in parentheses right after the release is part of it, not a build
		{"12.4(25)", "12.4(25)", false},         // a release numbered "<train>(<release>)"
		{"9.16(3)", "9.16(3)", false},
		{"v9.16(3)", "v9.16(3)", false},
		{"v4.2.9 (31207)", "4.2.9", true},     // both
		{" 5.0.1 (7) ", "5.0.1", true},        // around spaces
		{"1.2.3", "1.2.3", false},             // a plain release: nothing to read
		{"v8", "v8", false},                   // a tag without a dotted release
		{"beta 1.2.3", "beta 1.2.3", false},   // a word that qualifies the release is no vendor's word
		{"Update 3", "Update 3", false},       // no release after the word
		{"build 1.2.3", "build 1.2.3", false}, // a build, not the release
		{"two words 1.2.3", "two words 1.2.3", false},
		{"x64 1.2.3", "x64 1.2.3", false},                                         // a word with a digit
		{"1.2.3 (x64)", "1.2.3 (x64)", false},                                     // an architecture, not a build
		{"8.0 Update 3 (build 24022510)", "8.0 Update 3 (build 24022510)", false}, // a scheme's own form, read by its scheme
		{"8.0.3 (build 24022510)", "8.0.3 (build 24022510)", false},
		{"2024 (123)", "2024 (123)", false}, // a single number is no release form
		{"1.2.3 beta (45)", "1.2.3 beta (45)", false},
		{"", "", false},
	} {
		got, ok := Reported(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Reported(%q) = %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
