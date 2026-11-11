package inventory

import "testing"

// L12: cleanText refuses C1 controls, every format character and every default-ignorable code point, besides C0 and DEL.
func TestCleanTextRefusesInvisibleCharacters(t *testing.T) {
	t.Parallel()
	if !cleanText("Cisco IOS 15.2 ünï 日本") {
		t.Fatal("plain text refused")
	}
	for name, r := range map[string]rune{"c0": 0x01, "del": 0x7f, "c1 low": 0x80, "c1 high": 0x9f, "zwsp": 0x200b, "zwj": 0x200d, "lre": 0x202a, "rlo": 0x202e,
		"word joiner": 0x2060, "lri": 0x2066, "pdi": 0x2069, "bom": 0xfeff, "tag start": 0xe0000, "tag end": 0xe007f,
		// close-out of L12: the rest of Cf and of Default_Ignorable_Code_Point, as the honeypot and account names refuse
		"lrm": 0x200e, "rlm": 0x200f, "alm": 0x061c, "invisible plus": 0x2064, "nads": 0x206f, "vs1": 0xfe00, "vs16": 0xfe0f, "vs17": 0xe0100,
		"vs256": 0xe01ef, "soft hyphen": 0x00ad, "mongolian fvs1": 0x180b, "mongolian vowel separator": 0x180e, "hangul filler": 0x3164} {
		if cleanText("a" + string(r) + "b") {
			t.Errorf("%s (U+%04X) accepted", name, r)
		}
	}
	if !cleanText("a\u00a0b") || !cleanText("e\u0301") { // NBSP is visible spacing, a combining accent is a letter: left alone
		t.Error("NBSP or a combining accent refused")
	}
}
