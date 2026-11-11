package inventory

import "testing"

// L12: cleanText refuses C1 controls, bidi controls, zero-width and tag characters, besides C0 and DEL.
func TestCleanTextRefusesInvisibleCharacters(t *testing.T) {
	t.Parallel()
	if !cleanText("Cisco IOS 15.2 ünï 日本") {
		t.Fatal("plain text refused")
	}
	for name, r := range map[string]rune{"c0": 0x01, "del": 0x7f, "c1 low": 0x80, "c1 high": 0x9f, "zwsp": 0x200b, "zwj": 0x200d, "lre": 0x202a, "rlo": 0x202e,
		"word joiner": 0x2060, "lri": 0x2066, "pdi": 0x2069, "bom": 0xfeff, "tag start": 0xe0000, "tag end": 0xe007f} {
		if cleanText("a" + string(r) + "b") {
			t.Errorf("%s (U+%04X) accepted", name, r)
		}
	}
	if !cleanText("a\u00a0b") || !cleanText("a\u200eb") { // NBSP and LRM are visible spacing / mark, left alone
		t.Error("NBSP or LRM refused")
	}
}
