package observe

import "unicode"

// Ignorable reports whether r has the Unicode property Default_Ignorable_Code_Point: invisible or layout-only characters
// (soft hyphen, zero-width and bidi controls, hangul fillers, variation selectors, the tag block and others) that let
// untrusted text hide or read as something else. One table for every module that cleans or checks such text (core/auth
// names, honeypot hit text; WP-31 L13, D-189).
func Ignorable(r rune) bool { return unicode.Is(defaultIgnorable, r) }

// defaultIgnorable is the Unicode property Default_Ignorable_Code_Point (Unicode 16.0, DerivedCoreProperties.txt,
// https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt). Go's unicode package has no
// table for it. ponytail: written out by hand, so a later Unicode version that adds a code point is not
// covered until the table is updated; upgrade path: generate it from DerivedCoreProperties.txt.
var defaultIgnorable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00AD, Hi: 0x00AD, Stride: 1},
		{Lo: 0x034F, Hi: 0x034F, Stride: 1},
		{Lo: 0x061C, Hi: 0x061C, Stride: 1},
		{Lo: 0x115F, Hi: 0x1160, Stride: 1},
		{Lo: 0x17B4, Hi: 0x17B5, Stride: 1},
		{Lo: 0x180B, Hi: 0x180F, Stride: 1},
		{Lo: 0x200B, Hi: 0x200F, Stride: 1},
		{Lo: 0x202A, Hi: 0x202E, Stride: 1},
		{Lo: 0x2060, Hi: 0x206F, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1},
		{Lo: 0xFEFF, Hi: 0xFEFF, Stride: 1},
		{Lo: 0xFFA0, Hi: 0xFFA0, Stride: 1},
		{Lo: 0xFFF0, Hi: 0xFFF8, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1BCA0, Hi: 0x1BCA3, Stride: 1},
		{Lo: 0x1D173, Hi: 0x1D17A, Stride: 1},
		{Lo: 0xE0000, Hi: 0xE0FFF, Stride: 1},
	},
}
