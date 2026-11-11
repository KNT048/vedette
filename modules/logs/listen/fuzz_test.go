package listen

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func FuzzParseSyslog(f *testing.F) {
	for _, s := range []string{
		"<165>1 2026-11-11T08:30:15.003Z h a 1 ID [x a=\"b\\\"]\"] msg", "<34>Nov 11 08:30:15 gw sshd[1]: hi", "<189>date=2026 devname=fg", "<34>1 - - - - - -",
		"<", "<>", "<999>", "", "\x00", "<34>1 ", "<34>1 - h a - - [", "<34>Nov  1 08:30:15 ", "CEF:0|a|b|c|d|e|f|g", "<1>LEEF:2.0|a|b|c|d|^|k=v",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e := Parse(s)
		switch e.Format {
		case FormatRaw:
			if e.PRI != -1 || e.Msg != s {
				t.Fatalf("raw but %+v", e)
			}
		case FormatRFC5424, FormatRFC3164:
			if e.PRI < 0 || e.PRI > 191 || e.Facility != e.PRI/8 || e.Severity != e.PRI%8 {
				t.Fatalf("bad priority %+v", e)
			}
		default:
			t.Fatalf("format %q", e.Format)
		}
		if len(e.Msg) > len(s) || len(e.Host) > maxHost || len(e.App) > maxApp || len(e.ProcID) > maxProcID || len(e.MsgID) > maxMsgID {
			t.Fatalf("a field is longer than allowed: %+v", e)
		}
		if !strings.Contains(s, e.Msg) {
			t.Fatalf("the message %q is not part of the input %q", e.Msg, s)
		}
		if e.Counted() == "" {
			t.Fatal("not counted")
		}
	})
}

func FuzzCEF(f *testing.F) {
	for _, s := range []string{
		"CEF:0|V|P|1|2|name|5|a=b", "CEF:0|a\\|b|c\\\\d|1|2|n|low|", "LEEF:1.0|V|P|1|E|k=v", "LEEF:2.0|V|P|1|E|^|k=v", "CEF:", "LEEF:", "CEF:0|||||||", "CEF:0|\\", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := ParseCEF(s)
		if !ok {
			if c != nil {
				t.Fatal("not ok but a value")
			}
			return
		}
		if c.Kind != "cef" && c.Kind != "leef" {
			t.Fatalf("kind %q", c.Kind)
		}
		for _, v := range []string{c.Version, c.Vendor, c.Product, c.DevVersion, c.SigID, c.Name, c.Severity, c.Delimiter} {
			if len(v) > maxCEFVal {
				t.Fatalf("a header field of %d bytes", len(v))
			}
		}
		if len(c.Ext) > len(s) {
			t.Fatal("the extension is longer than the input")
		}
	})
}

// FuzzOctetFraming reads an arbitrary byte stream: it must end, never return a frame over the limit, never read more than it
// was given, and say io.EOF, ErrFrameTooLarge or ErrShortFrame and nothing else.
func FuzzOctetFraming(f *testing.F) {
	for _, s := range []string{"5 <34>a6 <34>bc", "<34>a\n<34>b\r\n", "99999 <34>x", "20 <34>x", "1234567 <34>x\n", "0 <", "9 <", "1", "1 ", "\x00\n", "12 <34>ab\n\n\n"} {
		f.Add([]byte(s), uint8(0))
	}
	f.Fuzz(func(t *testing.T, in []byte, bufSel uint8) {
		const maxLine, maxFrame = 32, 64
		r := bufio.NewReaderSize(bytes.NewReader(in), 16+int(bufSel%64))
		frames := 0
		for {
			fr, trunc, err := ReadFrame(r, maxLine, maxFrame)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, ErrFrameTooLarge) && !errors.Is(err, ErrShortFrame) {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if len(fr) > maxLine {
				t.Fatalf("a frame of %d bytes", len(fr))
			}
			if len(fr) == 0 && !trunc {
				t.Fatal("an empty frame")
			}
			if frames++; frames > len(in)+1 {
				t.Fatalf("%d frames from %d bytes", frames, len(in))
			}
		}
	})
}
