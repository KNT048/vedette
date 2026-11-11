package listen

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func frames(t *testing.T, in string, maxLine, maxFrame int) (out []string, trunc []bool, err error) {
	t.Helper()
	r := bufio.NewReaderSize(strings.NewReader(in), 16) // a small buffer: lines longer than it take the ErrBufferFull path
	for range 100 {
		f, tr, e := ReadFrame(r, maxLine, maxFrame)
		if e != nil {
			if errors.Is(e, io.EOF) {
				return out, trunc, nil
			}
			return out, trunc, e
		}
		out, trunc = append(out, string(f)), append(trunc, tr)
	}
	t.Fatal("ReadFrame did not end")
	return nil, nil, nil
}

func TestReadFrame(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
		err  error
	}{
		{"newline lines", "<34>a\n<34>b\n", []string{"<34>a", "<34>b"}, nil},
		{"CRLF", "<34>a\r\n<34>b\r\n", []string{"<34>a", "<34>b"}, nil},
		{"empty lines are skipped", "\n\n<34>a\n\r\n\n", []string{"<34>a"}, nil},
		{"last line without a newline", "<34>a\n<34>b", []string{"<34>a", "<34>b"}, nil},
		{"octet counting", "5 <34>a6 <34>bc", []string{"<34>a", "<34>bc"}, nil},
		{"octet counting then a newline line", "5 <34>a<34>line\n", []string{"<34>a", "<34>line"}, nil},
		{"a newline after an octet frame is skipped", "5 <34>a\n5 <34>b\n", []string{"<34>a", "<34>b"}, nil},
		{"a frame that holds a newline", "9 <34>a\nbcd", []string{"<34>a\nbcd"}, nil},
		{"digits that are not a count", "2026-11-11 08:30 x\n12 apples\n7 x\n", []string{"2026-11-11 08:30 x", "12 apples", "7 x"}, nil},
		{"seven digits are not a count", "1234567 <34>x\n", []string{"1234567 <34>x"}, nil},
		{"a count above the frame limit", "100 <34>x", nil, ErrFrameTooLarge},
		{"a short frame at the end", "20 <34>x", nil, ErrShortFrame},
		{"a short line is a line", "12", []string{"12"}, nil},
		{"digits then a space then the end", "12 ", []string{"12 "}, nil},
		{"a line without a newline above the frame limit", strings.Repeat("a", 80), nil, ErrFrameTooLarge},
		{"nothing", "", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := frames(t, tc.in, 1000, 64)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v (frames %q)", err, tc.err, got)
			}
			if tc.err == nil && strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("frames = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadFrameCutsAtTheLineLimitAndGoesOn(t *testing.T) {
	long := "<34>" + strings.Repeat("x", 40)
	got, trunc, err := frames(t, long+"\n<34>next\n20 <34>"+strings.Repeat("y", 16)+"\n", 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"<34>xxxxxx", "<34>next", "<34>yyyyyy"}
	if strings.Join(got, "|") != strings.Join(want, "|") || !trunc[0] || trunc[1] || !trunc[2] {
		t.Errorf("frames = %q truncated = %v", got, trunc)
	}
}
