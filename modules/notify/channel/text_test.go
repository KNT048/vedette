package channel

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in    string
		multi bool
		want  string
	}{
		{"a\r\nb", true, "a\nb"},
		{"a\r\nb", false, "a b"},
		{"a\tb\x00c\x1bd", false, "a bcd"},
		{"x\xe2\x80\xaety", false, "xty"}, // bidi override dropped
		{"x\xe2\x80\x8by", false, "xy"},   // zero-width space dropped
		{"a b", true, "a\nb"},
		{"bad\xffbyte", false, "bad�byte"},
		{"Cảnh báo: máy chủ", false, "Cảnh báo: máy chủ"},
	} {
		if got := clean(c.in, c.multi); got != c.want {
			t.Errorf("clean(%q,%v) = %q, want %q", c.in, c.multi, got, c.want)
		}
	}
}

func TestTruncRunes(t *testing.T) {
	t.Parallel()
	if got := truncRunes("ábcdef", 4); got != "ábc…" {
		t.Errorf("got %q", got)
	}
	if got := truncRunes("abc", 3); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestFitKeepsLink(t *testing.T) {
	t.Parallel()
	got := fit([]string{"head", strings.Repeat("x", 9000), "Details: https://h/x"}, 100)
	if !strings.HasSuffix(got, "\nDetails: https://h/x") || utf8.RuneCountInString(got) > 100 {
		t.Errorf("fit result %d runes: %q", utf8.RuneCountInString(got), got)
	}
}

func TestSafeLink(t *testing.T) {
	t.Parallel()
	for in, ok := range map[string]bool{
		"https://192.168.10.2/incidents/al-4":  true,
		"http://box.lan/x?a=1&b=2":             true,
		"":                                     true, // no link: the message says to open Vedette
		"/incidents/al-4":                      false,
		"javascript:alert(1)":                  false,
		"https://h/x|evil":                     false,
		"https://h/x>y":                        false,
		"https://h/x y":                        false,
		"https://h/\r\nBcc: x":                 false,
		"https://user:pw@h/x":                  false,
		"https://héllo/x":                      false,
		"ftp://h/x":                            false,
		"https://" + strings.Repeat("a", 1100): false,
	} {
		if _, err := safeLink(in); (err == nil) != ok {
			t.Errorf("safeLink(%q) err=%v, want ok=%v", in, err, ok)
		}
	}
}

// FuzzNorm: whatever the feed sends, normalised text has no control or format characters, valid UTF-8, bounded size.
func FuzzNorm(f *testing.F) {
	f.Add("Title", "what\r\nmore", "do <!channel> & *this*", "item")
	f.Add("\xe2\x80\xaeevil", "\x00\x01", "\xff\xfe", strings.Repeat("é", 5000))
	f.Fuzz(func(t *testing.T, title, what, action, item string) {
		n := Message{ID: title, Kind: what, Severity: "high", Title: title, Device: what, What: what, Action: action, Items: []string{item, action}, Link: "https://h/x"}.norm()
		all := append([]string{n.ID, n.Kind, n.Title, n.Device, n.What, n.Action}, n.Items...)
		for _, s := range all {
			if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxLine {
				t.Fatalf("bad normalised field %q", s)
			}
			for _, r := range s {
				if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
					t.Fatalf("control/format rune %U in %q", r, s)
				}
			}
		}
		for _, s := range []string{n.ID, n.Kind, n.Title, n.Device} {
			if strings.Contains(s, "\n") {
				t.Fatalf("single-line field has newline: %q", s)
			}
		}
	})
}

// The subject and first line of a vulnerability notice is its title, which names the finding's status: never a routing severity
// ("Critical:") the app does not show for that finding. An incident keeps its severity; a test message is its title.
func TestHeadOfAFindingNoticeIsItsTitle(t *testing.T) {
	t.Parallel()
	vuln := Message{ID: "nt-1", Kind: "vuln", Severity: "critical", Title: "VMware ESXi on esxi-01: exploited in the wild (CVE-2026-41709)",
		Action: "Update VMware ESXi to 8.0 U3j.", Link: "https://box.example/findings/f-1"}
	subj, text, err := Preview(Email, vuln)
	if err != nil {
		t.Fatal(err)
	}
	if subj != "[Vedette] "+vuln.Title || !strings.HasPrefix(text, "Hello,") || strings.Contains(text, "Critical") {
		t.Fatalf("subject %q\n%s", subj, text)
	}
	if _, text, _ = Preview(Telegram, vuln); !strings.HasPrefix(text, vuln.Title+"\n") || !strings.Contains(text, "What to do first: Update VMware ESXi to 8.0 U3j.") {
		t.Fatalf("telegram %q", text)
	}
	inc := Message{ID: "in-1", Kind: "incident", Severity: "high", Title: "203.0.113.5 touched the SSH trap", Link: "https://box.example/incidents/in-1"}
	if subj, _, _ := Preview(Email, inc); subj != "[Vedette] High: 203.0.113.5 touched the SSH trap" {
		t.Fatalf("incident subject %q", subj)
	}
	test := Message{ID: "t-1", Kind: "test", Severity: "info", Title: "Test message from Vedette", Link: "https://box.example/settings"}
	if subj, _, _ := Preview(Email, test); subj != "[Vedette] Test message from Vedette" {
		t.Fatalf("test subject %q", subj)
	}
}
