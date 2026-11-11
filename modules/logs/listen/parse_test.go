package listen

import (
	"strings"
	"testing"
	"time"
)

func TestParseSyslog(t *testing.T) {
	ts := time.Date(2026, 11, 11, 8, 30, 15, 3000000, time.UTC)
	tests := []struct {
		name string
		in   string
		want Envelope
	}{
		{"5424 full", `<165>1 2026-11-11T08:30:15.003Z fw-hq sshd 4321 ID47 [exampleSDID@32473 iut="3" eventSource="App\"x\]"][meta a="b"] user login`,
			Envelope{Format: FormatRFC5424, PRI: 165, Facility: 20, Severity: 5, Time: ts, Host: "fw-hq", App: "sshd", ProcID: "4321", MsgID: "ID47", Msg: "user login"}},
		{"5424 nil values and no message", `<34>1 - - - - - -`,
			Envelope{Format: FormatRFC5424, PRI: 34, Facility: 4, Severity: 2}},
		{"5424 BOM is not part of the message", "<34>1 - h a - - - \xef\xbb\xbfhello",
			Envelope{Format: FormatRFC5424, PRI: 34, Facility: 4, Severity: 2, Host: "h", App: "a", Msg: "hello"}},
		{"5424 offset zone is converted", `<13>1 2026-11-11T10:30:15.003+02:00 h a - - - m`,
			Envelope{Format: FormatRFC5424, PRI: 13, Facility: 1, Severity: 5, Time: ts, Host: "h", App: "a", Msg: "m"}},
		{"5424 with an unclosed element is not 5424", `<34>1 - h a - - [x a="b" m`,
			Envelope{Format: FormatRFC3164, PRI: 34, Facility: 4, Severity: 2, Msg: `1 - h a - - [x a="b" m`}},
		{"5424 with a bad time is not 5424", `<34>1 yesterday h a - - - m`,
			Envelope{Format: FormatRFC3164, PRI: 34, Facility: 4, Severity: 2, Msg: `1 yesterday h a - - - m`}},
		{"3164 with tag and pid", `<38>Nov 11 08:30:15 mikrotik sshd[812]: Accepted password for admin`,
			Envelope{Format: FormatRFC3164, PRI: 38, Facility: 4, Severity: 6, Host: "mikrotik", App: "sshd", ProcID: "812", Msg: "Accepted password for admin"}},
		{"3164 padded day", `<38>Nov  1 08:30:15 gw kernel: link up`,
			Envelope{Format: FormatRFC3164, PRI: 38, Facility: 4, Severity: 6, Host: "gw", App: "kernel", Msg: "link up"}},
		{"3164 without a tag", `<38>Nov 11 08:30:15 gw just some words`,
			Envelope{Format: FormatRFC3164, PRI: 38, Facility: 4, Severity: 6, Host: "gw", Msg: "just some words"}},
		{"priority and key=value without a timestamp (FortiGate style)", `<189>date=2026-11-11 time=08:30:15 devname=fg logid=0000000013`,
			Envelope{Format: FormatRFC3164, PRI: 189, Facility: 23, Severity: 5, Msg: "date=2026-11-11 time=08:30:15 devname=fg logid=0000000013"}},
		{"no priority is raw", `Nov 11 08:30:15 gw sshd: hi`, Envelope{Format: FormatRaw, PRI: -1, Facility: -1, Severity: -1, Msg: "Nov 11 08:30:15 gw sshd: hi"}},
		{"priority above 191 is raw", `<192>1 - - - - - - x`, Envelope{Format: FormatRaw, PRI: -1, Facility: -1, Severity: -1, Msg: "<192>1 - - - - - - x"}},
		{"four digit priority is raw", `<1234>x`, Envelope{Format: FormatRaw, PRI: -1, Facility: -1, Severity: -1, Msg: "<1234>x"}},
		{"empty is raw", ``, Envelope{Format: FormatRaw, PRI: -1, Facility: -1, Severity: -1}},
		{"NUL is data", "<34>Nov 11 08:30:15 gw a\x00b: c\x00", Envelope{Format: FormatRFC3164, PRI: 34, Facility: 4, Severity: 2, Host: "gw", Msg: "a\x00b: c\x00"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSyslog(tc.in)
			if !got.Time.Equal(tc.want.Time) {
				t.Errorf("time = %v, want %v", got.Time, tc.want.Time)
			}
			got.Time, tc.want.Time = time.Time{}, time.Time{}
			if got != tc.want {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestParseCEF(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want CEF
		ok   bool
	}{
		{"cef", `CEF:0|Fortinet|FortiGate|7.2|13|traffic denied|5|src=10.0.0.5 dst=8.8.8.8`,
			CEF{Kind: "cef", Version: "0", Vendor: "Fortinet", Product: "FortiGate", DevVersion: "7.2", SigID: "13", Name: "traffic denied", Severity: "5", Ext: "src=10.0.0.5 dst=8.8.8.8"}, true},
		{"cef escapes", `CEF:0|a\|b|c\\d|1|2|n\|m|low|`, CEF{Kind: "cef", Version: "0", Vendor: "a|b", Product: `c\d`, DevVersion: "1", SigID: "2", Name: "n|m", Severity: "low"}, true},
		{"leef 1.0", "LEEF:1.0|Microsoft|MSExchange|2016|15345|src=1.2.3.4\tdst=5.6.7.8", CEF{Kind: "leef", Version: "1.0", Vendor: "Microsoft", Product: "MSExchange", DevVersion: "2016", SigID: "15345", Ext: "src=1.2.3.4\tdst=5.6.7.8"}, true},
		{"leef 2.0 delimiter", "LEEF:2.0|V|P|1|E1|^|a=1^b=2", CEF{Kind: "leef", Version: "2.0", Vendor: "V", Product: "P", DevVersion: "1", SigID: "E1", Delimiter: "^", Ext: "a=1^b=2"}, true},
		{"cef header cut short", `CEF:0|a|b|c|d|e`, CEF{}, false},
		{"leef header cut short", `LEEF:1.0|a|b|c`, CEF{}, false},
		{"not a header", `hello|a|b`, CEF{}, false},
		{"empty", ``, CEF{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseCEF(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && *got != tc.want {
				t.Errorf("got  %+v\nwant %+v", *got, tc.want)
			}
		})
	}
}

func TestParseFindsTheCEFHeaderInsideAnEnvelope(t *testing.T) {
	e := Parse(`<134>Nov 11 08:30:15 fw CEF:0|V|P|1|2|n|3|k=v`)
	if e.CEF == nil || e.CEF.Vendor != "V" || e.Counted() != "cef" || e.Format != FormatRFC3164 || e.Host != "fw" {
		t.Errorf("got %+v cef=%+v", e, e.CEF)
	}
	e = Parse(`<134>1 - fw app - - - LEEF:1.0|V|P|1|E|k=v`)
	if e.CEF == nil || e.Counted() != "leef" {
		t.Errorf("got %+v", e)
	}
	if e := Parse(`<134>Nov 11 08:30:15 fw note: the word CEF: is only a word`); e.CEF != nil || e.Counted() != FormatRFC3164 {
		t.Errorf("a CEF-like word made a header: %+v", e.CEF)
	}
	if e := Parse("xCEF:0|a|b|c|d|e|f|g"); e.CEF != nil {
		t.Error("CEF: inside a word is not a header")
	}
}

func TestParseKeepsEveryFieldBounded(t *testing.T) {
	big := strings.Repeat("a", 5000)
	for _, in := range []string{"<34>1 - " + big + " a - - - m", "<34>Nov 11 08:30:15 " + big + " x: y", "CEF:0|" + big + "|b|c|d|e|f|g", "<1>" + big} {
		e := Parse(in)
		for _, f := range []string{e.Host, e.App, e.ProcID, e.MsgID} {
			if len(f) > 255 {
				t.Errorf("a field of %d bytes", len(f))
			}
		}
		if e.CEF != nil && len(e.CEF.Vendor) > maxCEFVal {
			t.Errorf("a vendor of %d bytes", len(e.CEF.Vendor))
		}
	}
}
