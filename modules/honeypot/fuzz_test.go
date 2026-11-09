package honeypot_test

import (
	"testing"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/honeypot"
)

func FuzzParseLine(f *testing.F) {
	for _, s := range []string{
		`{"dst_host":"192.168.10.240","dst_port":22,"logdata":{"USERNAME":"root","PASSWORD":"x"},"logtype":4002,"src_host":"10.0.0.2","src_port":51322,"utc_time":"2026-11-09 10:00:00.123456"}`,
		`{"logtype":14001,"src_host":"1.2.3.4","logdata":{"USERNAME":1}}`,
		`{"logtype":3000,"src_host":"1.2.3.4","logdata":{"PATH":"/\u202e..","USERAGENT":"\u0000"}}`,
		`{"logtype":4000,"src_host":"::1"}`, `[]`, `{`, ``, `null`, `{"logtype":1e400,"src_host":"1.2.3.4"}`, "{\"logtype\":4000,\"src_host\":\"1.2.3.4\",\"logdata\":{\"USERNAME\":\"\xff\xfe\"}}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := honeypot.ParseLine(b)
		if err != nil {
			return
		}
		if !r.Src.Is4() || r.Src.IsUnspecified() || r.LogType <= 0 {
			t.Fatalf("bad record %+v", r)
		}
		if r.Dst.IsValid() && !r.Dst.Is4() {
			t.Fatalf("dst %v", r.Dst)
		}
		if r.SrcPort < 0 || r.SrcPort > 65535 || r.DstPort < 0 || r.DstPort > 65535 {
			t.Fatalf("ports %+v", r)
		}
		for name, s := range map[string]string{"user": r.User, "host": r.Hostname, "path": r.Path, "file": r.Filename, "agent": r.UserAgent, "version": r.RemoteVersion} {
			if !utf8.ValidString(s) || utf8.RuneCountInString(s) > 200 {
				t.Fatalf("%s: %q", name, s)
			}
			for _, c := range s {
				if c < 0x20 || c == 0x7f || c >= 0x202A && c <= 0x202E {
					t.Fatalf("%s has control %U", name, c)
				}
			}
		}
	})
}
