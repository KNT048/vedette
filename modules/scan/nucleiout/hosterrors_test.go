package nucleiout

import (
	"strings"
	"testing"
)

// The error-log lines below are HAND-MADE in the shape of nuclei v3.11.1's JSONLogRequest (pkg/output/output.go), not a
// recording: the lab check against the pinned binary is a deferred item (.ai/deferred/feat-scan-autostop.md).
var hostErrTargets = []string{"192.168.10.21:5000", "192.168.10.21:443", "192.168.10.21:22"}

func errLog(address, input, kind string) string {
	return `{"template":"/usr/share/vedette/nuclei-templates/http/cves/x.yaml","type":"http","input":"` + input + `","address":"` + address + `","error":"i/o timeout","kind":"` + kind + `"}`
}

func TestParseHostErrors(t *testing.T) {
	t.Parallel()
	to := "network-temporary-error"
	cases := []struct {
		name string
		in   string
		mhe  int
		want []HostError
	}{
		{"nothing", "", 3, nil},
		{"below the limit", errLog("192.168.10.21:5000", "http://192.168.10.21:5000", to), 3,
			[]HostError{{Target: "192.168.10.21:5000", Errors: 1}}},
		{"at the limit", strings.Join([]string{
			errLog("192.168.10.21:5000", "http://192.168.10.21:5000", to), errLog("192.168.10.21:5000", "http://192.168.10.21:5000", to), errLog("192.168.10.21:5000", "http://192.168.10.21:5000", to),
		}, "\n"), 3, []HostError{{Target: "192.168.10.21:5000", Errors: 3, Unreachable: true}}},
		{"refused is a live device", strings.Repeat(errLog("192.168.10.21:22", "192.168.10.21:22", "network-permanent-error")+"\n", 5), 2, nil},
		{"template logic and unknown kinds are not counted", errLog("192.168.10.21:22", "192.168.10.21:22", "template-logic-error") + "\n" + errLog("192.168.10.21:22", "192.168.10.21:22", "unknown-error"), 2, nil},
		{"address missing, input names the target", errLog("", "https://192.168.10.21", to), 2, []HostError{{Target: "192.168.10.21:443", Errors: 1}}},
		{"a target the job did not name", errLog("10.0.0.9:80", "http://10.0.0.9", to), 2, nil},
		{"order is the job's", errLog("192.168.10.21:22", "192.168.10.21:22", to) + "\n" + errLog("192.168.10.21:5000", "http://192.168.10.21:5000", to), 2,
			[]HostError{{Target: "192.168.10.21:5000", Errors: 1}, {Target: "192.168.10.21:22", Errors: 1}}},
		{"log lines and junk between are skipped", "[INF] hello\n{not json\n[]\n\x00\xff\n" + errLog("192.168.10.21:22", "192.168.10.21:22", to) + "\r\n", 2, []HostError{{Target: "192.168.10.21:22", Errors: 1}}},
		{"duplicate keys are ambiguous", `{"kind":"network-temporary-error","kind":"x","address":"192.168.10.21:22"}`, 2, nil},
		{"a line over the cap", `{"kind":"network-temporary-error","address":"192.168.10.21:22","error":"` + strings.Repeat("a", maxErrorLogLine) + `"}`, 2, nil},
	}
	for _, c := range cases {
		got := ParseHostErrors([]byte(c.in), hostErrTargets, c.mhe)
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
			}
		}
	}
}

// Only the first MaxErrorLog bytes are read, so a flood on stderr cannot cost more than that.
func TestParseHostErrors_ReadsOnlyTheCap(t *testing.T) {
	t.Parallel()
	line := errLog("192.168.10.21:22", "192.168.10.21:22", "network-temporary-error") + "\n"
	got := ParseHostErrors([]byte(strings.Repeat(line, MaxErrorLog/len(line)*2)), hostErrTargets, 2)
	if len(got) != 1 || got[0].Errors > MaxErrorLog/len(line)+1 || !got[0].Unreachable {
		t.Fatalf("%+v", got)
	}
}

func FuzzParseHostErrors(f *testing.F) {
	f.Add(errLog("192.168.10.21:5000", "http://192.168.10.21:5000", "network-temporary-error"), 3)
	f.Add("{\"a\":"+strings.Repeat("[", 50), 2)
	f.Add("\xff\n{\"kind\":\"network-temporary-error\",\"address\":\"192.168.10.21:22\"}\n", 0)
	f.Fuzz(func(t *testing.T, in string, mhe int) {
		got := ParseHostErrors([]byte(in), hostErrTargets, mhe)
		if len(got) > len(hostErrTargets) {
			t.Fatalf("more entries than targets: %+v", got)
		}
		for _, h := range got {
			ok := false
			for _, tg := range hostErrTargets {
				ok = ok || h.Target == tg
			}
			if !ok || h.Errors < 1 || h.Unreachable != (mhe > 0 && h.Errors >= mhe) {
				t.Fatalf("bad entry %+v (mhe %d)", h, mhe)
			}
		}
	})
}
