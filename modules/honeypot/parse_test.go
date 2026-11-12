package honeypot

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// A real log type 5000 line written by the honeypot image (WP-08e): OpenCanary's smb module sets "src_port" to the STRING "-1".
// Before the fix the whole line was refused, so no SMB file-token hit ever reached core.
const realSMBLine = `{"dst_host": "10.89.0.2", "dst_port": 445, "local_time": "2026-11-11 07:57:08.484465", "local_time_adjusted": "2026-11-11 07:57:08.484477", "logdata": {"AUDITACTION": "openat", "DOMAIN": "", "FILENAME": "/passwords.txt", "LOCALNAME": "FILESERVER", "REMOTENAME": "10.89.0.3", "SHARENAME": "Shared", "SMBARCH": "Vista", "SMBVER": "SMB3_11", "STATUS": "ok", "USER": "anonymous"}, "logtype": 5000, "node_id": "vedette-honeypot", "src_host": "10.89.0.3", "src_port": "-1", "utc_time": "2026-11-11 07:57:08.484465"}`

func TestParseLineSMBPortsAsStrings(t *testing.T) {
	t.Parallel()
	rec, err := ParseLine([]byte(realSMBLine))
	if err != nil {
		t.Fatalf("the real SMB line is refused: %v", err)
	}
	if rec.LogType != 5000 || rec.Src != netip.MustParseAddr("10.89.0.3") || rec.Dst != netip.MustParseAddr("10.89.0.2") || rec.DstPort != 445 || rec.SrcPort != 0 || rec.Filename != "/passwords.txt" {
		t.Errorf("record = %+v", rec)
	}
	for name, tc := range map[string]struct {
		ports    string
		src, dst int
	}{
		"numbers":           {`"src_port": 51000, "dst_port": 22`, 51000, 22},
		"strings":           {`"src_port": "51000", "dst_port": "22"`, 51000, 22},
		"negative number":   {`"src_port": -1, "dst_port": 22`, 0, 22},
		"text":              {`"src_port": "abc", "dst_port": "x"`, 0, 0},
		"out of range":      {`"src_port": 70000, "dst_port": "0"`, 0, 0},
		"object and absent": {`"src_port": {"a": 1}`, 0, 0},
		"21 digits":         {`"src_port": 999999999999999999999, "dst_port": 22`, 0, 22},
		"20 digits":         {`"src_port": 99999999999999999999, "dst_port": "99999999999999999999"`, 0, 0},
		"exponent":          {`"src_port": 1e3, "dst_port": "1e3"`, 0, 0},
		"plus sign":         {`"src_port": "+22", "dst_port": "+22"`, 0, 0},
		"booleans and null": {`"src_port": true, "dst_port": null`, 0, 0},
		"padded":            {`"src_port": " 22 ", "dst_port": "\t445\n"`, 22, 445},
		"fraction":          {`"src_port": 22.5, "dst_port": "22.0"`, 0, 0},
		"leading zeros":     {`"src_port": "0022", "dst_port": "00"`, 22, 0},
	} {
		rec, err := ParseLine([]byte(`{"logtype": 4000, "src_host": "10.0.0.5", ` + tc.ports + `}`))
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if rec.SrcPort != tc.src || rec.DstPort != tc.dst {
			t.Errorf("%s: ports %d/%d, want %d/%d", name, rec.SrcPort, rec.DstPort, tc.src, tc.dst)
		}
	}
}

// The first request of a scanner is GET / (OpenCanary's redirect to the login page, logtype 3003) or a refused method (3002):
// both belong to the HTTP trap and show what was asked.
func TestHTTPRedirectAndRefusedMethodAreHTTPHits(t *testing.T) {
	t.Parallel()
	for lt, want := range map[int]string{
		ltHTTPRedirect: "request GET / (redirected to the login page), User-Agent: curl/8",
		ltHTTPOther:    "request with a method the page refuses, / , User-Agent: curl/8",
	} {
		line := `{"logtype":` + strconv.Itoa(lt) + `,"src_host":"192.168.18.50","dst_host":"192.168.18.240","src_port":5,"dst_port":80,"utc_time":"2026-11-12 10:00:00.1","logdata":{"HOSTNAME":"192.168.18.240","PATH":"/","USERAGENT":"curl/8"}}`
		r, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		svc, scan, ok := classify(r.LogType)
		if svc != HTTP || scan || !ok {
			t.Fatalf("%d: %v %v %v", lt, svc, scan, ok)
		}
		if got := detail(r, svc); lt == ltHTTPRedirect && got != want {
			t.Fatalf("%q", got)
		} else if lt == ltHTTPOther && !strings.HasPrefix(got, "request with a method the page refuses") {
			t.Fatalf("%q", got)
		}
	}
}

func TestSMBConnectDetail(t *testing.T) {
	t.Parallel()
	if got := detail(Record{LogType: ltSMBFile, Filename: "/"}, SMB); got != "share opened" {
		t.Fatalf("%q", got)
	}
}
