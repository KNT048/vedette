package main

import (
	"strings"
	"testing"
)

func TestBuildKeepsTheLatestOrganisationPerPrefix(t *testing.T) {
	t.Parallel()
	src := `{
	 "000000000000/24": [{"t":"add","o":"XEROX CORPORATION"},{"t":"change","o":"Xerox Corp  "}],
	 "001bc5000000/24": [{"t":"add","o":"IEEE Registration Authority"}],
	 "001bc5000000/36": [{"t":"add","o":"Converging Systems Inc."}],
	 "0055da100000/28": [{"t":"add","o":"KoolPOS Inc."}],
	 "00242d000000/24": [{"t":"add","o":"Ronan Engineering"},{"t":"delete","o":"Ronan Engineering"}],
	 "00243e000000/24": [{"t":"add","o":"PRIVATE"}],
	 "00aabb000000/24": [{"t":"add","o":"IEEE REGISTRATION AUTHORITY - Please see OUI36 public listing"}],
	 "00ccdd000000/32": [{"t":"add","o":"Wrong length"}],
	 "zz": [{"t":"add","o":"Bad key"}],
	 "00eeff000000/24": []
	}`
	rows, skipped, err := build([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.prefix+"|"+r.vendor)
	}
	want := "000000|Xerox Corp,0055da1|KoolPOS Inc.,001bc5000|Converging Systems Inc."
	if strings.Join(got, ",") != want || skipped != 7 {
		t.Errorf("rows %v skipped %d", got, skipped)
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	t.Parallel()
	rows := []row{{24, "000000", "A"}, {28, "0055da1", "B"}}
	a, err := encode(rows)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := encode(rows)
	if string(a) != string(b) {
		t.Error("two encodings differ")
	}
}

func TestDownloadRefusesOtherHosts(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"http://raw.githubusercontent.com/x", "https://example.org/macs.json", "file:///etc/passwd"} {
		if _, err := download(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}
