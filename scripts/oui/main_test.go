package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
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

// The vendor name goes to the inventory as text a person reads: no control, bidirectional, zero-width, soft hyphen
// or tag character, no space at the ends (the 2026-11 table held U+200E, U+200B and U+00AD).
func TestCleanDropsBidiAndInvisibleCharacters(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Evil\u202eCorp":               "EvilCorp",
		"Gilbarco Veeder-Root \u200e":  "Gilbarco Veeder-Root",
		"\u200bASUNG TECHNO CO.,Ltd":   "ASUNG TECHNO CO.,Ltd",
		"C1\u0085control\tand  tabs":   "C1 control and tabs",
		"Soft\u00adhyphen":             "Softhyphen",
		"Tag\U000E0041\U000E007Fchars": "Tagchars",
		"\u2060\ufeff  padded \u200d ": "padded",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	long := clean(strings.Repeat("\u00e9", 150) + "\u200b")
	if len(long) > maxVendor || strings.HasSuffix(long, " ") || !strings.HasPrefix(long, "\u00e9") {
		t.Errorf("long name: %d bytes", len(long))
	}
}

func aliasedSource(vendorB string) string {
	var src strings.Builder
	src.WriteString(`{"00000c000000/24":[{"t":"add","o":"Cisco"}],"00000c123456/24":[{"t":"add","o":"` + vendorB + `"}]`)
	const h = "0123456789abcdef"
	for i := range 200 { // enough other keys that map order and an unstable sort would show
		src.WriteString(`,"1111` + string([]byte{h[i>>4&15], h[i&15]}) + `000000/24":[{"t":"add","o":"V"}]`)
	}
	src.WriteString("}")
	return src.String()
}

// Two keys can name one prefix. The same vendor twice is one row, and the same input gives the same bytes every time.
func TestBuildIsDeterministicWithAliasedKeys(t *testing.T) {
	t.Parallel()
	first := ""
	for i := range 50 {
		rows, skipped, err := build([]byte(aliasedSource("Cisco")))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rows {
			if r.prefix == "00000c" {
				n++
			}
		}
		if n != 1 || skipped != 1 {
			t.Fatalf("prefix 00000c appears %d times, skipped %d", n, skipped)
		}
		gz, err := encode(rows)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = string(gz)
		} else if first != string(gz) {
			t.Fatal("two builds of the same input differ")
		}
	}
}

// Two vendors for one prefix: there is no honest way to choose, so the build stops.
func TestBuildRefusesTwoVendorsForOnePrefix(t *testing.T) {
	t.Parallel()
	if _, _, err := build([]byte(aliasedSource("Not Cisco"))); err == nil || !strings.Contains(err.Error(), "00000c") {
		t.Errorf("err = %v", err)
	}
}

// The gzip header carries no time and no name, and the OS byte is "unknown": the file is the same on every machine.
func TestEncodeHeaderIsFixed(t *testing.T) {
	t.Parallel()
	gz, err := encode([]row{{24, "000000", "A"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gz[4:8], []byte{0, 0, 0, 0}) || gz[3] != 0 || gz[9] != 255 {
		t.Errorf("header % x", gz[:10])
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(zr); string(body) != "000000\t24\tA\n" {
		t.Errorf("body %q", body)
	}
}

// A download is used only if it hashes to the value recorded for its commit; a commit that was never recorded is not built from.
func TestPinnedSourceIsVerified(t *testing.T) {
	t.Parallel()
	raw := []byte(`{}`)
	sum := sha256.Sum256(raw)
	if err := verify("c", raw, hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("matching file refused: %v", err)
	}
	if err := verify("c", []byte(`{ }`), hex.EncodeToString(sum[:])); err == nil {
		t.Error("a file with another hash was accepted")
	}
	if _, err := fetchPinned(strings.Repeat("a", 40)); err == nil {
		t.Error("an unrecorded commit was fetched")
	}
	if err := run("", "feature", t.TempDir()+"/x.tsv.gz"); err == nil {
		t.Error("-ref other than main accepted")
	}
	if pinnedCommit != "" && (!commitRE.MatchString(pinnedCommit) || len(pinnedSHA256) != 64) {
		t.Errorf("the pin is malformed: %q %q", pinnedCommit, pinnedSHA256)
	}
}
