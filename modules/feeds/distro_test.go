package feeds

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/knt048/vedette/core/events"
)

// Every fixture here is written for these tests (D-516): Canonical's data is CC BY-SA 4.0 and the Debian tracker states
// no licence, so none of it is copied into the repository.

// xzTar packs files (name → text) into an xz tar archive, in the given order.
func xzTar(t testing.TB, files ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := xz.WriterConfig{DictCap: 1 << 16}.NewWriter(&buf) // a small dictionary: the default costs seconds per archive
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, f := range files {
		h := &tar.Header{Name: f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg}
		if strings.HasSuffix(f[0], "/") {
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var wantKEV = map[string]bool{"CVE-2026-10001": true, "CVE-2026-10002": true, "CVE-2026-10003": true}

const osvSudo = `{"id":"UBUNTU-CVE-2026-10001","affected":[
 {"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"sudo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.9.15p5-3ubuntu5.24.04.1"}]}]},
 {"package":{"ecosystem":"Ubuntu:Pro:20.04:LTS","name":"sudo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.8.31-1ubuntu1.5+esm2"}]}]},
 {"package":{"ecosystem":"Ubuntu:20.04:LTS","name":"sudo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
 {"package":{"ecosystem":"Ubuntu:Pro:FIPS:22.04:LTS","name":"sudo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.9.9-1ubuntu2.4+fips1"}]}]},
 {"package":{"ecosystem":"Ubuntu:26.10","name":"sudo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.9.17-1ubuntu1"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.9.17-1ubuntu2"}]}]}]}`

func TestParseUbuntuOSV(t *testing.T) {
	t.Parallel()
	data := xzTar(t,
		[2]string{"osv/", ""},
		[2]string{"osv/cve/2026/UBUNTU-CVE-2026-10001.json", osvSudo},
		[2]string{"osv/cve/2026/UBUNTU-CVE-2026-99999.json", `{"not":"read"}`}, // not on the CISA list: never parsed
		[2]string{"osv/usn/USN-1-1.json", `{"not":"read"}`},
		[2]string{"osv/cve/2026/UBUNTU-CVE-2026-10002.json", `{"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"git"},"ranges":[{"events":[{"fixed":"1:2.43.0-1ubuntu7.3"}]}]},{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"git"},"ranges":[{"events":[{"fixed":"rm -rf /"}]}]}]}`},
		[2]string{"osv/cve/2026/UBUNTU-CVE-2026-10003.json", `{"affected":[`},
	)
	res, err := ParseUbuntuOSV(bytes.NewReader(data), wantKEV)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(res.Rows, func(a, b DistroFix) int { return strings.Compare(a.Release, b.Release) })
	want := []DistroFix{
		{Distro: "ubuntu", Release: "20.04", Package: "sudo", CVE: "CVE-2026-10001", Status: "fixed", Fixed: "1.8.31-1ubuntu1.5+esm2", Pro: true},
		{Distro: "ubuntu", Release: "24.04", Package: "sudo", CVE: "CVE-2026-10001", Status: "fixed", Fixed: "1.9.15p5-3ubuntu5.24.04.1"},
		{Distro: "ubuntu", Release: "26.10", Package: "sudo", CVE: "CVE-2026-10001", Status: "fixed", Fixed: "1.9.17-1ubuntu2"}, // the higher of two fixes
	}
	if !slices.Equal(res.Rows, want) {
		t.Fatalf("rows:\n%+v\nwant\n%+v", res.Rows, want)
	}
	// the git file has one bad version: dropped whole (never half a CVE); the truncated file is rejected too
	if res.Accepted != 1 || res.Rejected != 2 || len(res.Reasons) != 2 {
		t.Fatalf("stats %+v", res.Stats)
	}
}

func TestParseUbuntuVEX(t *testing.T) {
	t.Parallel()
	doc := `{"statements":[
 {"status":"not_affected","products":[{"@id":"pkg:deb/ubuntu/openssh@1:10.2p1-2ubuntu3.8?arch=source&distro=resolute"},
  {"@id":"pkg:deb/ubuntu/openssh-server@1:10.2p1-2ubuntu3.8?arch=amd64&distro=resolute"},
  {"@id":"pkg:deb/ubuntu/openssh@1:8.2p1-4ubuntu0.13+esm3?arch=source&distro=esm-infra/focal"},
  {"@id":"pkg:deb/ubuntu/openssh@1:11.0p1-1?arch=source&distro=zealous"}]},
 {"status":"fixed","products":[{"@id":"pkg:deb/ubuntu/openssh@1:9.6p1-3ubuntu13.20?arch=source&distro=noble"}]},
 {"status":"affected","products":[{"@id":"pkg:deb/ubuntu/openssh-ssh1@1:7.5p1-18?arch=source&distro=resolute"}]}]}`
	data := xzTar(t,
		[2]string{"vex/cve/2026/CVE-2026-10001.json", doc},
		[2]string{"vex/cve/2026/CVE-2026-10002.json", `{"statements":[{"status":"not_affected","products":[{"@id":"pkg:rpm/redhat/x@1"}]}]}`},
	)
	res, err := ParseUbuntuVEX(bytes.NewReader(data), wantKEV)
	if err != nil {
		t.Fatal(err)
	}
	want := []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "openssh", CVE: "CVE-2026-10001", Status: "not_affected"}}
	if !slices.Equal(res.Rows, want) {
		t.Fatalf("rows %+v", res.Rows)
	}
	// the unknown codename is said once (with its name); the CVE whose product is not a deb package is rejected whole
	if res.Accepted != 1 || res.Rejected != 2 || !strings.Contains(res.Reasons[0].Example+res.Reasons[1].Example, "zealous") {
		t.Fatalf("stats %+v", res.Stats)
	}
}

const debianJSON = `{
 "sudo": {"CVE-2026-10001": {"description": "x", "releases": {
   "bookworm": {"status": "resolved", "repositories": {"bookworm": "1.9.13p3-1+deb12u4"}, "fixed_version": "0", "urgency": "unimportant"},
   "trixie": {"status": "resolved", "fixed_version": "1.9.16p2-3", "urgency": "not yet assigned"},
   "sid": {"status": "resolved", "fixed_version": "1.9.16p2-3"},
   "bullseye": {"status": "open", "nodsa": "Minor issue", "nodsa_reason": "postponed"}}},
  "CVE-2026-55555": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "1.0-1"}}}},
 "openssh": {"CVE-2026-10002": {"releases": {"bookworm": {"status": "open"}, "forky": {"status": "undetermined"}}}},
 "glibc": {"CVE-2026-10003": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "not a version"}, "trixie": {"status": "resolved", "fixed_version": "2.41-1"}}},
   "TEMP-0000000-ABCDEF": {"releases": {}}}
}`

func TestParseDebianTracker(t *testing.T) {
	t.Parallel()
	res, err := ParseDebianTracker(strings.NewReader(debianJSON), wantKEV)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(res.Rows, func(a, b DistroFix) int { return strings.Compare(a.Release, b.Release) })
	want := []DistroFix{
		{Distro: "debian", Release: "12", Package: "sudo", CVE: "CVE-2026-10001", Status: "not_affected"},
		{Distro: "debian", Release: "13", Package: "sudo", CVE: "CVE-2026-10001", Status: "fixed", Fixed: "1.9.16p2-3"},
	}
	if !slices.Equal(res.Rows, want) {
		t.Fatalf("rows %+v", res.Rows)
	}
	// openssh: nothing resolved, accepted with no row; glibc: one bad version drops the whole entry
	if res.Accepted != 2 || res.Rejected != 1 {
		t.Fatalf("stats %+v", res.Stats)
	}
}

func TestDistroParsersFailClosed(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		parse func() (DistroResult, error)
	}{
		"osv not xz": {func() (DistroResult, error) { return ParseUbuntuOSV(strings.NewReader("<html>"), wantKEV) }},
		"vex cut short": {func() (DistroResult, error) {
			a := xzTar(t, [2]string{"vex/cve/2026/CVE-2026-10001.json", strings.Repeat(" ", 4000) + "{}"})
			return ParseUbuntuVEX(bytes.NewReader(a[:len(a)-30]), wantKEV)
		}},
		"debian not an object": {func() (DistroResult, error) { return ParseDebianTracker(strings.NewReader(`[1,2]`), wantKEV) }},
		"debian cut short":     {func() (DistroResult, error) { return ParseDebianTracker(strings.NewReader(debianJSON[:200]), wantKEV) }},
	} {
		if _, err := c.parse(); !errors.Is(err, ErrBadSample) {
			t.Errorf("%s: %v, want ErrBadSample", name, err)
		}
	}
}

// D-516: the pull keeps the CISA list's CVEs, sends the validators back (a 304 keeps the rows), tells findings which
// CVEs changed (the first fill as a baseline), and a feed that is turned off is not used.
func TestDistroPull(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(debianTrackerFeedID)
	e.mirror(debianTrackerFeedID, o.url("/tracker.json"))
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	o.body("/tracker.json", `"v1"`, debianJSON)
	// without the CISA list nothing is asked and nothing recorded: the feed waits for the list
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil || o.count("/tracker.json") != 0 || e.feed(debianTrackerFeedID).Status != "never" {
		t.Fatalf("pulled before the CISA list: %v %d %+v", err, o.count("/tracker.json"), e.feed(debianTrackerFeedID))
	}
	e.loadKEV()
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	fixes, err := e.svc.st.DistroFixes(t.Context())
	if err != nil || len(fixes["CVE-2026-10001"]) != 2 || len(fixes) != 1 {
		t.Fatalf("stored %+v %v", fixes, err)
	}
	if f := e.feed(debianTrackerFeedID); f.Status != "ok" || f.Records == nil || *f.Records != 2 {
		t.Fatalf("feed %+v", f)
	}
	if len(got) != 1 || !got[0].First || !slices.Equal(got[0].CVEs, []string{"CVE-2026-10001"}) {
		t.Fatalf("events %+v", got)
	}
	// unchanged file: 304, rows kept, no event
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	if fixes, _ := e.svc.st.DistroFixes(t.Context()); len(fixes["CVE-2026-10001"]) != 2 || len(got) != 1 || o.count("/tracker.json") != 2 {
		t.Fatalf("after 304: %+v, %d events, %d requests", fixes, len(got), o.count("/tracker.json"))
	}
	// a changed file: only the changed CVE is news
	o.body("/tracker.json", `"v2"`, strings.Replace(debianJSON, `"fixed_version": "1.9.16p2-3", "urgency"`, `"fixed_version": "1.9.16p2-4", "urgency"`, 1))
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].First || !slices.Equal(got[1].CVEs, []string{"CVE-2026-10001"}) {
		t.Fatalf("events %+v", got)
	}
	// turned off: findings no longer uses its rows (they stay) and the devices of its CVEs are matched again (review M1)
	if c, b := e.put(debianTrackerFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if fixes, _ := e.svc.st.DistroFixes(t.Context()); len(fixes) != 0 || rowsOf(t, e.db, "feeds_distro_fix") != 2 {
		t.Fatalf("a feed that is off is used: %+v", fixes)
	}
	if len(got) != 3 || got[2].First || !slices.Equal(got[2].CVEs, []string{"CVE-2026-10001"}) {
		t.Fatalf("turning the feed off told findings %+v", got)
	}
	if c, _ := e.put(debianTrackerFeedID, `{"interval_hours":12}`); c != 200 || len(got) != 3 {
		t.Fatalf("a schedule change matched again: %d %+v", c, got)
	}
	if c, _ := e.put(debianTrackerFeedID, `{"enabled":true}`); c != 200 || len(got) != 4 {
		t.Fatalf("turning the feed on did not match again: %d %+v", c, got)
	}
	if fixes, _ := e.svc.st.DistroFixes(t.Context()); len(fixes["CVE-2026-10001"]) != 2 {
		t.Fatalf("turned on again: %+v", fixes)
	}
}

// distroInv is an inventory that answers only Distros (D-570).
type distroInv struct {
	Inventory
	got   map[string]bool
	err   error
	asked int
}

func (d *distroInv) Distros(context.Context) (map[string]bool, error) { d.asked++; return d.got, d.err }

// D-570 (LEAN): a distribution feed fills once whatever the inventory says (review H1: the first device of that distribution is
// judged on its rows), then is fetched only while a device needs it. Otherwise nothing is fetched or recorded, the rows stay,
// the feed stays due (the next tick asks again) and the Feeds page says why; a failed read of the inventory pulls as before.
func TestDistroPullOnlyWhileADeviceNeedsIt(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(debianTrackerFeedID)
	e.mirror(debianTrackerFeedID, o.url("/tracker.json"))
	o.body("/tracker.json", `"v1"`, debianJSON)
	e.loadKEV()
	inv := &distroInv{got: map[string]bool{DistroUbuntu: true}}
	e.svc.Inventory = inv
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f := e.svc.live(e.feed(debianTrackerFeedID)); o.count("/tracker.json") != 1 || inv.asked != 0 || f.Status != "ok" || rowsOf(t, e.db, "feeds_distro_fix") != 2 {
		t.Fatalf("first fill: %d requests, asked %d, feed %+v", o.count("/tracker.json"), inv.asked, f)
	}
	const note = "Not updated: no Debian device now. Vedette updates it on the next check after an agent reports the packages of a Debian device."
	for range 2 { // due again (a day later): no Debian device, so nothing is fetched and the next tick asks again
		e.setNow(e.clock().Add(25 * time.Hour))
		if err := e.svc.RunPull(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	f := e.svc.live(e.feed(debianTrackerFeedID))
	if o.count("/tracker.json") != 1 || inv.asked != 2 || f.Status != "ok" || f.Error == nil || *f.Error != note || rowsOf(t, e.db, "feeds_distro_fix") != 2 {
		t.Fatalf("no Debian device: %d requests, asked %d, feed %+v", o.count("/tracker.json"), inv.asked, f)
	}
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil || o.count("/tracker.json") != 1 {
		t.Fatalf("Fetch now without a Debian device: %v, %d requests", err, o.count("/tracker.json"))
	}
	inv.got = map[string]bool{DistroUbuntu: true, DistroDebian: true}
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f := e.svc.live(e.feed(debianTrackerFeedID)); o.count("/tracker.json") != 2 || f.Status != "ok" || f.Error != nil && *f.Error == note {
		t.Fatalf("a Debian device appeared: %d requests, feed %+v", o.count("/tracker.json"), f)
	}
	// the inventory cannot be read: pull as before
	inv.got, inv.err = nil, errors.New("database is locked")
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil || o.count("/tracker.json") != 3 {
		t.Fatalf("read error: %v, %d requests", err, o.count("/tracker.json"))
	}
}

// A file that keeps no row (none of the CISA CVEs in it) fails, so the stored rows are never replaced with nothing.
func TestDistroPullOfNothingKeepsTheRows(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(debianTrackerFeedID)
	e.mirror(debianTrackerFeedID, o.url("/tracker.json"))
	e.loadKEV()
	o.body("/tracker.json", `"v1"`, debianJSON)
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	o.body("/tracker.json", `"v2"`, `{"sudo": {"CVE-2026-55555": {"releases": {}}}}`)
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(debianTrackerFeedID); f.Status != "error" || rowsOf(t, e.db, "feeds_distro_fix") != 2 {
		t.Fatalf("feed %+v, rows %d", f, rowsOf(t, e.db, "feeds_distro_fix"))
	}
}

func FuzzParseDebianTracker(f *testing.F) {
	f.Add([]byte(debianJSON))
	f.Add([]byte(`{"a":{"CVE-2026-10001":{"releases":{"bookworm":{"status":"resolved","fixed_version":"0"}}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseDebianTracker(bytes.NewReader(data), wantKEV)
		if err != nil {
			return
		}
		checkDistroRows(t, res)
	})
}

// FuzzParseUbuntuEntry fuzzes the CVE file of each archive (the xz and tar layers are the libraries').
func FuzzParseUbuntuEntry(f *testing.F) {
	f.Add([]byte(osvSudo), false)
	f.Add([]byte(`{"statements":[{"status":"not_affected","products":[{"@id":"pkg:deb/ubuntu/a@1?arch=source&distro=noble"}]}]}`), true)
	f.Fuzz(func(t *testing.T, data []byte, vex bool) {
		var res DistroResult
		var err error
		if vex {
			res, err = ParseUbuntuVEX(bytes.NewReader(xzTar(t, [2]string{"vex/cve/2026/CVE-2026-10001.json", string(data)})), wantKEV)
		} else {
			res, err = ParseUbuntuOSV(bytes.NewReader(xzTar(t, [2]string{"osv/cve/2026/UBUNTU-CVE-2026-10001.json", string(data)})), wantKEV)
		}
		if err != nil {
			t.Fatalf("a bad CVE file failed the whole archive: %v", err)
		}
		checkDistroRows(t, res)
	})
}

// checkDistroRows holds every row to what feeds_distro_fix accepts.
func checkDistroRows(t *testing.T, res DistroResult) {
	t.Helper()
	for _, r := range res.Rows {
		if !wantKEV[r.CVE] || (r.Distro != DistroUbuntu && r.Distro != DistroDebian) || !debPackageRE.MatchString(r.Package) ||
			r.Release == "" || len(r.Release) > 8 || strings.Trim(r.Release, "0123456789.") != "" ||
			(r.Status == DistroFixed) == (r.Fixed == "") || (r.Status != DistroFixed && r.Status != DistroNotAffected) {
			t.Fatalf("row %+v", r)
		}
	}
}

// Review L2 of #732: the LZMA2 dictionary an archive asks for is read before unpacking; above 64 MiB it is refused.
func TestDistroXZDictionaryCap(t *testing.T) {
	t.Parallel()
	a := xzTar(t, [2]string{"osv/cve/2026/UBUNTU-CVE-2026-10001.json", osvSudo})
	if d, ok := xzFirstDict(a); !ok || d != 1<<16 {
		t.Fatalf("dictionary of the fixture: %d %v", d, ok)
	}
	i := bytes.Index(a[12:12+(int(a[12])+1)*4], []byte{0x21, 0x01}) // LZMA2, one property byte
	if i < 0 {
		t.Fatal("no LZMA2 filter in the block header")
	}
	big := bytes.Clone(a)
	big[12+i+2] = 30 // 128 MiB
	if _, err := ParseUbuntuOSV(bytes.NewReader(big), wantKEV); !errors.Is(err, ErrBadSample) || !strings.Contains(err.Error(), "128 MiB") {
		t.Fatalf("a 128 MiB dictionary: %v", err)
	}
	canonical := bytes.Clone(a)
	canonical[12+i+2] = 28 // 64 MiB, what Canonical's archives use
	if d, ok := xzFirstDict(canonical); !ok || d != 64<<20 {
		t.Fatalf("64 MiB: %d %v", d, ok)
	}
	for _, b := range [][]byte{nil, []byte("PK\x03\x04"), a[:13]} {
		if _, ok := xzFirstDict(b); ok {
			t.Errorf("xzFirstDict(%q) read a header", b)
		}
	}
}

// Review L3 of #732: an error of the body itself (a cut connection, the wire cap) is the error of the pull, not "the answer
// is not an archive"; the unpack cap has its own error, never the wire cap's.
func TestDistroParsersPassBodyErrorsThrough(t *testing.T) {
	t.Parallel()
	cut := errors.New("connection reset by peer")
	a := xzTar(t, [2]string{"osv/cve/2026/UBUNTU-CVE-2026-10001.json", osvSudo + strings.Repeat(" ", 1<<16)})
	failing := func(b []byte) io.Reader { return io.MultiReader(bytes.NewReader(b), iotest.ErrReader(cut)) }
	if _, err := ParseUbuntuOSV(failing(a[:len(a)/2]), wantKEV); !errors.Is(err, cut) {
		t.Errorf("xz cut by the connection: %v", err)
	}
	if _, err := ParseDebianTracker(failing([]byte(debianJSON[:300])), wantKEV); !errors.Is(err, cut) {
		t.Errorf("JSON cut by the connection: %v", err)
	}
	if _, err := ParseDebianTracker(iotest.ErrReader(ErrTooLarge), wantKEV); !errors.Is(err, ErrTooLarge) {
		t.Errorf("the wire cap: %v", err)
	}
	u := &unpackCap{r: strings.NewReader("0123456789"), left: 4}
	if b, err := io.ReadAll(u); string(b) != "0123" || !errors.Is(err, errUnpackedTooLarge) || errors.Is(err, ErrTooLarge) {
		t.Errorf("unpack cap: %q %v", b, err)
	}
}

// Review L4 of #732: a purl percent-encodes its package name.
func TestSourcePurlUnescapesTheName(t *testing.T) {
	t.Parallel()
	if name, code, ok, bad := sourcePurl("pkg:deb/ubuntu/libsigc%2B%2B-2.0@2.12.1-2?arch=source&distro=noble"); name != "libsigc++-2.0" || code != "noble" || !ok || bad {
		t.Fatalf("%q %q %v %v", name, code, ok, bad)
	}
	if _, _, _, bad := sourcePurl("pkg:deb/ubuntu/a%2Fb@1?arch=source&distro=noble"); !bad {
		t.Fatal("a name with a slash after unescaping is accepted")
	}
}
