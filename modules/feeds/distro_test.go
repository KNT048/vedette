package feeds

import (
	"archive/tar"
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

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
	// turned off: findings no longer uses its rows (they stay)
	if c, b := e.put(debianTrackerFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	if fixes, _ := e.svc.st.DistroFixes(t.Context()); len(fixes) != 0 || rowsOf(t, e.db, "feeds_distro_fix") != 2 {
		t.Fatalf("a feed that is off is used: %+v", fixes)
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
