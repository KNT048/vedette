package ops

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// The current templates are pinned: a change of one must keep its text before the change in legacyTemplates (D-316 (10)), or every
// box that runs the earlier host would find its units "not ours" after a self-update and refuse every container command.
func TestUnitTemplatesArePinned(t *testing.T) {
	t.Parallel()
	pins := map[string]string{
		api.ServiceCore:     "9deb6b916ecc1d85abde7d6f7697e5e6752e4c7ac9cca7c6f4be804a58e20882",
		api.ServiceSensor:   "9ccbe814284990c74a6f719aaec34804b6f62c32b288ea4979390d14c4b54aad",
		api.ServiceHoneypot: "0798bd35bf60e40c56529e03b1a41cc472ef87863012282e00e761ed1814d59a",
		api.ServiceScan:     "4aac18dfd69ee1220ca8b1210d9de23ef66c896147b507731ad03227324ce7e2",
	}
	texts := map[string]string{api.ServiceCore: coreUnitText, api.ServiceSensor: sensorUnitText, api.ServiceHoneypot: honeypotUnitText, api.ServiceScan: scanUnitText}
	for svc, text := range texts {
		if got := sha256Hex([]byte(text)); got != pins[svc] {
			t.Errorf("the %s template changed (sha256 %s). Boxes keep units of the earlier template: append the text before your change to "+
				"legacyTemplates[%q] in quadlet_legacy.go and its golden files to testdata/units/legacy (unless the change must be made in two "+
				"units together, see quadlet_legacy.go), then update this pin", svc, got, svc)
		}
	}
}

// Every earlier template makes, byte for byte, the golden file the test of its own release kept (copied from git into
// testdata/units/legacy): what a box that ran that release has on disk.
func TestLegacyTemplatesMatchTheGoldenFilesOfTheirRelease(t *testing.T) {
	t.Parallel()
	n := 0
	for svc, list := range legacyTemplates {
		for i, tmpl := range list {
			for _, install := range []bool{true, false} {
				f := goldFill(install)
				got, err := services[svc].render(tmpl, f)
				if err != nil {
					t.Fatalf("%s %d: %v", svc, i+1, err)
				}
				name := fmt.Sprintf("%d-%s.container", i+1, svc)
				if !install {
					name = fmt.Sprintf("%d-%s.noinstall.container", i+1, svc)
				}
				want, err := os.ReadFile(filepath.Join("testdata", "units", "legacy", name)) //nolint:gosec // a golden file under testdata
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s differs from what that release wrote:\n%s", name, got)
				}
				if d, inst, err := parseUnit(svc, got); err != nil || d != f.Digest || inst != install {
					t.Errorf("%s does not read back: %s %t %v", name, d, inst, err)
				}
				if cur, _ := renderUnit(svc, f); bytes.Equal(cur, got) {
					t.Errorf("%s is the current template, not an earlier one", name)
				}
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no legacy template was checked")
	}
}

func legacyOps(t *testing.T) *Ops {
	t.Helper()
	f := goldFill(true)
	return &Ops{cfg: Config{CoreUID: f.CoreUID, CoreGID: f.CoreGID, SensorUID: f.SensorUID, SensorGID: f.SensorGID, CoreData: f.DataDir}}
}

// A unit on an earlier template is ours and stale; the current one is ours and not stale; one byte changed, other ids or a
// template the lists do not hold is not ours.
func TestOurUnitAcceptsAnEarlierTemplateOnlyByteForByte(t *testing.T) {
	t.Parallel()
	o := legacyOps(t)
	for _, install := range []bool{true, false} {
		f := goldFill(install)
		cur, err := renderUnit(api.ServiceCore, f)
		if err != nil {
			t.Fatal(err)
		}
		if d, inst, stale, err := o.ourUnitAge(api.ServiceCore, cur); err != nil || stale || d != f.Digest || inst != install {
			t.Fatalf("current: %s %t %t %v", d, inst, stale, err)
		}
		for i, tmpl := range legacyTemplates[api.ServiceCore] {
			old, err := services[api.ServiceCore].render(tmpl, f)
			if err != nil {
				t.Fatal(err)
			}
			if d, inst, stale, err := o.ourUnitAge(api.ServiceCore, old); err != nil || !stale || d != f.Digest || inst != install {
				t.Fatalf("legacy %d: %s %t %t %v", i+1, d, inst, stale, err)
			}
			for name, edit := range map[string][]byte{
				"a hand edit":     bytes.Replace(old, []byte("--cpus=2"), []byte("--cpus=4"), 1),
				"an extra line":   bytes.Replace(old, []byte("ReadOnly=true\n"), []byte("ReadOnly=true\nPublishPort=2222:22\n"), 1),
				"a comment added": append([]byte("# mine\n"), old...),
				"a trailing byte": append(bytes.Clone(old), '\n'),
			} {
				if _, _, _, err := o.ourUnitAge(api.ServiceCore, edit); !errors.Is(err, errUnitNotOurs) {
					t.Errorf("legacy %d with %s: %v", i+1, name, err)
				}
			}
			other := f
			other.CoreUID++
			withOther, err := services[api.ServiceCore].render(tmpl, other)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := o.ourUnitAge(api.ServiceCore, withOther); !errors.Is(err, errUnitNotOurs) {
				t.Errorf("legacy %d for another core_uid: %v", i+1, err)
			}
		}
	}
	// A template older than the lists (before D-318: the honeypot log was a bind of a directory) is not ours.
	old := strings.Replace(string(mustRender(t, api.ServiceHoneypot, goldFill(true))), "Volume="+hpLogVolume+".volume:/var/lib/vedette/honeypot/log:U,noexec",
		"Volume="+hpHostDir+"/log:/var/lib/vedette/honeypot/log:U", 1)
	if _, _, _, err := o.ourUnitAge(api.ServiceHoneypot, []byte(old)); !errors.Is(err, errUnitNotOurs) {
		t.Errorf("a pre-D-318 honeypot unit: %v", err)
	}
	// sensor and scan have no earlier template: only the current bytes are theirs.
	for _, svc := range []string{api.ServiceSensor, api.ServiceScan} {
		if l := legacyTemplates[svc]; len(l) != 0 {
			t.Errorf("%s: %d legacy templates, and this test expects none", svc, len(l))
		}
	}
}

func mustRender(t *testing.T, svc string, f unitFill) []byte {
	t.Helper()
	b, err := renderUnit(svc, f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// volumeIDs reads the ids back only from the exact text the host writes.
func TestVolumeIDsReadsBackOnlyWhatTheHostWrote(t *testing.T) {
	t.Parallel()
	for _, role := range credsRoles {
		text, err := renderVolume(role, 10001, 10004)
		if err != nil {
			t.Fatal(err)
		}
		if u, g, ok := volumeIDs(role, text); !ok || u != 10001 || g != 10004 {
			t.Fatalf("%s: %d %d %t", role, u, g, ok)
		}
		other := "passive"
		if role == other {
			other = "active"
		}
		for name, bad := range map[string]string{
			"leading zero":    strings.Replace(string(text), "User=10001", "User=010001", 1),
			"plus sign":       strings.Replace(string(text), "User=10001", "User=+10001", 1),
			"root":            strings.Replace(string(text), "User=10001", "User=0", 1),
			"a name":          strings.Replace(string(text), "Group=10004", "Group=vedette", 1),
			"an extra key":    string(text) + "Label=x\n",
			"the other role":  strings.ReplaceAll(string(text), role, other),
			"no trailing eol": strings.TrimSuffix(string(text), "\n"),
		} {
			if _, _, ok := volumeIDs(role, []byte(bad)); ok {
				t.Errorf("%s %s: read back", role, name)
			}
		}
	}
}

// "podman volume exists" is allowed only for the two credential volumes, in exactly that shape.
func TestPodmanGrammarOfTheVolumeLook(t *testing.T) {
	t.Parallel()
	for _, role := range credsRoles {
		argv, err := volumeExistsArgv(role)
		if err != nil || validatePodman(argv) != nil {
			t.Fatalf("%s: %v %v", role, argv, err)
		}
	}
	if _, err := volumeExistsArgv("other"); err == nil {
		t.Error("a role outside the list got an argv")
	}
	for _, bad := range [][]string{
		{"volume", "exists", "vedette-hp-log"}, {"volume", "exists", "vedette-creds-"}, {"volume", "exists", "vedette-creds-passive", "x"},
		{"volume", "rm", "vedette-creds-passive"}, {"volume", "inspect", "vedette-creds-passive"}, {"volume", "exists", "--help"},
	} {
		if validatePodman(bad) == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// The label retention finds a nameless build by is the one the constant Containerfile sets.
func TestScanBuildLabelIsTheContainerfiles(t *testing.T) {
	t.Parallel()
	if !strings.Contains(scanContainerfile, "\nLABEL "+scanBuildLabel+"="+scanBuildLabelValue+"\n") {
		t.Fatal("scanContainerfile does not set the label retention reads")
	}
}

// A scan image with no name is listed for retention only with the build label, and only for scan; it is kept or removed by its ID.
func TestParseImageListTakesANamelessScanBuildByItsLabel(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("c", 64)
	labeled := fmt.Sprintf(`{"Id":%q,"Digest":"sha256:%s","Names":null,"RepoTags":null,"RepoDigests":[],"Containers":0,"Labels":{"io.vedette.build":"scan"}}`, id, strings.Repeat("d", 64))
	noDigest := fmt.Sprintf(`{"Id":%q,"Names":[],"Containers":1,"Labels":{"io.vedette.build":"scan"}}`, strings.Repeat("e", 64))
	unlabeled := fmt.Sprintf(`{"Id":%q,"Digest":"sha256:%s","Names":null,"Containers":0,"Labels":{"io.buildah.version":"1.42.1"}}`, strings.Repeat("f", 64), strings.Repeat("f", 64))
	otherValue := fmt.Sprintf(`{"Id":%q,"Digest":"sha256:%s","Names":null,"Containers":0,"Labels":{"io.vedette.build":"core"}}`, strings.Repeat("a", 64), strings.Repeat("a", 64))
	out := []byte("[" + strings.Join([]string{labeled, noDigest, unlabeled, otherValue}, ",") + "]")
	imgs, err := parseImageList(out, api.ServiceScan)
	if err != nil || len(imgs) != 2 {
		t.Fatalf("%+v %v", imgs, err)
	}
	if imgs[0].ID != id || len(imgs[0].Digests) != 1 || imgs[0].Digests[0] != "sha256:"+id || imgs[0].InUse || len(imgs[0].Untag) != 0 {
		t.Fatalf("%+v", imgs[0])
	}
	if !imgs[1].InUse {
		t.Fatalf("a nameless build a container uses is not marked in use: %+v", imgs[1])
	}
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceGreenbone} {
		if imgs, err := parseImageList(out, svc); err != nil || len(imgs) != 0 {
			t.Errorf("%s took a nameless image: %+v %v", svc, imgs, err)
		}
	}
}
