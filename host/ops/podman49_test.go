package ops

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// The outputs of the real Podman 4.9.3 of Ubuntu 24.04 (lab VM ubuntu2404, 2026-11-12, after vedette-host -bootstrap of the
// test channel; docs/lab/2026-11-12-podman-nuclei.md). The parsers must read them as they are.

const labCoreDigest = "sha256:cf8437b22c7a261e19dbae726c72f00acd3e712ac305808f2be782a546d94d12"

func labOutput(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/podman49/" + name) //nolint:gosec // fixed fixture names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A pulled release has two names (its local tag and its pull reference), so retention untags the local tag before
// "rmi <Id>": Podman refuses rmi by ID of an image with more than one name (exit 125 in the lab).
func TestRealPodmanImageListOfARelease(t *testing.T) {
	t.Parallel()
	imgs, err := parseImageList(labOutput(t, "image-ls-release.json"), api.ServiceCore)
	if err != nil || len(imgs) != 1 {
		t.Fatalf("%+v %v", imgs, err)
	}
	i := imgs[0]
	if i.ID != "19982429c04ab281451f051d0d792d56066f4685e2d60f0b9a96d1e9b73d6b75" || !i.InUse || !slices.Contains(i.Digests, labCoreDigest) ||
		!slices.Equal(i.Untag, []string{"localhost/vedette-core:0.0.1-test.1"}) {
		t.Fatalf("%+v", i)
	}
	// the honeypot image: two RepoDigests per repository (index and platform manifest), still two names
	hp, err := parseImageList(labOutput(t, "image-ls-release.json"), api.ServiceHoneypot)
	if err != nil || len(hp) != 1 || hp[0].InUse || len(hp[0].Digests) != 2 || !slices.Equal(hp[0].Untag, []string{"localhost/vedette-honeypot:0.0.1-test.1"}) {
		t.Fatalf("%+v %v", hp, err)
	}
	// the list with a foreign image (busybox tagged localhost/vedette-labtest) beside them: not this service's, left alone
	all, err := parseImageList(labOutput(t, "image-ls-two-names.json"), api.ServiceSensor)
	if err != nil || len(all) != 1 || !slices.Equal(all[0].Untag, []string{"localhost/vedette-sensor:0.0.1-test.1"}) {
		t.Fatalf("%+v %v", all, err)
	}
	for _, tag := range i.Untag {
		if a, err := untagArgv(i.ID, tag); err != nil || validatePodman(a) != nil {
			t.Fatalf("untag %q: %q %v", tag, a, err)
		}
	}
}

// After the real untag of its local tag the lab image is left with its one registry name (the state rmi <Id> accepts),
// and a foreign image like it is never one of this service's.
func TestRealPodmanImageListAfterUntag(t *testing.T) {
	t.Parallel()
	b := labOutput(t, "image-ls-after-untag.json")
	var docs []imageListDoc
	if err := json.Unmarshal(b, &docs); err != nil || len(docs) != 1 || len(docs[0].Names) != 1 || strings.HasPrefix(docs[0].Names[0], "localhost/") {
		t.Fatalf("%+v %v", docs, err)
	}
	if imgs, err := parseImageList(b, api.ServiceCore); err != nil || len(imgs) != 0 {
		t.Fatalf("%+v %v", imgs, err)
	}
}

// An image that would keep two registry names after its local tags are off can never be removed by ID: left out of the list
// (so it takes none of the 16 removals of a run); one with only local tags keeps one of them.
func TestImageListUntagPlan(t *testing.T) {
	t.Parallel()
	core := "ghcr.io/knt048/vedette-core"
	twoRegistry := listEntry(dg1, []string{"localhost/vedette-core:1.0.0", core + "@" + dg1, core + "@" + dg2}, nil, 0)
	localOnly := listEntry(dg2, []string{"localhost/vedette-core:1.0.0", "localhost/vedette-core:1.1.0"}, nil, 0)
	dg3 := "sha256:" + strings.Repeat("3", 64)
	one := listEntry(dg3, []string{core + "@" + dg3}, nil, 0)
	imgs, err := parseImageList(listJSON(twoRegistry, localOnly, one), api.ServiceCore)
	if err != nil || len(imgs) != 2 || imgs[0].ID != dg2[len("sha256:"):] || !slices.Equal(imgs[0].Untag, []string{"localhost/vedette-core:1.1.0"}) || len(imgs[1].Untag) != 0 {
		t.Fatalf("%+v %v", imgs, err)
	}
}

func TestRealPodmanContainerInspect(t *testing.T) {
	t.Parallel()
	info, err := parseInspect(labOutput(t, "container-inspect-core.json"), api.ServiceCore)
	if err != nil || info.Digest != labCoreDigest || !info.Running || info.Health != api.HealthHealthy || info.Started == "" {
		t.Fatalf("%+v %v", info, err)
	}
}

// image inspect of the local tag: Digest is the digest the release pulled (an image index), RepoDigests names it too.
func TestRealPodmanImageInspect(t *testing.T) {
	t.Parallel()
	if err := parseImageInspect(labOutput(t, "image-inspect-core.json"), api.ServiceCore, labCoreDigest, "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := parseImageInspect(labOutput(t, "image-inspect-core.json"), api.ServiceCore, labCoreDigest, "arm64"); err == nil {
		t.Fatal("another architecture was accepted")
	}
}

func TestUntagArgv(t *testing.T) {
	t.Parallel()
	id := "19982429c04ab281451f051d0d792d56066f4685e2d60f0b9a96d1e9b73d6b75"
	for _, tag := range []string{"localhost/vedette-core:1.4.0", "localhost/vedette-scan-nmap:1.4.0"} {
		if a, err := untagArgv(id, tag); err != nil || !slices.Equal(a, []string{"untag", id, tag}) || validatePodman(a) != nil {
			t.Errorf("%q: %q %v", tag, a, err)
		}
	}
	for _, bad := range [][2]string{
		{id, "ghcr.io/knt048/vedette-core@" + labCoreDigest}, {id, "localhost/vedette-core:latest"}, {id, "docker.io/library/busybox:1"},
		{id[:63], "localhost/vedette-core:1.4.0"}, {"-f", "localhost/vedette-core:1.4.0"}, {id, ""},
	} {
		if a, err := untagArgv(bad[0], bad[1]); err == nil {
			t.Errorf("%q accepted: %q", bad, a)
		}
		if validatePodman([]string{"untag", bad[0], bad[1]}) == nil {
			t.Errorf("validator accepted untag %q", bad)
		}
	}
	if validatePodman([]string{"untag", id}) == nil || validatePodman([]string{"untag", id, "localhost/vedette-core:1.4.0", "x"}) == nil {
		t.Error("untag of another arity was accepted")
	}
}
