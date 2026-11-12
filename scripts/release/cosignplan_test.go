package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

// planTree writes, under a fresh working directory, what steps 3–5 leave for the plan: release.in.json, dist/release/images.json
// and the eight SBOMs of make sbom (named after the local images, scan-base for service scan), each naming the config digest of
// its platform image in localStore (version 0.2.0) as trivy does.
func planTree(t *testing.T) (dir string, doc *ImagesDoc) {
	t.Helper()
	dir = t.TempDir()
	t.Chdir(dir)
	doc = imagesFor("0.2.0")
	in := Inputs{Version: "0.2.0", Channel: "stable"}
	for _, im := range doc.Images {
		in.Images = append(in.Images, ImageIn{Service: im.Service, Digest: im.IndexDigest, Size: 1, Platforms: []string{"linux/amd64", "linux/arm64"}})
	}
	writeJSON(t, "release.in.json", in)
	must(t, os.MkdirAll("dist/release", 0o700))
	writeJSON(t, "dist/release/images.json", doc)
	must(t, os.MkdirAll("dist/sbom", 0o700))
	for _, local := range localNames {
		for _, arch := range []string{"amd64", "arm64"} {
			writeSBOM(t, "dist/sbom/"+local+"-"+arch+".cdx.json", "sha256:"+cfgID(local, arch))
		}
	}
	return dir, doc
}

func writeSBOM(t *testing.T, p string, imageIDs ...string) {
	t.Helper()
	props := []map[string]string{{"name": "aquasecurity:trivy:DiffID", "value": digestOf("layer")}}
	for _, id := range imageIDs {
		props = append(props, map[string]string{"name": trivyImageID, "value": id})
	}
	writeJSON(t, p, map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6",
		"metadata": map[string]any{"component": map[string]any{"type": "container", "properties": props}}, "components": []any{}})
}

func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(p, b, 0o600))
}

func readInJSON(t *testing.T) Inputs {
	t.Helper()
	in, err := readInputs("release.in.json")
	must(t, err)
	return in
}

// planRun is `release cosign-plan -key /keys/cosign.key ARGS` with podman faked by store.
func planRun(store func([]string) ([]byte, error), args ...string) (string, error) {
	var out bytes.Buffer
	fr := &fakeRun{fn: store}
	err := cosignPlanCmd(context.Background(), fr.run, append([]string{"-key", "/keys/cosign.key"}, args...), &out)
	return out.String(), err
}

func TestCosignPlanSignsAndAttests(t *testing.T) {
	dir, doc := planTree(t)
	out, err := planRun(localStore("0.2.0"), "-cosign", "/opt/cosign v2/cosign")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2+4+8 || lines[0] != "cd "+shellQuote(dir) || lines[1] != "mkdir -p dist/release/cosign" {
		t.Fatalf("%d lines: %q", len(lines), lines)
	}
	bin := `'/opt/cosign v2/cosign'`
	for i, im := range doc.Images {
		want := bin + " sign --key /keys/cosign.key --new-bundle-format=false --use-signing-config=false --upload=false --tlog-upload=false" +
			" --output-payload dist/release/cosign/" + im.Service + ".payload.json --output-signature dist/release/cosign/" + im.Service + ".sig " +
			im.Repo + "@" + im.IndexDigest
		if lines[2+i] != want {
			t.Errorf("sign %s:\n got %s\nwant %s", im.Service, lines[2+i], want)
		}
		local := localName(im.Service)
		for j, p := range im.Platforms {
			arch := strings.TrimPrefix(p.Platform, "linux/")
			want := bin + " attest --key /keys/cosign.key --type cyclonedx --predicate dist/sbom/" + local + "-" + arch + ".cdx.json" +
				" --new-bundle-format=false --use-signing-config=false --tlog-upload=false --replace " + im.Repo + "@" + p.Digest
			if got := lines[6+2*i+j]; got != want {
				t.Errorf("attest %s %s:\n got %s\nwant %s", im.Service, arch, got, want)
			}
		}
	}
	if !strings.Contains(out, "dist/sbom/scan-base-arm64.cdx.json") {
		t.Error("service scan is not mapped to the local image scan-base")
	}

	// What the sign lines write is what release-manifest reads: do each line's effect (the payload and signature cosign writes at
	// the printed paths), then readCosign over the directory the Makefile gives release-manifest.
	cos := releasetest.NewCosign(t)
	must(t, os.MkdirAll("dist/release/cosign", 0o700))
	for _, line := range lines[2:6] {
		f := strings.Fields(line)[2:] // after the quoted binary
		repo, digest, _ := strings.Cut(f[len(f)-1], "@")
		p := releasetest.Payload(repo, digest)
		_, sig := cos.Sign(t, p)
		must(t, os.WriteFile(f[slices.Index(f, "--output-payload")+1], p, 0o600))
		must(t, os.WriteFile(f[slices.Index(f, "--output-signature")+1], []byte(sig+"\n"), 0o600))
	}
	for _, im := range doc.Images {
		if _, err := readCosign("dist/release/cosign", im.Service, im.IndexDigest); err != nil {
			t.Errorf("release-manifest would refuse %s: %v", im.Service, err)
		}
	}
}

func TestCosignPlanRefuses(t *testing.T) {
	images := func(t *testing.T, f func(d *ImagesDoc)) {
		d := imagesFor("0.2.0")
		f(d)
		writeJSON(t, "dist/release/images.json", d)
	}
	inputs := func(t *testing.T, f func(in *Inputs)) {
		in := readInJSON(t)
		f(&in)
		writeJSON(t, "release.in.json", in)
	}
	for name, c := range map[string]struct {
		args  []string
		mut   func(t *testing.T)
		store func([]string) ([]byte, error)
		want  string
	}{
		"no key":            {args: []string{"-key", ""}, want: "-key is required"},
		"relative key":      {args: []string{"-key", "keys/cosign.key"}, want: "absolute"},
		"key is a flag":     {args: []string{"-key", "--upload=true"}, want: "starts with '-'"},
		"newline in key":    {args: []string{"-key", "/k\n/x"}, want: "control character"},
		"empty cosign":      {args: []string{"-cosign", ""}, want: "-cosign is empty"},
		"assignment cosign": {args: []string{"-cosign", "A=/x"}, want: "absolute path or cosign"},
		"out outside dist":  {args: []string{"-out", "/tmp/cosign"}, want: "inside dist/"},
		"out climbs":        {args: []string{"-out", "dist/../x"}, want: "inside dist/"},
		"sbom outside dist": {args: []string{"-sbom", "sbom"}, want: "inside dist/"},
		"out symlink": {mut: func(t *testing.T) {
			must(t, os.MkdirAll("elsewhere", 0o700))
			must(t, os.Symlink("../../elsewhere", "dist/release/cosign"))
		}, want: "-out: dist/release/cosign is a symlink"},
		"missing sbom": {mut: func(t *testing.T) { must(t, os.Remove("dist/sbom/scan-base-arm64.cdx.json")) }, want: "scan linux/arm64"},
		"sbom not cyclonedx": {mut: func(t *testing.T) {
			must(t, os.WriteFile("dist/sbom/core-amd64.cdx.json", []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600))
		}, want: "not CycloneDX"},
		"sbom of another build": {mut: func(t *testing.T) {
			writeSBOM(t, "dist/sbom/sensor-arm64.cdx.json", "sha256:"+cfgID("sensor", "amd64"))
		}, want: "sensor linux/arm64: SBOM dist/sbom/sensor-arm64.cdx.json is of image"},
		"sbom without image id": {mut: func(t *testing.T) { writeSBOM(t, "dist/sbom/core-amd64.cdx.json") }, want: "is of image []"},
		"sbom with two image ids": {mut: func(t *testing.T) {
			writeSBOM(t, "dist/sbom/core-amd64.cdx.json", "sha256:"+cfgID("core", "amd64"), digestOf("x"))
		}, want: "is of image"},
		"local image of another version": {store: localStore("0.1.9"), want: "not version 0.2.0"},
		"no local list": {store: func(a []string) ([]byte, error) {
			if a[1] == "manifest" && a[2] == "exists" {
				return nil, os.ErrNotExist
			}
			return localStore("0.2.0")(a)
		}, want: "no local manifest list"},
		"sbom symlink": {mut: func(t *testing.T) {
			must(t, os.Rename("dist/sbom/core-amd64.cdx.json", "elsewhere.json"))
			must(t, os.Symlink("../../elsewhere.json", "dist/sbom/core-amd64.cdx.json"))
		}, want: "dist/sbom/core-amd64.cdx.json is a symlink"},
		"sbom dir symlink": {mut: func(t *testing.T) {
			must(t, os.Rename("dist/sbom", "outside"))
			must(t, os.Symlink("../outside", "dist/sbom"))
		}, want: "-sbom: dist/sbom is a symlink"},
		"version differs":      {mut: func(t *testing.T) { writeJSON(t, "dist/release/images.json", imagesFor("0.2.1")) }, want: "images.json is version"},
		"index digest differs": {mut: func(t *testing.T) { images(t, func(d *ImagesDoc) { d.Images[2].IndexDigest = digestOf("other") }) }, want: "scan: release.in.json names"},
		"platforms differ": {mut: func(t *testing.T) {
			images(t, func(d *ImagesDoc) { d.Images[1].Platforms = d.Images[1].Platforms[:1] })
		}, want: "sensor: release.in.json has platforms"},
		"platform twice": {mut: func(t *testing.T) {
			images(t, func(d *ImagesDoc) { d.Images[1].Platforms[1].Platform = "linux/amd64" })
			inputs(t, func(in *Inputs) { in.Images[1].Platforms = []string{"linux/amd64", "linux/amd64"} })
		}, want: "sensor: release.in.json has platforms"},
		"rehearsal images.json": {mut: func(t *testing.T) {
			images(t, func(d *ImagesDoc) { d.Images[0].Repo = "127.0.0.1:5000/vedette-core" })
		}, want: "rehearsal"},
		"bad platform digest": {mut: func(t *testing.T) {
			images(t, func(d *ImagesDoc) { d.Images[3].Platforms[0].Digest = "sha256:" + strings.Repeat("A", 64) })
		}, want: "malformed"},
		"in.json has another service": {mut: func(t *testing.T) { inputs(t, func(in *Inputs) { in.Images[0].Service = "greenbone" }) }, want: "not in images.json"},
		"in.json repeats a service":   {mut: func(t *testing.T) { inputs(t, func(in *Inputs) { in.Images[1] = in.Images[0] }) }, want: "lists core twice"},
	} {
		t.Run(name, func(t *testing.T) {
			planTree(t)
			if c.mut != nil {
				c.mut(t)
			}
			store := c.store
			if store == nil {
				store = localStore("0.2.0")
			}
			out, err := planRun(store, c.args...)
			if err == nil || out != "" || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("out %q, err %v (want %q)", out, err, c.want)
			}
		})
	}
}

func TestAttestArgv(t *testing.T) {
	d := digestOf("x")
	for _, c := range [][2]string{{"greenbone", d}, {"scan-base", d}, {"core", "sha256:abc"}, {"core", d + "\n"}} {
		if _, err := AttestArgv("cosign", "k", c[0], c[1], "dist/sbom/x.cdx.json"); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
	argv, err := AttestArgv("cosign", "k", "scan", d, "dist/sbom/scan-base-amd64.cdx.json")
	if err != nil || argv[len(argv)-1] != release.RegistryPrefix+"scan@"+d {
		t.Fatal(argv, err)
	}
}
