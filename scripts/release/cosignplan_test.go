package main

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

// planTree writes, under a fresh working directory, what steps 3–5 leave for the plan: release.in.json, dist/release/images.json
// and the eight SBOMs of make sbom (named after the local images, scan-base for service scan).
func planTree(t *testing.T) (*ImagesDoc, Inputs) {
	t.Helper()
	t.Chdir(t.TempDir())
	doc := imagesFor("0.2.0")
	in := Inputs{Version: "0.2.0", Channel: "stable"}
	for _, im := range doc.Images {
		in.Images = append(in.Images, ImageIn{Service: im.Service, Digest: im.IndexDigest, Size: 1, Platforms: []string{"linux/amd64", "linux/arm64"}})
	}
	writeJSON(t, "release.in.json", in)
	must(t, os.MkdirAll("dist/release", 0o700))
	writeJSON(t, "dist/release/images.json", doc)
	must(t, os.MkdirAll("dist/sbom", 0o700))
	for _, local := range []string{"core", "sensor", "scan-base", "honeypot"} {
		for _, arch := range []string{"amd64", "arm64"} {
			must(t, os.WriteFile("dist/sbom/"+local+"-"+arch+".cdx.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), 0o600))
		}
	}
	return doc, in
}

func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(p, b, 0o600))
}

func planRun(args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	code := run(append([]string{"cosign-plan", "-key", "/keys/cosign.key"}, args...), nil, &out, &errb)
	return out.String(), errb.String(), code
}

func TestCosignPlanSignsAndAttests(t *testing.T) {
	doc, _ := planTree(t)
	out, errs, code := planRun("-cosign", "/opt/cosign v2/cosign")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1+4+8 || lines[0] != "mkdir -p dist/release/cosign" {
		t.Fatalf("%d lines: %q", len(lines), lines)
	}
	bin := `'/opt/cosign v2/cosign'`
	for i, im := range doc.Images {
		want := bin + " sign --key /keys/cosign.key --new-bundle-format=false --use-signing-config=false --upload=false --tlog-upload=false" +
			" --output-payload dist/release/cosign/" + im.Service + ".payload.json --output-signature dist/release/cosign/" + im.Service + ".sig " +
			im.Repo + "@" + im.IndexDigest
		if lines[1+i] != want {
			t.Errorf("sign %s:\n got %s\nwant %s", im.Service, lines[1+i], want)
		}
		local := map[string]string{"scan": "scan-base"}[im.Service]
		if local == "" {
			local = im.Service
		}
		for j, p := range im.Platforms {
			arch := strings.TrimPrefix(p.Platform, "linux/")
			want := bin + " attest --key /keys/cosign.key --type cyclonedx --predicate dist/sbom/" + local + "-" + arch + ".cdx.json" +
				" --new-bundle-format=false --use-signing-config=false --tlog-upload=false --replace " + im.Repo + "@" + p.Digest
			if got := lines[5+2*i+j]; got != want {
				t.Errorf("attest %s %s:\n got %s\nwant %s", im.Service, arch, got, want)
			}
		}
	}

	// What the sign lines write is what release-manifest reads: run each line's effect (the payload and signature cosign writes at
	// the printed paths), then readCosign over the directory the Makefile gives release-manifest.
	cos := releasetest.NewCosign(t)
	must(t, os.MkdirAll("dist/release/cosign", 0o700))
	for _, line := range lines[1:5] {
		f := strings.Fields(line)[2:] // after the quoted binary
		img := f[len(f)-1]
		repo, digest, _ := strings.Cut(img, "@")
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
	for name, c := range map[string]struct {
		args []string
		mut  func(t *testing.T)
		want string
	}{
		"no key":            {args: []string{"-key", ""}, want: "-key is required"},
		"key is a flag":     {args: []string{"-key", "--upload=true"}, want: "starts with '-'"},
		"newline in key":    {args: []string{"-key", "/k\n/x"}, want: "control character"},
		"empty cosign":      {args: []string{"-cosign", ""}, want: "-cosign"},
		"out outside dist":  {args: []string{"-out", "/tmp/cosign"}, want: "inside dist/"},
		"out climbs":        {args: []string{"-out", "dist/../x"}, want: "inside dist/"},
		"sbom outside dist": {args: []string{"-sbom", "sbom"}, want: "inside dist/"},
		"missing sbom":      {mut: func(t *testing.T) { must(t, os.Remove("dist/sbom/scan-base-arm64.cdx.json")) }, want: "scan linux/arm64"},
		"sbom not cyclonedx": {mut: func(t *testing.T) {
			must(t, os.WriteFile("dist/sbom/core-amd64.cdx.json", []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600))
		}, want: "not CycloneDX"},
		"sbom symlink": {mut: func(t *testing.T) {
			must(t, os.Rename("dist/sbom/core-amd64.cdx.json", "elsewhere.json"))
			must(t, os.Symlink("../../elsewhere.json", "dist/sbom/core-amd64.cdx.json"))
		}, want: "not a regular file"},
		"sbom dir symlink": {mut: func(t *testing.T) {
			must(t, os.Rename("dist/sbom", "outside"))
			must(t, os.Symlink("../outside", "dist/sbom"))
		}, want: "symlink"},
		"version differs": {mut: func(t *testing.T) {
			d := imagesFor("0.2.1")
			writeJSON(t, "dist/release/images.json", d)
		}, want: "version"},
		"index digest differs": {mut: func(t *testing.T) {
			d := imagesFor("0.2.0")
			d.Images[2].IndexDigest = digestOf("other")
			writeJSON(t, "dist/release/images.json", d)
		}, want: "scan: release.in.json names"},
		"platforms differ": {mut: func(t *testing.T) {
			d := imagesFor("0.2.0")
			d.Images[1].Platforms = d.Images[1].Platforms[:1]
			writeJSON(t, "dist/release/images.json", d)
		}, want: "platforms"},
		"rehearsal images.json": {mut: func(t *testing.T) {
			d := imagesFor("0.2.0")
			d.Images[0].Repo = "127.0.0.1:5000/vedette-core"
			writeJSON(t, "dist/release/images.json", d)
		}, want: "rehearsal"},
		"bad platform digest": {mut: func(t *testing.T) {
			d := imagesFor("0.2.0")
			d.Images[3].Platforms[0].Digest = "sha256:" + strings.Repeat("A", 64)
			writeJSON(t, "dist/release/images.json", d)
		}, want: "malformed"},
		"in.json has another service": {mut: func(t *testing.T) {
			var in Inputs
			raw, err := os.ReadFile("release.in.json")
			must(t, err)
			must(t, json.Unmarshal(raw, &in))
			in.Images[0].Service = "greenbone"
			writeJSON(t, "release.in.json", in)
		}, want: "not in images.json"},
	} {
		t.Run(name, func(t *testing.T) {
			planTree(t)
			if c.mut != nil {
				c.mut(t)
			}
			out, errs, code := planRun(c.args...)
			if code == 0 || out != "" || !strings.Contains(errs, c.want) {
				t.Fatalf("code %d, out %q, err %q (want %q)", code, out, errs, c.want)
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
