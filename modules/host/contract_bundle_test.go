package host_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

// container.pull with source=bundle (spec 6.7, update-manifest.md §11, D-452; host CONTRACT INV-19 and PULL-8). Core wrote the
// uploaded bundle to <core_data>/bundles/<id>.tar and names only the id; the host reads the four signed documents out of it, verifies
// them exactly as for a registry pull, copies the service's image archive into a layout of its own blob by blob (each must hash to its
// name, the archive must be the signed digest), and loads that with "podman pull -q oci:<dir>:<image ref>". The rest is the registry
// path: inspect by the pull reference, tag, record.

// bundleArgs writes a bundle holding the four documents (index of sequence 5, a manifest of pullVersion naming im for svc) and im as
// images/<svc>.oci.tar; edit may change the entries first. It returns the args core sends.
func (e *pullEnv) bundleArgs(t *testing.T, svc string, im *opstest.OCIImage, edit func([]opstest.TarEntry) []opstest.TarEntry) api.ContainerPullArgs {
	t.Helper()
	idx := e.rel.IndexDoc(5)
	man := e.rel.ManifestDoc(pullVersion, opstest.Img{Service: svc, Digest: im.Digest, Size: 1000})
	entries := append(e.rel.BundleDocs(opstest.JSON(t, idx), opstest.JSON(t, man)),
		opstest.TarEntry{Name: "images/", Type: tar.TypeDir}, opstest.TarEntry{Name: "images/" + svc + ".oci.tar", Body: im.Tar(t)},
		opstest.TarEntry{Name: "sbom.json", Body: []byte(`{}`)})
	if edit != nil {
		entries = edit(entries)
	}
	return e.bundleOf(t, svc, opstest.Tar(t, entries...))
}

func (e *pullEnv) bundleOf(t *testing.T, svc string, content []byte) api.ContainerPullArgs {
	t.Helper()
	return api.ContainerPullArgs{Service: svc, Version: pullVersion, Source: api.PullSourceBundle, BundleID: e.m.CoreBundle(content)}
}

// replace swaps the body of the entry name (or drops it when body is nil).
func replace(name string, body []byte) func([]opstest.TarEntry) []opstest.TarEntry {
	return func(es []opstest.TarEntry) []opstest.TarEntry {
		var out []opstest.TarEntry
		for _, x := range es {
			if x.Name == name {
				if body == nil {
					continue
				}
				x.Body = body
			}
			out = append(out, x)
		}
		return out
	}
}

func with(extra ...opstest.TarEntry) func([]opstest.TarEntry) []opstest.TarEntry {
	return func(es []opstest.TarEntry) []opstest.TarEntry { return append(es, extra...) }
}

// stagedGone says the host left no staged layout behind.
func (e *pullEnv) stagedGone(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(e.m.State, "bundle")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged layout was left behind (%v)", err)
	}
}

// failedWithNothing expects a run that ended failed with code, no load, no tag, no record and no staged layout.
func (e *pullEnv) failedWithNothing(t *testing.T, a api.ContainerPullArgs, code string) {
	t.Helper()
	e.final(t, api.CmdContainerPull, a, api.StatusFailed, code)
	for _, c := range e.podman() {
		if c[0] == "pull" || c[0] == "tag" {
			t.Fatalf("a refused bundle ran %v", c)
		}
	}
	if _, err := os.Stat(e.pulledFile(a.Service)); err == nil {
		t.Error("a version was recorded")
	}
	e.stagedGone(t)
}

func TestContract_Bundle_VerifiesCopiesBlobByBlobLoadsTagsAndRecords(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	ref := "ghcr.io/knt048/vedette-core@" + im.Digest
	const tag = "localhost/vedette-core:1.4.0"
	a := e.bundleArgs(t, api.ServiceCore, im, nil)
	r := e.pull(t, a)
	res := result[api.ContainerPullResult](t, r)
	if res.Digest != im.Digest || !slices.Equal(res.Verified, []string{"minisign", "cosign"}) {
		t.Fatalf("result %+v", res)
	}
	got := e.podman()
	if len(got) != 6 || got[2][0] != "pull" || got[2][1] != "-q" {
		t.Fatalf("podman calls %v", got)
	}
	oci := got[2][2]
	dir, name, _ := strings.Cut(strings.TrimPrefix(oci, "oci:"), ":")
	if !strings.HasPrefix(oci, "oci:") || name != "ghcr.io/knt048/vedette-core:1.4.0" || filepath.Dir(dir) != filepath.Join(e.m.State, "bundle") {
		t.Fatalf("the load names %q", oci)
	}
	want := [][]string{
		{"image", "inspect", "--format", "json", ref}, // Check: here already?
		{"image", "inspect", "--format", "json", ref}, // Run: the same look
		{"pull", "-q", oci},                           // the host's own layout, never the registry
		{"image", "inspect", "--format", "json", ref}, // the digest is read back by the pull reference, as for the registry
		{"tag", ref, tag},
		{"image", "inspect", "--format", "json", tag},
	}
	if !equal2(got, want) {
		t.Fatalf("podman calls\n got %v\nwant %v", got, want)
	}
	if e.m.ImageTag(tag) != im.Digest || len(e.m.OCIPulls()) != 1 {
		t.Fatalf("tag %q, loads %v", e.m.ImageTag(tag), e.m.OCIPulls())
	}
	// The record and the stored index are the bundle's, as if core had sent them.
	if st := e.state(t)[api.ServiceCore]; st.LatestPulled == nil || st.LatestPulled.Digest != im.Digest || *st.LatestPulled.Version != pullVersion {
		t.Fatalf("state %+v", st.LatestPulled)
	}
	if e.storedSequence(t) != 5 {
		t.Errorf("stored sequence %d", e.storedSequence(t))
	}
	// The layout (GiBs on a real box) is gone once Podman has its copy; core's file is core's to remove.
	e.stagedGone(t)
	if _, err := os.Stat(e.m.CoreBundlePath(a.BundleID)); err != nil {
		t.Errorf("the host touched core's bundle: %v", err)
	}
}

func TestContract_Bundle_AnImageAlreadyHereIsNotLoadedAgainButTheSignaturesAreStillChecked(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	a := e.bundleArgs(t, api.ServiceCore, im, nil)
	e.pull(t, a)
	n := len(e.m.OCIPulls())
	// The same bundle again: verified, found, tagged and recorded, nothing copied or loaded.
	e.pull(t, a)
	if len(e.m.OCIPulls()) != n || e.pulls() != 1 {
		t.Fatalf("loaded again: %v", e.podman())
	}
	e.stagedGone(t)
	// A bundle whose manifest no longer verifies is refused although the image is here.
	bad := e.bundleArgs(t, api.ServiceCore, im, func(es []opstest.TarEntry) []opstest.TarEntry {
		for i := range es {
			if es[i].Name == "release-manifest.json" {
				es[i].Body = flip(es[i].Body, 30)
			}
		}
		return es
	})
	before := len(e.podman())
	e.refused(t, api.CmdContainerPull, bad, 412, api.CodeSignatureInvalid)
	if len(e.podman()) != before {
		t.Fatal("podman ran for a bundle that does not verify")
	}
}

func TestContract_Bundle_ABadSignatureIsRefusedBeforeAnything(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	other := opstest.NewRelease(t) // keys the host does not trust
	idx := opstest.JSON(t, e.rel.IndexDoc(5))
	for name, edit := range map[string]func([]opstest.TarEntry) []opstest.TarEntry{
		"a flipped bit in the manifest": func(es []opstest.TarEntry) []opstest.TarEntry {
			for i := range es {
				if es[i].Name == "release-manifest.json" {
					es[i].Body = flip(es[i].Body, 50)
				}
			}
			return es
		},
		"the index signed by another key": replace("index.json.minisig", other.Sign(idx)),
		"the manifest with the index's signature": func(es []opstest.TarEntry) []opstest.TarEntry {
			return replace("release-manifest.json.minisig", e.rel.Sign(idx))(es)
		},
	} {
		e.refuse(t, name, e.bundleArgs(t, api.ServiceCore, im, edit), api.CodeSignatureInvalid)
	}
	e.stagedGone(t)
}

func TestContract_Bundle_AnArchiveThatIsNotTheSignedImageIsArchiveDigestMismatch(t *testing.T) {
	t.Parallel()
	for name, prep := range map[string]func(t *testing.T, im *opstest.OCIImage) func([]opstest.TarEntry) []opstest.TarEntry{
		"the layout names another image": func(t *testing.T, _ *opstest.OCIImage) func([]opstest.TarEntry) []opstest.TarEntry {
			other := opstest.NewOCIImage(t, "amd64", "evil")
			return replace("images/core.oci.tar", other.Tar(t)) // signed: im.Digest; archive: other's
		},
		"a layer that does not hash to its name": func(t *testing.T, im *opstest.OCIImage) func([]opstest.TarEntry) []opstest.TarEntry {
			im.Leave[opstest.Hex(im.Layer)] = true
			im.Extra = []opstest.TarEntry{{Name: "blobs/sha256/" + opstest.Hex(im.Layer), Body: []byte("not the layer")}}
			return replace("images/core.oci.tar", im.Tar(t))
		},
		"the top index swapped under its name": func(t *testing.T, im *opstest.OCIImage) func([]opstest.TarEntry) []opstest.TarEntry {
			im.Leave[opstest.Hex(im.Index)] = true
			im.Extra = []opstest.TarEntry{{Name: "blobs/sha256/" + opstest.Hex(im.Index), Body: bytes.Replace(im.Index, []byte("amd64"), []byte("arm64"), 1)}}
			return replace("images/core.oci.tar", im.Tar(t))
		},
		"a layout index with two images": func(t *testing.T, im *opstest.OCIImage) func([]opstest.TarEntry) []opstest.TarEntry {
			s := string(im.LayoutIndex)
			i := strings.Index(s, "[") + 1
			j := strings.LastIndex(s, "]")
			im.LayoutIndex = []byte(s[:i] + s[i:j] + "," + s[i:j] + s[j:])
			return replace("images/core.oci.tar", im.Tar(t))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			im := opstest.NewOCIImage(t, "amd64", "core")
			edit := prep(t, im)
			e.failedWithNothing(t, e.bundleArgs(t, api.ServiceCore, im, edit), api.CodeArchiveDigestMismatch)
		})
	}
}

func TestContract_Bundle_PathTraversalLinksAndDevicesAreRefused(t *testing.T) {
	t.Parallel()
	// In the bundle itself: Check refuses (412), no podman at all.
	for name, extra := range map[string]opstest.TarEntry{
		"a parent path":            {Name: "../escaped", Body: []byte("x")},
		"a parent path in images/": {Name: "images/../../escaped.oci.tar", Body: []byte("x")},
		"an absolute path":         {Name: "/etc/escaped", Body: []byte("x")},
		"a name outside the list":  {Name: "notes.txt", Body: []byte("x")},
		"an unknown image":         {Name: "images/evil.oci.tar", Body: []byte("x")},
		"a symlink":                {Name: "host/x.deb", Type: tar.TypeSymlink, Linkname: "/etc/shadow"},
		"a hard link":              {Name: "sbom2.json", Type: tar.TypeLink, Linkname: "index.json"},
		"a device":                 {Name: "host/dev.deb", Type: tar.TypeChar},
		"a fifo":                   {Name: "host/fifo.deb", Type: tar.TypeFifo},
		"another folder":           {Name: "etc/", Type: tar.TypeDir},
		"a duplicate":              {Name: "sbom.json", Body: []byte("{}")},
	} {
		t.Run("bundle: "+name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			e.refuse(t, name, e.bundleArgs(t, api.ServiceCore, opstest.NewOCIImage(t, "amd64", "core"), with(extra)), api.CodeBundleInvalid)
			e.noIndexStored(t) // refused before the documents were even verified
			e.stagedGone(t)
		})
	}
	// In the image archive: the run fails, nothing is written outside the staged layout, which is removed.
	for name, extra := range map[string]opstest.TarEntry{
		"a parent path":      {Name: "../../../escaped", Body: []byte("x")},
		"a blob path climb":  {Name: "blobs/sha256/../../../../escaped", Body: []byte("x")},
		"an absolute path":   {Name: "/tmp/escaped", Body: []byte("x")},
		"a symlink":          {Name: "blobs/sha256/" + strings.Repeat("e", 64), Type: tar.TypeSymlink, Linkname: "/etc/shadow"},
		"a hard link":        {Name: "blobs/sha256/" + strings.Repeat("f", 64), Type: tar.TypeLink, Linkname: "index.json"},
		"a device":           {Name: "blobs/sha256/" + strings.Repeat("d", 64), Type: tar.TypeBlock},
		"another blob algo":  {Name: "blobs/sha512/" + strings.Repeat("a", 128), Body: []byte("x")},
		"a duplicate layout": {Name: "oci-layout", Body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
	} {
		t.Run("archive: "+name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			im := opstest.NewOCIImage(t, "amd64", "core")
			im.Extra = []opstest.TarEntry{extra}
			e.failedWithNothing(t, e.bundleArgs(t, api.ServiceCore, im, nil), api.CodeBundleInvalid)
			for _, p := range []string{filepath.Join(e.m.State, "escaped"), filepath.Join(filepath.Dir(e.m.State), "escaped"), "/tmp/escaped"} {
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("%s was written", p)
				}
			}
		})
	}
}

func TestContract_Bundle_TheStagingPathMustBeCoresPlainFile(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	good := e.bundleArgs(t, api.ServiceCore, im, nil)
	// A symlink at <core_data>/bundles/<id>.tar, to a perfectly good bundle: refused (core could point the root host anywhere).
	link := strings.Repeat("b", 32)
	if err := os.Symlink(e.m.CoreBundlePath(good.BundleID), e.m.CoreBundlePath(link)); err != nil {
		t.Fatal(err)
	}
	a := good
	a.BundleID = link
	e.refuse(t, "a symlink", a, api.CodeBundleInvalid)
	// A hard link (two names for one file) is refused too.
	hard := strings.Repeat("c", 32)
	if err := os.Link(e.m.CoreBundlePath(good.BundleID), e.m.CoreBundlePath(hard)); err != nil {
		t.Fatal(err)
	}
	a.BundleID = hard
	e.refuse(t, "a hard link", a, api.CodeBundleInvalid)
	if err := os.Remove(e.m.CoreBundlePath(hard)); err != nil {
		t.Fatal(err)
	}
	// A folder, a FIFO, and a file over 8 GiB (sparse: nothing is written).
	for name, mk := range map[string]func(p string) error{
		"a folder": func(p string) error { return os.Mkdir(p, 0o700) },
		"a fifo":   func(p string) error { return syscall.Mkfifo(p, 0o600) },
		"over 8 GiB": func(p string) error {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				return err
			}
			return os.Truncate(p, 8<<30+1)
		},
	} {
		id := opstest.Hex([]byte(name))[:32]
		if err := mk(e.m.CoreBundlePath(id)); err != nil {
			t.Fatal(err)
		}
		a.BundleID = id
		e.refuse(t, name, a, api.CodeBundleInvalid)
	}
	// A bundle core never wrote.
	a.BundleID = strings.Repeat("0", 32)
	e.refuse(t, "missing", a, api.CodeBundleNotFound)
	e.noIndexStored(t)
	// The good one still works after all that.
	e.pull(t, good)
}

func TestContract_Bundle_OversizeMembersAreRefused(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	big := bytes.Repeat([]byte(" "), 256<<10+1)
	e.refuse(t, "index.json over 256 KiB", e.bundleArgs(t, api.ServiceCore, im, replace("index.json", big)), api.CodeBundleInvalid)
	e.refuse(t, "a signature over 2 KiB", e.bundleArgs(t, api.ServiceCore, im, replace("index.json.minisig", bytes.Repeat([]byte("x"), 2<<10+1))), api.CodeBundleInvalid)
	e.refuse(t, "bundle.json over 1 MiB", e.bundleArgs(t, api.ServiceCore, im, replace("bundle.json", bytes.Repeat([]byte("x"), 1<<20+1))), api.CodeBundleInvalid)
	many := func(es []opstest.TarEntry) []opstest.TarEntry {
		for i := range 64 {
			es = append(es, opstest.TarEntry{Name: "host/p" + string(rune('a'+i%26)) + strings.Repeat("x", i) + ".deb", Body: []byte("x")})
		}
		return es
	}
	e.refuse(t, "more than 64 entries", e.bundleArgs(t, api.ServiceCore, im, many), api.CodeBundleInvalid)
	e.refuse(t, "not a tar", e.bundleOf(t, api.ServiceCore, []byte("this is not a tar")), api.CodeBundleInvalid)
	e.refuse(t, "empty", e.bundleOf(t, api.ServiceCore, nil), api.CodeBundleInvalid)
	// In the image archive: an oci-layout or an index.json over its cap.
	im2 := opstest.NewOCIImage(t, "amd64", "core")
	im2.LayoutIndex = append(im2.LayoutIndex, bytes.Repeat([]byte(" "), 256<<10)...)
	e.failedWithNothing(t, e.bundleArgs(t, api.ServiceCore, im2, nil), api.CodeBundleInvalid)
}

func TestContract_Bundle_MissingPiecesAreRefused(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "core")
	for _, doc := range []string{"index.json", "index.json.minisig", "release-manifest.json", "release-manifest.json.minisig"} {
		e.refuse(t, "no "+doc, e.bundleArgs(t, api.ServiceCore, im, replace(doc, nil)), api.CodeBundleInvalid)
	}
	e.noIndexStored(t)
	// No image for the service: refused in Check, after the documents verified (the manifest decides which services exist).
	e.refuse(t, "no image", e.bundleArgs(t, api.ServiceCore, im, replace("images/core.oci.tar", nil)), api.CodeBundleInvalid)
	// The image of another service only.
	e.refuse(t, "another service's image", e.bundleArgs(t, api.ServiceCore, im, func(es []opstest.TarEntry) []opstest.TarEntry {
		for i := range es {
			if es[i].Name == "images/core.oci.tar" {
				es[i].Name = "images/sensor.oci.tar"
			}
		}
		return es
	}), api.CodeBundleInvalid)
	// In the archive: each blob of the chain, the platform manifest, and index.json itself.
	for name, prep := range map[string]func(im *opstest.OCIImage){
		"no layer":       func(im *opstest.OCIImage) { im.Leave[opstest.Hex(im.Layer)] = true },
		"no config":      func(im *opstest.OCIImage) { im.Leave[opstest.Hex(im.Config)] = true },
		"no manifest":    func(im *opstest.OCIImage) { im.Leave[opstest.Hex(im.Manifest)] = true },
		"no top index":   func(im *opstest.OCIImage) { im.Leave[opstest.Hex(im.Index)] = true },
		"no index.json":  func(im *opstest.OCIImage) { im.LayoutIndex = nil },
		"no amd64 image": nil, // built for arm64 below
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			arch := "amd64"
			if prep == nil {
				arch = "arm64"
			}
			im := opstest.NewOCIImage(t, arch, "core")
			if prep != nil {
				prep(im)
			}
			edit := func(es []opstest.TarEntry) []opstest.TarEntry { return es }
			if im.LayoutIndex == nil { // the archive without its index.json
				im.LayoutIndex = []byte("{}")
				edit = replace("images/core.oci.tar", stripEntry(t, im.Tar(t), "index.json"))
			}
			e.failedWithNothing(t, e.bundleArgs(t, api.ServiceCore, im, edit), api.CodeBundleInvalid)
		})
	}
}

// stripEntry rebuilds the tar b without the entry name.
func stripEntry(t *testing.T, b []byte, name string) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(b))
	var es []opstest.TarEntry
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Name == name {
			continue
		}
		body, _ := readAllTar(tr)
		es = append(es, opstest.TarEntry{Name: h.Name, Body: body, Type: h.Typeflag, Linkname: h.Linkname})
	}
	return opstest.Tar(t, es...)
}

func readAllTar(tr *tar.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(tr)
	return buf.Bytes(), err
}

func TestContract_Bundle_ScanIsBuiltOnTheBoxAfterTheLoad(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	im := opstest.NewOCIImage(t, "amd64", "scan")
	e.pull(t, e.bundleArgs(t, api.ServiceScan, im, nil))
	var seq []string
	for _, c := range e.podman() {
		if slices.Contains([]string{"pull", "tag", "build", "run"}, c[0]) {
			seq = append(seq, c[0])
		}
	}
	if !slices.Equal(seq, []string{"pull", "tag", "build", "run"}) || len(e.m.OCIPulls()) != 1 {
		t.Fatalf("podman did %v (loads %v)", seq, e.m.OCIPulls())
	}
	builds := e.m.Builds()
	if len(builds) != 1 || !strings.Contains(builds[0], "BASE_IMAGE=ghcr.io/knt048/vedette-scan@"+im.Digest) {
		t.Fatalf("builds %v", builds)
	}
	if st := e.state(t)[api.ServiceScan]; st.LatestPulled == nil || st.LatestPulled.Digest != "sha256:"+opstest.BuiltID(1) {
		t.Fatalf("state %+v", st.LatestPulled)
	}
	e.stagedGone(t)
}

func TestContract_Bundle_ArgsCarryNoDocumentsAndLowDiskIsThreeTimesTheArchive(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var free uint64
	e := startPull(t, func(_ *ops.Config, d *ops.Deps) {
		d.FreeBytes = func(string) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			return free, nil
		}
	})
	im := opstest.NewOCIImage(t, "amd64", "core")
	a := e.bundleArgs(t, api.ServiceCore, im, nil)
	// A bundle source with documents of its own: two sources of truth, refused as an argument.
	withDocs := a
	withDocs.Manifest = "aGk="
	e.refused(t, api.CmdContainerPull, withDocs, 400, api.CodeInvalidArgs)
	size := uint64(len(im.Tar(t)))
	mu.Lock()
	free = 3*size - 1
	mu.Unlock()
	e.refused(t, api.CmdContainerPull, a, 412, api.CodeLowDisk)
	for _, c := range e.podman() {
		if c[0] != "image" {
			t.Fatalf("a refused pull ran %v", c)
		}
	}
	mu.Lock()
	free = 3 * size
	mu.Unlock()
	e.pull(t, a)
}

func TestContract_Bundle_StartRemovesALayoutLeftByARunThatWasCutShort(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	left := filepath.Join(e.m.State, "bundle", "img-123", "blobs", "sha256")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	e.startAudit(t)
	e.stagedGone(t)
}
