package host_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/internal/release"
)

// container.pull (WP-07b part 3, slice 3-7; spec 6.7, D-103, D-104, D-130; host CONTRACT INV-7 and INV-19).
// The machine is the fake of opstest with a fake podman that remembers images (StatefulImages) and
// signing keys made for the test (opstest.Release, handed to the host through Deps.Keys). A refusal
// must leave no podman call behind; the happy path asserts the argv of every call in order.

const (
	pullVersion = "1.4.0"
	coreSize    = 1000
)

var coreRef = "ghcr.io/knt048/vedette-core@" + digA

type pullEnv struct {
	*sysEnv
	rel  *opstest.Release
	keys atomic.Pointer[release.Trust] // the keys the host trusts now; a test may swap them
}

func startPull(t *testing.T, muts ...mut) *pullEnv {
	t.Helper()
	rel := opstest.NewRelease(t)
	pe := &pullEnv{rel: rel}
	pe.keys.Store(&rel.Trust)
	e := startSys(t, append([]mut{func(_ *ops.Config, d *ops.Deps) {
		d.Keys = func() (release.Trust, error) { return *pe.keys.Load(), nil }
	}}, muts...)...)
	e.m.StatefulImages()
	pe.sysEnv = e
	return pe
}

// docs are an index with the given sequence and a manifest of version holding core (digA) and sensor (digB).
func (e *pullEnv) docs(seq uint64, version string) (idx, man opstest.Doc) {
	return e.rel.IndexDoc(seq), e.rel.ManifestDoc(version,
		opstest.Img{Service: api.ServiceCore, Digest: digA, Size: coreSize}, opstest.Img{Service: api.ServiceSensor, Digest: digB, Size: 2000})
}

func (e *pullEnv) argsFor(t *testing.T, svc, version string, idx, man opstest.Doc) api.ContainerPullArgs {
	t.Helper()
	return e.rel.Args(svc, version, opstest.JSON(t, idx), opstest.JSON(t, man))
}

func (e *pullEnv) std(t *testing.T, seq uint64) api.ContainerPullArgs {
	t.Helper()
	idx, man := e.docs(seq, pullVersion)
	return e.argsFor(t, api.ServiceCore, pullVersion, idx, man)
}

func (e *pullEnv) pull(t *testing.T, a api.ContainerPullArgs) api.Run {
	t.Helper()
	return e.ok(t, api.CmdContainerPull, a)
}

// refuse expects a 412 with the code and no podman call at all (nothing was pulled, tagged or inspected).
func (e *pullEnv) refuse(t *testing.T, name string, a api.ContainerPullArgs, code string) {
	t.Helper()
	e.refused(t, api.CmdContainerPull, a, 412, code)
	if calls := e.m.Calls("podman"); len(calls) != 0 {
		t.Fatalf("%s: a refused pull ran podman: %v", name, calls)
	}
}

func (e *pullEnv) state(t *testing.T) map[string]api.ContainerState {
	t.Helper()
	st, err := e.h.Client.StateContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]api.ContainerState{}
	for _, s := range st.Services {
		m[s.Service] = s
	}
	return m
}

func (e *pullEnv) podman() [][]string { return e.m.Calls("podman") }

func (e *pullEnv) pulls() int {
	n := 0
	for _, c := range e.podman() {
		if c[0] == "pull" {
			n++
		}
	}
	return n
}

func (e *pullEnv) indexFile() string { return filepath.Join(e.m.State, "releases", "index.json") }
func (e *pullEnv) pulledFile(svc string) string {
	return filepath.Join(e.m.State, "containers", "pulled-"+svc+".json")
}

// storedIndex reads releases/index.json: the raw index it holds and the file's own bytes.
func (e *pullEnv) storedIndex(t *testing.T) (raw []byte, file []byte) {
	t.Helper()
	file, err := os.ReadFile(e.indexFile())
	if err != nil {
		t.Fatal(err)
	}
	var st struct{ Index, Sig string }
	if err := json.Unmarshal(file, &st); err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(st.Index)
	if err != nil {
		t.Fatal(err)
	}
	return raw, file
}

func (e *pullEnv) storedSequence(t *testing.T) uint64 {
	t.Helper()
	raw, _ := e.storedIndex(t)
	var x struct{ Sequence uint64 }
	if err := json.Unmarshal(raw, &x); err != nil {
		t.Fatal(err)
	}
	return x.Sequence
}

func (e *pullEnv) noIndexStored(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(e.indexFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an index was stored (%v)", err)
	}
}

func flip(b []byte, at int) []byte {
	c := slices.Clone(b)
	c[at%len(c)] ^= 0x01
	return c
}

// --- the happy path -------------------------------------------------------------------------------

func TestContract_Pull_VerifiesThenPullsByDigestTagsAndRecords(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	args := e.argsFor(t, api.ServiceCore, pullVersion, idx, man)
	r := e.pull(t, args)
	res := result[api.ContainerPullResult](t, r)
	if res.Digest != digA || res.Size != coreSize || !slices.Equal(res.Verified, []string{"minisign", "cosign"}) {
		t.Fatalf("result %+v", res)
	}
	const tag = "localhost/vedette-core:1.4.0"
	want := [][]string{
		{"image", "inspect", "--format", "json", coreRef}, // Check: is it here already, for the disk check? (no)
		{"image", "inspect", "--format", "json", coreRef}, // Run: the same look
		{"pull", "-q", coreRef},
		{"image", "inspect", "--format", "json", coreRef}, // what podman says is not believed: the digest is read back
		{"tag", coreRef, tag},
		{"image", "inspect", "--format", "json", tag}, // and so is the tag
	}
	if got := e.podman(); !equal2(got, want) {
		t.Fatalf("podman calls\n got %v\nwant %v", got, want)
	}
	if e.m.ImageTag(tag) != digA || !e.m.ImagePresent(digA) {
		t.Fatalf("tag -> %q", e.m.ImageTag(tag))
	}
	// Nothing else ran: no systemctl, no unit.
	if len(e.m.Calls("systemctl")) != 0 {
		t.Errorf("systemctl ran: %v", e.m.Calls("systemctl"))
	}
	// The index is stored; the record holds the version, the digest, the key and the signed manifest.
	if raw, _ := e.storedIndex(t); !bytes.Equal(raw, opstest.JSON(t, idx)) || e.storedSequence(t) != 5 {
		t.Error("the stored index is not the one that was sent")
	}
	b, err := os.ReadFile(e.pulledFile(api.ServiceCore))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Service, Version, Digest string
		KeyID                    string `json:"key_id"`
		Size                     int64
		Manifest                 string
		ManifestSig              string `json:"manifest_sig"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	manRaw, _ := base64.StdEncoding.DecodeString(rec.Manifest)
	if rec.Service != "core" || rec.Version != pullVersion || rec.Digest != digA || rec.KeyID != e.rel.ActiveKeyID() || rec.Size != coreSize ||
		!bytes.Equal(manRaw, opstest.JSON(t, man)) || rec.ManifestSig == "" {
		t.Fatalf("record %+v", rec)
	}
	for _, p := range []string{e.indexFile(), e.pulledFile("core")} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	// GET /v1/state/containers reads it as latest_pulled; the running version is not a pull's business.
	core := e.state(t)["core"]
	if core.LatestPulled == nil || core.LatestPulled.Version == nil || *core.LatestPulled.Version != pullVersion || core.LatestPulled.Digest != digA || core.Version != nil || core.Previous != nil {
		t.Fatalf("state %+v", core)
	}
	if got := e.state(t)["sensor"]; got.LatestPulled != nil {
		t.Errorf("sensor was never pulled: %+v", got.LatestPulled)
	}
	// The run's log says what was verified.
	if r.Status != api.StatusSucceeded {
		t.Fatalf("%+v", r)
	}
}

func equal2(a, b [][]string) bool {
	return slices.EqualFunc(a, b, slices.Equal[[]string])
}

func TestContract_Pull_AnotherServiceFromTheSameManifestUsesItsOwnDigestAndTag(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx, man))
	e.pull(t, e.argsFor(t, api.ServiceSensor, pullVersion, idx, man))
	got := e.podman()
	sensor := "ghcr.io/knt048/vedette-sensor@" + digB
	if last := got[len(got)-2]; !slices.Equal(last, []string{"tag", sensor, "localhost/vedette-sensor:1.4.0"}) {
		t.Fatalf("calls %v", got)
	}
	if e.m.ImageTag("localhost/vedette-sensor:1.4.0") != digB || e.m.ImageTag("localhost/vedette-core:1.4.0") != digA {
		t.Error("the tags are wrong")
	}
	st := e.state(t)
	if st["sensor"].LatestPulled == nil || st["sensor"].LatestPulled.Digest != digB || st["core"].LatestPulled.Digest != digA {
		t.Fatalf("%+v %+v", st["sensor"], st["core"])
	}
}

// --- idempotency, replay and freeze ---------------------------------------------------------------

func TestContract_Pull_ADigestAlreadyHereIsNotPulledAgainButTheSignaturesAreStillChecked(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.m.SetImagePresent(digA)
	args := e.std(t, 5)
	e.pull(t, args)
	if e.pulls() != 0 {
		t.Fatalf("pulled an image that was there: %v", e.podman())
	}
	if e.m.ImageTag("localhost/vedette-core:1.4.0") != digA {
		t.Error("an image that was already here was not tagged")
	}
	if _, err := os.Stat(e.pulledFile("core")); err != nil {
		t.Error("no record")
	}
	// The same call again is a success with no pull either.
	e.pull(t, args)
	if e.pulls() != 0 {
		t.Fatal("pulled on the second call")
	}
	// A tampered manifest with the image present is still refused: the signatures decide, not the disk.
	bad := args
	raw, _ := base64.StdEncoding.DecodeString(args.Manifest)
	bad.Manifest = base64.StdEncoding.EncodeToString(flip(raw, 40))
	n := len(e.podman())
	e.refused(t, api.CmdContainerPull, bad, 412, api.CodeSignatureInvalid)
	if len(e.podman()) != n {
		t.Fatal("podman ran for a manifest that does not verify")
	}
}

func TestContract_Pull_AnOlderIndexIsRefusedAnEqualOneIsAcceptedAndOnlyANewerOneIsStored(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx5, man := e.docs(5, pullVersion)
	a5 := e.argsFor(t, api.ServiceCore, pullVersion, idx5, man)
	e.pull(t, a5)
	_, file5 := e.storedIndex(t)

	// The same index again: accepted (equal sequence, same bytes), and the file is not rewritten.
	st5, _ := os.Stat(e.indexFile())
	e.pull(t, a5)
	st5b, _ := os.Stat(e.indexFile())
	if !os.SameFile(st5, st5b) { // a rewrite is a rename of a new file
		t.Error("an equal index was stored again")
	}

	// A lower sequence: replay. Refused before anything runs, the stored index untouched.
	idx4, _ := e.docs(4, pullVersion)
	before := len(e.podman())
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx4, man), 412, api.CodeSequenceRegress)
	if len(e.podman()) != before {
		t.Fatal("podman ran for a replayed index")
	}
	if _, f := e.storedIndex(t); !bytes.Equal(f, file5) {
		t.Fatal("a replayed index changed the stored one")
	}
	// The same sequence with other bytes is not "equal": it is refused too.
	idx5b, _ := e.docs(5, pullVersion)
	idx5b["advisories"] = []any{opstest.Doc{"id": "A-1", "severity": "low", "title": "t", "affects": "core", "fixed_in": "", "url": "https://example.com/a"}}
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx5b, man), 412, api.CodeSequenceRegress)

	// A newer one is stored.
	idx9, _ := e.docs(9, pullVersion)
	e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx9, man))
	if e.storedSequence(t) != 9 {
		t.Fatalf("stored sequence %d", e.storedSequence(t))
	}
}

func TestContract_Pull_AStoredNewerIndexRevokesAndAReplayCannotUndoIt(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx5, man := e.docs(5, pullVersion)
	e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx5, man))
	// Index 6 revokes the release: refused, and the revoking index is stored all the same, so the
	// host knows of the revocation even though this very index is the reason the pull was refused.
	idx6, _ := e.docs(6, pullVersion)
	idx6["revoked"] = []any{opstest.Revocation("release", pullVersion)}
	n := len(e.podman())
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx6, man), 412, api.CodeReleaseRevoked)
	if len(e.podman()) != n || e.storedSequence(t) != 6 {
		t.Fatalf("podman %d -> %d, stored sequence %d", n, len(e.podman()), e.storedSequence(t))
	}
	// The old index that did not revoke it cannot bring it back.
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx5, man), 412, api.CodeSequenceRegress)
	// A later index that forgot the revocation: carried forward all the same (it is sticky).
	idx7, _ := e.docs(7, pullVersion)
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx7, man), 412, api.CodeReleaseRevoked)
	if e.storedSequence(t) != 7 {
		t.Fatal("the later index was not stored")
	}
	// Another version is not affected.
	idx8, man2 := e.docs(8, "1.4.1")
	e.pull(t, e.argsFor(t, api.ServiceCore, "1.4.1", idx8, man2))
}

func TestContract_Pull_ARevokedDigestIsRefusedUnderAnyVersionLabel(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, "1.4.2")
	idx["revoked"] = []any{opstest.Revocation("image_digest", digA)}
	e.refuse(t, "revoked digest", e.argsFor(t, api.ServiceCore, "1.4.2", idx, man), api.CodeReleaseRevoked)
}

func TestContract_Pull_ARevokedKeyIsRefusedAndStaysRevoked(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	idx["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())}
	idxRaw, manRaw := opstest.JSON(t, idx), opstest.JSON(t, man)
	// Only the offline backup key can revoke a key; the manifest is signed by the revoked one.
	e.refuse(t, "revoked signer of the manifest", e.rel.ArgsSig("core", pullVersion, idxRaw, e.rel.SignBackup(idxRaw), manRaw, e.rel.Sign(manRaw)), api.CodeKeyRevoked)
	// The revocation is stored: an index the revoked key signs later is refused.
	idx6, man6 := e.docs(6, pullVersion)
	e.refuse(t, "index of the revoked signer", e.argsFor(t, api.ServiceCore, pullVersion, idx6, man6), api.CodeKeyRevoked)
	// A revocation in an index the active key signs does not count (a leaked key must not revoke others).
	e2 := startPull(t)
	i2, m2 := e2.docs(5, pullVersion)
	i2["revoked"] = []any{opstest.Revocation("key", e2.rel.BackupKeyID())}
	e2.pull(t, e2.argsFor(t, api.ServiceCore, pullVersion, i2, m2))
}

// --- every refusal, with no pull run -------------------------------------------------------------

func TestContract_Pull_Refusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		code   string
		mutate func(_ *pullEnv, idx, man opstest.Doc) (svc, version string)
	}{
		"registry_not_allowed: another registry": {api.CodeRegistryNotAllowed, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["ref"] = "ghcr.io/evil/vedette-core:1.4.0"
			return "core", pullVersion
		}},
		"registry_not_allowed: a tag of another version": {api.CodeRegistryNotAllowed, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["ref"] = "ghcr.io/knt048/vedette-core:1.4.1"
			return "core", pullVersion
		}},
		"registry_not_allowed: a digest ref": {api.CodeRegistryNotAllowed, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["ref"] = coreRef
			return "core", pullVersion
		}},
		"registry_not_allowed: another image of the manifest": {api.CodeRegistryNotAllowed, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[1].(opstest.Doc)["ref"] = "docker.io/library/alpine:latest"
			return "core", pullVersion // the pull is for core; the manifest as a whole is refused
		}},
		"release_revoked": {api.CodeReleaseRevoked, func(_ *pullEnv, idx, _ opstest.Doc) (string, string) {
			idx["revoked"] = []any{opstest.Revocation("release", pullVersion)}
			return "core", pullVersion
		}},
		"release_revoked: another image of the manifest has a revoked digest": {api.CodeReleaseRevoked, func(_ *pullEnv, idx, _ opstest.Doc) (string, string) {
			idx["revoked"] = []any{opstest.Revocation("image_digest", digB)}
			return "core", pullVersion
		}},
		"digest_not_in_manifest: the service has no image": {api.CodeDigestNotInManifest, func(_ *pullEnv, _, _ opstest.Doc) (string, string) {
			return "honeypot", pullVersion
		}},
		"platform_mismatch": {api.CodePlatformMismatch, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["platforms"] = []string{"linux/arm64", "linux/riscv64"}
			return "core", pullVersion
		}},
		"manifest_mismatch: version of the args": {api.CodeManifestMismatch, func(_ *pullEnv, _, _ opstest.Doc) (string, string) {
			return "core", "1.4.1"
		}},
		"manifest_mismatch: the hash the index names": {api.CodeManifestMismatch, func(_ *pullEnv, idx, _ opstest.Doc) (string, string) {
			idx["channels"].(opstest.Doc)["stable"].(opstest.Doc)["latest"] = pullVersion // a hash is named for the latest of the channel
			return "core", pullVersion
		}},
		"not_appliance: the release is container-only": {api.CodeNotAppliance, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["install_modes"] = []string{"container"}
			return "core", pullVersion
		}},
		"signature_invalid: the cosign signature of the image": {api.CodeSignatureInvalid, func(e *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["cosign"] = e.rel.CosignSig("core", digB) // a valid signature, for another digest
			return "core", pullVersion
		}},
		"signature_invalid: the cosign signature is another service's": {api.CodeSignatureInvalid, func(e *pullEnv, _, man opstest.Doc) (string, string) {
			man["images"].([]any)[0].(opstest.Doc)["cosign"] = e.rel.CosignSig("sensor", digA)
			return "core", pullVersion
		}},
		"signature_invalid: an unknown field in the manifest": {api.CodeSignatureInvalid, func(_ *pullEnv, _, man opstest.Doc) (string, string) {
			man["surprise"] = true
			return "core", pullVersion
		}},
		"signature_invalid: a schema from the future": {api.CodeSignatureInvalid, func(_ *pullEnv, idx, _ opstest.Doc) (string, string) {
			idx["schema"] = 2
			return "core", pullVersion
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			idx, man := e.docs(5, pullVersion)
			svc, version := c.mutate(e, idx, man)
			e.refuse(t, name, e.argsFor(t, svc, version, idx, man), c.code)
			if _, err := os.Stat(e.pulledFile(svc)); err == nil {
				t.Error("a record was written")
			}
		})
	}
}

func TestContract_Pull_ABitFlipInAnyOfTheFourDocumentsIsSignatureInvalid(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"index", "index_sig", "manifest", "manifest_sig"} {
		for _, at := range []int{0, 7, 40, 100} {
			e := startPull(t)
			a := e.std(t, 5)
			get := map[string]*string{"index": &a.Index, "index_sig": &a.IndexSig, "manifest": &a.Manifest, "manifest_sig": &a.ManifestSig}[field]
			raw, _ := base64.StdEncoding.DecodeString(*get)
			*get = base64.StdEncoding.EncodeToString(flip(raw, at))
			e.refuse(t, field, a, api.CodeSignatureInvalid)
		}
	}
}

func TestContract_Pull_ASignatureOfAnotherDocumentOrAnUntrustedKeyIsSignatureInvalid(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	idxRaw, manRaw := opstest.JSON(t, idx), opstest.JSON(t, man)
	e.refuse(t, "manifest signed with the index's signature", e.rel.ArgsSig("core", pullVersion, idxRaw, e.rel.Sign(idxRaw), manRaw, e.rel.Sign(idxRaw)), api.CodeSignatureInvalid)
	other := opstest.NewRelease(t) // keys the host does not trust
	e.refuse(t, "untrusted key", other.Args("core", pullVersion, idxRaw, manRaw), api.CodeSignatureInvalid)
}

func TestContract_Pull_BundleIsRefusedAndNotAnApplianceIsRefused(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.refuse(t, "bundle", api.ContainerPullArgs{Service: "core", Version: pullVersion, Source: api.PullSourceBundle, BundleID: strings.Repeat("a", 32)}, api.CodeBundleUnsupported)
	e.m.OSRelease("ubuntu", "20.04", "Ubuntu 20.04")
	e.refuse(t, "old ubuntu", e.std(t, 5), api.CodeNotAppliance)
	e.noIndexStored(t) // the appliance check comes first: nothing was verified, nothing stored
}

func TestContract_Pull_LowDiskIsTwiceTheSizeOfTheImageMeasuredWhereImagesLive(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var probed []string
	free := uint64(2*coreSize - 1)
	e := startPull(t, func(_ *ops.Config, d *ops.Deps) {
		d.FreeBytes = func(p string) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			probed = append(probed, p)
			return free, nil
		}
	})
	e.refused(t, api.CmdContainerPull, e.std(t, 5), 412, api.CodeLowDisk)
	for _, c := range e.podman() { // the one look "is it here already?" and nothing that changes anything
		if c[0] != "image" {
			t.Fatalf("a refused pull ran %v", c)
		}
	}
	mu.Lock()
	free = 2 * coreSize // exactly twice the size is enough
	mu.Unlock()
	e.pull(t, e.std(t, 5))
	mu.Lock()
	defer mu.Unlock()
	if len(probed) == 0 || probed[0] != filepath.Join(e.m.Root, "var/lib/containers") {
		t.Fatalf("measured %v, want <root>/var/lib/containers", probed)
	}
}

func TestContract_Pull_ThePathTheDiskIsMeasuredAtFallsBackToTheNearestExistingParent(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var probed []string
	e := startPull(t, func(_ *ops.Config, d *ops.Deps) {
		d.FreeBytes = func(p string) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			probed = append(probed, p)
			if strings.HasSuffix(p, "var/lib/containers") || strings.HasSuffix(p, "var/lib") {
				return 0, os.ErrNotExist
			}
			return 100 << 30, nil
		}
	})
	e.pull(t, e.std(t, 5))
	mu.Lock()
	defer mu.Unlock()
	if len(probed) < 3 || !strings.HasSuffix(probed[2], "/var") {
		t.Fatalf("probed %v", probed)
	}
}

func TestContract_Pull_ABusyHostRefusesAndRunsNothing(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		_ = e.h.Server.WithWriteLock(context.Background(), func(context.Context) { close(started); <-done })
	}()
	<-started
	e.refused(t, api.CmdContainerPull, e.std(t, 5), 409, "busy")
	close(done)
	if len(e.podman()) != 0 {
		t.Fatalf("podman ran: %v", e.podman())
	}
}

func TestContract_Pull_ExpiryOfTheIndexOnlyWarns(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	idx["generated_at"] = "2026-10-01T00:00:00Z"
	idx["expires_at"] = "2026-10-10T00:00:00Z" // before the machine's clock
	r := e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx, man))
	var warned bool
	s := e.h.Client.Events(context.Background(), r.RunID, 0)
	defer s.Close()
	for {
		ev, err := s.Next()
		if err != nil {
			break
		}
		if strings.Contains(ev.Line, "past its expiry") {
			warned = true
		}
	}
	if !warned {
		t.Error("no warning in the run's log")
	}
}

// --- hostile podman output and failures in the middle ---------------------------------------------

func TestContract_Pull_PodmanOutputIsNotBelieved(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	good := `[{"Id":"` + id + `","Digest":"` + digA + `","RepoDigests":[]}]`
	for name, c := range map[string]struct {
		prep func(e *pullEnv)
	}{
		"a wrong digest": {func(e *pullEnv) { e.m.ImageLie(digB) }},
		"trailing data":  {func(e *pullEnv) { e.m.ImageRaw(good + " x") }},
		"two documents":  {func(e *pullEnv) { e.m.ImageRaw(good + good) }},
		"oversize":       {func(e *pullEnv) { e.m.ImageRaw(good + strings.Repeat(" ", 1<<20+10)) }},
		"not json":       {func(e *pullEnv) { e.m.ImageRaw("Error: something odd") }},
		"an empty array": {func(e *pullEnv) { e.m.ImageRaw("[]") }},
		"no id":          {func(e *pullEnv) { e.m.ImageRaw(`[{"Digest":"` + digA + `"}]`) }},
		"another platform": {func(e *pullEnv) {
			e.m.ImageRaw(`[{"Id":"` + id + `","Digest":"` + digA + `","Architecture":"arm64","Os":"linux"}]`)
		}},
		"deep nesting":      {func(e *pullEnv) { e.m.ImageRaw(strings.Repeat("[", 50000)) }},
		"digest of the tag": {func(e *pullEnv) { e.m.ImageRaw(`[{"Id":"` + id + `","Digest":"latest"}]`) }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			c.prep(e)
			r := e.final(t, api.CmdContainerPull, e.std(t, 5), api.StatusFailed, api.CodeEffectNotVerified)
			_ = r
			for _, call := range e.podman() {
				if call[0] == "tag" {
					t.Fatalf("tagged an image podman did not show: %v", e.podman())
				}
			}
			if _, err := os.Stat(e.pulledFile("core")); err == nil {
				t.Error("a version was recorded")
			}
			if e.m.ImageTag("localhost/vedette-core:1.4.0") != "" {
				t.Error("a tag exists")
			}
			if st := e.state(t)["core"]; st.LatestPulled != nil {
				t.Errorf("latest_pulled %+v", st.LatestPulled)
			}
		})
	}
}

func TestContract_Pull_AFailedPullLeavesNoTagAndKeepsTheRecordOfTheEarlierPull(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, "1.3.0")
	e.pull(t, e.argsFor(t, api.ServiceCore, "1.3.0", idx, man))
	recBefore, err := os.ReadFile(e.pulledFile("core"))
	if err != nil {
		t.Fatal(err)
	}
	e.m.Mark("pull-fails", true)
	idx2, man2 := e.docs(6, pullVersion)
	// the digests are the same, so make the new image another one: it is not here to be found
	man2["images"] = []any{e.rel.ImageDoc(pullVersion, opstest.Img{Service: "core", Digest: opstest.Digest('c'), Size: coreSize})}
	e.final(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx2, man2), api.StatusFailed, api.CodePullFailed)
	if e.m.ImageTag("localhost/vedette-core:1.4.0") != "" {
		t.Error("a tag was made for a failed pull")
	}
	if recAfter, _ := os.ReadFile(e.pulledFile("core")); !bytes.Equal(recAfter, recBefore) {
		t.Error("the record of the earlier pull changed")
	}
	for _, c := range e.podman() {
		if c[0] == "rmi" || c[0] == "tag" && strings.HasSuffix(c[2], ":1.4.0") {
			t.Errorf("unexpected call %v", c)
		}
	}
	if v := e.state(t)["core"].LatestPulled; v == nil || *v.Version != "1.3.0" {
		t.Errorf("latest_pulled %+v", v)
	}
}

func TestContract_Pull_AFailedTagLeavesNoRecordAndNeverRemovesTheImage(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.m.Mark("tag-fails", true)
	e.final(t, api.CmdContainerPull, e.std(t, 5), api.StatusFailed, api.CodePullFailed)
	if _, err := os.Stat(e.pulledFile("core")); err == nil {
		t.Error("a version was recorded")
	}
	for _, c := range e.podman() {
		if c[0] == "rmi" {
			t.Errorf("rmi was called: %v", c)
		}
	}
	// What is left is the verified image: a retry finds it, does not pull, and finishes the job.
	e.m.Mark("tag-fails", false)
	n := e.pulls()
	e.pull(t, e.std(t, 5))
	if e.pulls() != n || e.m.ImageTag("localhost/vedette-core:1.4.0") != digA {
		t.Errorf("pulls %d -> %d, tag %q", n, e.pulls(), e.m.ImageTag("localhost/vedette-core:1.4.0"))
	}
}

// --- the core cannot make the host pull any reference ---------------------------------------------

func TestContract_Pull_NoFieldOfTheRequestNamesWhatIsPulled(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	a := e.std(t, 5)
	base := map[string]any{
		"service": a.Service, "version": a.Version, "source": a.Source, "index": a.Index, "index_sig": a.IndexSig, "manifest": a.Manifest, "manifest_sig": a.ManifestSig,
	}
	// Fields that would name a reference, a digest, a registry, a path or an argv do not exist.
	for _, extra := range []string{"image", "ref", "digest", "registry", "argv", "path", "tag", "repo", "url", "platform", "size", "args"} {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m[extra] = "ghcr.io/evil/x@" + digB
		e.refused(t, api.CmdContainerPull, m, 400, api.CodeInvalidArgs)
	}
	// The fields that exist are checked text: a reference or an option in version or service is refused.
	for name, mutate := range map[string]func(map[string]any){
		"version is a ref":     func(m map[string]any) { m["version"] = "1.4.0@" + digB },
		"version with option":  func(m map[string]any) { m["version"] = "1.4.0 --tls-verify=false" },
		"version is a path":    func(m map[string]any) { m["version"] = "../1.4.0" },
		"service is a ref":     func(m map[string]any) { m["service"] = "ghcr.io/evil/x" },
		"service with newline": func(m map[string]any) { m["service"] = "core\n" },
		"source is a url":      func(m map[string]any) { m["source"] = "docker://evil.example/x" },
		"bundle id in pull":    func(m map[string]any) { m["bundle_id"] = strings.Repeat("a", 32) },
	} {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mutate(m)
		_, err := e.call(t, api.CmdContainerPull, m)
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.podman()) != 0 {
		t.Fatalf("podman ran: %v", e.podman())
	}
	// And a manifest cannot either: a signed manifest names only a digest, the registry is a constant.
	idx, man := e.docs(5, pullVersion)
	man["images"].([]any)[0].(opstest.Doc)["digest"] = "ghcr.io/evil/x@" + digB
	e.refuse(t, "digest that is a ref", e.argsFor(t, api.ServiceCore, pullVersion, idx, man), api.CodeSignatureInvalid)
	// Every call of the happy path names the constant registry and the manifest's digest, nothing else.
	e2 := startPull(t)
	e2.pull(t, e2.std(t, 5))
	for _, c := range e2.podman() {
		for _, arg := range c[1:] {
			if strings.Contains(arg, "/") && !strings.HasPrefix(arg, "ghcr.io/knt048/vedette-core@"+digA) && arg != "localhost/vedette-core:1.4.0" {
				t.Errorf("a call names %q: %v", arg, c)
			}
		}
	}
}

func TestContract_Pull_BodyOfOneMiBIsAcceptedAndMoreIsNot(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), n)) }
	args := func(docSize int) api.ContainerPullArgs {
		return api.ContainerPullArgs{
			Service: "core", Version: pullVersion, Source: api.PullSourceRegistry,
			Index: b64(docSize), IndexSig: b64(100), Manifest: b64(docSize), ManifestSig: b64(100),
		}
	}
	// Two documents of 256 KiB are about 700 KiB of JSON: over the 512 KiB of other commands, under 1 MiB,
	// so the request is read, decoded and then refused for what the documents are (not signed).
	e.refused(t, api.CmdContainerPull, args(maxDoc), 412, api.CodeSignatureInvalid)
	// A document one byte over 256 KiB is refused as an argument.
	e.refused(t, api.CmdContainerPull, args(maxDoc+1), 400, api.CodeInvalidArgs)
	// A body over 1 MiB is refused before it is read.
	huge := args(10)
	huge.Index = strings.Repeat("A", 1<<20+10)
	e.refused(t, api.CmdContainerPull, huge, 400, api.CodeInvalidArgs)
	if len(e.podman()) != 0 {
		t.Fatal("podman ran")
	}
}

const maxDoc = 256 << 10

// --- the stored index is not trusted blindly -------------------------------------------------------

func TestContract_Pull_ADamagedStoredIndexRefusesEverythingInsteadOfStartingOver(t *testing.T) {
	t.Parallel()
	for name, damage := range map[string]func(e *pullEnv){
		"truncated": func(e *pullEnv) {
			raw, _ := os.ReadFile(e.indexFile())
			_ = os.WriteFile(e.indexFile(), raw[:len(raw)/2], 0o600) //nolint:gosec // test: damage the stored index
		},
		"emptied": func(e *pullEnv) { _ = os.WriteFile(e.indexFile(), nil, 0o600) },
		"unknown key": func(e *pullEnv) {
			_ = os.WriteFile(e.indexFile(), []byte(`{"index":"","sig":"","carried":[],"x":1}`), 0o600)
		},
		"bit flip in the raw index": func(e *pullEnv) {
			raw, _ := os.ReadFile(e.indexFile())
			var st map[string]any
			_ = json.Unmarshal(raw, &st)
			ix, _ := base64.StdEncoding.DecodeString(st["index"].(string))
			st["index"] = base64.StdEncoding.EncodeToString(flip(ix, 30))
			out, _ := json.Marshal(st)
			_ = os.WriteFile(e.indexFile(), out, 0o600)
		},
		"a link": func(e *pullEnv) {
			raw, _ := os.ReadFile(e.indexFile())
			other := filepath.Join(e.m.State, "elsewhere.json")
			_ = os.WriteFile(other, raw, 0o600) //nolint:gosec // test: a file the link will point to
			_ = os.Remove(e.indexFile())
			_ = os.Symlink(other, e.indexFile())
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startPull(t)
			e.pull(t, e.std(t, 5))
			damage(e)
			n := len(e.podman())
			e.refused(t, api.CmdContainerPull, e.std(t, 9), 412, api.CodeReleaseStateInvalid)
			if len(e.podman()) != n {
				t.Fatal("podman ran with a stored index the host could not believe")
			}
		})
	}
}

func TestContract_Pull_AStoredIndexSignedByAKeyThisBuildDoesNotTrustIsNotBelieved(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.pull(t, e.std(t, 5))
	// The same state under a host whose keys are others: it must not read the stored index as "none"
	// (that would forget the replay and revocation memory), it refuses until an operator decides.
	other := opstest.NewRelease(t)
	e.keys.Store(&other.Trust)
	idx, man := other.IndexDoc(9), other.ManifestDoc(pullVersion, opstest.Img{Service: "core", Digest: digA, Size: coreSize})
	n := len(e.podman())
	e.refused(t, api.CmdContainerPull, other.Args("core", pullVersion, opstest.JSON(t, idx), opstest.JSON(t, man)), 412, api.CodeReleaseStateInvalid)
	if len(e.podman()) != n {
		t.Fatal("podman ran")
	}
	// The operator's remedy named in the message: remove the file, and the host starts from nothing.
	if err := os.Remove(e.indexFile()); err != nil {
		t.Fatal(err)
	}
	e.pull(t, other.Args("core", pullVersion, opstest.JSON(t, idx), opstest.JSON(t, man)))
}

func TestContract_Pull_StateOfARecordThatIsNotValidReadsAsNotPulled(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.pull(t, e.std(t, 5))
	for name, text := range map[string]string{
		"empty": "", "not json": "x", "unknown field": `{"service":"core","version":"1.4.0","extra":1}`,
		"other service": strings.Replace(mustRead(t, e.pulledFile("core")), `"service":"core"`, `"service":"sensor"`, 1),
		"bad digest":    strings.Replace(mustRead(t, e.pulledFile("core")), digA, "sha256:zz", 1),
		"bad version":   strings.Replace(mustRead(t, e.pulledFile("core")), `"version":"1.4.0"`, `"version":"latest"`, 1),
	} {
		if err := os.WriteFile(e.pulledFile("core"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if st := e.state(t)["core"]; st.LatestPulled != nil {
			t.Errorf("%s: latest_pulled %+v", name, st.LatestPulled)
		}
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test: a path under the fake state dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- fail closed without real keys ----------------------------------------------------------------

func TestContract_Pull_AHostWithoutKeysRefusesEveryPullAndStoresNothing(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) {
		d.Keys = func() (release.Trust, error) { return release.Trust{}, release.ErrNoTrustKeys }
	})
	e.m.StatefulImages()
	rel := opstest.NewRelease(t) // perfectly signed, but the host has no key to know it by
	idx := rel.IndexDoc(5)
	man := rel.ManifestDoc(pullVersion, opstest.Img{Service: "core", Digest: digA, Size: coreSize})
	e.refused(t, api.CmdContainerPull, rel.Args("core", pullVersion, opstest.JSON(t, idx), opstest.JSON(t, man)), 412, api.CodeNoTrustedKeys)
	if len(e.m.Calls("podman")) != 0 {
		t.Fatal("podman ran")
	}
	if _, err := os.Stat(filepath.Join(e.m.State, "releases", "index.json")); err == nil {
		t.Error("an index was stored")
	}
}

// The keys of this very build (production seam: Deps.Keys unset). A production build embeds the real
// release keys (D-256), so the committed vectors, signed by the throwaway test keys, are refused as not
// signed by a trusted key; a build with the releasetestkeys tag (CI runs the tests both ways) embeds the
// throwaway keys of internal/release/testdata and then accepts them, which is the end-to-end check of the
// format; a build with no usable keys refuses everything.
func TestContract_Pull_TheEmbeddedKeysOfThisBuild(t *testing.T) {
	t.Parallel()
	tr, kerr := release.Embedded()
	e := startSys(t) // no Deps.Keys
	e.m.StatefulImages()
	rd := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "release", "testdata", "release", name)) //nolint:gosec // test: fixed vector names
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	idx, man := rd("index.json"), rd("release-manifest.json")
	args := (&opstest.Release{}).ArgsSig("core", "1.4.0", idx, rd("index.json.minisig"), man, rd("release-manifest.json.minisig"))
	if kerr != nil {
		e.refused(t, api.CmdContainerPull, args, 412, api.CodeNoTrustedKeys)
		if len(e.m.Calls("podman")) != 0 {
			t.Fatal("a build without keys ran podman")
		}
		return
	}
	if !tr.TestOnly {
		e.refused(t, api.CmdContainerPull, args, 412, api.CodeSignatureInvalid)
		if len(e.m.Calls("podman")) != 0 {
			t.Fatal("test-key vectors made a production build run podman")
		}
		return
	}
	r := e.final(t, api.CmdContainerPull, args, api.StatusSucceeded, "")
	res := result[api.ContainerPullResult](t, r)
	const vectorCore = "sha256:449b697acb4a314e61ae461e8c35e3422924f1d126a22e70eed0ab0b1e0ccb0a"
	if res.Digest != vectorCore {
		t.Fatalf("%+v", res)
	}
	if got := e.m.Calls("podman"); !slices.ContainsFunc(got, func(c []string) bool {
		return slices.Equal(c, []string{"pull", "-q", "ghcr.io/knt048/vedette-core@" + vectorCore})
	}) {
		t.Fatalf("podman calls %v", got)
	}
	// A bit flipped in a vector is refused, with the committed signatures.
	bad := args
	bad.Manifest = base64.StdEncoding.EncodeToString(flip(man, 20))
	e.refused(t, api.CmdContainerPull, bad, 412, api.CodeSignatureInvalid)
}

func TestContract_Pull_TheIndexDirectoryIsPrivateAndTheCommandIsInTheTable(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	st, err := os.Stat(filepath.Join(e.m.State, "releases"))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", st, err)
	}
	info, err := e.h.Client.Info(context.Background())
	if err != nil || !slices.Contains(info.Commands, api.CmdContainerPull) {
		t.Fatalf("%v %v", info.Commands, err)
	}
	// sha256 of the manifest is what the index names for the latest release: a matching hash passes.
	idx, man := e.docs(5, pullVersion)
	sum := sha256.Sum256(opstest.JSON(t, man))
	idx["channels"].(opstest.Doc)["stable"].(opstest.Doc)["latest"] = pullVersion
	idx["channels"].(opstest.Doc)["stable"].(opstest.Doc)["manifest_sha256"] = hex.EncodeToString(sum[:])
	e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx, man))
}

// --- review fixes of slice 3-7 (D-130 amendments) -----------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startAudit starts the host side that audits what the host does on its own (production: Ops.Start with the server).
func (e *pullEnv) startAudit(t *testing.T) {
	t.Helper()
	e.o.Start(context.Background(), e.h.Server)
	t.Cleanup(e.o.Close)
}

func (e *pullEnv) notes(t *testing.T, code string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range audit(t, e.h) {
		if r.Code != nil && *r.Code == code && r.Actor == "system" {
			var m map[string]any
			if err := json.Unmarshal(r.ArgsRedacted, &m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m)
		}
	}
	return out
}

func logTo(buf *syncBuf) mut {
	return func(c *ops.Config, _ *ops.Deps) { c.Logger = slog.New(slog.NewTextHandler(buf, nil)) }
}

// M2: a refused pull can change what the host knows (the stored index); it leaves a warning and an audit line.
func TestContract_Pull_AStoredNewerIndexLeavesALogAndAnAuditLineEvenWhenTheManifestIsRefused(t *testing.T) {
	t.Parallel()
	var buf syncBuf
	e := startPull(t, logTo(&buf))
	e.startAudit(t)
	e.pull(t, e.std(t, 5))
	idx6, man := e.docs(6, pullVersion)
	idx6["revoked"] = []any{opstest.Revocation("release", pullVersion)}
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, idx6, man), 412, api.CodeReleaseRevoked)
	// A recovery index signed by the backup key, lower sequence, revoking the active key: stored, audited.
	idx3, _ := e.docs(3, pullVersion)
	idx3["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())}
	raw := opstest.JSON(t, idx3)
	manRaw := opstest.JSON(t, man)
	e.pull(t, e.rel.ArgsSig("core", pullVersion, raw, e.rel.SignBackup(raw), manRaw, e.rel.SignBackup(manRaw))) // its own list is authoritative

	notes := e.notes(t, "release_index_stored")
	if len(notes) != 3 {
		t.Fatalf("%d audit lines: %v", len(notes), notes)
	}
	first, second, third := notes[0], notes[1], notes[2]
	if first["old_sequence"] != float64(0) || first["new_sequence"] != float64(5) || first["signer"] != e.rel.ActiveKeyID() || first["backup_signed"] != false {
		t.Errorf("first: %v", first)
	}
	if second["old_sequence"] != float64(5) || second["new_sequence"] != float64(6) || second["backup_signed"] != false ||
		!slices.Equal(anyStrings(second["revoked_added"]), []string{"release:" + pullVersion}) {
		t.Errorf("second: %v", second)
	}
	if third["old_sequence"] != float64(6) || third["new_sequence"] != float64(3) || third["signer"] != e.rel.BackupKeyID() || third["backup_signed"] != true ||
		!slices.Contains(anyStrings(third["revoked_added"]), "key:"+e.rel.ActiveKeyID()) {
		t.Errorf("third: %v", third)
	}
	if log := buf.String(); strings.Count(log, "release index stored") != 3 || !strings.Contains(log, "level=WARN") {
		t.Errorf("log:\n%s", log)
	}
	// The same index again (same bytes, same signer) stores nothing and is not audited again.
	e.pull(t, e.rel.ArgsSig("core", pullVersion, raw, e.rel.SignBackup(raw), manRaw, e.rel.SignBackup(manRaw)))
	if n := e.notes(t, "release_index_stored"); len(n) != 3 {
		t.Errorf("%d audit lines after an index that changed nothing", len(n))
	}
}

func anyStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

// L1: a retired minisign key only re-verifies the stored index; it never accepts a new one.
func TestContract_Pull_AStoredIndexSignedByARetiredKeyStillLoadsAndHoldsItsFloorAndRevocations(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, "1.4.1")
	idx["revoked"] = []any{opstest.Revocation("release", "1.4.1")}
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, "1.4.1", idx, man), 412, api.CodeReleaseRevoked) // stored, signed by the old active key
	// The build rotates: a new active key, the old one retired.
	next := opstest.NewRelease(t)
	tr := e.rel.Trust
	tr.Active, tr.Retired = next.Trust.Active, []release.MinisignKey{e.rel.Trust.Active}
	e.keys.Store(&tr)
	sign := func(idx, man opstest.Doc, version string) api.ContainerPullArgs {
		return next.Args("core", version, opstest.JSON(t, idx), opstest.JSON(t, man))
	}
	// The floor holds (5): a lower index by the new key is a replay, a higher one is fine.
	i4, m := e.docs(4, pullVersion)
	e.refused(t, api.CmdContainerPull, sign(i4, m, pullVersion), 412, api.CodeSequenceRegress)
	// The revocation holds: 1.4.1 is still revoked under an index of the new key that forgot it.
	i6, m61 := e.docs(6, "1.4.1")
	e.refused(t, api.CmdContainerPull, sign(i6, m61, "1.4.1"), 412, api.CodeReleaseRevoked)
	i7, m7 := e.docs(7, pullVersion)
	e.pull(t, sign(i7, m7, pullVersion))
	// The retired key accepts nothing new: not an index, not a manifest.
	i8, m8 := e.docs(8, pullVersion)
	e.refused(t, api.CmdContainerPull, e.argsFor(t, api.ServiceCore, pullVersion, i8, m8), 412, api.CodeSignatureInvalid)
	i9, m9 := e.docs(9, pullVersion)
	raw, mraw := opstest.JSON(t, i9), opstest.JSON(t, m9)
	e.refused(t, api.CmdContainerPull, e.rel.ArgsSig("core", pullVersion, raw, next.Sign(raw), mraw, e.rel.Sign(mraw)), 412, api.CodeSignatureInvalid)
}

// L2: a build-time floor when nothing is stored, and an expired index is visible.
func TestContract_Pull_TheBuildsMinimumSequenceIsTheFloorWhenNothingIsStored(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	tr := e.rel.Trust
	tr.MinSequence = 10
	e.keys.Store(&tr)
	e.refuse(t, "below the floor", e.std(t, 9), api.CodeSequenceRegress)
	e.noIndexStored(t)
	e.pull(t, e.std(t, 10))
	// Once something is stored the stored sequence is the floor (10 here, not the build's).
	e.refused(t, api.CmdContainerPull, e.std(t, 9), 412, api.CodeSequenceRegress)
}

func TestContract_Pull_AnExpiredIndexIsInTheResultAndInTheAudit(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.startAudit(t)
	res := result[api.ContainerPullResult](t, e.pull(t, e.std(t, 5)))
	if res.IndexExpired {
		t.Error("a fresh index was reported expired")
	}
	idx, man := e.docs(6, pullVersion)
	idx["generated_at"], idx["expires_at"] = "2026-10-01T00:00:00Z", "2026-10-10T00:00:00Z"
	res = result[api.ContainerPullResult](t, e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx, man)))
	if !res.IndexExpired {
		t.Fatalf("%+v", res)
	}
	if n := e.notes(t, "index_expired"); len(n) != 1 || n[0]["sequence"] != float64(6) {
		t.Fatalf("audit %v", n)
	}
}

// L3: the manifest hash is compared with every channel whose latest is this version.
func TestContract_Pull_TheManifestHashIsCheckedAgainstEveryChannelThatNamesTheVersion(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	idx, man := e.docs(5, pullVersion)
	sum := sha256.Sum256(opstest.JSON(t, man))
	stable := idx["channels"].(opstest.Doc)["stable"].(opstest.Doc)
	stable["latest"], stable["manifest_sha256"] = pullVersion, hex.EncodeToString(sum[:])
	beta := opstest.Doc{}
	for k, v := range stable {
		beta[k] = v
	}
	beta["manifest_sha256"] = strings.Repeat("0", 64)
	idx["channels"].(opstest.Doc)["beta"] = beta
	e.refuse(t, "beta names another hash", e.argsFor(t, api.ServiceCore, pullVersion, idx, man), api.CodeManifestMismatch)
	beta["manifest_sha256"] = stable["manifest_sha256"]
	beta["manifest_sha256"] = stable["manifest_sha256"]
	idx["sequence"] = 6 // the refused index was stored; the corrected one is a newer one
	e.pull(t, e.argsFor(t, api.ServiceCore, pullVersion, idx, man))
}

// L4: only a path that is not there sends the disk check to its parent; a present image needs no space.
func TestContract_Pull_OnlyAMissingPathSendsTheDiskCheckToItsParent(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var probed []string
	e := startPull(t, func(_ *ops.Config, d *ops.Deps) {
		d.FreeBytes = func(p string) (uint64, error) {
			mu.Lock()
			defer mu.Unlock()
			probed = append(probed, p)
			return 0, fmt.Errorf("statfs %s: %w", p, syscall.EACCES)
		}
	})
	e.refused(t, api.CmdContainerPull, e.std(t, 5), 412, api.CodeLowDisk)
	mu.Lock()
	defer mu.Unlock()
	if len(probed) != 1 {
		t.Fatalf("a permission error walked up: %v", probed)
	}
}

func TestContract_Pull_AnImageThatIsAlreadyHereNeedsNoFreeSpace(t *testing.T) {
	t.Parallel()
	e := startPull(t, func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 0, nil } })
	e.m.SetImagePresent(digA)
	e.pull(t, e.std(t, 5))
	if e.pulls() != 0 || e.m.ImageTag("localhost/vedette-core:1.4.0") != digA {
		t.Fatalf("%v", e.podman())
	}
}

// L5: podman may show the pull reference in RepoDigests with another Digest (an image index); that is enough.
func TestContract_Pull_ARepoDigestsOnlyAnswerIsEnough(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.m.ImageRepoOnly()
	e.pull(t, e.std(t, 5))
	if e.m.ImageTag("localhost/vedette-core:1.4.0") != digA {
		t.Fatal("not tagged")
	}
}

// L5: the recovery index: signed by the backup key, revokes the signer of the stored index, a lower sequence.
func TestContract_Pull_ABackupSignedRecoveryIndexWithALowerSequenceIsStoredAndReloaded(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	e.pull(t, e.std(t, 9))
	recovery := func(seq uint64) api.ContainerPullArgs {
		idx, man := e.docs(seq, pullVersion)
		idx["revoked"] = []any{opstest.Revocation("key", e.rel.ActiveKeyID())}
		raw, mraw := opstest.JSON(t, idx), opstest.JSON(t, man)
		return e.rel.ArgsSig("core", pullVersion, raw, e.rel.SignBackup(raw), mraw, e.rel.SignBackup(mraw))
	}
	e.pull(t, recovery(3))
	if e.storedSequence(t) != 3 {
		t.Fatalf("stored %d", e.storedSequence(t))
	}
	// Reloaded from disk by the next call: its sequence is the floor, its revocation of the old key holds.
	e.refused(t, api.CmdContainerPull, recovery(2), 412, api.CodeSequenceRegress)
	e.pull(t, recovery(4))
	e.refused(t, api.CmdContainerPull, e.std(t, 10), 412, api.CodeKeyRevoked) // the leaked active key signs nothing again
	if e.storedSequence(t) != 4 {
		t.Fatalf("stored %d", e.storedSequence(t))
	}
}

// Nits: temp files of a cut-short write in releases/ are cleaned at Start; the carried-revocation cap has its own message.
func TestContract_Pull_StartCleansTheTempFilesOfACutShortWrite(t *testing.T) {
	t.Parallel()
	e := startPull(t)
	junk := []string{filepath.Join(e.m.State, "releases", ".tmp-123"), filepath.Join(e.m.State, "containers", ".tmp-456")}
	keep := filepath.Join(e.m.State, "releases", "not-a-temp")
	for _, p := range append(junk, keep) {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.startAudit(t)
	for _, p := range junk {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was left", p)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("a file that is not a temp file was removed")
	}
}

func TestContract_Pull_TooManyCarriedRevocationsSaysSo(t *testing.T) {
	t.Parallel()
	var buf syncBuf
	e := startPull(t, logTo(&buf))
	rev := `{"kind":"release","id":"1.0.0","reason":"x","since":"2026-01-01T00:00:00Z","action":"block_install"}`
	body := `{"index":"aGk=","sig":"aGk=","carried":[` + strings.TrimSuffix(strings.Repeat(rev+",", 4097), ",") + `]}`
	if err := os.WriteFile(e.indexFile(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e.refused(t, api.CmdContainerPull, e.std(t, 5), 412, api.CodeReleaseStateInvalid)
	if !strings.Contains(buf.String(), "more than 4096 revocations") {
		t.Errorf("log: %s", buf.String())
	}
}
