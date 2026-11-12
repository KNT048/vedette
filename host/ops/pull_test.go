package ops

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

const (
	dg1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dg2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func TestPodmanGrammarOfThePullCommand(t *testing.T) {
	t.Parallel()
	for _, s := range api.Services {
		ref := "ghcr.io/knt048/vedette-" + s + "@" + dg1
		tag := "localhost/vedette-" + s + ":1.4.0-rc.1"
		for _, a := range [][]string{
			{"pull", "-q", ref},
			{"image", "inspect", "--format", "json", ref},
			{"image", "inspect", "--format", "json", tag},
			{"tag", ref, tag},
			{"rmi", strings.Repeat("1", 64)},
			{"untag", strings.Repeat("1", 64), tag},
			{"image", "ls", "--format", "json"},
		} {
			if err := validatePodman(a); err != nil {
				t.Errorf("%q: %v", a, err)
			}
		}
	}
	good := "ghcr.io/knt048/vedette-core@" + dg1
	tag := "localhost/vedette-core:1.4.0"
	for name, a := range map[string][]string{
		"pull by tag":             {"pull", "-q", "ghcr.io/knt048/vedette-core:1.4.0"},
		"pull without -q":         {"pull", good},
		"pull other registry":     {"pull", "-q", "docker.io/knt048/vedette-core@" + dg1},
		"pull other owner":        {"pull", "-q", "ghcr.io/evil/vedette-core@" + dg1},
		"pull other repo":         {"pull", "-q", "ghcr.io/knt048/vedette-nope@" + dg1},
		"pull prefix trick":       {"pull", "-q", "ghcr.io/knt048/vedette-core@" + dg1 + "x"},
		"pull short digest":       {"pull", "-q", "ghcr.io/knt048/vedette-core@sha256:abc"},
		"pull upper digest":       {"pull", "-q", "ghcr.io/knt048/vedette-core@sha256:" + strings.Repeat("A", 64)},
		"pull newline":            {"pull", "-q", good + "\n"},
		"pull two refs":           {"pull", "-q", good, good},
		"pull option first":       {"pull", "--tls-verify=false", "-q", good},
		"pull with option after":  {"pull", "-q", good, "--creds=a:b"},
		"pull from dir":           {"pull", "-q", "dir:/tmp/x"},
		"pull docker-archive":     {"pull", "-q", "docker-archive:/tmp/x.tar"},
		"pull transport prefix":   {"pull", "-q", "docker://" + good},
		"pull a path":             {"pull", "-q", "../" + good},
		"inspect no format":       {"image", "inspect", good},
		"inspect other format":    {"image", "inspect", "--format", "{{.Id}}", good},
		"inspect other registry":  {"image", "inspect", "--format", "json", "docker.io/library/alpine:latest"},
		"inspect bare":            {"image", "inspect", "--format", "json", "alpine"},
		"inspect tag of registry": {"image", "inspect", "--format", "json", "ghcr.io/knt048/vedette-core:1.4.0"},
		"inspect local bad ver":   {"image", "inspect", "--format", "json", "localhost/vedette-core:latest"},
		"inspect local plus":      {"image", "inspect", "--format", "json", "localhost/vedette-core:1.4.0+x"},
		"inspect local digest":    {"image", "inspect", "--format", "json", "localhost/vedette-core@" + dg1},
		"inspect local nope":      {"image", "inspect", "--format", "json", "localhost/vedette-nope:1.4.0"},
		"inspect two":             {"image", "inspect", "--format", "json", good, tag},
		"inspect all":             {"image", "inspect", "--all"},
		"tag arg order":           {"tag", tag, good},
		"tag to registry":         {"tag", good, "ghcr.io/knt048/vedette-core:1.4.0"},
		"tag to other local":      {"tag", good, "localhost/evil:1.4.0"},
		"tag latest":              {"tag", good, "localhost/vedette-core:latest"},
		"tag extra":               {"tag", good, tag, "x"},
		"tag from tag":            {"tag", "localhost/vedette-core:1.0.0", tag},
		"rmi force":               {"rmi", "-f", good},
		"rmi by name":             {"rmi", good},
		"rmi by tag":              {"rmi", tag},
		"rmi by digest":           {"rmi", dg1},
		"rmi two":                 {"rmi", strings.Repeat("1", 64), strings.Repeat("2", 64)},
		"rmi force id":            {"rmi", "-f", strings.Repeat("1", 64)},
		"rmi all":                 {"rmi", "-a"},
		"rmi no digest":           {"rmi"},
		"rmi short id":            {"rmi", "abc"},
		"rmi newline":             {"rmi", strings.Repeat("1", 64) + "\n"},
		"image ls other format":   {"image", "ls", "--format", "{{.ID}}"},
		"image ls all":            {"image", "ls", "-a", "--format", "json"},
		"image ls filter":         {"image", "ls", "--format", "json", "--filter", "dangling=true"},
		"image ls bare":           {"image", "ls"},
		"system prune":            {"system", "prune", "-a"},
		"image prune":             {"image", "prune", "-a"},
		"images":                  {"images"},
		"run":                     {"run", "--privileged", good},
		"push":                    {"push", good},
		"load":                    {"load", "-i", "/tmp/x"},
		"build":                   {"build", "-t", tag, "."},
		"global option":           {"--root", "/x", "pull", "-q", good},
	} {
		if err := validatePodman(a); err == nil {
			t.Errorf("%s: %q was accepted", name, a)
		}
	}
}

func TestPodmanBuildersMakeTheFixedShapes(t *testing.T) {
	t.Parallel()
	got, err := pullArgv("sensor", dg1)
	if err != nil || !slices.Equal(got, []string{"pull", "-q", "ghcr.io/knt048/vedette-sensor@" + dg1}) {
		t.Fatalf("%q %v", got, err)
	}
	got, err = tagArgv("sensor", dg1, "1.4.0")
	if err != nil || !slices.Equal(got, []string{"tag", "ghcr.io/knt048/vedette-sensor@" + dg1, "localhost/vedette-sensor:1.4.0"}) {
		t.Fatalf("%q %v", got, err)
	}
	got, err = inspectImageArgv("localhost/vedette-sensor:1.4.0")
	if err != nil || !slices.Equal(got, []string{"image", "inspect", "--format", "json", "localhost/vedette-sensor:1.4.0"}) {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []struct{ svc, dig, ver string }{
		{"nope", dg1, "1.0.0"}, {"core", "sha256:x", "1.0.0"}, {"core", dg1, "latest"}, {"core", dg1, "1.0.0+b"}, {"core", dg1, "-1.0.0"},
		{"", dg1, "1.0.0"}, {"core\n", dg1, "1.0.0"}, {"core", dg1 + "\n", "1.0.0"}, {"core", dg1, "1.0.0\n"}, {"core", dg1, strings.Repeat("1", 70) + ".0.0"},
	} {
		if a, err := tagArgv(bad.svc, bad.dig, bad.ver); err == nil {
			t.Errorf("tagArgv(%q, %q, %q) = %q", bad.svc, bad.dig, bad.ver, a)
		}
	}
	if _, err := inspectImageArgv("--all"); err == nil {
		t.Error("an option was taken as an image reference")
	}
}

// FuzzPullArgvBuilders: whatever the builders are given, they either refuse or make an argv that the
// validator accepts, whose pieces are the constants, the closed list and the digest and version they
// were given, and nothing else.
func FuzzPullArgvBuilders(f *testing.F) {
	f.Add("core", dg1, "1.4.0")
	f.Add("sensor", dg2, "1.0.0-rc.1")
	f.Add("../x", "sha256:"+strings.Repeat("0", 64), "1.0.0\n")
	f.Add("scan", dg1+" --tls-verify=false", "1.0.0 --x")
	f.Add("core", dg1, "1.0.0@"+dg1)
	f.Fuzz(func(t *testing.T, svc, digest, version string) {
		if a, err := pullArgv(svc, digest); err == nil {
			if validatePodman(a) != nil || !knownService(svc) || a[2] != "ghcr.io/knt048/vedette-"+svc+"@"+digest || !digestRE.MatchString(digest) || len(a) != 3 {
				t.Fatalf("pullArgv(%q, %q) = %q", svc, digest, a)
			}
		}
		if a, err := tagArgv(svc, digest, version); err == nil {
			if validatePodman(a) != nil || a[2] != "localhost/vedette-"+svc+":"+version || a[1] != "ghcr.io/knt048/vedette-"+svc+"@"+digest || len(a) != 3 || !tagVersionRE.MatchString(version) {
				t.Fatalf("tagArgv(%q, %q, %q) = %q", svc, digest, version, a)
			}
		}
		if a, err := inspectImageArgv(svc); err == nil {
			if validatePodman(a) != nil || len(a) != 5 || a[4] != svc || (!isPullRef(svc) && !isLocalTag(svc)) {
				t.Fatalf("inspectImageArgv(%q) = %q", svc, a)
			}
		}
	})
}

// FuzzValidatePodmanPull: an argv the validator accepts is one of the four shapes, every piece of it is
// checked text, and nothing with a space, a newline, a NUL or a leading dash passes.
func FuzzValidatePodmanPull(f *testing.F) {
	f.Add("pull", "-q", "ghcr.io/knt048/vedette-core@"+dg1, "")
	f.Add("tag", "ghcr.io/knt048/vedette-core@"+dg1, "localhost/vedette-core:1.4.0", "")
	f.Add("image", "inspect", "--format", "json")
	f.Add("rmi", dg1, "", "")
	f.Add("rmi", "-f", dg1, "")
	f.Add("image", "ls", "--format", "json")
	f.Add("pull", "-q", "ghcr.io/knt048/vedette-core@"+dg1+"\n", "")
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		args := []string{a, b, c}
		if d != "" {
			args = append(args, d, "ghcr.io/knt048/vedette-core@"+dg1)
		}
		if validatePodman(args) != nil {
			return
		}
		for _, s := range args {
			if s == "" || strings.ContainsAny(s, " \t\r\n\x00\\\"'`$;&|<>*?") {
				t.Fatalf("accepted a piece with a risky character: %q", args)
			}
		}
		switch args[0] {
		case "container":
			if len(args) != 3 || args[1] != "inspect" {
				t.Fatalf("accepted %q", args)
			}
		case "pull":
			if len(args) != 3 || args[1] != "-q" || !isPullRef(args[2]) {
				t.Fatalf("accepted %q", args)
			}
		case "image":
			inspect := len(args) == 5 && args[1] == "inspect" && args[2] == "--format" && args[3] == "json"
			ls := len(args) == 4 && args[1] == "ls" && args[2] == "--format" && args[3] == "json"
			if !inspect && !ls {
				t.Fatalf("accepted %q", args)
			}
		case "rmi":
			if len(args) != 2 || !imageIDRE.MatchString(args[1]) {
				t.Fatalf("accepted %q", args)
			}
		case "untag":
			if len(args) != 3 || !imageIDRE.MatchString(args[1]) || !isLocalTag(args[2]) && !isNmapTag(args[2]) {
				t.Fatalf("accepted %q", args)
			}
		case "tag":
			if len(args) != 3 || !isPullRef(args[1]) || !isLocalTag(args[2]) {
				t.Fatalf("accepted %q", args)
			}
		default:
			t.Fatalf("accepted %q", args)
		}
	})
}

func imageJSON(id, digest, repoDigests, extra string) string {
	return fmt.Sprintf(`[{"Id":%q,"Digest":%q,"RepoDigests":[%s]%s}]`, id, digest, repoDigests, extra)
}

func TestParseImageInspect(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	ref := `"ghcr.io/knt048/vedette-core@` + dg1 + `"`
	for name, text := range map[string]string{
		"digest":                imageJSON(id, dg1, "", ""),
		"repo digest only":      imageJSON(id, dg2, ref, ""),
		"with platform":         imageJSON(id, dg1, ref, `,"Architecture":"amd64","Os":"linux"`),
		"extra fields":          imageJSON(id, dg1, ref, `,"Config":{"Env":["A=1"]},"History":[{"created":"x"}],"Size":123`),
		"empty platform fields": imageJSON(id, dg1, ref, `,"Architecture":"","Os":""`),
	} {
		if err := parseImageInspect([]byte(text), "core", dg1, "amd64"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"empty":                          "",
		"garbage":                        "Error: no such image",
		"object":                         `{"Id":"` + id + `","Digest":"` + dg1 + `"}`,
		"empty array":                    `[]`,
		"two images":                     strings.TrimSuffix(imageJSON(id, dg1, "", ""), "]") + "," + strings.TrimPrefix(imageJSON(id, dg1, "", ""), "["),
		"wrong digest":                   imageJSON(id, dg2, `"ghcr.io/knt048/vedette-core@`+dg2+`"`, ""),
		"digest of another":              imageJSON(id, dg2, "", ""),
		"repo digest of another service": imageJSON(id, dg2, `"ghcr.io/knt048/vedette-sensor@`+dg1+`"`, ""),
		"repo digest other registry":     imageJSON(id, dg2, `"docker.io/knt048/vedette-core@`+dg1+`"`, ""),
		"no digest":                      `[{"Id":"` + id + `"}]`,
		"no id":                          `[{"Digest":"` + dg1 + `"}]`,
		"short id":                       imageJSON("abc", dg1, "", ""),
		"sha256 id":                      imageJSON("sha256:"+id, dg1, "", ""),
		"upper digest":                   imageJSON(id, "sha256:"+strings.Repeat("A", 64), "", ""),
		"trailing data":                  imageJSON(id, dg1, "", "") + " x",
		"two documents":                  imageJSON(id, dg1, "", "") + imageJSON(id, dg1, "", ""),
		"wrong os":                       imageJSON(id, dg1, "", `,"Os":"windows"`),
		"wrong arch":                     imageJSON(id, dg1, "", `,"Architecture":"arm64"`),
		"wrong type":                     `[{"Id":5,"Digest":"` + dg1 + `"}]`,
		"repo digests not a list":        `[{"Id":"` + id + `","Digest":"` + dg1 + `","RepoDigests":"x"}]`,
		"too many repo digests":          imageJSON(id, dg1, strings.TrimSuffix(strings.Repeat(`"x",`, maxRepoDigests+1), ","), ""),
		"too large":                      imageJSON(id, dg1, "", "") + strings.Repeat(" ", maxInspectOutput),
		"deep":                           strings.Repeat("[", 100000),
		"null":                           `null`,
	} {
		if err := parseImageInspect([]byte(text), "core", dg1, "amd64"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := parseImageInspect([]byte(imageJSON(id, dg1, "", "")), "nope", dg1, "amd64"); err == nil {
		t.Error("an unknown service was accepted")
	}
	if err := parseImageInspect([]byte(imageJSON(id, "x", "", "")), "core", "x", "amd64"); err == nil {
		t.Error("a bad digest was accepted")
	}
}

func FuzzParseImageInspect(f *testing.F) {
	id := strings.Repeat("a", 64)
	f.Add([]byte(imageJSON(id, dg1, "", "")))
	f.Add([]byte(imageJSON(id, dg2, `"ghcr.io/knt048/vedette-core@`+dg1+`"`, `,"Architecture":"amd64"`)))
	f.Add([]byte(strings.Repeat("[", 5000)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if parseImageInspect(b, "core", dg1, "amd64") != nil {
			return
		}
		// Accepted: it holds the digest, as Digest or as the pull reference, and nothing else was believed.
		if !strings.Contains(string(b), dg1) {
			t.Fatalf("accepted an output without the digest: %q", b)
		}
	})
}

func TestDecodeDocIsStrict(t *testing.T) {
	t.Parallel()
	for in, ok := range map[string]bool{
		"aGk=": true, "aGk": false, "": false, "aGk=\n": false, "aG\nk=": false, "aG k=": false, " aGk=": false,
		"aGk=aGk=": false, "aGl=": false, // non-canonical padding bits
		"====": false, "a": false, "\xff": false,
	} {
		_, err := decodeDoc(in, 16)
		if (err == nil) != ok {
			t.Errorf("%q: ok=%v err=%v", in, ok, err)
		}
	}
	if _, err := decodeDoc(strings.Repeat("QUFB", 100), 16); err == nil {
		t.Error("a document over the limit was accepted")
	}
}

func TestRefusePullMapsEveryTypedErrorToTheCodeOfSection67(t *testing.T) {
	t.Parallel()
	wrapped := func(e error) error { return fmt.Errorf("%w: detail", e) }
	for _, c := range []struct {
		err  error
		code string
	}{
		{release.ErrNoTrustKeys, api.CodeNoTrustedKeys},
		{release.ErrKeyRevoked, api.CodeKeyRevoked},
		{release.ErrReleaseRevoked, api.CodeReleaseRevoked},
		{release.ErrSequenceRegress, api.CodeSequenceRegress},
		{release.ErrRegistryNotAllowed, api.CodeRegistryNotAllowed},
		{release.ErrDigestNotInManifest, api.CodeDigestNotInManifest},
		{release.ErrPlatform, api.CodePlatformMismatch},
		{release.ErrInstallMode, api.CodeNotAppliance},
		{release.ErrManifestHash, api.CodeManifestMismatch},
		{release.ErrBadSignature, api.CodeSignatureInvalid},
		{release.ErrMalformed, api.CodeSignatureInvalid},
		{release.ErrTooLarge, api.CodeSignatureInvalid},
		{release.ErrUnknownSchema, api.CodeSignatureInvalid},
		{release.ErrKeyNotAuthorised, api.CodeSignatureInvalid},
		{errors.New("anything else"), api.CodeSignatureInvalid},
	} {
		for _, e := range []error{c.err, wrapped(c.err)} {
			if got := codeOf(t, refusePull(e, "index")); got != c.code {
				t.Errorf("%v: %s, want %s", e, got, c.code)
			}
		}
	}
	// The wording of the typed error never reaches the answer.
	msg := refusePull(fmt.Errorf("%w: <script>evil</script>", release.ErrBadSignature), "manifest").Error()
	if strings.Contains(msg, "evil") {
		t.Errorf("the error text leaked: %s", msg)
	}
}

func TestValidatePullArgs(t *testing.T) {
	t.Parallel()
	b := "aGk="
	good := api.ContainerPullArgs{Service: "core", Version: "1.4.0", Source: "registry", Index: b, IndexSig: b, Manifest: b, ManifestSig: b}
	if err := validatePullArgs(&good); err != nil {
		t.Fatal(err)
	}
	bundle := api.ContainerPullArgs{Service: "core", Version: "1.4.0", Source: "bundle", BundleID: strings.Repeat("a", 32)}
	if err := validatePullArgs(&bundle); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*api.ContainerPullArgs){
		"service":              func(a *api.ContainerPullArgs) { a.Service = "nope" },
		"no service":           func(a *api.ContainerPullArgs) { a.Service = "" },
		"version latest":       func(a *api.ContainerPullArgs) { a.Version = "latest" },
		"version v":            func(a *api.ContainerPullArgs) { a.Version = "v1.4.0" },
		"version build":        func(a *api.ContainerPullArgs) { a.Version = "1.4.0+x" },
		"version empty":        func(a *api.ContainerPullArgs) { a.Version = "" },
		"version ref":          func(a *api.ContainerPullArgs) { a.Version = "1.4.0@" + dg1 },
		"source empty":         func(a *api.ContainerPullArgs) { a.Source = "" },
		"source other":         func(a *api.ContainerPullArgs) { a.Source = "docker" },
		"bundle id on pull":    func(a *api.ContainerPullArgs) { a.BundleID = strings.Repeat("a", 32) },
		"index empty":          func(a *api.ContainerPullArgs) { a.Index = "" },
		"index not b64":        func(a *api.ContainerPullArgs) { a.Index = "!!" },
		"index sig empty":      func(a *api.ContainerPullArgs) { a.IndexSig = "" },
		"manifest too big":     func(a *api.ContainerPullArgs) { a.Manifest = strings.Repeat("QUFB", 100000) },
		"manifest sig newline": func(a *api.ContainerPullArgs) { a.ManifestSig = "aGk=\n" },
	} {
		a := good
		mutate(&a)
		if err := validatePullArgs(&a); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, mutate := range map[string]func(*api.ContainerPullArgs){
		"bundle without id": func(a *api.ContainerPullArgs) { a.BundleID = "" },
		"bundle bad id":     func(a *api.ContainerPullArgs) { a.BundleID = "xyz" },
	} {
		a := bundle
		mutate(&a)
		if err := validatePullArgs(&a); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var r interface{ Error() string }
	if !errors.As(err, &r) {
		t.Fatalf("not an error: %v", err)
	}
	s := err.Error() // "refused: <code>"
	return strings.TrimPrefix(s, "refused: ")
}
