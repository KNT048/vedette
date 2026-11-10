package ops

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestRmiArgvIsADigestAndNothingElse(t *testing.T) {
	t.Parallel()
	id1 := strings.TrimPrefix(dg1, "sha256:")
	got, err := rmiArgv(id1)
	if err != nil || !slices.Equal(got, []string{"rmi", id1}) {
		t.Fatalf("%q %v", got, err)
	}
	if validatePodman(got) != nil {
		t.Fatal("the validator refuses what the builder makes")
	}
	for _, bad := range []string{"", "abc", dg1, "ghcr.io/knt048/vedette-core@" + dg1, "localhost/vedette-core:1.0.0", "-f", "--all", id1 + "\n", id1 + " ", " " + id1,
		strings.Repeat("A", 64), strings.Repeat("g", 64), "latest", id1 + "0", id1[1:]} {
		if a, err := rmiArgv(bad); err == nil {
			t.Errorf("rmiArgv(%q) = %q", bad, a)
		}
	}
}

// FuzzRmiArgv: whatever text is given, the argv is either refused or exactly ["rmi", <a digest>].
func FuzzRmiArgv(f *testing.F) {
	id1 := strings.TrimPrefix(dg1, "sha256:")
	f.Add(id1, "", "")
	f.Add("-f", id1, "")
	f.Add(id1, "-f", "x")
	f.Add(dg1, "", "")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		if got, err := rmiArgv(a); err == nil {
			if len(got) != 2 || got[0] != "rmi" || got[1] != a || !imageIDRE.MatchString(a) || validatePodman(got) != nil {
				t.Fatalf("rmiArgv(%q) = %q", a, got)
			}
		}
		// And the validator, on the shapes that have two and four pieces.
		for _, args := range [][]string{{a, b}, {a, b, c}, {a, b, c, "json"}, {a, b, "--format", c}} {
			if validatePodman(args) != nil {
				continue
			}
			okRmi := len(args) == 2 && args[0] == "rmi" && imageIDRE.MatchString(args[1])
			okLs := slices.Equal(args, []string{"image", "ls", "--format", "json"})
			okOld := len(args) == 3 || len(args) == 5
			if !okRmi && !okLs && !okOld {
				t.Fatalf("accepted %q", args)
			}
			if len(args) == 2 && !okRmi {
				t.Fatalf("accepted %q", args)
			}
		}
	})
}

func listJSON(entries ...string) []byte { return []byte("[" + strings.Join(entries, ",") + "]") }

func listEntry(digest string, names []string, repoDigests []string, containers int) string {
	q := func(l []string) string {
		var o []string
		for _, s := range l {
			o = append(o, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(o, ",") + "]"
	}
	return fmt.Sprintf(`{"Id":%q,"Digest":%q,"Names":%s,"RepoDigests":%s,"Containers":%d}`, strings.TrimPrefix(digest, "sha256:"), digest, q(names), q(repoDigests), containers)
}

func TestParseImageListKeepsOnlyImagesThatAreOnlyThisServices(t *testing.T) {
	t.Parallel()
	core := "ghcr.io/knt048/vedette-core"
	mine := listEntry(dg1, []string{"localhost/vedette-core:1.0.0"}, []string{core + "@" + dg1}, 0)
	leftover := listEntry(dg2, nil, []string{core + "@" + dg2}, 0) // the leftover of a failed pull: a digest name only
	foreign := listEntry("sha256:"+strings.Repeat("3", 64), []string{"docker.io/library/alpine:3"}, nil, 0)
	mixed := listEntry("sha256:"+strings.Repeat("4", 64), []string{"localhost/vedette-core:1.0.0", "docker.io/library/alpine:3"}, nil, 0)
	other := listEntry("sha256:"+strings.Repeat("5", 64), []string{"localhost/vedette-sensor:1.0.0"}, nil, 0)
	nameless := listEntry("sha256:"+strings.Repeat("6", 64), nil, nil, 0)
	badDigest := listEntry("latest", []string{"localhost/vedette-core:1.0.0"}, nil, 0)
	prefix := listEntry("sha256:"+strings.Repeat("7", 64), []string{"localhost/vedette-core-evil:1.0.0"}, nil, 0)
	registryOther := listEntry("sha256:"+strings.Repeat("8", 64), []string{"ghcr.io/evil/vedette-core:1.0.0"}, nil, 0)
	got, err := ParseImageList(listJSON(mine, leftover, foreign, mixed, other, nameless, badDigest, prefix, registryOther), api.ServiceCore)
	if err != nil || !slices.Equal(got, []string{strings.TrimPrefix(dg1, "sha256:"), strings.TrimPrefix(dg2, "sha256:")}) { // the IDs rmi is given
		t.Fatalf("%q %v", got, err)
	}
	// An entry whose Id is not 64 hex digits is left alone.
	if got, err := ParseImageList(listJSON(`{"Id":"abc","Digest":"`+dg1+`","Names":["localhost/vedette-core:1.0.0"]}`), api.ServiceCore); err != nil || len(got) != 0 {
		t.Fatalf("%q %v", got, err)
	}
	imgs, _ := parseImageList(listJSON(listEntry(dg1, []string{"localhost/vedette-core:1.0.0"}, []string{core + "@" + dg2}, 1)), api.ServiceCore)
	if len(imgs) != 1 || !imgs[0].InUse || !slices.Equal(imgs[0].Digests, []string{dg1, dg2}) {
		t.Fatalf("%+v", imgs)
	}
	for name, text := range map[string]string{
		"empty": "", "not json": "x", "object": `{"Digest":"` + dg1 + `"}`, "trailing": string(listJSON(mine)) + " x", "two arrays": string(listJSON(mine)) + string(listJSON(mine)),
		"too large": string(listJSON(mine)) + strings.Repeat(" ", maxInspectOutput), "deep": strings.Repeat("[", 100000),
		"too many": "[" + strings.Repeat(mine+",", maxListedImages) + mine + "]",
	} {
		if got, err := ParseImageList([]byte(text), api.ServiceCore); err == nil {
			t.Errorf("%s accepted: %q", name, got)
		}
	}
	if _, err := ParseImageList(listJSON(mine), "nope"); err == nil {
		t.Error("an unknown service was accepted")
	}
}

func FuzzParseImageList(f *testing.F) {
	f.Add(listJSON(listEntry(dg1, []string{"localhost/vedette-core:1.0.0"}, []string{"ghcr.io/knt048/vedette-core@" + dg1}, 0)), "core")
	f.Add([]byte(`[{"Digest":"`+dg1+`","Names":["x"]}]`), "sensor")
	f.Add([]byte(strings.Repeat("[", 5000)), "scan")
	f.Fuzz(func(t *testing.T, b []byte, svc string) {
		got, err := ParseImageList(b, svc)
		if err != nil {
			return
		}
		for _, d := range got {
			if !imageIDRE.MatchString(d) {
				t.Fatalf("image id %q", d)
			}
		}
		if len(got) > maxListedImages {
			t.Fatal("too many")
		}
	})
}

func TestOwnedNameIsExactlyTheTwoRepositories(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"ghcr.io/knt048/vedette-core":                             true,
		"ghcr.io/knt048/vedette-core:1.0.0":                       true,
		"ghcr.io/knt048/vedette-core@" + dg1:                      true,
		"localhost/vedette-core:1.0.0":                            true,
		"localhost/vedette-core":                                  true,
		"localhost/vedette-core@" + dg1:                           true,
		"ghcr.io/knt048/vedette-core-x:1.0.0":                     false,
		"ghcr.io/knt048/vedette-sensor:1.0.0":                     false,
		"docker.io/ghcr.io/knt048/vedette-core":                   false,
		"ghcr.io/knt048/vedette-core@sha256:short":                false,
		"ghcr.io/knt048/vedette-core:":                            false,
		"ghcr.io:5000/knt048/vedette-core":                        false,
		"":                                                        false,
		"localhost/vedette-core:1.0.0\n":                          true, // a tag character; the digest is what rmi takes, never this text
		"ghcr.io/knt048/vedette-core:" + strings.Repeat("a", 129): false,
	} {
		if got := ownedName(name, api.ServiceCore); got != want {
			t.Errorf("ownedName(%q) = %t, want %t", name, got, want)
		}
	}
}
