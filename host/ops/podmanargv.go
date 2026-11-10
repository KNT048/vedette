package ops

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// The argv of podman (spec 6.7, D-104 (1), D-130, D-138). Six shapes and no others:
//
//	container inspect vedette-<service>
//	pull -q ghcr.io/knt048/vedette-<service>@sha256:<64 hex>
//	image inspect --format json <ref>          ref: the pull reference or localhost/vedette-<service>:<version>
//	tag <pull reference> localhost/vedette-<service>:<version>
//	image ls --format json                     what retention reads (slice 3-8a)
//	rmi sha256:<64 hex>                        what retention removes: a digest, never a name, never -f
//
// Every shape is built here from the closed service list, a digest that passed digestRE and a version
// that passed tagVersionRE; the registry part is the compile-time constant release.RegistryPrefix. Nothing
// a request carried reaches argv as text. The validator below accepts exactly what the builders make,
// so a builder that went wrong would be refused by the runner.

var (
	// tagVersionRE is a release version as a Podman tag: digits first, so it cannot look like an option,
	// and no "+" (a tag may not hold one; release versions have no build metadata). A prerelease is at most
	// 32 characters here; a longer one is a valid release version that container.pull refuses as
	// invalid_args (the local tag is a Podman reference, whose length the host bounds itself).
	tagVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]{1,32})?$`)

	errPodmanArgs = errors.New("not one of the fixed podman command lines")
)

const localPrefix = "localhost/vedette-"

func knownService(s string) bool { return slices.Contains(api.Services, s) }

// pullRef is the reference podman pulls: the constant registry, the service, the verified digest.
func pullRef(service, digest string) (string, error) {
	if !knownService(service) || !digestRE.MatchString(digest) {
		return "", errPodmanArgs
	}
	return release.PullRef(service, digest)
}

// localTag is localhost/vedette-<service>:<version>.
func localTag(service, version string) (string, error) {
	if !knownService(service) || len(version) > 64 || !tagVersionRE.MatchString(version) {
		return "", errPodmanArgs
	}
	return localPrefix + service + ":" + version, nil
}

func pullArgv(service, digest string) ([]string, error) {
	ref, err := pullRef(service, digest)
	if err != nil {
		return nil, err
	}
	return []string{"pull", "-q", ref}, nil
}

func inspectImageArgv(ref string) ([]string, error) {
	args := []string{"image", "inspect", "--format", "json", ref}
	if err := validatePodman(args); err != nil {
		return nil, err
	}
	return args, nil
}

func tagArgv(service, digest, version string) ([]string, error) {
	ref, err := pullRef(service, digest)
	if err != nil {
		return nil, err
	}
	tag, err := localTag(service, version)
	if err != nil {
		return nil, err
	}
	return []string{"tag", ref, tag}, nil
}

// rmiArgv removes one image by digest. There is no force flag: an image a container uses is refused by
// Podman itself, which is the last line of the rule that retention never removes what runs.
func rmiArgv(digest string) ([]string, error) {
	if !digestRE.MatchString(digest) {
		return nil, errPodmanArgs
	}
	return []string{"rmi", digest}, nil
}

// listImagesArgv lists every image in Podman's storage as JSON (read only).
func listImagesArgv() []string { return []string{"image", "ls", "--format", "json"} }

// isPullRef says whether s is exactly release.RegistryPrefix + service + "@" + digest.
func isPullRef(s string) bool {
	rest, ok := strings.CutPrefix(s, release.RegistryPrefix)
	if !ok {
		return false
	}
	svc, digest, ok := strings.Cut(rest, "@")
	return ok && knownService(svc) && digestRE.MatchString(digest)
}

// isLocalTag says whether s is exactly localhost/vedette-<service>:<version>.
func isLocalTag(s string) bool {
	rest, ok := strings.CutPrefix(s, localPrefix)
	if !ok {
		return false
	}
	svc, version, ok := strings.Cut(rest, ":")
	return ok && knownService(svc) && len(version) <= 64 && tagVersionRE.MatchString(version)
}

// validatePodman is the validator of the podman binary: the six shapes above.
func validatePodman(args []string) error {
	switch {
	case len(args) == 3 && args[0] == "container" && args[1] == "inspect" && slices.ContainsFunc(api.Services, func(s string) bool { return args[2] == containerName(s) }):
		return nil
	case len(args) == 3 && args[0] == "pull" && args[1] == "-q" && isPullRef(args[2]):
		return nil
	case len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[2] == "--format" && args[3] == "json" && (isPullRef(args[4]) || isLocalTag(args[4])):
		return nil
	case len(args) == 3 && args[0] == "tag" && isPullRef(args[1]) && isLocalTag(args[2]):
		return nil
	case slices.Equal(args, listImagesArgv()):
		return nil
	case len(args) == 2 && args[0] == "rmi" && digestRE.MatchString(args[1]):
		return nil
	}
	return errPodmanArgs
}
