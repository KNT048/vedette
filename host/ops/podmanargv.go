package ops

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// The argv of podman (spec 6.7, D-104 (1), D-130, D-138). Seven shapes and no others:
//
//	container inspect vedette-<service>
//	pull -q ghcr.io/knt048/vedette-<service>@sha256:<64 hex>
//	image inspect --format json <ref>          ref: the pull reference or localhost/vedette-<service>:<version>
//	tag <pull reference> localhost/vedette-<service>:<version>
//	image ls --format json                     what retention reads (slice 3-8a)
//	rmi <64 hex>                               what retention removes: an image ID, never a name, never -f
//	untag <64 hex> <local tag>                 retention, before rmi: Podman refuses "rmi <ID>" of an image with more than one name
//	                                           (exit 125, Podman 4.9.3 in the lab, 2026-11-12), and a pulled release has two (its
//	                                           local tag and its pull reference); local tag: localhost/vedette-<service>:<version>
//	                                           or localhost/vedette-scan-nmap:<version>
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

// localRef is how the host asks podman about an image it holds, given the digest it keeps for it (the "digest" of units, versions and
// records): the pull reference by digest, except for scan, whose image is built on the box and has no registry digest: its "digest" is
// "sha256:" + the image ID and it is asked about by that bare ID (D-147).
func localRef(service, digest string) (string, error) {
	if service == api.ServiceScan {
		id, ok := strings.CutPrefix(digest, "sha256:")
		if !ok || !imageIDRE.MatchString(id) {
			return "", errPodmanArgs
		}
		return id, nil
	}
	return pullRef(service, digest)
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

// rmiArgv removes one image by its ID (64 lower-case hex, as "image ls" prints it). There is no force flag:
// an image a container uses is refused by Podman itself, which is the last line of the rule that
// retention never removes what runs.
func rmiArgv(id string) ([]string, error) {
	if !imageIDRE.MatchString(id) {
		return nil, errPodmanArgs
	}
	return []string{"rmi", id}, nil
}

// untagArgv takes one local tag off an image (by its ID), so that the image keeps a single name and rmi of its ID removes it.
func untagArgv(id, tag string) ([]string, error) {
	if !imageIDRE.MatchString(id) || !isLocalTag(tag) && !isNmapTag(tag) {
		return nil, errPodmanArgs
	}
	return []string{"untag", id, tag}, nil
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

// The build of the scan image on the box (D-147) adds four shapes (podman builds as root, so each is as closed as the rest):
//
//	build --pull=never --no-cache --network vedette-int --iidfile <context dir>/iid --build-arg BASE_IMAGE=<pull ref of scan> --build-arg NMAP_MIN_VERSION=<floor> --tag localhost/vedette-scan-nmap:<version> <context dir>
//	run --rm --pull=never --network none --cap-drop ALL --read-only --security-opt no-new-privileges --memory=256m --pids-limit=64 --entrypoint nmap <image id> --version
//	tag <image id> localhost/vedette-scan-nmap:<version>      puts the previous image back under its tag after a build that failed the check
//	image inspect --format json <image id>                    (also a shape of the list above: ref is an ID)
//
// The base reference is the pull reference of the digest that was verified, the floor is a constant, the tag is built from a version that
// passed tagVersionRE, the context is a directory the host made (a plain absolute path), and the Containerfile in it is a constant of the
// binary. Nothing a request carried is text in any of them. --no-cache because a cached apt layer would never see a newer nmap.
// --network vedette-int (#467): the RUN step needs the internet, and on a box with Docker (FORWARD policy DROP) only Vedette's own network
// is let through, by the DOCKER-USER rules of dockerfwd.go (D-267); podman's default network would be dropped. Never host, never another.

const (
	nmapTagPrefix = "localhost/vedette-scan-nmap:"
	// nmapFloor is NMAP_MIN_VERSION of deploy/containers/pins.env (a test keeps the two equal): the oldest nmap the build accepts.
	nmapFloor = "7.95"
)

// buildDirRE is the context directory of a build: absolute, plain characters, no empty, "." or ".." segment (checked apart).
var buildDirRE = regexp.MustCompile(`^(/[A-Za-z0-9_][A-Za-z0-9._-]*){1,16}$`)

func validBuildDir(p string) bool {
	return len(p) <= 240 && buildDirRE.MatchString(p) && !strings.Contains(p, "/.")
}

// nmapTag is localhost/vedette-scan-nmap:<version>.
func nmapTag(version string) (string, error) {
	if len(version) > 64 || !tagVersionRE.MatchString(version) {
		return "", errPodmanArgs
	}
	return nmapTagPrefix + version, nil
}

func isNmapTag(s string) bool {
	v, ok := strings.CutPrefix(s, nmapTagPrefix)
	return ok && len(v) <= 64 && tagVersionRE.MatchString(v)
}

func buildArgv(digest, version, dir string) ([]string, error) {
	ref, err := pullRef(api.ServiceScan, digest)
	if err != nil {
		return nil, err
	}
	tag, err := nmapTag(version)
	if err != nil || !validBuildDir(dir) {
		return nil, errPodmanArgs
	}
	return []string{"build", "--pull=never", "--no-cache", "--network", intNetwork, "--iidfile", dir + "/" + iidName, "--build-arg", "BASE_IMAGE=" + ref, "--build-arg", "NMAP_MIN_VERSION=" + nmapFloor, "--tag", tag, dir}, nil
}

// iidName is the file in the build context directory where podman writes the ID of the image it built.
const iidName = "iid"

func nmapCheckArgv(id string) ([]string, error) {
	if !imageIDRE.MatchString(id) {
		return nil, errPodmanArgs
	}
	return []string{"run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges", "--memory=256m", "--pids-limit=64", "--entrypoint", "nmap", id, "--version"}, nil
}

func tagIDArgv(id, version string) ([]string, error) {
	tag, err := nmapTag(version)
	if err != nil || !imageIDRE.MatchString(id) {
		return nil, errPodmanArgs
	}
	return []string{"tag", id, tag}, nil
}

func isBuildArgv(a []string) bool {
	if len(a) != 14 || a[0] != "build" || a[1] != "--pull=never" || a[2] != "--no-cache" || a[3] != "--network" || a[4] != intNetwork || a[5] != "--iidfile" ||
		a[7] != "--build-arg" || a[9] != "--build-arg" || a[10] != "NMAP_MIN_VERSION="+nmapFloor || a[11] != "--tag" || !isNmapTag(a[12]) || !validBuildDir(a[13]) ||
		a[6] != a[13]+"/"+iidName {
		return false
	}
	ref, ok := strings.CutPrefix(a[8], "BASE_IMAGE=")
	return ok && isPullRef(ref) && strings.HasPrefix(ref, release.RegistryPrefix+api.ServiceScan+"@")
}

func isNmapCheckArgv(a []string) bool {
	if len(a) != 16 || !imageIDRE.MatchString(a[14]) {
		return false
	}
	want, err := nmapCheckArgv(a[14])
	return err == nil && slices.Equal(a, want)
}

// validatePodman is the validator of the podman binary: the shapes above.
func validatePodman(args []string) error {
	switch {
	case isBuildArgv(args), isNmapCheckArgv(args):
		return nil
	case len(args) == 3 && args[0] == "tag" && imageIDRE.MatchString(args[1]) && isNmapTag(args[2]):
		return nil
	case len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[2] == "--format" && args[3] == "json" && (imageIDRE.MatchString(args[4]) || isNmapTag(args[4])):
		return nil
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
	case len(args) == 2 && args[0] == "rmi" && imageIDRE.MatchString(args[1]):
		return nil
	case len(args) == 3 && args[0] == "untag" && imageIDRE.MatchString(args[1]) && (isLocalTag(args[2]) || isNmapTag(args[2])):
		return nil
	}
	return errPodmanArgs
}
