package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
)

// Image retention (spec 6.8, D-104 (6), D-130 (4), D-138). After a start or rollback that worked, the
// images of that service that nothing keeps are removed with "podman rmi <image id>", after "podman untag <id> <tag>"
// of its local tags: Podman refuses rmi by ID of an image with more than one name (exit 125, "by ID with more than
// one tag"), and every release the host pulled has two, localhost/vedette-<service>:<version> and the pull reference
// (Podman 4.9.3 in the lab VM, 2026-11-12, docs/lab/2026-11-12-podman-nuclei.md). The image keeps one name, so a
// failed rmi leaves it listed for the next run:
//
//	kept: the digest of every unit, of every current and previous version, of every pulled record
//	      (of all services, so an image two services share is never removed), and the digest the
//	      service's container reports;
//	not touched: any image that has a name outside this service's two repositories
//	      (ghcr.io/knt048/vedette-<service>, localhost/vedette-<service>), or no name at all, or a
//	      container (Podman's own "Containers" count; and rmi has no force flag, so Podman refuses an
//	      image that a container uses anyway).
//
// The one image with no name that is the service's own is a scan image built on the box whose tag moved to a newer build of the
// same version (D-147 (2)), or a build that failed its check and could not be removed then: it carries the label of the constant
// Containerfile (scanBuildLabel, the same mark install.sh --uninstall removes it by), and it is removed by its ID when no unit,
// record or container keeps "sha256:<ID>" (D-316 (10)).
//
// There is no "image prune -a". A failed rmi is logged and audited, and never fails the run: the
// service already switched. The list Podman prints is untrusted: strict, capped, and an image that
// does not read as expected is left alone.

const (
	// maxListedImages caps the images read from one listing.
	maxListedImages = 512
	// maxRmiPerRun bounds the removals of one run (the rest is for the next one).
	maxRmiPerRun = 16
	rmiLimit     = probeLimit
)

type imageListDoc struct {
	ID          string            `json:"Id"`
	Digest      string            `json:"Digest"`
	Names       []string          `json:"Names"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Containers  int               `json:"Containers"`
	Labels      map[string]string `json:"Labels"`
}

// listedImage is an image that belongs to the service and may be considered for removal.
type listedImage struct {
	ID      string   // what rmi is given: the 64-hex image ID (a digest names a manifest, not always one image)
	Digests []string // every digest the image is known by (Digest and its RepoDigests); the keep check reads these
	InUse   bool
	Untag   []string // local tags taken off before rmi, so that the image has one name left (rmi by ID refuses more)
}

var errImageList = errors.New("ops: podman image ls output is not usable")

// ParseImageList reads the output of "podman image ls --format json" and returns the images that
// belong to service and nothing else: a JSON array (nothing after it, 1 MiB at most, 512 images at
// most) whose entries have an Id of 64 hex digits, a Digest of the form sha256:<64 hex> and at least one name, every name of
// which is in ghcr.io/knt048/vedette-<service> or localhost/vedette-<service> (with a tag or a digest
// or neither); for scan also an entry with no name at all that carries the build label (scanBuildLabel).
// An entry that does not read like that is left out, not an error; an output that is not that array is
// an error. Exported for fuzzing.
func ParseImageList(out []byte, service string) ([]string, error) {
	imgs, err := parseImageList(out, service)
	var ids []string
	for _, i := range imgs {
		ids = append(ids, i.ID)
	}
	return ids, err
}

func parseImageList(out []byte, service string) ([]listedImage, error) {
	if !knownService(service) || len(out) == 0 || len(out) > maxInspectOutput {
		return nil, errImageList
	}
	var docs []imageListDoc
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&docs); err != nil {
		return nil, errImageList
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errImageList
	}
	if len(docs) > maxListedImages {
		return nil, errImageList
	}
	var res []listedImage
	for _, d := range docs {
		if !imageIDRE.MatchString(d.ID) || len(d.Names)+len(d.RepoTags)+len(d.RepoDigests) > 3*maxRepoDigests {
			continue
		}
		names := slices.Concat(d.Names, d.RepoTags, d.RepoDigests)
		if len(names) == 0 {
			if services[service].byID && d.Labels[scanBuildLabel] == scanBuildLabelValue { // a build of the box that lost its tag (L4)
				res = append(res, listedImage{ID: d.ID, Digests: []string{"sha256:" + d.ID}, InUse: d.Containers != 0})
			}
			continue
		}
		if !digestRE.MatchString(d.Digest) || !slices.ContainsFunc(names, func(n string) bool { return ownedName(n, service) }) {
			continue
		}
		if slices.ContainsFunc(names, func(n string) bool { return !ownedName(n, service) }) {
			continue
		}
		img := listedImage{ID: d.ID, Digests: []string{d.Digest}, InUse: d.Containers != 0}
		if len(d.Names) > 1 { // Podman's own names; RepoTags is null and RepoDigests does not count (lab, Podman 4.9.3)
			for _, n := range d.Names {
				if isLocalTag(n) || isNmapTag(n) {
					img.Untag = append(img.Untag, n)
				}
			}
			if len(img.Untag) == len(d.Names) {
				img.Untag = img.Untag[1:] // only local tags: one stays, rmi by ID removes an image with one name
			}
			if len(d.Names)-len(img.Untag) > 1 {
				// two or more registry names would be left, and rmi by ID would refuse it on every run: left alone, not
				// counted against the cap (not seen in the lab, where a pulled image had one registry name; IMPACT.md)
				continue
			}
		}
		if services[service].byID {
			img.Digests = append(img.Digests, "sha256:"+d.ID) // the image built on the box is kept by its ID (D-147)
		}
		for _, rd := range d.RepoDigests {
			if _, dg, ok := strings.Cut(rd, "@"); ok && digestRE.MatchString(dg) && !slices.Contains(img.Digests, dg) {
				img.Digests = append(img.Digests, dg)
			}
		}
		res = append(res, img)
	}
	return res, nil
}

// untagImage takes img's extra local tags off and returns the tags it took off; false when one of them could not be (the
// image then stays, with the tags not yet taken off).
func (o *Ops) untagImage(ctx context.Context, img listedImage) ([]string, bool) {
	var done []string
	for _, tag := range img.Untag {
		argv, err := untagArgv(img.ID, tag)
		if err != nil {
			return done, false
		}
		uctx, cancel := context.WithTimeout(ctx, rmiLimit)
		_, code, err := o.exec(uctx, binPodman, argv...)
		cancel()
		if err != nil || code != 0 {
			return done, false
		}
		done = append(done, tag)
	}
	return done, true
}

// ownedName says whether name is a reference into one of the two repositories of service.
func ownedName(name, service string) bool {
	repo := name
	if i := strings.IndexByte(repo, '@'); i >= 0 {
		if !digestRE.MatchString(repo[i+1:]) {
			return false
		}
		repo = repo[:i]
	}
	if i := strings.LastIndexByte(repo, ':'); i >= 0 && i > strings.LastIndexByte(repo, '/') {
		tag := repo[i+1:]
		if tag == "" || len(tag) > 128 {
			return false
		}
		repo = repo[:i]
	}
	return repo == release.RegistryPrefix+service || repo == localPrefix+service || (service == api.ServiceScan && repo == strings.TrimSuffix(nmapTagPrefix, ":"))
}

// keptDigests is every digest retention must not remove (see the head of this file).
func (o *Ops) keptDigests(ctx context.Context, service string) map[string]bool {
	keep := map[string]bool{}
	for _, svc := range api.Services {
		if text, st := o.readUnit(svc); st == fileOK {
			if d, _, err := o.ourUnit(svc, text); err == nil {
				keep[d] = true
			}
		}
		vs := o.loadVersions(svc)
		for _, r := range []*versionRecord{vs.Current, vs.Previous} {
			if r != nil {
				keep[r.Digest] = true
				if r.BaseDigest != "" {
					keep[r.BaseDigest] = true // the signed base a scan image was built from stays (D-147)
				}
			}
		}
		if r, ok := o.loadPulled(svc); ok {
			keep[r.Digest] = true
			if r.BaseDigest != "" {
				keep[r.BaseDigest] = true
			}
		}
	}
	if info, err := o.inspect(ctx, service); err == nil {
		keep[info.Digest] = true
	}
	return keep
}

// retainImages removes the images of service that nothing keeps. It never returns an error.
func (o *Ops) retainImages(ctx context.Context, rc *server.RunContext, command, service string) {
	keep := o.keptDigests(ctx, service)
	cctx, cancel := context.WithTimeout(ctx, probeLimit)
	res, code, err := o.exec(cctx, binPodman, listImagesArgv()...)
	cancel()
	if err != nil || code != 0 || res.Truncated {
		rcLog(rc, "retention: the list of images could not be read; no image was removed")
		return
	}
	imgs, err := parseImageList(res.Stdout, service)
	if err != nil {
		rcLog(rc, "retention: the list of images is not usable; no image was removed")
		return
	}
	removed := 0
	for _, img := range imgs {
		if img.InUse || slices.ContainsFunc(img.Digests, func(d string) bool { return keep[d] }) {
			continue
		}
		if removed == maxRmiPerRun {
			rcLog(rc, "retention: more images are left for the next run")
			return
		}
		removed++
		argv, err := rmiArgv(img.ID)
		if err != nil {
			continue
		}
		untagged, ok := o.untagImage(ctx, img)
		if ok {
			rctx, cancel := context.WithTimeout(ctx, rmiLimit)
			_, code, err := o.exec(rctx, binPodman, argv...)
			cancel()
			ok = err == nil && code == 0
		}
		detail := map[string]any{"service": service, "image_id": img.ID, "digests": img.Digests, "run_id": rcID(rc)}
		if len(untagged) > 0 {
			detail["untagged"] = untagged // also when rmi then failed: the image is left with one name, its tags are gone
		}
		if !ok {
			rcLog(rc, "retention: podman could not remove "+img.ID+"; it stays")
			o.log.WarnContext(ctx, "retention: podman rmi failed", "service", service, "image_id", img.ID)
			detail["removed"] = false
			o.note(command, "image_removal_failed", detail)
			continue
		}
		rcLog(rc, "retention: removed the image "+img.ID)
		detail["removed"] = true
		o.note(command, "image_removed", detail)
	}
}
