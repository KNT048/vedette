package main

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// The sensor protocol gate of release-manifest (D-410, D-459, docs/specs/sensor-protocol.md §10). core accepts its own protocol
// (sensorlink.ProtoVersion) and the one before (sensorlink.ProtoPrevious); an update moves core first, then the sensors. So a box may
// update straight to this release only from a release whose sensors speak at least ProtoPrevious: min_upgrade_from must exclude every
// earlier release below that. The protocols are read from git at each tag, never typed by hand.

// sensorProtoFile holds sensorlink.ProtoVersion.
const sensorProtoFile = "core/sensorlink/limits.go"

var (
	sensorProtoRE     = regexp.MustCompile(`(?m)^\s*ProtoVersion\s*=\s*"([1-9][0-9]{0,5})"`)
	sensorProtoPrevRE = regexp.MustCompile(`(?m)^\s*ProtoPrevious\s*=\s*"([0-9]{1,6})"`)
)

// releaseProto is the sensor protocol of one earlier release.
type releaseProto struct {
	Version string
	Proto   int
}

// sensorProtoAt reads sensorlink.ProtoVersion and, when prev, sensorlink.ProtoPrevious (the oldest protocol core accepts) of ref from git.
func sensorProtoAt(ctx context.Context, repo, ref string, prev bool) (cur, accepts int, err error) {
	if !gitRefRE.MatchString(ref) || strings.Contains(ref, "..") {
		return 0, 0, fmt.Errorf("git ref %q is not a plain tag, branch or commit name", ref)
	}
	b, err := gitRun(ctx, repo, "show", ref+":"+sensorProtoFile)
	if err != nil {
		return 0, 0, fmt.Errorf("the sensor protocol of %s: %w", ref, err)
	}
	m := sensorProtoRE.FindSubmatch(b)
	if m == nil {
		return 0, 0, fmt.Errorf("the sensor protocol of %s: no ProtoVersion = \"<n>\" in %s", ref, sensorProtoFile)
	}
	if cur, err = strconv.Atoi(string(m[1])); err != nil || !prev {
		return cur, 0, err
	}
	if m = sensorProtoPrevRE.FindSubmatch(b); m == nil {
		return 0, 0, fmt.Errorf("the sensor protocol of %s: no ProtoPrevious = \"<n>\" in %s", ref, sensorProtoFile)
	}
	if accepts, err = strconv.Atoi(string(m[1])); err != nil || accepts >= cur {
		return 0, 0, fmt.Errorf("the sensor protocol of %s: ProtoPrevious %s is not below ProtoVersion %d", ref, m[1], cur)
	}
	return cur, accepts, nil
}

// earlierProtos reads the sensor protocol of every release tag of repo below version: v<SemVer>, never a -test. one (those are
// the test channel), oldest first.
func earlierProtos(ctx context.Context, repo, version string) ([]releaseProto, error) {
	out, err := gitRun(ctx, repo, "tag", "--list", "v*")
	if err != nil {
		return nil, err
	}
	var res []releaseProto
	for _, tag := range strings.Fields(string(out)) {
		v := strings.TrimPrefix(tag, "v")
		if _, err := release.CompareVersions(v, v); err != nil || refuseTestVersion(v) != nil {
			continue
		}
		if c, _ := release.CompareVersions(v, version); c >= 0 {
			continue
		}
		p, _, err := sensorProtoAt(ctx, repo, tag, false)
		if err != nil {
			return nil, err
		}
		res = append(res, releaseProto{Version: v, Proto: p})
	}
	slices.SortFunc(res, func(a, b releaseProto) int { c, _ := release.CompareVersions(a.Version, b.Version); return c })
	return res, nil
}

// checkTagsCover refuses a clone that lacks the tag of a release the published index names (the latest of each channel): the gate
// below would not see that release, and pass for it. A clone made before kien pushed a tag, or with --no-tags, is the case.
func checkTagsCover(earlier []releaseProto, idx *release.Index) error {
	if idx == nil {
		return nil
	}
	for name, ch := range idx.Channels {
		if refuseTestVersion(ch.Latest) != nil {
			continue
		}
		if !slices.ContainsFunc(earlier, func(e releaseProto) bool { return e.Version == ch.Latest }) {
			return fmt.Errorf("no tag v%s here, the latest of channel %s in the published index: fetch the tags (git fetch --tags origin) so the sensor protocol gate sees every release", ch.Latest, name)
		}
	}
	return nil
}

// checkSensorProto refuses a release whose core accepts sensor protocols accepts..cur when min_upgrade_from lets a box update straight
// from an earlier release whose sensors speak an older one: core would refuse them (426) until they are updated too, and a failed
// update would leave the box with sensors core never accepts again. A release whose sensors are at least accepts is fine (D-459).
func checkSensorProto(version, minUpgradeFrom string, cur, accepts int, earlier []releaseProto) error {
	last, lastProto := "", 0 // the newest earlier release whose protocol core no longer accepts
	for _, e := range earlier {
		if e.Proto < accepts {
			last, lastProto = e.Version, e.Proto
		}
	}
	if last == "" {
		return nil
	}
	next := ""
	for _, e := range earlier {
		if c, _ := release.CompareVersions(e.Version, last); c > 0 {
			next = e.Version
			break
		}
	}
	if next == "" {
		return fmt.Errorf("release %s speaks sensor protocol %d and every earlier release speaks below %d: no box could update to it (core accepts %d to %d only); release one with protocol %d first (docs/specs/sensor-protocol.md §10)", version, cur, accepts, accepts, cur, accepts)
	}
	if minUpgradeFrom != "" {
		if c, err := release.CompareVersions(minUpgradeFrom, last); err == nil && c > 0 {
			return nil
		}
	}
	return fmt.Errorf("release %s speaks sensor protocol %d and release %s speaks %d, which core no longer accepts: set min_upgrade_from to %s or later (RELEASE_MIN_UPGRADE_FROM of make release-in, or min_upgrade_from in release.in.json; docs/specs/sensor-protocol.md §10), got %q", version, cur, last, lastProto, next, minUpgradeFrom)
}
